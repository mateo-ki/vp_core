//! auto-route：操作系统路由表接管与异常退出自愈恢复。
//!
//! 核心保障：
//! 1. 启动前自愈预清理：消除历史进程崩溃/强杀残留的坏路由；
//! 2. 跨平台适配：Windows (route.exe) / Linux (iproute2) / macOS (BSD route)；
//! 3. RAII 资源守卫：AutoRouteGuard 在 Drop 时自动恢复路由；
//! 4. 全局一键恢复：clean_all_routes 清理可能残留的所有 TUN 网段及双 /1 路由。

use std::net::IpAddr;
use std::process::Command;
use tracing::info;
#[cfg(windows)]
use tracing::warn;

use vp_common::{Error, Result};

/// auto-route 可选策略配置
#[derive(Debug, Clone, Default)]
pub struct AutoRouteOptions {
    /// 路由策略模式：full（接管双 /1 全流量）或 fake-ip-only（仅接管 fake-ip 网段）
    pub mode: Option<String>,
    /// 自定义额外下发的 CIDR 列表（如 ["10.0.0.0/8"]）
    pub route_address: Vec<String>,
    /// 排除的 CIDR 列表
    pub route_exclude_address: Vec<String>,
}

/// RAII 路由守护器：生命周期结束或发生 panic 时自动清理路由
pub struct AutoRouteGuard {
    address: String,
    netmask: String,
    opts: AutoRouteOptions,
    active: bool,
}

impl AutoRouteGuard {
    pub fn new(address: &str, netmask: &str) -> Self {
        Self {
            address: address.to_string(),
            netmask: netmask.to_string(),
            opts: AutoRouteOptions::default(),
            active: true,
        }
    }

    pub fn new_with_options(address: &str, netmask: &str, opts: AutoRouteOptions) -> Self {
        Self {
            address: address.to_string(),
            netmask: netmask.to_string(),
            opts,
            active: true,
        }
    }

    pub fn disable(&mut self) {
        if self.active {
            let _ = disable_with_options(&self.address, &self.netmask, &self.opts);
            self.active = false;
        }
    }
}

impl Drop for AutoRouteGuard {
    fn drop(&mut self) {
        self.disable();
    }
}

/// 启用 auto-route（默认全量双 /1 模式）
/// 启用 auto-route（默认全量双 /1 模式）
pub fn enable(address: &str, netmask: &str) -> Result<AutoRouteGuard> {
    enable_with_options(address, netmask, &AutoRouteOptions::default())
}

/// 启用带策略的 auto-route
pub fn enable_with_options(
    address: &str,
    netmask: &str,
    opts: &AutoRouteOptions,
) -> Result<AutoRouteGuard> {
    // 1. 启动前无条件自愈清理：消除前序崩溃遗留的孤儿路由，避免 Windows "已存在" 报错
    let _ = disable_with_options(address, netmask, opts);

    let addr: IpAddr = address
        .parse()
        .map_err(|e| Error::Config(format!("tun 地址非法: {e}")))?;
    let mask: IpAddr = netmask
        .parse()
        .map_err(|e| Error::Config(format!("tun 掩码非法: {e}")))?;
    let (net, prefix) = network_of(addr, mask)?;
    let _ = prefix;

    let is_fake_ip_only = opts
        .mode
        .as_deref()
        .map(|m| m.eq_ignore_ascii_case("fake-ip-only") || m.eq_ignore_ascii_case("fakeip-only"))
        .unwrap_or(false);

    #[cfg(windows)]
    {
        // 1. 基础 TUN 网段路由
        let out = Command::new("route")
            .args([
                "add",
                &net,
                "mask",
                &mask.to_string(),
                address,
                "metric",
                "1",
            ])
            .output()
            .map_err(|e| Error::Other(format!("route 命令执行失败: {e}")))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let detail = String::from_utf8_lossy(&out.stdout);
            return Err(Error::Other(format!(
                "route add 基础网段失败: {}{}",
                detail.trim(),
                stderr.trim()
            )));
        }

        // 2. 接管全网双 /1 拆分路由（若非 fake-ip-only）
        if !is_fake_ip_only {
            let mut installed = 0;
            for (net_route, mask_route) in [("0.0.0.0", "128.0.0.0"), ("128.0.0.0", "128.0.0.0")] {
                match Command::new("route")
                    .args(["add", net_route, "mask", mask_route, address, "metric", "1"])
                    .output()
                {
                    Ok(out) if out.status.success() => installed += 1,
                    Ok(out) => {
                        let detail = String::from_utf8_lossy(&out.stdout);
                        let detail = detail.trim();
                        let detail = if detail.is_empty() {
                            String::from_utf8_lossy(&out.stderr).trim().to_string()
                        } else {
                            detail.to_string()
                        };
                        warn!(
                            "route add {net_route} mask {mask_route} 失败（exit={}，{detail}）\
                             —— 该半区流量不会被 TUN 接管",
                            out.status.code().unwrap_or(-1)
                        );
                    }
                    Err(e) => warn!("route add {net_route} mask {mask_route} 执行失败: {e}"),
                }
            }
            if installed == 2 {
                info!(
                    "Windows auto-route 启用: {net}/{mask} + 0.0.0.0/1 + 128.0.0.0/1 -> {address}"
                );
            } else {
                warn!(
                    "Windows auto-route 不完整：双 /1 路由仅成功 {installed}/2，\
                     TUN 无法接管全部系统流量（常见原因：进程无管理员权限）"
                );
            }
        } else {
            info!(
                "Windows auto-route: fake-ip-only 模式已生效，仅接管 {net}/{mask}，保留系统默认路由"
            );
        }

        // 3. 自定义路由下发
        for cidr in &opts.route_address {
            if let Some((c_ip, c_plen)) = cidr.split_once('/') {
                if let Ok(plen) = c_plen.parse::<u8>() {
                    let m_u32 = if plen == 0 {
                        0
                    } else {
                        !((1u32 << (32 - plen)) - 1)
                    };
                    let m_ip = std::net::Ipv4Addr::from(m_u32);
                    let _ = Command::new("route")
                        .args([
                            "add",
                            c_ip,
                            "mask",
                            &m_ip.to_string(),
                            address,
                            "metric",
                            "1",
                        ])
                        .output();
                    info!("Windows auto-route 自定义路由已添加: {cidr} -> {address}");
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let cidr = format!("{net}/{prefix}");
        let out = Command::new("ip")
            .args(["route", "replace", &cidr, "dev", "vpcore-tun"])
            .output()
            .map_err(|e| Error::Other(format!("ip route 执行失败: {e}")))?;
        if !out.status.success() {
            return Err(Error::Other(format!(
                "ip route 失败: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        if !is_fake_ip_only {
            let _ = Command::new("ip")
                .args(["route", "replace", "0.0.0.0/1", "dev", "vpcore-tun"])
                .output();
            let _ = Command::new("ip")
                .args(["route", "replace", "128.0.0.0/1", "dev", "vpcore-tun"])
                .output();
            info!("Linux auto-route 启用: {cidr} + 0.0.0.0/1 + 128.0.0.0/1 dev vpcore-tun");
        } else {
            info!("Linux auto-route: fake-ip-only 模式已生效，仅接管 {cidr} dev vpcore-tun");
        }

        for c in &opts.route_address {
            let _ = Command::new("ip")
                .args(["route", "replace", c, "dev", "vpcore-tun"])
                .output();
            info!("Linux auto-route 自定义路由已添加: {c} dev vpcore-tun");
        }
    }

    #[cfg(target_os = "macos")]
    {
        let out = Command::new("route")
            .args(["add", "-net", &net, "-netmask", &mask.to_string(), address])
            .output()
            .map_err(|e| Error::Other(format!("macOS route 执行失败: {e}")))?;
        if !out.status.success() {
            return Err(Error::Other(format!(
                "macOS route 失败: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        if !is_fake_ip_only {
            let _ = Command::new("route")
                .args(["add", "-net", "0.0.0.0/1", address])
                .output();
            let _ = Command::new("route")
                .args(["add", "-net", "128.0.0.0/1", address])
                .output();
            info!("macOS auto-route 启用: {net} + 0.0.0.0/1 + 128.0.0.0/1 -> {address}");
        } else {
            info!("macOS auto-route: fake-ip-only 模式已生效，仅接管 {net} -> {address}");
        }

        for c in &opts.route_address {
            let _ = Command::new("route")
                .args(["add", "-net", c, address])
                .output();
            info!("macOS auto-route 自定义路由已添加: {c} -> {address}");
        }
    }

    Ok(AutoRouteGuard::new_with_options(
        address,
        netmask,
        opts.clone(),
    ))
}

/// 禁用并清理路由（默认模式）
pub fn disable(address: &str, netmask: &str) -> Result<()> {
    disable_with_options(address, netmask, &AutoRouteOptions::default())
}

/// 禁用并清理带选项的路由
pub fn disable_with_options(address: &str, netmask: &str, opts: &AutoRouteOptions) -> Result<()> {
    let addr: IpAddr = address
        .parse()
        .map_err(|e| Error::Config(format!("tun 地址非法: {e}")))?;
    let mask: IpAddr = netmask
        .parse()
        .map_err(|e| Error::Config(format!("tun 掩码非法: {e}")))?;
    let (net, prefix) = network_of(addr, mask)?;
    let _ = prefix;

    #[cfg(windows)]
    {
        let _ = Command::new("route")
            .args(["delete", &net, "mask", &mask.to_string(), address])
            .output();
        let _ = Command::new("route")
            .args(["delete", "0.0.0.0", "mask", "128.0.0.0"])
            .output();
        let _ = Command::new("route")
            .args(["delete", "128.0.0.0", "mask", "128.0.0.0"])
            .output();
        for cidr in &opts.route_address {
            if let Some((c_ip, c_plen)) = cidr.split_once('/') {
                if let Ok(plen) = c_plen.parse::<u8>() {
                    let m_u32 = if plen == 0 {
                        0
                    } else {
                        !((1u32 << (32 - plen)) - 1)
                    };
                    let m_ip = std::net::Ipv4Addr::from(m_u32);
                    let _ = Command::new("route")
                        .args(["delete", c_ip, "mask", &m_ip.to_string()])
                        .output();
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let cidr = format!("{net}/{prefix}");
        let _ = Command::new("ip")
            .args(["route", "del", &cidr, "dev", "vpcore-tun"])
            .output();
        let _ = Command::new("ip")
            .args(["route", "del", "0.0.0.0/1", "dev", "vpcore-tun"])
            .output();
        let _ = Command::new("ip")
            .args(["route", "del", "128.0.0.0/1", "dev", "vpcore-tun"])
            .output();
        for c in &opts.route_address {
            let _ = Command::new("ip")
                .args(["route", "del", c, "dev", "vpcore-tun"])
                .output();
        }
    }

    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("route")
            .args([
                "delete",
                "-net",
                &net,
                "-netmask",
                &mask.to_string(),
                address,
            ])
            .output();
        let _ = Command::new("route")
            .args(["delete", "-net", "0.0.0.0/1"])
            .output();
        let _ = Command::new("route")
            .args(["delete", "-net", "128.0.0.0/1"])
            .output();
        for c in &opts.route_address {
            let _ = Command::new("route").args(["delete", "-net", c]).output();
        }
    }

    Ok(())
}

/// 一键清理所有 TUN 历史残留路由（应急恢复工具）
pub fn clean_all_routes() -> Result<()> {
    let _ = disable("198.18.0.1", "255.255.0.0");

    #[cfg(windows)]
    {
        let _ = Command::new("route")
            .args(["delete", "0.0.0.0", "mask", "128.0.0.0"])
            .output();
        let _ = Command::new("route")
            .args(["delete", "128.0.0.0", "mask", "128.0.0.0"])
            .output();
    }

    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("ip")
            .args(["route", "del", "0.0.0.0/1"])
            .output();
        let _ = Command::new("ip")
            .args(["route", "del", "128.0.0.0/1"])
            .output();
    }

    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("route")
            .args(["delete", "-net", "0.0.0.0/1"])
            .output();
        let _ = Command::new("route")
            .args(["delete", "-net", "128.0.0.0/1"])
            .output();
    }

    info!("已完成系统 TUN 路由自愈与残留清理");
    Ok(())
}

/// 计算网络地址与前缀长度
fn network_of(addr: IpAddr, mask: IpAddr) -> Result<(String, u8)> {
    let (IpAddr::V4(a), IpAddr::V4(m)) = (addr, mask) else {
        return Err(Error::Config("auto-route 暂只支持 IPv4".into()));
    };
    let net = std::net::Ipv4Addr::from(u32::from(a) & u32::from(m));
    let prefix = u32::from(m).count_ones() as u8;
    Ok((net.to_string(), prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_of() {
        let (net, prefix) = network_of(
            "198.18.0.1".parse().unwrap(),
            "255.255.0.0".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(net, "198.18.0.0");
        assert_eq!(prefix, 16);
    }
}

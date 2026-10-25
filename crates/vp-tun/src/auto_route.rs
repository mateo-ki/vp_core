//! auto-route：为 TUN 接口写入默认路由（Windows route add / Linux ip route）。

use std::net::IpAddr;
use std::process::Command;

use vp_common::{Error, Result};

/// 启用 auto-route：
/// - Windows：route add <netmask 网段> mask <mask> <tun 地址> metric 1
/// - Linux：ip route add <网段> dev tun
/// 完整默认路由接管（0.0.0.0/1 + 128.0.0.0/1 双路由方案）随 M3 完善。
pub fn enable(address: &str, netmask: &str) -> Result<()> {
    let addr: IpAddr = address
        .parse()
        .map_err(|e| Error::Config(format!("tun 地址非法: {e}")))?;
    let mask: IpAddr = netmask
        .parse()
        .map_err(|e| Error::Config(format!("tun 掩码非法: {e}")))?;
    let (net, _prefix) = network_of(addr, mask)?;
    #[cfg(windows)]
    {
        let out = Command::new("route")
            .args(["add", &net, "mask", &mask.to_string(), address, "metric", "1"])
            .output()
            .map_err(|e| Error::Other(format!("route 命令执行失败: {e}")))?;
        if !out.status.success() {
            return Err(Error::Other(format!(
                "route add 失败: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = prefix;
        let out = Command::new("ip")
            .args(["route", "replace", &net, "dev", "vpcore-tun"])
            .output()
            .map_err(|e| Error::Other(format!("ip route 执行失败: {e}")))?;
        if !out.status.success() {
            return Err(Error::Other(format!(
                "ip route 失败: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(())
    }
}

pub fn disable(address: &str, netmask: &str) -> Result<()> {
    let addr: IpAddr = address
        .parse()
        .map_err(|e| Error::Config(format!("tun 地址非法: {e}")))?;
    let mask: IpAddr = netmask
        .parse()
        .map_err(|e| Error::Config(format!("tun 掩码非法: {e}")))?;
    let (net, _) = network_of(addr, mask)?;
    #[cfg(windows)]
    {
        let out = Command::new("route")
            .args(["delete", &net, "mask", &mask.to_string(), address])
            .output()
            .map_err(|e| Error::Other(format!("route delete 失败: {e}")))?;
        let _ = out;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let out = Command::new("ip")
            .args(["route", "del", &net, "dev", "vpcore-tun"])
            .output();
        let _ = out;
        Ok(())
    }
}

/// 计算网络地址与前缀长度
fn network_of(addr: IpAddr, mask: IpAddr) -> Result<(String, u8)> {
    let (IpAddr::V4(a), IpAddr::V4(m)) = (addr, mask) else {
        return Err(Error::Config("auto-route 暂只支持 IPv4".into()));
    };
    let (ab, mb) = (u32::from(a), u32::from(m));
    let prefix = (!mb).trailing_ones() as u8;
    let net = std::net::Ipv4Addr::from(ab & mb);
    Ok((net.to_string(), prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_calc() {
        let (net, p) = network_of(
            "198.18.0.1".parse().unwrap(),
            "255.255.0.0".parse().unwrap(),
        )
        .unwrap();
        assert_eq!((net.as_str(), p), ("198.18.0.0", 16));
    }

    #[test]
    fn v6_rejected() {
        assert!(network_of("::1".parse().unwrap(), "ffff::".parse().unwrap()).is_err());
    }
}

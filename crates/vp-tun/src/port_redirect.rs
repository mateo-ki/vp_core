//! Linux iptables / ip6tables UDP 多端口重定向与抗 QoS 自动守护器。
//!
//! 功能特性：
//! 1. 启动时自动检查与注入内核 REDIRECT 规则，将端口跳跃范围（如 20000-40000）重定向到主监听端口；
//! 2. RAII 资源守护：`IptablesPortRedirectGuard` 在生命周期结束或进程退出时自动清理已注入的规则；
//! 3. 孤儿规则深度自愈：所有规则统一打上 `vpcore-mport-<listener>` 注释标签，
//!    联动 `vpcore clean-routes` 可随时一键全盘扫描并彻底清除残留规则；
//! 4. 跨平台适配与平滑降级：非 Linux 环境自动编译为空操作（no-op），无 root 权限或未安装 iptables 时输出警告并平滑回退，绝不 panic。

#[allow(unused_imports)]
use tracing::{debug, info, warn};
use vp_common::{Error, Result};

pub const RULE_COMMENT_PREFIX: &str = "vpcore-mport-";

/// 端口范围：(起始端口, 结束端口) 闭区间
pub type PortRange = (u16, u16);

/// 解析端口配置字符串（支持 "20000-40000", "20001,20002", "20000-25000,30000-35000" 等格式）
pub fn parse_port_ranges(spec: &str) -> Vec<PortRange> {
    let mut out = Vec::new();
    for seg in spec.split(',') {
        let seg = seg.trim();
        if seg.is_empty() {
            continue;
        }
        if let Some((a, b)) = seg.split_once('-') {
            if let (Ok(start), Ok(end)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                if start > 0 && end >= start {
                    out.push((start, end));
                }
            }
        } else if let Ok(p) = seg.parse::<u16>() {
            if p > 0 {
                out.push((p, p));
            }
        }
    }
    // 合并重叠或相邻的端口范围并排序
    out.sort_by_key(|r| r.0);
    let mut merged: Vec<PortRange> = Vec::new();
    for (start, end) in out {
        if let Some(last) = merged.last_mut() {
            if start <= last.1.saturating_add(1) {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}

/// 格式化端口范围为 iptables 参数格式（单端口 "20000"，范围 "20000:40000"）
pub fn format_range_arg(range: PortRange) -> String {
    if range.0 == range.1 {
        format!("{}", range.0)
    } else {
        format!("{}:{}", range.0, range.1)
    }
}

/// 解析 iptables -S 输出行为独立的命令行参数（处理引号等）
pub fn parse_iptables_tokens(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut quote_char = ' ';

    for c in line.chars() {
        match c {
            '"' | '\'' if !in_quote => {
                in_quote = true;
                quote_char = c;
            }
            c if in_quote && c == quote_char => {
                in_quote = false;
            }
            ' ' | '\t' if !in_quote => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            _ => {
                current.push(c);
            }
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// RAII 端口重定向守卫：管理已注入的 iptables / ip6tables 规则
#[derive(Debug)]
pub struct IptablesPortRedirectGuard {
    pub listener_name: String,
    pub port_ranges: Vec<PortRange>,
    pub target_port: u16,
    pub ipv6: bool,
    active: bool,
}

impl IptablesPortRedirectGuard {
    /// 构造并立即注入端口重定向规则
    pub fn setup(
        listener_name: &str,
        port_spec: &str,
        target_port: u16,
        ipv6: bool,
    ) -> Result<Self> {
        let port_ranges = parse_port_ranges(port_spec);
        if port_ranges.is_empty() {
            return Err(Error::Config(format!("无效的端口跳跃配置: {port_spec:?}")));
        }

        #[allow(unused_mut)]
        let mut guard = Self {
            listener_name: listener_name.to_string(),
            port_ranges,
            target_port,
            ipv6,
            active: false,
        };

        #[cfg(target_os = "linux")]
        {
            guard.enable_linux()?;
        }

        #[cfg(not(target_os = "linux"))]
        {
            debug!(
                "当前操作系统非 Linux，跳过 iptables 端口重定向注入（监听器: {}）",
                listener_name
            );
        }

        Ok(guard)
    }

    #[cfg(target_os = "linux")]
    fn enable_linux(&mut self) -> Result<()> {
        let comment = format!("{}{}", RULE_COMMENT_PREFIX, self.listener_name);

        for &range in &self.port_ranges {
            let range_str = format_range_arg(range);
            // 1. IPv4 注入
            insert_rule("iptables", &range_str, self.target_port, &comment)?;

            // 2. IPv6 注入（可选）
            if self.ipv6 {
                if let Err(e) = insert_rule("ip6tables", &range_str, self.target_port, &comment) {
                    warn!("ip6tables 注入端口重定向失败（若未启用 IPv6 可忽略）: {e}");
                }
            }
        }

        self.active = true;
        info!(
            "已为入站 [{}] 启用内核级 UDP 端口重定向: 范围 {:?} -> 主端口 {}",
            self.listener_name, self.port_ranges, self.target_port
        );
        Ok(())
    }

    /// 撤销并清理已注入的规则
    pub fn disable(&mut self) {
        if !self.active {
            return;
        }

        #[cfg(target_os = "linux")]
        {
            let comment = format!("{}{}", RULE_COMMENT_PREFIX, self.listener_name);
            for &range in &self.port_ranges {
                let range_str = format_range_arg(range);
                delete_rule("iptables", &range_str, self.target_port, &comment);
                if self.ipv6 {
                    delete_rule("ip6tables", &range_str, self.target_port, &comment);
                }
            }
            info!(
                "已清理入站 [{}] 的内核级 UDP 端口重定向规则",
                self.listener_name
            );
        }

        self.active = false;
    }
}

impl Drop for IptablesPortRedirectGuard {
    fn drop(&mut self) {
        self.disable();
    }
}

#[cfg(target_os = "linux")]
fn check_rule(tool: &str, range_arg: &str, target_port: u16, comment: &str) -> bool {
    let port_str = target_port.to_string();
    let status = std::process::Command::new(tool)
        .args([
            "-t",
            "nat",
            "-C",
            "PREROUTING",
            "-p",
            "udp",
            "--dport",
            range_arg,
            "-m",
            "comment",
            "--comment",
            comment,
            "-j",
            "REDIRECT",
            "--to-ports",
            &port_str,
        ])
        .status();
    status.is_ok_and(|s| s.success())
}

#[cfg(target_os = "linux")]
fn insert_rule(tool: &str, range_arg: &str, target_port: u16, comment: &str) -> Result<()> {
    if check_rule(tool, range_arg, target_port, comment) {
        return Ok(());
    }
    let port_str = target_port.to_string();
    let output = std::process::Command::new(tool)
        .args([
            "-t",
            "nat",
            "-I",
            "PREROUTING",
            "-p",
            "udp",
            "--dport",
            range_arg,
            "-m",
            "comment",
            "--comment",
            comment,
            "-j",
            "REDIRECT",
            "--to-ports",
            &port_str,
        ])
        .output()
        .map_err(Error::Io)?;

    if !output.status.success() {
        let err_msg = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Other(format!(
            "执行 {tool} 端口重定向注入失败（需 root 或 CAP_NET_ADMIN 权限）: {}",
            err_msg.trim()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn delete_rule(tool: &str, range_arg: &str, target_port: u16, comment: &str) {
    let port_str = target_port.to_string();
    // 循环删除直到规则不存在（清理可能存在的重复规则）
    while check_rule(tool, range_arg, target_port, comment) {
        let _ = std::process::Command::new(tool)
            .args([
                "-t",
                "nat",
                "-D",
                "PREROUTING",
                "-p",
                "udp",
                "--dport",
                range_arg,
                "-m",
                "comment",
                "--comment",
                comment,
                "-j",
                "REDIRECT",
                "--to-ports",
                &port_str,
            ])
            .status();
    }
}

/// 扫描并清理系统内所有带有 `vpcore-mport-` 标签的残留规则（包括历史异常遗留的孤儿规则）
pub fn clean_all_port_redirects() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        sweep_tool("iptables")?;
        sweep_tool("ip6tables")?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn sweep_tool(tool: &str) -> Result<()> {
    let output = match std::process::Command::new(tool)
        .args(["-t", "nat", "-S", "PREROUTING"])
        .output()
    {
        Ok(out) => out,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // 工具不存在直接跳过
            return Ok(());
        }
        Err(e) => return Err(Error::Io(e)),
    };

    if !output.status.success() {
        return Ok(());
    }

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if line.contains(RULE_COMMENT_PREFIX) && line.starts_with("-A PREROUTING") {
            let mut tokens = parse_iptables_tokens(line);
            if tokens.len() >= 2 && tokens[0] == "-A" && tokens[1] == "PREROUTING" {
                tokens[0] = "-D".to_string();
                let _ = std::process::Command::new(tool)
                    .args(["-t", "nat"])
                    .args(&tokens)
                    .status();
                debug!("{tool} 已清除残留端口重定向规则: {line}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_port_ranges() {
        // 单端口
        assert_eq!(parse_port_ranges("80"), vec![(80, 80)]);
        // 范围
        assert_eq!(parse_port_ranges("20000-20050"), vec![(20000, 20050)]);
        // 复合与乱序（自动排序）
        assert_eq!(
            parse_port_ranges("30000-30010, 20000-20005, 8080"),
            vec![(8080, 8080), (20000, 20005), (30000, 30010)]
        );
        // 相邻合并 (20000-20005 与 20006-20010 应合并为 20000-20010)
        assert_eq!(
            parse_port_ranges("20000-20005, 20006-20010"),
            vec![(20000, 20010)]
        );
        // 重叠合并
        assert_eq!(
            parse_port_ranges("20000-20050, 20020-20080"),
            vec![(20000, 20080)]
        );
        // 空白与非法字符跳过
        assert_eq!(parse_port_ranges("  , abc, 0, 443 "), vec![(443, 443)]);
    }

    #[test]
    fn test_format_range_arg() {
        assert_eq!(format_range_arg((443, 443)), "443");
        assert_eq!(format_range_arg((20000, 40000)), "20000:40000");
    }

    #[test]
    fn test_parse_iptables_tokens() {
        let line = r#"-A PREROUTING -p udp -m udp --dport 20000:40000 -m comment --comment "vpcore-mport-hy2" -j REDIRECT --to-ports 28282"#;
        let tokens = parse_iptables_tokens(line);
        assert_eq!(tokens[0], "-A");
        assert_eq!(tokens[1], "PREROUTING");
        assert_eq!(tokens[tokens.len() - 1], "28282");
        assert!(tokens.contains(&"vpcore-mport-hy2".to_string()));
    }

    #[test]
    fn test_guard_noop_on_non_linux() {
        let mut guard =
            IptablesPortRedirectGuard::setup("test-listener", "20000-20010", 443, false).unwrap();
        assert_eq!(guard.port_ranges, vec![(20000, 20010)]);
        guard.disable();
    }
}

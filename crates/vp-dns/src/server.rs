//! DNS 服务器：TUN/fake-ip 模式的入口。
//!
//! - fake-ip 模式：A 查询返回池内 IP（TTL=1）；AAAA 返回空；PTR 反查域名
//! - 其余（非 A/AAAA、过滤名单域名）：原样转发上游并回带应答
//! - PTR：in-addr.arpa 反解 → fake-ip 命中则回域名

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tracing::warn;

use vp_common::{Error, Result};

use crate::Resolver;
use crate::fakeip::FakeIpPool;
use crate::wire;

pub struct DnsServer {
    pub listen: SocketAddr,
    resolver: Arc<Resolver>,
    fake_ip: Option<Arc<FakeIpPool>>,
    fake_ip_filter: Vec<String>,
    ipv6: bool,
}

const QTYPE_A: u16 = 1;
const QTYPE_PTR: u16 = 12;
const QTYPE_AAAA: u16 = 28;
const QTYPE_SVCB: u16 = 64;
const QTYPE_HTTPS: u16 = 65;

impl DnsServer {
    pub fn new(
        listen: SocketAddr,
        resolver: Arc<Resolver>,
        fake_ip: Option<Arc<FakeIpPool>>,
        fake_ip_filter: Vec<String>,
        ipv6: bool,
    ) -> Self {
        DnsServer {
            listen,
            resolver,
            fake_ip,
            fake_ip_filter,
            ipv6,
        }
    }

    /// 启动 UDP 与 TCP（同端口）监听，返回实际绑定地址与接收循环任务句柄
    pub async fn spawn_handle(self) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
        let sock = Arc::new(UdpSocket::bind(self.listen).await?);
        let bound = sock.local_addr()?;
        let this = Arc::new(self);
        let resolver = this.resolver.clone();

        // 尝试同端口绑定 TCP DNS 监听器（兼容 dig +tcp / RFC 7766 标准 DNS 查询）
        let tcp_listener = tokio::net::TcpListener::bind(bound).await.ok();

        let handle = tokio::spawn(async move {
            let this_udp = this.clone();
            let sock_udp = sock.clone();
            let resolver_udp = resolver.clone();

            let udp_task = tokio::spawn(async move {
                // RFC 6891: EDNS0 允许最大 4096 字节的 UDP 报文，避免 1500 MTU 截断
                let mut buf = vec![0u8; 4096];
                loop {
                    match sock_udp.recv_from(&mut buf).await {
                        Ok((n, from)) => {
                            let pkt = buf[..n].to_vec();
                            let this = this_udp.clone();
                            let sock = sock_udp.clone();
                            let resolver = resolver_udp.clone();
                            tokio::spawn(async move {
                                if let Err(e) = this.handle(&sock, &pkt, from, &resolver).await {
                                    warn!("dns 查询处理失败: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            warn!("dns 服务器 recv 失败: {e}");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            });

            if let Some(listener) = tcp_listener {
                let this_tcp = this.clone();
                let resolver_tcp = resolver.clone();
                let tcp_task = tokio::spawn(async move {
                    loop {
                        match listener.accept().await {
                            Ok((mut stream, _)) => {
                                let this = this_tcp.clone();
                                let resolver = resolver_tcp.clone();
                                tokio::spawn(async move {
                                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                                    // RFC 7766: TCP 连接上允许连续或流水线发送多个 DNS 查询，维护 10s 空闲保持
                                    let idle_timeout = Duration::from_secs(10);
                                    loop {
                                        let mut len_buf = [0u8; 2];
                                        let read_len = tokio::time::timeout(
                                            idle_timeout,
                                            stream.read_exact(&mut len_buf),
                                        )
                                        .await;
                                        let Ok(Ok(_)) = read_len else {
                                            break;
                                        };
                                        let len = u16::from_be_bytes(len_buf) as usize;
                                        if len == 0 || len > 4096 {
                                            break;
                                        }
                                        let mut pkt = vec![0u8; len];
                                        if stream.read_exact(&mut pkt).await.is_err() {
                                            break;
                                        }
                                        if let Ok(Some(resp)) =
                                            this.process_query(&pkt, &resolver).await
                                        {
                                            let resp_len = (resp.len() as u16).to_be_bytes();
                                            if stream.write_all(&resp_len).await.is_err() {
                                                break;
                                            }
                                            if stream.write_all(&resp).await.is_err() {
                                                break;
                                            }
                                        }
                                    }
                                });
                            }
                            Err(_) => {
                                tokio::time::sleep(Duration::from_millis(50)).await;
                            }
                        }
                    }
                });
                let _ = tokio::join!(udp_task, tcp_task);
            } else {
                let _ = udp_task.await;
            }
        });
        Ok((bound, handle))
    }

    /// 启动 UDP 与 TCP 监听（不保留任务句柄）
    pub async fn spawn(self) -> Result<SocketAddr> {
        self.spawn_handle().await.map(|(addr, _)| addr)
    }

    async fn handle(
        &self,
        sock: &UdpSocket,
        pkt: &[u8],
        from: SocketAddr,
        resolver: &Arc<Resolver>,
    ) -> Result<()> {
        if let Some(resp) = self.process_query(pkt, resolver).await? {
            let _ = sock.send_to(&resp, from).await;
        }
        Ok(())
    }

    pub async fn process_query(
        &self,
        pkt: &[u8],
        resolver: &Arc<Resolver>,
    ) -> Result<Option<Vec<u8>>> {
        let Some((_id, name, qtype)) = wire::parse_query(pkt) else {
            return Ok(None);
        };

        // 0. 静态 hosts 优先命中
        if qtype == QTYPE_A {
            if let Some(ips) = resolver.lookup_hosts(&name, false) {
                if let Some(std::net::IpAddr::V4(v4)) = ips.first() {
                    return Ok(Some(wire::build_a_response(pkt, *v4)));
                }
            }
        }
        if qtype == QTYPE_AAAA && self.ipv6 {
            if let Some(ips) = resolver.lookup_hosts(&name, true) {
                if let Some(std::net::IpAddr::V6(v6)) = ips.iter().find(|ip| ip.is_ipv6()) {
                    return Ok(Some(wire::build_aaaa_response(pkt, *v6)));
                }
            }
        }

        // PTR 反查
        if qtype == QTYPE_PTR {
            if let Some(ipv4) = parse_ptr(&name) {
                if let Some(pool) = &self.fake_ip {
                    if let Some(domain) = pool.reverse(std::net::IpAddr::V4(ipv4)) {
                        return Ok(Some(wire::build_ptr_response(pkt, &domain)));
                    }
                }
            }
            // 交由上游
            return self.forward_query(pkt, resolver).await.map(Some);
        }

        let fake_mode = self.fake_ip.is_some() && !self.filtered(&name);

        if qtype == QTYPE_A && fake_mode {
            let pool = self.fake_ip.as_ref().unwrap();
            if let Some(ip) = pool.allocate(&name) {
                return Ok(Some(wire::build_a_response(pkt, ip)));
            }
            return self.forward_query(pkt, resolver).await.map(Some);
        }

        if qtype == QTYPE_AAAA && fake_mode && !self.ipv6 {
            return Ok(Some(wire::build_empty_response(pkt)));
        }

        // HTTPS/SVCB 查询优化：Fake-IP 模式下立即应答空记录（NOERROR 且 0 应答），
        // 彻底根除现代浏览器并发查询 Type 65 导致的 1~3 秒白屏/转圈卡顿，并防止真 IP 泄露绕过代理
        if (qtype == QTYPE_HTTPS || qtype == QTYPE_SVCB) && fake_mode {
            return Ok(Some(wire::build_empty_response(pkt)));
        }

        // 其余真实 A / AAAA 记录查询：当匹配 Policy 规则、Fallback 规则、或无普通 UDP 上游时，
        // 优先通过 Resolver（支持 nameserver-policy / DoH / DoT / 缓存 / 污染过滤）
        let needs_resolver = resolver.has_policy_match(&name)
            || (resolver.first_udp_server().is_none() && !resolver.use_system);
        if qtype == QTYPE_A && needs_resolver {
            if let Ok(ips) = resolver.resolve_domain(&name, false).await {
                if let Some(std::net::IpAddr::V4(v4)) = ips.iter().find(|ip| ip.is_ipv4()) {
                    return Ok(Some(wire::build_a_response(pkt, *v4)));
                }
            }
        }
        if qtype == QTYPE_AAAA && self.ipv6 && needs_resolver {
            if let Ok(ips) = resolver.resolve_domain(&name, true).await {
                if let Some(std::net::IpAddr::V6(v6)) = ips.iter().find(|ip| ip.is_ipv6()) {
                    return Ok(Some(wire::build_aaaa_response(pkt, *v6)));
                }
            }
        }

        // 原样转发上游
        self.forward_query(pkt, resolver).await.map(Some)
    }

    fn filtered(&self, domain: &str) -> bool {
        is_fake_ip_filtered(domain, &self.fake_ip_filter)
    }

    async fn forward_query(&self, pkt: &[u8], resolver: &Arc<Resolver>) -> Result<Vec<u8>> {
        // 如果有 UDP 上游，使用防路由环路 UDP 套接字（绑定物理网卡出站）直接转送原始报文
        if let Some(upstream) = resolver.first_udp_server() {
            let fwd = crate::create_udp_socket("0.0.0.0:0".parse().unwrap())?;
            fwd.connect(upstream).await?;
            fwd.send(pkt).await?;
            // RFC 6891: EDNS0 允许上游应答载荷至多达 4096 字节
            let mut buf = vec![0u8; 4096];
            let n = tokio::time::timeout(Duration::from_millis(1500), fwd.recv(&mut buf))
                .await
                .map_err(|_| Error::Dns("上游超时".into()))??;
            // 保证 id 与查询一致
            if n >= 2 && pkt.len() >= 2 {
                buf[0] = pkt[0];
                buf[1] = pkt[1];
            }
            buf.truncate(n);
            return Ok(buf);
        }

        // 无普通 UDP 上游时（如纯 DoH / DoT 配置），尝试使用 resolver 进行解析
        if let Some((_id, name, qtype)) = wire::parse_query(pkt) {
            if qtype == QTYPE_A {
                if let Ok(ips) = resolver.resolve_domain(&name, false).await {
                    if let Some(std::net::IpAddr::V4(v4)) = ips.iter().find(|ip| ip.is_ipv4()) {
                        return Ok(wire::build_a_response(pkt, *v4));
                    }
                }
            } else if qtype == QTYPE_AAAA && self.ipv6 {
                if let Ok(ips) = resolver.resolve_domain(&name, true).await {
                    if let Some(std::net::IpAddr::V6(v6)) = ips.iter().find(|ip| ip.is_ipv6()) {
                        return Ok(wire::build_aaaa_response(pkt, *v6));
                    }
                }
            }
        }

        // 无法解析时返回空应答
        Ok(wire::build_empty_response(pkt))
    }
}

static GLOBAL_GEOSITE_DB: std::sync::RwLock<Option<Arc<vp_rule::geosite::GeoSiteDb>>> =
    std::sync::RwLock::new(None);

/// 注册全局 GeoSite 数据库（用于 fake-ip-filter 中的 geosite:xx / rule:geosite:xx 规则匹配）
pub fn set_global_geosite_db(db: Option<Arc<vp_rule::geosite::GeoSiteDb>>) {
    *GLOBAL_GEOSITE_DB.write().unwrap() = db;
}

/// fake-ip 过滤名单匹配（mihomo 语法）：
/// - `+.x` → x 及任意层级子域；`*.x` → x 的单层子域（`*` 恰好匹配一段）
/// - 裸域名 → 该域名及其任意层级子域（本内核语义，保留向后兼容）
/// - `geosite:xxx` / `rule:geosite:xxx` → 若已加载 GeoSite 数据库则按类别匹配
pub fn is_fake_ip_filtered(domain: &str, filter: &[String]) -> bool {
    let d = domain.to_ascii_lowercase();
    // 内置保留：Tailscale MagicDNS 域名永不使用 Fake-IP（防止点对点 100.64/10 通信被劫持中断）
    if d == "ts.net" || d.ends_with(".ts.net") {
        return true;
    }
    filter.iter().any(|f| {
        let f = f.trim().to_ascii_lowercase();
        if f.is_empty() {
            return false;
        }
        if let Some(cat) = f
            .strip_prefix("rule:geosite:")
            .or_else(|| f.strip_prefix("geosite:"))
        {
            if let Some(db) = GLOBAL_GEOSITE_DB.read().unwrap().as_ref() {
                if let Some(site) = db.compile(cat) {
                    return site.matches(&d);
                }
            }
            return false;
        }
        if f.starts_with("rule:") {
            return false;
        }
        if let Some(rest) = f.strip_prefix("+.") {
            return d == rest || d.ends_with(&format!(".{rest}"));
        }
        if !f.contains('*') {
            return d == f || d.ends_with(&format!(".{f}"));
        }
        let pl: Vec<&str> = f.split('.').collect();
        let dl: Vec<&str> = d.split('.').collect();
        pl.len() == dl.len() && pl.iter().zip(dl.iter()).all(|(p, x)| *p == "*" || p == x)
    })
}

/// "x.y.z.w.in-addr.arpa" → Ipv4Addr
fn parse_ptr(name: &str) -> Option<std::net::Ipv4Addr> {
    let suffix = ".in-addr.arpa";
    let prefix = name.strip_suffix(suffix)?;
    let parts: Vec<&str> = prefix.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let a: u8 = parts[3].parse().ok()?;
    let b: u8 = parts[2].parse().ok()?;
    let c: u8 = parts[1].parse().ok()?;
    let d: u8 = parts[0].parse().ok()?;
    Some(std::net::Ipv4Addr::new(a, b, c, d))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn query(sock: &UdpSocket, server: SocketAddr, domain: &str, qtype: u16) -> Vec<u8> {
        let q = wire::build_query(
            0x1234,
            domain,
            match qtype {
                QTYPE_A => wire::QType::A,
                _ => wire::QType::Aaaa,
            },
        );
        sock.send_to(&q, server).await.unwrap();
        let mut buf = vec![0u8; 1500];
        let n = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
            .await
            .expect("超时")
            .expect("recv")
            .0;
        buf.truncate(n);
        buf
    }

    #[tokio::test]
    async fn fake_ip_a_and_stability() {
        let pool = Arc::new(FakeIpPool::new("198.18.0.0/15").unwrap());
        let resolver = Arc::new(Resolver::new(vec![])); // system（无上游 forward 场景）
        let srv = DnsServer::new(
            "127.0.0.1:0".parse().unwrap(),
            resolver,
            Some(pool),
            vec![],
            false,
        );
        let addr = srv.spawn().await.unwrap();

        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let r1 = query(&sock, addr, "www.example.org", QTYPE_A).await;
        let m1 = wire::parse_response(&r1).unwrap();
        let ips = wire::extract_ips(&m1, wire::TYPE_A);
        assert_eq!(ips.len(), 1);
        let ip1 = ips[0].0;

        // 同域名稳定
        let r2 = query(&sock, addr, "www.example.org", QTYPE_A).await;
        let m2 = wire::parse_response(&r2).unwrap();
        let ip2 = wire::extract_ips(&m2, wire::TYPE_A)[0].0;
        assert_eq!(ip1, ip2);

        // AAAA 返回空
        let r3 = query(&sock, addr, "www.example.org", QTYPE_AAAA).await;
        let m3 = wire::parse_response(&r3).unwrap();
        assert!(wire::extract_ips(&m3, wire::TYPE_AAAA).is_empty());
    }

    #[test]
    fn ptr_name_parse() {
        let ip = parse_ptr("4.3.2.1.in-addr.arpa").unwrap();
        assert_eq!(ip.to_string(), "1.2.3.4");
        assert!(parse_ptr("x.in-addr.arpa").is_none());
    }

    #[test]
    fn fake_ip_filter_patterns() {
        let srv = DnsServer::new(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(Resolver::new(vec![])),
            None,
            vec![
                "*.lan".into(),
                "+.local".into(),
                "+.msftconnecttest.com".into(),
                "mydevice.example".into(),
                "rule:geosite:cn".into(),
            ],
            false,
        );
        // *.lan：单层子域命中，裸域与多层不命中
        assert!(srv.filtered("pc.lan"));
        assert!(!srv.filtered("lan"));
        assert!(!srv.filtered("a.b.lan"));
        // +.local：裸域与任意层级子域命中
        assert!(srv.filtered("local"));
        assert!(srv.filtered("a.local"));
        assert!(srv.filtered("a.b.local"));
        assert!(srv.filtered("x.MSFTCONNECTTEST.com")); // 大小写不敏感
        // 裸域名：域名本身与任意层级子域命中
        assert!(srv.filtered("mydevice.example"));
        assert!(srv.filtered("a.mydevice.example"));
        // rule: 前缀暂不支持，不命中
        assert!(!srv.filtered("baidu.com"));
        // Tailscale 域名过滤
        assert!(srv.filtered("node.ts.net"));
        assert!(srv.filtered("ts.net"));
        // 未列出的域名不命中
        assert!(!srv.filtered("www.example.org"));
    }

    #[tokio::test]
    async fn test_server_static_hosts_and_aaaa() {
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "myhost.local".to_string(),
            vec!["1.2.3.4".parse().unwrap(), "2001:db8::1".parse().unwrap()],
        );
        let resolver = Arc::new(Resolver::new(vec![]).with_hosts(hosts));
        let srv = DnsServer::new(
            "127.0.0.1:0".parse().unwrap(),
            resolver,
            None,
            vec![],
            true, // 开启 ipv6
        );
        let addr = srv.spawn().await.unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let r_a = query(&sock, addr, "myhost.local", QTYPE_A).await;
        let m_a = wire::parse_response(&r_a).unwrap();
        let ips_a = wire::extract_ips(&m_a, wire::TYPE_A);
        assert_eq!(ips_a.len(), 1);
        assert_eq!(ips_a[0].0.to_string(), "1.2.3.4");

        let r_aaaa = query(&sock, addr, "myhost.local", QTYPE_AAAA).await;
        let m_aaaa = wire::parse_response(&r_aaaa).unwrap();
        let ips_aaaa = wire::extract_ips(&m_aaaa, wire::TYPE_AAAA);
        assert_eq!(ips_aaaa.len(), 1);
        assert_eq!(ips_aaaa[0].0.to_string(), "2001:db8::1");
    }
}

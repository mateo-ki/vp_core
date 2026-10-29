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

    /// 启动 UDP 监听，返回实际绑定地址与接收循环任务句柄（热停用 TUN 时 abort 用）
    pub async fn spawn_handle(self) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
        let sock = Arc::new(UdpSocket::bind(self.listen).await?);
        let bound = sock.local_addr()?;
        let this = Arc::new(self);
        let resolver = this.resolver.clone();
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            loop {
                match sock.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        let pkt = buf[..n].to_vec();
                        let this = this.clone();
                        let sock = sock.clone();
                        let resolver = resolver.clone();
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
        Ok((bound, handle))
    }

    /// 启动 UDP 监听（不保留任务句柄）
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
        let Some((_id, name, qtype)) = wire::parse_query(pkt) else {
            return Ok(());
        };

        // PTR 反查
        if qtype == QTYPE_PTR {
            if let Some(ipv4) = parse_ptr(&name) {
                if let Some(pool) = &self.fake_ip {
                    if let Some(domain) = pool.reverse(std::net::IpAddr::V4(ipv4)) {
                        let resp = wire::build_ptr_response(pkt, &domain);
                        let _ = sock.send_to(&resp, from).await;
                        return Ok(());
                    }
                }
            }
            // 交由上游
            return self.forward(sock, pkt, from, resolver).await;
        }

        let fake_mode = self.fake_ip.is_some() && !self.filtered(&name);

        if qtype == QTYPE_A && fake_mode {
            let pool = self.fake_ip.as_ref().unwrap();
            if let Some(ip) = pool.allocate(&name) {
                let resp = wire::build_a_response(pkt, ip);
                let _ = sock.send_to(&resp, from).await;
                return Ok(());
            }
            return self.forward(sock, pkt, from, resolver).await;
        }

        if qtype == QTYPE_AAAA && fake_mode && !self.ipv6 {
            let resp = wire::build_empty_response(pkt);
            let _ = sock.send_to(&resp, from).await;
            return Ok(());
        }

        // 其余原样转发上游
        self.forward(sock, pkt, from, resolver).await
    }

    /// fake-ip 过滤名单匹配（mihomo 语法）：
    /// - `+.x` → x 及任意层级子域；`*.x` → x 的单层子域（`*` 恰好匹配一段）
    /// - 裸域名 → 该域名及其任意层级子域（本内核语义，保留向后兼容）
    /// - `rule:` 前缀（mihomo 扩展语法）暂不支持，忽略该条
    fn filtered(&self, domain: &str) -> bool {
        let d = domain.to_ascii_lowercase();
        self.fake_ip_filter.iter().any(|f| {
            let f = f.trim().to_ascii_lowercase();
            if f.is_empty() || f.starts_with("rule:") {
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

    async fn forward(
        &self,
        sock: &UdpSocket,
        pkt: &[u8],
        from: SocketAddr,
        resolver: &Arc<Resolver>,
    ) -> Result<()> {
        // 无上游服务器 → NXDOMAIN 兜底
        let Some(upstream) = resolver.first_udp_server() else {
            let resp = wire::build_empty_response(pkt);
            let _ = sock.send_to(&resp, from).await;
            return Ok(());
        };
        let fwd = UdpSocket::bind("0.0.0.0:0").await?;
        fwd.connect(upstream).await?;
        fwd.send(pkt).await?;
        let mut buf = vec![0u8; 1500];
        let n = tokio::time::timeout(Duration::from_secs(3), fwd.recv(&mut buf))
            .await
            .map_err(|_| Error::Dns("上游超时".into()))??;
        // 保证 id 与查询一致
        if n >= 2 && pkt.len() >= 2 {
            buf[0] = pkt[0];
            buf[1] = pkt[1];
        }
        let _ = sock.send_to(&buf[..n], from).await;
        Ok(())
    }
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
        // 未列出的域名不命中
        assert!(!srv.filtered("www.example.org"));
    }
}

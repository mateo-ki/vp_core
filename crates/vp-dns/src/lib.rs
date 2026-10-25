//! vp-dns：DNS 解析器（UDP/TCP）+ TTL 缓存。

pub mod wire;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use vp_common::{Error, Host, Result};

pub use wire::QType;

const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
const CACHE_CAP: usize = 4096;
const MIN_TTL: u32 = 30;

#[derive(Debug, Clone)]
struct CacheEntry {
    ips: Arc<Vec<IpAddr>>,
    at: Instant,
    ttl: u32,
}

#[derive(Default)]
struct CacheInner {
    map: HashMap<(String, bool), CacheEntry>,
}

/// DNS 解析器：多上游，UDP 优先 TCP 兜底；进程内共享缓存。
pub struct Resolver {
    servers: Vec<ServerAddr>,
    cache: Mutex<CacheInner>,
    /// 无 nameserver 配置时走系统解析
    pub use_system: bool,
}

#[derive(Debug, Clone)]
struct ServerAddr {
    addr: SocketAddr,
    tcp: bool,
}

impl Resolver {
    pub fn new(servers: Vec<String>) -> Self {
        let parsed: Vec<ServerAddr> = servers.iter().filter_map(|s| parse_server(s)).collect();
        let use_system = parsed.is_empty();
        Resolver { servers: parsed, cache: Mutex::new(CacheInner::default()), use_system }
    }

    pub fn system() -> Self {
        Resolver {
            servers: Vec::new(),
            cache: Mutex::new(CacheInner::default()),
            use_system: true,
        }
    }

    /// 解析目标。ipv6=false 时仅查 A 记录。
    pub async fn resolve(&self, host: &Host, ipv6: bool) -> Result<Arc<Vec<IpAddr>>> {
        match host {
            Host::Ip(ip) => Ok(Arc::new(vec![*ip])),
            Host::Domain(domain) => self.resolve_domain(domain, ipv6).await,
        }
    }

    pub async fn resolve_domain(&self, domain: &str, ipv6: bool) -> Result<Arc<Vec<IpAddr>>> {
        let key = (domain.to_ascii_lowercase(), ipv6);
        {
            let c = self.cache.lock().unwrap();
            if let Some(e) = c.map.get(&key) {
                if e.at.elapsed() < Duration::from_secs(e.ttl.max(MIN_TTL) as u64) {
                    return Ok(e.ips.clone());
                }
            }
        }
        let ips = self.query_all(domain, ipv6).await?;
        let mut c = self.cache.lock().unwrap();
        if c.map.len() >= CACHE_CAP {
            c.map.clear();
        }
        c.map.insert(key, CacheEntry { ips: ips.clone(), at: Instant::now(), ttl: MIN_TTL });
        Ok(ips)
    }

    async fn query_all(&self, domain: &str, ipv6: bool) -> Result<Arc<Vec<IpAddr>>> {
        if self.servers.is_empty() {
            return self.system_lookup(domain).await;
        }
        let qtype = if ipv6 { QType::Aaaa } else { QType::A };
        let mut last_err = None;
        for server in &self.servers {
            match query_server(server, domain, qtype).await {
                Ok(ips) if !ips.is_empty() => return Ok(Arc::new(ips)),
                Ok(_) => last_err = Some(Error::Dns(format!("域名 {domain} 无 {qtype:?} 记录"))),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| Error::Dns("无可用 DNS 服务器".into())))
    }

    async fn system_lookup(&self, domain: &str) -> Result<Arc<Vec<IpAddr>>> {
        let d = domain.to_string();
        let addrs = tokio::task::spawn_blocking(move || {
            use std::net::ToSocketAddrs;
            (d.as_str(), 0u16).to_socket_addrs()
        })
        .await
        .map_err(|e| Error::Dns(format!("解析任务失败: {e}")))?
        .map_err(|e| Error::Dns(format!("系统解析 {domain} 失败: {e}")))?;
        let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
        if ips.is_empty() {
            return Err(Error::Dns(format!("域名 {domain} 解析为空")));
        }
        Ok(Arc::new(ips))
    }
}

fn parse_server(s: &str) -> Option<ServerAddr> {
    let (proto, host) = match s.split_once("://") {
        Some((p, h)) => (p, h),
        None => ("udp", s),
    };
    // 允许 host:port，默认 53
    let (host, port) = match host.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), p.parse::<u16>().ok()?)
        }
        _ => (host.to_string(), 53),
    };
    let ip: IpAddr = host.parse().ok()?;
    let tcp = match proto {
        "tcp" => true,
        "udp" => false,
        _ => return None, // tls/https 随 M2
    };
    Some(ServerAddr { addr: SocketAddr::new(ip, port), tcp })
}

async fn query_server(server: &ServerAddr, domain: &str, qtype: QType) -> Result<Vec<IpAddr>> {
    if server.tcp {
        query_tcp(server.addr, domain, qtype).await
    } else {
        query_udp(server.addr, domain, qtype).await
    }
}

/// 超时包装：Elapsed → io::TimedOut
async fn with_timeout<T, E, F>(f: F) -> Result<T>
where
    E: Into<Error>,
    F: std::future::Future<Output = std::result::Result<T, E>>,
{
    match timeout(QUERY_TIMEOUT, f).await {
        Ok(r) => r.map_err(Into::into),
        Err(_) => Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "dns query timeout",
        ))),
    }
}

fn query_id() -> u16 {
    let mut b = [0u8; 2];
    vp_common::rand_bytes(&mut b);
    u16::from_be_bytes(b)
}

async fn query_udp(addr: SocketAddr, domain: &str, qtype: QType) -> Result<Vec<IpAddr>> {
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(addr).await?;
    let id = query_id();
    let q = wire::build_query(id, domain, qtype);
    sock.send(&q).await?;
    let mut buf = vec![0u8; 1500];
    let n = with_timeout(sock.recv(&mut buf)).await?;
    let msg = wire::parse_response(&buf[..n]).ok_or(Error::Proto("DNS 响应解析失败"))?;
    if msg.rcode != 0 {
        return Err(Error::Dns(format!("DNS 错误码 {}", msg.rcode)));
    }
    Ok(wire::extract_ips(&msg, qtype.code()).into_iter().map(|(ip, _)| ip).collect())
}

async fn query_tcp(addr: SocketAddr, domain: &str, qtype: QType) -> Result<Vec<IpAddr>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = with_timeout(TcpStream::connect(addr)).await?;
    let id = query_id();
    let q = wire::build_query(id, domain, qtype);
    let mut framed = Vec::with_capacity(q.len() + 2);
    framed.extend_from_slice(&(q.len() as u16).to_be_bytes());
    framed.extend_from_slice(&q);
    stream.write_all(&framed).await?;
    let mut len_buf = [0u8; 2];
    with_timeout(stream.read_exact(&mut len_buf)).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; len];
    with_timeout(stream.read_exact(&mut resp)).await?;
    let msg = wire::parse_response(&resp).ok_or(Error::Proto("DNS 响应解析失败"))?;
    if msg.rcode != 0 {
        return Err(Error::Dns(format!("DNS 错误码 {}", msg.rcode)));
    }
    Ok(wire::extract_ips(&msg, qtype.code()).into_iter().map(|(ip, _)| ip).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_parsing() {
        assert_eq!(
            parse_server("8.8.8.8").map(|s| (s.addr.to_string(), s.tcp)),
            Some(("8.8.8.8:53".into(), false))
        );
        assert_eq!(parse_server("udp://1.1.1.1:5353").map(|s| s.addr.port()), Some(5353));
        assert_eq!(parse_server("tcp://192.168.1.1").map(|s| s.tcp), Some(true));
        assert!(parse_server("https://doh.pub/dns-query").is_none()); // M2
    }

    #[tokio::test]
    async fn system_lookup_works() {
        // 本机回环域名必然可解析
        let r = Resolver::system();
        let ips = r.resolve_domain("localhost", false).await.unwrap();
        assert!(ips.iter().any(|ip| ip.is_loopback()));
    }
}

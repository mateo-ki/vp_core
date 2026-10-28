//! vp-dns：DNS 解析器（UDP/TCP）+ TTL 缓存。

pub mod fakeip;
pub mod server;
pub mod wire;

pub use fakeip::FakeIpPool;
pub use server::DnsServer;

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

#[derive(Clone)]
pub struct PolicyRule {
    pub trie: vp_rule::domain::DomainTrie,
    pub geosite: Vec<Arc<vp_rule::geosite::CompiledSite>>,
    pub resolver: Arc<Resolver>,
}

#[derive(Clone)]
pub struct CompiledFallbackFilter {
    pub geoip: bool,
    pub geoip_code: String,
    pub geoip_matcher: Option<vp_rule::geoip::GeoIpMatcher>,
    pub ipcidr: vp_rule::ipset::IpIntervalSet,
    pub domain: vp_rule::domain::DomainTrie,
    pub geosite: Vec<Arc<vp_rule::geosite::CompiledSite>>,
}

/// DNS 解析器：多上游，UDP 优先 TCP 兜底；进程内共享缓存；支持 nameserver-policy 分流与 fallback-filter 污染过滤。
pub struct Resolver {
    servers: Vec<ServerAddr>,
    fallbacks: Vec<ServerAddr>,
    policies: Vec<PolicyRule>,
    fallback_filter: Option<CompiledFallbackFilter>,
    cache: Mutex<CacheInner>,
    /// 无 nameserver 配置时走系统解析
    pub use_system: bool,
}

#[derive(Debug, Clone)]
struct ServerAddr {
    /// 连接目标主机（IP 或域名；DoH/DoT 域名上游查询时再解析）
    host: String,
    /// IP 直连地址（域名上游为 None）
    addr: Option<SocketAddr>,
    port: u16,
    proto: Proto,
    /// DoH 路径（如 /dns-query）
    path: String,
    /// 跳过证书校验（URL 片段 #insecure）
    skip_verify: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Proto {
    Udp,
    Tcp,
    Tls,
    Doh,
}

impl Resolver {
    pub fn new(servers: Vec<String>) -> Self {
        let parsed: Vec<ServerAddr> = servers.iter().filter_map(|s| parse_server(s)).collect();
        let use_system = parsed.is_empty();
        Resolver {
            servers: parsed,
            fallbacks: Vec::new(),
            policies: Vec::new(),
            fallback_filter: None,
            cache: Mutex::new(CacheInner::default()),
            use_system,
        }
    }

    pub fn build(
        servers: Vec<String>,
        fallbacks: Vec<String>,
        policies: Vec<PolicyRule>,
        fallback_filter: Option<CompiledFallbackFilter>,
    ) -> Self {
        let parsed_servers: Vec<ServerAddr> =
            servers.iter().filter_map(|s| parse_server(s)).collect();
        let parsed_fallbacks: Vec<ServerAddr> =
            fallbacks.iter().filter_map(|s| parse_server(s)).collect();
        let use_system =
            parsed_servers.is_empty() && parsed_fallbacks.is_empty() && policies.is_empty();
        Resolver {
            servers: parsed_servers,
            fallbacks: parsed_fallbacks,
            policies,
            fallback_filter,
            cache: Mutex::new(CacheInner::default()),
            use_system,
        }
    }

    pub fn system() -> Self {
        Resolver {
            servers: Vec::new(),
            fallbacks: Vec::new(),
            policies: Vec::new(),
            fallback_filter: None,
            cache: Mutex::new(CacheInner::default()),
            use_system: true,
        }
    }

    pub fn with_fallbacks(mut self, fallbacks: Vec<String>) -> Self {
        self.fallbacks = fallbacks.iter().filter_map(|s| parse_server(s)).collect();
        self
    }

    pub fn with_policies(mut self, policies: Vec<PolicyRule>) -> Self {
        self.policies = policies;
        self
    }

    pub fn with_fallback_filter(mut self, filter: Option<CompiledFallbackFilter>) -> Self {
        self.fallback_filter = filter;
        self
    }

    /// 第一个 UDP 上游（DNS 服务器原样转发用）
    pub fn first_udp_server(&self) -> Option<SocketAddr> {
        self.servers
            .iter()
            .find(|s| s.proto == Proto::Udp)
            .and_then(|s| s.addr)
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

        // 1. Policy 路由检查：nameserver-policy 优先专有分流
        for rule in &self.policies {
            if rule.trie.is_match(domain) || rule.geosite.iter().any(|s| s.matches(domain)) {
                if let Ok(ips) = Box::pin(rule.resolver.resolve_domain(domain, ipv6)).await {
                    if !ips.is_empty() {
                        self.cache_store(key, ips.clone());
                        return Ok(ips);
                    }
                }
                tracing::debug!("nameserver-policy 解析失败，平滑降级至主 DNS: {domain}");
            }
        }

        let qtype = if ipv6 { QType::Aaaa } else { QType::A };

        // 2. Fallback Filter 专有分流（域名或 geosite 强制 fallback）
        if let Some(ref ff) = self.fallback_filter {
            if (ff.domain.is_match(domain) || ff.geosite.iter().any(|s| s.matches(domain)))
                && !self.fallbacks.is_empty()
            {
                if let Ok(ips) = Self::query_servers(&self.fallbacks, domain, qtype).await {
                    let ips = Arc::new(ips);
                    self.cache_store(key, ips.clone());
                    return Ok(ips);
                }
            }
        }

        // 3. 主 DNS 解析
        let primary_res = if self.servers.is_empty() {
            self.system_lookup(domain).await
        } else {
            Self::query_servers(&self.servers, domain, qtype)
                .await
                .map(Arc::new)
        };

        let ips = match primary_res {
            Ok(ips) => {
                // 4. 污染检测（CIDR 污染网段 / 非 CN GeoIP 污染剔除）
                let mut poisoned = false;
                if let Some(ref ff) = self.fallback_filter {
                    for ip in ips.iter() {
                        // (1) IP-CIDR 污染库拦截（如 240.0.0.0/4、127.0.0.1、0.0.0.0/8 等）
                        if ff.ipcidr.contains(*ip) {
                            poisoned = true;
                            break;
                        }
                        // (2) GeoIP 国内归属检查
                        if ff.geoip {
                            if let Some(ref matcher) = ff.geoip_matcher {
                                if !matcher.matches(*ip) {
                                    poisoned = true;
                                    break;
                                }
                            }
                        }
                    }
                }

                if poisoned && !self.fallbacks.is_empty() {
                    tracing::info!(
                        "域名 {domain} 命中 fallback-filter 污染过滤，切换至 fallback 上游"
                    );
                    match Self::query_servers(&self.fallbacks, domain, qtype).await {
                        Ok(f_ips) if !f_ips.is_empty() => Arc::new(f_ips),
                        _ => ips,
                    }
                } else {
                    ips
                }
            }
            Err(e) => {
                if !self.fallbacks.is_empty() {
                    match Self::query_servers(&self.fallbacks, domain, qtype).await {
                        Ok(f_ips) if !f_ips.is_empty() => Arc::new(f_ips),
                        _ => return Err(e),
                    }
                } else {
                    return Err(e);
                }
            }
        };

        self.cache_store(key, ips.clone());
        Ok(ips)
    }

    fn cache_store(&self, key: (String, bool), ips: Arc<Vec<IpAddr>>) {
        let mut c = self.cache.lock().unwrap();
        if c.map.len() >= CACHE_CAP {
            c.map.clear();
        }
        c.map.insert(
            key,
            CacheEntry {
                ips,
                at: Instant::now(),
                ttl: MIN_TTL,
            },
        );
    }

    async fn query_servers(
        servers: &[ServerAddr],
        domain: &str,
        qtype: QType,
    ) -> Result<Vec<IpAddr>> {
        if servers.is_empty() {
            return Err(Error::Dns("无可用 DNS 服务器".into()));
        }
        if servers.len() == 1 {
            return match query_server(&servers[0], domain, qtype).await {
                Ok(ips) if !ips.is_empty() => Ok(ips),
                Ok(_) => Err(Error::Dns(format!("域名 {domain} 无 {qtype:?} 记录"))),
                Err(e) => Err(e),
            };
        }

        // 并发查询全部上游，取各上游答案的并集（保持配置顺序去重）。
        // 单一上游可能给出整轮被污染/失效的答案（如 GFW 对节点域名的"邻居 IP"污染），
        // 多上游并集后配合拨号竞速，任一上游给出活地址即可用。
        let mut set = tokio::task::JoinSet::new();
        for (idx, server) in servers.iter().enumerate() {
            let server = server.clone();
            let domain = domain.to_string();
            set.spawn(async move { (idx, query_server(&server, &domain, qtype).await) });
        }

        let mut merged: Vec<(usize, Vec<IpAddr>)> = Vec::new();
        let mut last_err = None;
        while let Some(res) = set.join_next().await {
            match res {
                Ok((idx, Ok(ips))) if !ips.is_empty() => merged.push((idx, ips)),
                Ok((_, Ok(_))) => {
                    last_err = Some(Error::Dns(format!("域名 {domain} 无 {qtype:?} 记录")))
                }
                Ok((_, Err(e))) => last_err = Some(e),
                Err(e) => last_err = Some(Error::Dns(format!("DNS 任务失败: {e}"))),
            }
        }
        if merged.is_empty() {
            return Err(last_err.unwrap_or_else(|| Error::Dns("全部 DNS 服务器查询失败".into())));
        }
        merged.sort_by_key(|(idx, _)| *idx);
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for (_, ips) in merged {
            for ip in ips {
                if seen.insert(ip) {
                    out.push(ip);
                }
            }
        }
        Ok(out)
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
    // #insecure 片段：跳过证书校验
    let (s, skip_verify) = match s.strip_suffix("#insecure") {
        Some(base) => (base, true),
        None => (s, false),
    };
    let (proto_str, rest) = match s.split_once("://") {
        Some((p, h)) => (p, h),
        None => ("udp", s),
    };
    // DoH：完整 URL 形式（host[:port][/path]）
    if proto_str == "https" {
        let (hostport, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/dns-query".to_string()),
        };
        let (host, port) = split_host_port(hostport, 443)?;
        return Some(ServerAddr {
            host,
            addr: None,
            port,
            proto: Proto::Doh,
            path,
            skip_verify,
        });
    }
    let (host, port) = split_host_port(rest, if proto_str == "tls" { 853 } else { 53 })?;
    // 非 DoH 上游要求 IP 直连（域名上游请用 DoH/DoT 或系统解析）
    let ip: IpAddr = host.parse().ok()?;
    let proto = match proto_str {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        "tls" => Proto::Tls,
        _ => return None,
    };
    Some(ServerAddr {
        host: host.clone(),
        addr: Some(SocketAddr::new(ip, port)),
        port,
        proto,
        path: String::new(),
        skip_verify,
    })
}

/// "host:port" → (host, port)；无端口用 default
fn split_host_port(s: &str, default_port: u16) -> Option<(String, u16)> {
    match s.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            Some((h.to_string(), p.parse().ok()?))
        }
        _ => Some((s.to_string(), default_port)),
    }
}

pub fn compile_nameserver_policy(
    policy: &std::collections::HashMap<String, serde_yaml::Value>,
    geosite_db: Option<&vp_rule::geosite::GeoSiteDb>,
) -> Vec<PolicyRule> {
    let mut rules = Vec::new();
    for (key, val) in policy {
        let server_strs: Vec<String> = match val {
            serde_yaml::Value::String(s) => vec![s.clone()],
            serde_yaml::Value::Sequence(seq) => seq
                .iter()
                .filter_map(|v| match v {
                    serde_yaml::Value::String(s) => Some(s.clone()),
                    _ => None,
                })
                .collect(),
            _ => continue,
        };
        if server_strs.is_empty() {
            continue;
        }
        let resolver = Arc::new(Resolver::new(server_strs));
        let mut trie = vp_rule::domain::DomainTrie::new();
        let mut geosite_list = Vec::new();

        for part in key.split(',') {
            let part = part.trim();
            if let Some(tag) = part.strip_prefix("geosite:") {
                if let Some(db) = geosite_db {
                    if let Some(compiled) = db.compile(tag) {
                        geosite_list.push(compiled);
                    }
                }
            } else {
                let clean = part
                    .trim_start_matches('+')
                    .trim_start_matches('*')
                    .trim_start_matches('.');
                trie.insert_suffix_all(clean);
            }
        }
        rules.push(PolicyRule {
            trie,
            geosite: geosite_list,
            resolver,
        });
    }
    rules
}

pub fn compile_fallback_filter(
    cfg: &vp_config::FallbackFilterConfig,
    geosite_db: Option<&vp_rule::geosite::GeoSiteDb>,
    geoip_db: Option<&vp_rule::geoip::GeoIpDb>,
) -> CompiledFallbackFilter {
    let mut ip_builder = vp_rule::ipset::IpIntervalSetBuilder::new();
    for cidr in &cfg.ipcidr {
        let _ = ip_builder.insert_cidr(cidr);
    }
    let ipcidr = ip_builder.build();

    let mut domain_trie = vp_rule::domain::DomainTrie::new();
    for d in &cfg.domain {
        let clean = d
            .trim_start_matches('+')
            .trim_start_matches('*')
            .trim_start_matches('.');
        domain_trie.insert_suffix_all(clean);
    }

    let mut geosite_list = Vec::new();
    if let Some(db) = geosite_db {
        for tag in &cfg.geosite {
            if let Some(compiled) = db.compile(tag) {
                geosite_list.push(compiled);
            }
        }
    }

    let geoip_matcher = if cfg.geoip && !cfg.geoip_code.is_empty() {
        geoip_db.and_then(|db| db.matcher(cfg.geoip_code.clone()))
    } else {
        None
    };

    CompiledFallbackFilter {
        geoip: cfg.geoip,
        geoip_code: cfg.geoip_code.clone(),
        geoip_matcher,
        ipcidr,
        domain: domain_trie,
        geosite: geosite_list,
    }
}

async fn query_server(server: &ServerAddr, domain: &str, qtype: QType) -> Result<Vec<IpAddr>> {
    match server.proto {
        Proto::Udp => query_udp(server.addr.expect("udp 必为 IP"), domain, qtype).await,
        Proto::Tcp => query_tcp(server.addr.expect("tcp 必为 IP"), domain, qtype).await,
        Proto::Tls => {
            query_tls(
                server.addr.expect("tls 必为 IP"),
                &server.host,
                domain,
                qtype,
            )
            .await
        }
        Proto::Doh => with_timeout(query_doh(server, domain, qtype)).await,
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
    Ok(wire::extract_ips(&msg, qtype.code())
        .into_iter()
        .map(|(ip, _)| ip)
        .collect())
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
    Ok(wire::extract_ips(&msg, qtype.code())
        .into_iter()
        .map(|(ip, _)| ip)
        .collect())
}

/// DoT（RFC 7858）：TLS 上的 DNS，2 字节长度前缀帧
async fn query_tls(
    addr: SocketAddr,
    sni_host: &str,
    domain: &str,
    qtype: QType,
) -> Result<Vec<IpAddr>> {
    use tokio::io::AsyncWriteExt;

    let connector = webpki_connector(false);
    let sni = server_name(sni_host, addr.ip())?;
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let mut tls = connector.connect(sni, tcp).await?;

    let id = query_id();
    let q = wire::build_query(id, domain, qtype);
    let mut framed = Vec::with_capacity(q.len() + 2);
    framed.extend_from_slice(&(q.len() as u16).to_be_bytes());
    framed.extend_from_slice(&q);
    tls.write_all(&framed).await?;
    let mut len_buf = [0u8; 2];
    with_timeout(stream_read_exact(&mut tls, &mut len_buf)).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; len];
    with_timeout(stream_read_exact(&mut tls, &mut resp)).await?;
    let msg = wire::parse_response(&resp).ok_or(Error::Proto("DoT 响应解析失败"))?;
    if msg.rcode != 0 {
        return Err(Error::Dns(format!("DoT 错误码 {}", msg.rcode)));
    }
    Ok(wire::extract_ips(&msg, qtype.code())
        .into_iter()
        .map(|(ip, _)| ip)
        .collect())
}

/// webpki 根证书连接器（DoT/DoH 共用）；skip=true 容忍自签
fn webpki_connector(skip_verify: bool) -> tokio_rustls::TlsConnector {
    static VERIFY: std::sync::OnceLock<tokio_rustls::TlsConnector> = std::sync::OnceLock::new();
    static NO_VERIFY: std::sync::OnceLock<tokio_rustls::TlsConnector> = std::sync::OnceLock::new();
    if skip_verify {
        NO_VERIFY.get_or_init(|| build_webpki_connector(true)).clone()
    } else {
        VERIFY.get_or_init(|| build_webpki_connector(false)).clone()
    }
}

fn build_webpki_connector(skip_verify: bool) -> tokio_rustls::TlsConnector {
    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };

    use std::sync::Arc;
    use tokio_rustls::rustls::DigitallySignedStruct;
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use tokio_rustls::{TlsConnector, rustls::ClientConfig};

    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if skip_verify {
        #[derive(Debug)]
        struct NoVerify;
        impl ServerCertVerifier for NoVerify {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp: &[u8],
                _now: UnixTime,
            ) -> std::result::Result<ServerCertVerified, tokio_rustls::rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _m: &[u8],
                _c: &CertificateDer<'_>,
                _d: &DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error>
            {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _m: &[u8],
                _c: &CertificateDer<'_>,
                _d: &DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error>
            {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
                vec![
                    tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA256,
                    tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                    tokio_rustls::rustls::SignatureScheme::ED25519,
                    tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA256,
                ]
            }
        }
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerify));
    }
    TlsConnector::from(Arc::new(config))
}

/// SNI：域名或 IP 形式
fn server_name(
    host: &str,
    fallback_ip: IpAddr,
) -> Result<tokio_rustls::rustls::pki_types::ServerName<'static>> {
    use tokio_rustls::rustls::pki_types::ServerName;
    ServerName::try_from(host.to_string())
        .or_else(|_| ServerName::try_from(fallback_ip.to_string()))
        .map_err(|e| Error::Addr(format!("SNI 非法 {host:?}: {e}")))
}

/// 借用流读满（避免泛型复杂度）
async fn stream_read_exact<S: tokio::io::AsyncRead + Unpin>(
    s: &mut S,
    buf: &mut [u8],
) -> std::result::Result<(), std::io::Error> {
    tokio::io::AsyncReadExt::read_exact(s, buf)
        .await
        .map(|_| ())
}

// ---------------------------------------------------------------------------
// DoH（RFC 8484）
// ---------------------------------------------------------------------------

async fn query_doh(server: &ServerAddr, domain: &str, qtype: QType) -> Result<Vec<IpAddr>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // 1) 解析 DoH 服务器自身（IP 直连 / 域名走系统解析，避免递归）
    let addr: SocketAddr = match server.addr {
        Some(a) => a,
        None => {
            let d = server.host.clone();
            let port = server.port;
            let mut addrs = tokio::task::spawn_blocking(move || {
                use std::net::ToSocketAddrs;
                (d.as_str(), port).to_socket_addrs()
            })
            .await
            .map_err(|e| Error::Dns(format!("DoH 服务器解析失败: {e}")))?
            .map_err(|e| Error::Dns(format!("DoH 服务器 {domain} 解析失败: {e}")))?;
            addrs.next().ok_or(Error::Dns("DoH 服务器无地址".into()))?
        }
    };

    // 2) TLS
    let connector = webpki_connector(server.skip_verify);
    let sni = server_name(&server.host, addr.ip())?;
    let tcp = with_timeout(tokio::net::TcpStream::connect(addr)).await?;
    let mut tls = with_timeout(connector.connect(sni, tcp)).await?;

    // 3) HTTP/1.1 POST（application/dns-message）
    let id = query_id();
    let q = wire::build_query(id, domain, qtype);
    let host_header = if server.port == 443 {
        server.host.clone()
    } else {
        format!("{}:{}", server.host, server.port)
    };
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {host_header}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        server.path,
        q.len()
    );
    tls.write_all(req.as_bytes()).await?;
    tls.write_all(&q).await?;
    tls.flush().await?;

    // 4) 读响应头 + body
    let mut head = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        let n = tls.read(&mut byte).await?;
        if n == 0 {
            return Err(Error::Proto("DoH: 响应中断"));
        }
        head.push(byte[0]);
        if head.len() > 64 * 1024 {
            return Err(Error::Proto("DoH: 响应头过长"));
        }
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let (status, headers) = parse_http_head(&head)?;
    if status != 200 {
        return Err(Error::Dns(format!("DoH: HTTP {status}")));
    }
    let body = read_http_body(&mut tls, &headers).await?;

    let msg = wire::parse_response(&body).ok_or(Error::Proto("DoH: DNS 消息解析失败"))?;
    if msg.rcode != 0 {
        return Err(Error::Dns(format!("DoH 错误码 {}", msg.rcode)));
    }
    Ok(wire::extract_ips(&msg, qtype.code())
        .into_iter()
        .map(|(ip, _)| ip)
        .collect())
}

/// 解析 HTTP/1.1 响应头：返回 (状态码, 小写头名 → 值)
fn parse_http_head(head: &[u8]) -> Result<(u16, Vec<(String, String)>)> {
    let text = std::str::from_utf8(head).map_err(|_| Error::Proto("DoH: 头非 utf8"))?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status: u16 = status_line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or(Error::Proto("DoH: 状态行非法"))?;
    let mut headers = Vec::new();
    for l in lines {
        if l.is_empty() {
            continue;
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    Ok((status, headers))
}

/// 按 Content-Length / chunked / EOF 三种方式读 body
async fn read_http_body<S: tokio::io::AsyncRead + Unpin>(
    s: &mut S,
    headers: &[(String, String)],
) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let get = |k: &str| {
        headers
            .iter()
            .find(|(hk, _)| hk == k)
            .map(|(_, v)| v.clone())
    };
    if let Some(len) = get("content-length").and_then(|v| v.parse::<usize>().ok()) {
        let mut body = vec![0u8; len];
        s.read_exact(&mut body).await?;
        return Ok(body);
    }
    if get("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        // chunked：读 [size hex]\r\n[data]\r\n ... 0\r\n[\r\n]
        let mut body = Vec::new();
        let mut line = Vec::new();
        loop {
            let mut b = [0u8; 1];
            if s.read(&mut b).await? == 0 {
                break;
            }
            if b[0] == b'\n' {
                if line.ends_with(b"\r") {
                    line.pop();
                }
                let size_str = String::from_utf8_lossy(&line);
                let size =
                    usize::from_str_radix(size_str.trim().split(';').next().unwrap_or("0"), 16)
                        .unwrap_or(0);
                line.clear();
                if size == 0 {
                    break;
                }
                let mut chunk = vec![0u8; size];
                s.read_exact(&mut chunk).await?;
                body.extend_from_slice(&chunk);
                // 吃掉块尾 \r\n
                let mut crlf = [0u8; 2];
                let _ = s.read_exact(&mut crlf).await;
            } else {
                line.push(b[0]);
                if line.len() > 16 {
                    return Err(Error::Proto("DoH: chunk size 行过长"));
                }
            }
        }
        return Ok(body);
    }
    // Connection: close — 读到 EOF
    let mut body = Vec::new();
    s.read_to_end(&mut body).await?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_parsing() {
        assert_eq!(
            parse_server("8.8.8.8").map(|s| (s.addr.map(|a| a.to_string()), s.proto)),
            Some((Some("8.8.8.8:53".into()), Proto::Udp))
        );
        assert_eq!(
            parse_server("udp://1.1.1.1:5353").map(|s| s.port),
            Some(5353)
        );
        assert!(matches!(parse_server("tcp://192.168.1.1"), Some(s) if s.proto == Proto::Tcp));
        // DoH
        let doh = parse_server("https://doh.pub/dns-query").unwrap();
        assert_eq!(doh.proto, Proto::Doh);
        assert_eq!(doh.host, "doh.pub");
        assert_eq!(doh.port, 443);
        assert_eq!(doh.path, "/dns-query");
        assert!(doh.addr.is_none());
        // DoH 默认路径
        assert_eq!(parse_server("https://1.1.1.1").unwrap().path, "/dns-query");
        // DoT
        let dot = parse_server("tls://8.8.8.8").unwrap();
        assert_eq!(dot.proto, Proto::Tls);
        assert_eq!(dot.port, 853);
    }

    #[tokio::test]
    async fn system_lookup_works() {
        // 本机回环域名必然可解析
        let r = Resolver::system();
        let ips = r.resolve_domain("localhost", false).await.unwrap();
        assert!(ips.iter().any(|ip| ip.is_loopback()));
    }

    /// 本地 DoH 自环：自签证书 + skip-verify + Content-Length 响应
    #[tokio::test]
    async fn doh_loopback_self_signed() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use tokio_rustls::{TlsAcceptor, rustls::ServerConfig};

        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut buf = Vec::new();
                    let mut b = [0u8; 1];
                    loop {
                        match tls.read(&mut b).await {
                            Ok(0) => return,
                            Err(_) => return,
                            Ok(_) => {}
                        }
                        buf.push(b[0]);
                        if buf.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    let head = String::from_utf8_lossy(&buf).to_ascii_lowercase();
                    let clen: usize = head
                        .lines()
                        .filter_map(|l| l.split_once(':'))
                        .find(|(k, _)| k.trim() == "content-length")
                        .and_then(|(_, v)| v.trim().parse().ok())
                        .unwrap_or(0);
                    let mut query = vec![0u8; clen];
                    if tls.read_exact(&mut query).await.is_err() {
                        return;
                    }
                    // 固定应答：test.local → 9.9.9.9
                    let resp_msg = {
                        let mut m = Vec::new();
                        m.extend_from_slice(&query[..2]);
                        m.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
                        // question 段（含 qtype/qclass）原样回带
                        m.extend_from_slice(&query[12..]);
                        m.extend_from_slice(&[
                            0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 9, 9, 9, 9,
                        ]);
                        m
                    };
                    let http = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        resp_msg.len()
                    );
                    let _ = tls.write_all(http.as_bytes()).await;
                    let _ = tls.write_all(&resp_msg).await;
                });
            }
        });

        let r = Resolver::new(vec![format!("https://127.0.0.1:{port}/dns-query#insecure")]);
        let ips = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            r.resolve_domain("test.local", false),
        )
        .await
        .expect("resolve 超时")
        .unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].to_string(), "9.9.9.9");
    }

    /// 真实 DoH 联测（需外网直连）：cargo test -p vp-dns -- --ignored
    #[tokio::test]
    #[ignore]
    async fn doh_live_cloudflare() {
        let r = Resolver::new(vec!["https://1.1.1.1/dns-query".into()]);
        assert!(!r.use_system);
        let ips = r.resolve_domain("www.google.com", false).await.unwrap();
        assert!(!ips.is_empty());
        // 证书按 1.1.1.1 签发（cloudflare-dns.com SAN 含 1.1.1.1），SNI 走 IP 形式可能失败，
        // 改用域名上游再验证一次
        let r2 = Resolver::new(vec!["https://dns.google/dns-query".into()]);
        let ips2 = r2.resolve_domain("www.google.com", false).await.unwrap();
        assert!(!ips2.is_empty());
    }

    async fn spawn_mock_dns(ip: [u8; 4]) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                if n < 12 {
                    continue;
                }
                let mut m = Vec::new();
                m.extend_from_slice(&buf[..2]);
                m.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
                m.extend_from_slice(&buf[12..n]);
                m.extend_from_slice(&[
                    0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, ip[0], ip[1], ip[2], ip[3],
                ]);
                let _ = sock.send_to(&m, from).await;
            }
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn nameserver_policy_routing() {
        let (primary_addr, _h1) = spawn_mock_dns([10, 0, 0, 1]).await;
        let (policy_addr, _h2) = spawn_mock_dns([8, 8, 8, 8]).await;

        let mut policy_map = std::collections::HashMap::new();
        policy_map.insert(
            "*.google.com".into(),
            serde_yaml::Value::String(format!("udp://{}", policy_addr)),
        );

        let policies = compile_nameserver_policy(&policy_map, None);
        let resolver = Resolver::build(
            vec![format!("udp://{}", primary_addr)],
            Vec::new(),
            policies,
            None,
        );

        // 匹配 policy 的域名解析到 8.8.8.8
        let google_ips = resolver
            .resolve_domain("www.google.com", false)
            .await
            .unwrap();
        assert_eq!(google_ips[0].to_string(), "8.8.8.8");

        // 不匹配 policy 的普通域名解析到 10.0.0.1
        let normal_ips = resolver.resolve_domain("example.com", false).await.unwrap();
        assert_eq!(normal_ips[0].to_string(), "10.0.0.1");
    }

    #[tokio::test]
    async fn fallback_filter_domain_routing() {
        let (primary_addr, _h1) = spawn_mock_dns([10, 0, 0, 1]).await;
        let (fallback_addr, _h2) = spawn_mock_dns([1, 1, 1, 1]).await;

        let ff_cfg = vp_config::FallbackFilterConfig {
            geoip: false,
            geoip_code: "CN".into(),
            ipcidr: vec![],
            domain: vec!["+.twitter.com".into()],
            geosite: vec![],
        };
        let filter = compile_fallback_filter(&ff_cfg, None, None);

        let resolver = Resolver::build(
            vec![format!("udp://{}", primary_addr)],
            vec![format!("udp://{}", fallback_addr)],
            Vec::new(),
            Some(filter),
        );

        // 命中 fallback-filter domain 的域名直接走 fallback
        let twitter_ips = resolver
            .resolve_domain("api.twitter.com", false)
            .await
            .unwrap();
        assert_eq!(twitter_ips[0].to_string(), "1.1.1.1");

        // 普通域名走 primary
        let normal_ips = resolver.resolve_domain("baidu.com", false).await.unwrap();
        assert_eq!(normal_ips[0].to_string(), "10.0.0.1");
    }

    #[tokio::test]
    async fn fallback_filter_cidr_poison_rejection() {
        // 主 DNS 返回污染网段 240.0.0.1 (Bogon)
        let (poison_primary, _h1) = spawn_mock_dns([240, 0, 0, 1]).await;
        // Fallback 返回正常 IP 1.1.1.1
        let (clean_fallback, _h2) = spawn_mock_dns([1, 1, 1, 1]).await;

        let ff_cfg = vp_config::FallbackFilterConfig {
            geoip: false,
            geoip_code: "CN".into(),
            ipcidr: vec!["240.0.0.0/4".into()],
            domain: vec![],
            geosite: vec![],
        };
        let filter = compile_fallback_filter(&ff_cfg, None, None);

        let resolver = Resolver::build(
            vec![format!("udp://{}", poison_primary)],
            vec![format!("udp://{}", clean_fallback)],
            Vec::new(),
            Some(filter),
        );

        // 主 DNS 返回的 IP 命中 240.0.0.0/4 污染列表，被自动拒绝并降级切换到 fallback (1.1.1.1)
        let ips = resolver
            .resolve_domain("blocked-service.com", false)
            .await
            .unwrap();
        assert_eq!(ips[0].to_string(), "1.1.1.1");
    }
}

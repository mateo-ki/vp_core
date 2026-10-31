//! vp-transport：传输层（TCP / TLS / WebSocket / HTTP 伪装）。

use std::sync::Arc;

pub mod grpc;
pub mod hpke;
pub mod http;
pub mod quic;
pub mod tls;
pub mod utls;
pub mod ws;

pub type ProxyStreamBox = Box<dyn vp_core::ProxyStream>;

pub use http::{HttpConfig, HttpStream, http_handshake_client};
pub use tls::{TlsClientConfig, connect_tls, tls_acceptor, tls_connect};
pub use ws::{WsConfig, WsStream, ws_handshake_client, ws_handshake_server};

use std::time::Duration;
use vp_common::Result;
use vp_core::ProxyStream;

/// 套接字调优快照（报告任务7 第一阶段）：四个独立 Atomic 合并为单一
/// `RwLock<SocketTuning>`，tune() 一次读取拿到**一致**的配置快照，
/// 不再出现"半新半旧"的混合参数。真正的多 Runtime 实例化（每 AppRuntime
/// 一份 SocketTuning）等出现第二个 Runtime 时再做——单实例进程里
/// 全局快照与实例语义等价。
#[derive(Debug, Clone, Copy)]
pub struct SocketTuning {
    pub rcvbuf: usize,
    pub sndbuf: usize,
    pub tcp_nodelay: bool,
    pub keepalive_secs: u64,
}

static TUNING: std::sync::RwLock<SocketTuning> = std::sync::RwLock::new(SocketTuning {
    rcvbuf: 0,
    sndbuf: 0,
    tcp_nodelay: true,
    keepalive_secs: 60,
});

/// 当前生效的调优快照（一致读取）
pub fn tuning_snapshot() -> SocketTuning {
    *TUNING.read().unwrap()
}

/// 全局配置套接字发送与接收缓冲区及 TCP 调优参数
pub fn set_global_tuning(rcvbuf: usize, sndbuf: usize, tcp_nodelay: bool, tcp_keepalive_secs: u64) {
    *TUNING.write().unwrap() = SocketTuning {
        rcvbuf,
        sndbuf,
        tcp_nodelay,
        keepalive_secs: if tcp_keepalive_secs == 0 {
            60
        } else {
            tcp_keepalive_secs
        },
    };
}

/// 套接字调优：内核持有的所有 TCP 连接统一设置。
/// - TCP_NODELAY：关闭 Nagle，交互流量不被合并延迟（流畅的关键）
/// - SO_RCVBUF / SO_SNDBUF：高带宽时延积 (BDP) 窗口放大
/// - TCP keepalive：探测对端僵死连接，避免句柄泄漏（稳定的保障）
pub fn tune(stream: &tokio::net::TcpStream) {
    let sock = socket2::SockRef::from(stream);
    let t = tuning_snapshot();
    let _ = sock.set_tcp_nodelay(t.tcp_nodelay);

    if t.rcvbuf > 0 {
        let _ = sock.set_recv_buffer_size(t.rcvbuf);
    }
    if t.sndbuf > 0 {
        let _ = sock.set_send_buffer_size(t.sndbuf);
    }

    let keepalive_secs = t.keepalive_secs;
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(keepalive_secs))
        .with_interval(Duration::from_secs(15));
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let ka = ka.with_retries(3);
    let _ = sock.set_tcp_keepalive(&ka);
}

/// REALITY 扩展配置（VLESS / Trojan 专有，对标 Xray-core / sing-box）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityConfig {
    /// 32 字节服务端静态 Curve25519 公钥
    pub public_key: [u8; 32],
    /// 0~8 字节 short_id（不足 8 字节右补零）
    pub short_id: [u8; 8],
    /// 爬虫探测路径（如 "/"）
    pub spider_x: Option<String>,
}

pub fn parse_reality_config(
    public_key_str: &str,
    short_id_str: Option<&str>,
    spider_x: Option<String>,
) -> Result<RealityConfig> {
    let clean_pk = public_key_str.trim();
    let pk_bytes = if clean_pk.len() == 64 && clean_pk.chars().all(|c| c.is_ascii_hexdigit()) {
        hex_decode(clean_pk).map_err(|e| {
            vp_common::Error::Config(format!("REALITY public_key 十六进制解码失败: {e}"))
        })?
    } else {
        use base64::Engine;
        use base64::engine::general_purpose::{
            STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD,
        };
        URL_SAFE_NO_PAD
            .decode(clean_pk)
            .or_else(|_| URL_SAFE.decode(clean_pk))
            .or_else(|_| STANDARD_NO_PAD.decode(clean_pk))
            .or_else(|_| STANDARD.decode(clean_pk))
            .map_err(|e| {
                vp_common::Error::Config(format!("REALITY public_key base64解码失败: {e}"))
            })?
    };
    if pk_bytes.len() != 32 {
        return Err(vp_common::Error::Config(format!(
            "REALITY public_key 必须为 32 字节 (当前 {} 字节)",
            pk_bytes.len()
        )));
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&pk_bytes);

    let mut short_id = [0u8; 8];
    if let Some(sid) = short_id_str {
        let clean_sid = sid.trim();
        if !clean_sid.is_empty() {
            let decoded = hex_decode(clean_sid).map_err(|e| {
                vp_common::Error::Config(format!("REALITY short_id 十六进制解码失败: {e}"))
            })?;
            if decoded.len() > 8 {
                return Err(vp_common::Error::Config(format!(
                    "REALITY short_id 最长 8 字节 (16 字符)，当前 {} 字节",
                    decoded.len()
                )));
            }
            short_id[..decoded.len()].copy_from_slice(&decoded);
        }
    }

    Ok(RealityConfig {
        public_key,
        short_id,
        spider_x,
    })
}

fn hex_decode(s: &str) -> std::result::Result<Vec<u8>, &'static str> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("长度必须为偶数");
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16).ok_or("非法字符")? as u8;
        let lo = (bytes[i + 1] as char).to_digit(16).ok_or("非法字符")? as u8;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// 节点声明的 ECH（Encrypted Client Hello）请求（Clash `ech-opts` / 分享链接 `ech=` 参数）
#[derive(Debug, Clone)]
pub struct EchRequest {
    /// 节点配置直接携带的 ECHConfigList（base64 解码后）；优先于 DNS 查询
    pub config: Option<Vec<u8>>,
    /// DNS HTTPS(type65) 记录查询名；缺省用 SNI/服务器域名
    pub query_name: Option<String>,
    /// 查询 ECH 记录专用的 DoH URL（分享链接 `ech=name+doh` 携带）；优先于全局解析器
    pub doh: Option<String>,
}

/// 传输配置（各协议出站共用）
#[derive(Debug, Clone, Default)]
pub struct TransportConfig {
    pub tls: bool,
    pub server_name: Option<String>,
    pub skip_cert_verify: bool,
    /// uTLS 指纹（"chrome"）：设置时 TLS 走手写指纹客户端
    pub fingerprint: Option<String>,
    /// 节点显式声明的 ALPN；为空时按传输类型推导（grpc→h2，ws→http/1.1）
    pub alpn: Vec<String>,
    /// network: "ws" 时启用 WebSocket
    pub ws: Option<WsConfig>,
    /// network: "http" 时启用 HTTP 伪装传输
    pub http: Option<http::HttpConfig>,
    /// network: "grpc" 时启用 gRPC（要求 TLS + ALPN h2）
    pub grpc: Option<grpc::GrpcConfig>,
    /// REALITY 认证扩展
    pub reality: Option<RealityConfig>,
    /// ECH（Encrypted Client Hello）
    pub ech: Option<EchRequest>,
}

/// ALPN 取值：节点显式声明的优先，否则按传输类型推导（grpc→h2，ws→http/1.1）
fn explicit_or_derived_alpn(cfg: &TransportConfig, grpc: &[String], ws: &[String]) -> Vec<String> {
    if !cfg.alpn.is_empty() {
        return cfg.alpn.clone();
    }
    if cfg.grpc.is_some() {
        return grpc.to_vec();
    }
    if cfg.ws.is_some() {
        return ws.to_vec();
    }
    Vec::new()
}

/// 在任意底层流之上层叠传输层封装（gRPC / TLS / uTLS / REALITY / WebSocket）
pub async fn wrap_transport(
    stream: Box<dyn ProxyStream>,
    server_host: &str,
    cfg: &TransportConfig,
) -> Result<Box<dyn ProxyStream>> {
    if let Some(g) = &cfg.grpc {
        // grpc 生态默认 TLS + ALPN h2
        let tls = tls::tls_connect(
            stream,
            server_host,
            &tls::TlsClientConfig {
                skip_cert_verify: cfg.skip_cert_verify,
                server_name: cfg.server_name.clone(),
                alpn: vec!["h2".into()],
                ech_config: None,
            },
        )
        .await?;
        let s = grpc::grpc_connect(tls, server_host, g).await?;
        return Ok(Box::new(s));
    }
    if cfg.tls || cfg.reality.is_some() {
        // uTLS（浏览器指纹）只在 REALITY 握手认证时使用：REALITY 依赖 uTLS ClientHello
        // 里的 auth 载荷。普通 TLS 站点（尤其 CDN 前置的 ws/grpc 节点）实测与手写 uTLS
        // 存在互操作缺陷（服务端 TLS 栈半卡：ws 帧头可达、payload 永不到达），一律走
        // rustls 标准栈——Mihomo 的 Go TLS 同样不是真 uTLS，指纹差异不影响可用性。
        // ECH 配置解析（ech-opts.config 优先，其次 DoH / DNS HTTPS 记录；解析器带缓存）
        let ech_config: Option<Arc<Vec<u8>>> = match &cfg.ech {
            Some(req) => match &req.config {
                Some(bytes) => Some(Arc::new(bytes.clone())),
                None => {
                    let qname = req
                        .query_name
                        .clone()
                        .or_else(|| cfg.server_name.clone())
                        .unwrap_or_else(|| server_host.to_string());
                    // 分享链接携带的 DoH（如 https://dns.alidns.com/dns-query）最可信：
                    // 系统/内置解析器在污染网络下常拿不到 HTTPS(type65) 记录
                    if let Some(doh) = &req.doh {
                        let r = vp_dns::Resolver::new(vec![doh.clone()]);
                        r.query_https_ech(&qname).await
                    } else {
                        match tls::global_resolver() {
                            Some(res) => res.query_https_ech(&qname).await,
                            None => {
                                tracing::debug!(
                                    "ech-opts 已启用但全局 DNS 未就绪，跳过 ECH: {server_host}"
                                );
                                None
                            }
                        }
                    }
                }
            },
            None => None,
        };
        let tls: Box<dyn ProxyStream> = if cfg.reality.is_some() {
            let fp = cfg.fingerprint.as_deref().unwrap_or("chrome");
            let alpn = explicit_or_derived_alpn(cfg, &["h2".into()], &["http/1.1".into()]);
            let s = utls::utls_connect(
                stream,
                server_host,
                &utls::UtlsConfig {
                    fingerprint: utls::Fingerprint::parse(fp)?,
                    server_name: cfg.server_name.clone(),
                    alpn,
                    skip_cert_verify: cfg.skip_cert_verify,
                    reality: cfg.reality.clone(),
                },
            )
            .await?;
            Box::new(vp_core::stream::Opaque(s))
        } else {
            let alpn = explicit_or_derived_alpn(cfg, &["h2".into()], &["http/1.1".into()]);
            let s = tls::tls_connect(
                stream,
                server_host,
                &tls::TlsClientConfig {
                    skip_cert_verify: cfg.skip_cert_verify,
                    server_name: cfg.server_name.clone(),
                    alpn,
                    ech_config,
                },
            )
            .await?;
            Box::new(vp_core::stream::Opaque(s))
        };
        if let Some(ws) = &cfg.ws {
            let ws_stream = ws::ws_handshake_client(tls, server_host, ws).await?;
            return Ok(Box::new(ws_stream));
        }
        if let Some(h) = &cfg.http {
            let s = http::http_handshake_client(tls, server_host, h)?;
            return Ok(Box::new(s));
        }
        return Ok(tls);
    }
    if let Some(ws) = &cfg.ws {
        let ws_stream = ws::ws_handshake_client(stream, server_host, ws).await?;
        return Ok(Box::new(ws_stream));
    }
    if let Some(h) = &cfg.http {
        let s = http::http_handshake_client(stream, server_host, h)?;
        return Ok(Box::new(s));
    }
    Ok(stream)
}

/// 节点拨号专用的全局解析器（进程内唯一 DNS 配置，随配置加载注入）。
/// 只用于拨号"代理节点自身的服务器域名"，不影响业务目标的分流解析（那是 DIRECT/规则的事）。
static NODE_RESOLVER: std::sync::RwLock<Option<(std::sync::Arc<vp_dns::Resolver>, bool)>> =
    std::sync::RwLock::new(None);

/// 注入节点拨号解析器与 IPv6 偏好（vp-app 加载配置后调用；配置热重载会再次覆盖）。
pub fn set_global_node_resolver(resolver: std::sync::Arc<vp_dns::Resolver>, ipv6: bool) {
    if let Ok(mut slot) = NODE_RESOLVER.write() {
        *slot = Some((resolver, ipv6));
    }
}

fn global_node_resolver() -> Option<(std::sync::Arc<vp_dns::Resolver>, bool)> {
    NODE_RESOLVER.read().ok().and_then(|slot| slot.clone())
}

static BIND_INTERFACE_INDEX: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// 设置出站套接字强制绑定的物理网卡索引（TUN 模式防环路）
pub fn set_bind_interface_index(if_idx: u32) {
    BIND_INTERFACE_INDEX.store(if_idx, std::sync::atomic::Ordering::Relaxed);
    vp_dns::set_bind_interface_index(if_idx);
}

/// 获取当前设置的物理网卡索引
pub fn get_bind_interface_index() -> Option<u32> {
    let idx = BIND_INTERFACE_INDEX.load(std::sync::atomic::Ordering::Relaxed);
    if idx > 0 { Some(idx) } else { None }
}

/// 创建 UDP 套接字，若配置了物理网卡索引则绑定 IP_UNICAST_IF / IPV6_UNICAST_IF 防止路由环路
pub fn create_udp_socket(
    bind_addr: std::net::SocketAddr,
) -> std::io::Result<tokio::net::UdpSocket> {
    vp_dns::create_udp_socket(bind_addr)
}

/// 自动探测系统的物理出站网卡索引（用于 Windows TUN 模式防环路）
#[cfg(windows)]
pub fn detect_default_physical_interface() -> Option<u32> {
    use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetIpForwardTable, MIB_IPFORWARDTABLE};

    let mut size: u32 = 0;
    unsafe {
        let ret = GetIpForwardTable(std::ptr::null_mut(), &mut size, 1);
        if ret != ERROR_INSUFFICIENT_BUFFER && ret != 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let table_ptr = buf.as_mut_ptr() as *mut MIB_IPFORWARDTABLE;
        if GetIpForwardTable(table_ptr, &mut size, 1) == 0 {
            let num_entries = (*table_ptr).dwNumEntries as usize;
            let rows_ptr = (*table_ptr).table.as_ptr();
            let mut best_if = 0;
            let mut best_metric = u32::MAX;

            for i in 0..num_entries {
                let row = *rows_ptr.add(i);
                // 默认路由：Destination 0.0.0.0 且 Mask 0.0.0.0
                if row.dwForwardDest == 0 && row.dwForwardMask == 0 && row.dwForwardNextHop != 0 {
                    // 排除 Fake-IP / TUN 保留网段 (198.18.0.0/15)
                    let hop_bytes = row.dwForwardNextHop.to_ne_bytes();
                    let is_tun_fake =
                        hop_bytes[0] == 198 && (hop_bytes[1] == 18 || hop_bytes[1] == 19);
                    if !is_tun_fake && row.dwForwardMetric1 < best_metric {
                        best_metric = row.dwForwardMetric1;
                        best_if = row.dwForwardIfIndex;
                    }
                }
            }
            if best_if > 0 {
                tracing::info!(
                    "自动从默认网关路由探测到物理出站网卡 IfIndex={best_if} (metric={best_metric})"
                );
                return Some(best_if);
            }
        }
    }
    tracing::warn!("未能自动探测物理出站网卡");
    None
}

#[cfg(not(windows))]
pub fn detect_default_physical_interface() -> Option<u32> {
    None
}

/// 建立 TCP 连接，若配置了物理网卡索引则绑定 IP_UNICAST_IF 防止路由环路
pub async fn connect_tcp_stream(
    addr: std::net::SocketAddr,
) -> std::io::Result<tokio::net::TcpStream> {
    #[cfg(windows)]
    {
        if !addr.ip().is_loopback() {
            if let Some(if_idx) = get_bind_interface_index() {
                let domain = match addr {
                    std::net::SocketAddr::V4(_) => socket2::Domain::IPV4,
                    std::net::SocketAddr::V6(_) => socket2::Domain::IPV6,
                };
                let socket = socket2::Socket::new(
                    domain,
                    socket2::Type::STREAM,
                    Some(socket2::Protocol::TCP),
                )?;
                socket.set_nonblocking(true)?;

                // UNICAST_IF + 显式源 IP 绑定（实现在 vp-dns，与 DNS 上游共用同一套）：
                // 只设 UNICAST_IF 不绑源 IP 时，Windows 的源地址/路由选择仍可能按路由
                // 表走 —— auto-route 下即 TUN 自身，节点拨号全部流回自己形成回环。
                vp_dns::bind_tcp_socket_to_interface(&socket, addr, if_idx)?;

                match socket.connect(&addr.into()) {
                    Ok(()) => {
                        let std_stream: std::net::TcpStream = socket.into();
                        return tokio::net::TcpStream::from_std(std_stream);
                    }
                    Err(e)
                        if e.raw_os_error()
                            == Some(windows_sys::Win32::Networking::WinSock::WSAEWOULDBLOCK) =>
                    {
                        let std_stream: std::net::TcpStream = socket.into();
                        let tokio_stream = tokio::net::TcpStream::from_std(std_stream)?;
                        tokio_stream.writable().await?;
                        if let Some(err) = tokio_stream.take_error()? {
                            return Err(err);
                        }
                        return Ok(tokio_stream);
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }
    tokio::net::TcpStream::connect(addr).await
}

// bind_socket_to_interface 已上移到 vp_dns（bind_tcp_socket_to_interface / connect_tcp_bound），
// DNS 上游与节点拨号共用同一套"UNICAST_IF + 源 IP 绑定"实现，避免两份实现漂移。

/// 多地址竞速 TCP 拨号。
///
/// 节点域名常返回多条 A 记录，且解析结果可能混入被污染/已失效的地址（GFW 的"邻居 IP"
/// 污染会返回与真实记录同网段的假地址）。顺序拨号时排在前面的一条假地址就能吃光整体
/// 超时预算，表现成节点"时通时不通"。这里把内置 DNS 与系统解析的并集地址并发竞速：
/// 后续地址错峰启动（保留解析器给出的优先序偏好），任一地址建立连接即胜出并取消其余。
pub async fn dial_tcp_multi(
    host: &str,
    port: u16,
    budget: Duration,
) -> Result<tokio::net::TcpStream> {
    use std::net::{IpAddr, SocketAddr};
    if let Ok(ip) = host.parse::<IpAddr>() {
        let addr = SocketAddr::new(ip, port);
        let tcp = tokio::time::timeout(budget, connect_tcp_stream(addr))
            .await
            .map_err(|_| {
                vp_common::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("连接 {host}:{port} 超时"),
                ))
            })??;
        tune(&tcp);
        return Ok(tcp);
    }
    let mut addrs: Vec<SocketAddr> = Vec::new();
    // 1) 内置 DNS（多上游并发 + 缓存 + 污染过滤）：节点域名优先走它
    if let Some((resolver, ipv6)) = global_node_resolver() {
        match resolver.resolve_domain(host, ipv6).await {
            Ok(ips) => {
                addrs.extend(ips.iter().map(|ip| SocketAddr::new(*ip, port)));
            }
            Err(e) => {
                tracing::debug!("节点域名 {host} 内置 DNS 解析失败，回退系统解析: {e}");
            }
        }
    }
    // 2) 系统解析并入并集：内置 DNS 若整轮被污染，系统答案里可能仍有活地址
    match tokio::net::lookup_host((host, port)).await {
        Ok(it) => addrs.extend(it),
        Err(e) if addrs.is_empty() => {
            return Err(vp_common::Error::Dns(format!("解析 {host} 失败: {e}")));
        }
        Err(_) => {}
    }
    addrs.dedup();
    if addrs.is_empty() {
        return Err(vp_common::Error::Dns(format!("解析 {host} 未得到任何地址")));
    }
    if addrs.len() == 1 {
        let tcp = tokio::time::timeout(budget, connect_tcp_stream(addrs[0]))
            .await
            .map_err(|_| {
                vp_common::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("连接 {host}:{port} 超时"),
                ))
            })??;
        tune(&tcp);
        return Ok(tcp);
    }
    dial_addrs_multi(&addrs, host, port, budget).await
}

/// 对既定地址列表竞速拨号（[`dial_tcp_multi`] 的核心，独立出来便于测试）。
pub async fn dial_addrs_multi(
    addrs: &[std::net::SocketAddr],
    host: &str,
    port: u16,
    budget: Duration,
) -> Result<tokio::net::TcpStream> {
    const STAGGER: Duration = Duration::from_millis(150);
    let total = addrs.len();
    let mut tasks: tokio::task::JoinSet<(
        std::net::SocketAddr,
        std::io::Result<tokio::net::TcpStream>,
    )> = tokio::task::JoinSet::new();
    for (idx, addr) in addrs.iter().enumerate() {
        let addr = *addr;
        let delay = STAGGER * (idx as u32).min(4);
        tasks.spawn(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let res = connect_tcp_stream(addr).await;
            (addr, res)
        });
    }

    let mut failed = 0usize;
    let mut last_err: Option<std::io::Error> = None;
    let winner = tokio::time::timeout(budget, async {
        while let Some(res) = tasks.join_next().await {
            match res {
                Ok((addr, Ok(tcp))) => return Some((addr, tcp)),
                Ok((addr, Err(e))) => {
                    tracing::debug!("竞速拨号 {addr} 失败: {e}");
                    failed += 1;
                    last_err = Some(e);
                }
                Err(_) => {
                    // 拨号任务 panic：按失败处理，继续等其余地址
                    failed += 1;
                }
            }
        }
        None
    })
    .await;

    match winner {
        Ok(Some((addr, tcp))) => {
            tasks.abort_all();
            tracing::debug!(
                "竞速拨号 {host}:{port} 经 {addr} 建立连接（{failed}/{total} 个地址此前失败）"
            );
            tune(&tcp);
            Ok(tcp)
        }
        Ok(None) => {
            let detail = last_err
                .as_ref()
                .map(|e| format!("，最后错误: {e}"))
                .unwrap_or_default();
            Err(vp_common::Error::Io(std::io::Error::other(format!(
                "连接 {host}:{port} 失败：{total} 个地址均不可达{detail}"
            ))))
        }
        Err(_) => {
            tasks.abort_all();
            Err(vp_common::Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("连接 {host}:{port} 超时（{failed}/{total} 个地址已失败）"),
            )))
        }
    }
}

/// 拨号：TCP → 传输层封装（wrap_transport）
pub async fn dial(
    server_host: &str,
    server_port: u16,
    cfg: &TransportConfig,
) -> Result<Box<dyn ProxyStream>> {
    let tcp = dial_tcp_multi(server_host, server_port, Duration::from_secs(8)).await?;
    match wrap_transport(Box::new(tcp), server_host, cfg).await {
        // ECH 被服务端拒绝：底层流已废弃，只能换新连接重拨。tls 层状态机决定重拨走什么：
        // 服务端给了新的 retry config → 再试一次 ECH；否则直接普通 TLS。
        // 至多重拨两轮即可收敛：ECH(DNS 配置) → ECH(retry config) → 普通 TLS，
        // 之后该主机被记住拒绝状态，后续连接首轮就直走普通 TLS，不再浪费握手。
        Err(e) if e.to_string().contains("ECH_REJECTED_FALLBACK") => {
            for _ in 0..2 {
                let tcp = dial_tcp_multi(server_host, server_port, Duration::from_secs(8)).await?;
                match wrap_transport(Box::new(tcp), server_host, cfg).await {
                    Err(e2) if e2.to_string().contains("ECH_REJECTED_FALLBACK") => continue,
                    other => return other,
                }
            }
            Err(e)
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dial_plain_tcp() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut s, _) = listener.accept().await.unwrap();
            let mut b = [0u8; 2];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(b"ok").await.unwrap();
        });
        let mut c = dial("127.0.0.1", addr.port(), &TransportConfig::default())
            .await
            .unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        c.write_all(b"hi").await.unwrap();
        let mut b = [0u8; 2];
        c.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"ok");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn dial_tcp_multi_single_address() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_s, _) = listener.accept().await.unwrap();
        });
        let c = dial_tcp_multi("127.0.0.1", addr.port(), Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(c.peer_addr().unwrap().port(), addr.port());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn dial_tcp_multi_races_around_dead_address() {
        // 首位放一个不可路由的黑洞地址（模拟被污染/失效的 A 记录），
        // 竞速应绕过它从活地址建立连接，而不是被它吃光预算。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live = listener.local_addr().unwrap();
        let dead: std::net::SocketAddr = "10.255.255.1:9".parse().unwrap();
        let server = tokio::spawn(async move {
            let (_s, _) = listener.accept().await.unwrap();
        });
        let c = dial_addrs_multi(
            &[dead, live],
            "race.test",
            live.port(),
            Duration::from_secs(6),
        )
        .await
        .unwrap();
        assert_eq!(c.peer_addr().unwrap(), live);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn dial_tcp_multi_reports_failure_when_all_dead() {
        let dead: std::net::SocketAddr = "10.255.255.1:9".parse().unwrap();
        let res = dial_addrs_multi(&[dead], "dead.test", 9, Duration::from_millis(700)).await;
        assert!(res.is_err(), "全黑洞地址应当失败: {res:?}");
    }

    #[test]
    fn test_detect_default_physical_interface() {
        #[cfg(windows)]
        {
            let if_idx = detect_default_physical_interface();
            assert!(if_idx.is_some(), "应当能检测到默认物理网卡");
            let idx = if_idx.unwrap();
            assert!(idx > 0);
            assert_ne!(idx, 82, "绝不能匹配到 vpcore-tun 自身");
        }
    }

    /// 回归测试（TUN 防回环）：绑卡拨号的源地址必须是物理网卡自己的 IP。
    /// 回归背景：TUN auto-route 下，"只设 IP_UNICAST_IF 不显式 bind 源 IP"的套接字，
    /// Windows 的源地址/路由选择仍按路由表走（即 TUN 自身 198.18.0.1），DNS 上游与
    /// 节点拨号全部流回自己形成回环 —— 表现为 TUN 开启后整机断网。修复 = UNICAST_IF
    /// + 源 IP 显式绑定（vp_dns::bind_tcp_socket_to_interface）。
    #[tokio::test]
    async fn bound_dial_source_must_be_physical_ip() {
        #[cfg(windows)]
        {
            let Some(if_idx) = detect_default_physical_interface() else {
                return; // 无多网卡环境跳过
            };
            let Some(expect_ip) = vp_dns::interface_ipv4(if_idx) else {
                return;
            };
            let addr: std::net::SocketAddr = "223.5.5.5:443".parse().unwrap();

            let prev = get_bind_interface_index();
            set_bind_interface_index(if_idx);
            let stream = vp_dns::connect_tcp_bound(addr).await.expect("绑卡拨号应成功");
            let local = stream.local_addr().unwrap();
            // 还原全局绑定状态，避免污染并行测试
            set_bind_interface_index(prev.unwrap_or(0));
            assert_eq!(
                local.ip(),
                std::net::IpAddr::V4(expect_ip),
                "绑卡拨号的源地址必须是物理网卡 {if_idx} 的 IP {expect_ip}"
            );
        }
    }

    #[test]
    fn parse_reality_config_formats() {
        use base64::Engine;
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

        let raw_pk = [42u8; 32];
        let b64_url = URL_SAFE_NO_PAD.encode(raw_pk);
        let b64_std = STANDARD.encode(raw_pk);
        let hex_pk = raw_pk
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        // 1. URL_SAFE_NO_PAD (Xray / sing-box 标准)
        let cfg1 =
            parse_reality_config(&b64_url, Some("0123456789abcdef"), Some("/".into())).unwrap();
        assert_eq!(cfg1.public_key, raw_pk);
        assert_eq!(
            cfg1.short_id,
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
        assert_eq!(cfg1.spider_x.as_deref(), Some("/"));

        // 2. STANDARD Base64
        let cfg2 = parse_reality_config(&b64_std, Some("1234"), None).unwrap();
        assert_eq!(cfg2.public_key, raw_pk);
        assert_eq!(cfg2.short_id, [0x12, 0x34, 0, 0, 0, 0, 0, 0]);
        assert_eq!(cfg2.spider_x, None);

        // 3. Hex 64 字符
        let cfg3 = parse_reality_config(&hex_pk, None, None).unwrap();
        assert_eq!(cfg3.public_key, raw_pk);
        assert_eq!(cfg3.short_id, [0u8; 8]);

        // 4. 异常输入校验
        assert!(parse_reality_config("short", None, None).is_err());
        assert!(parse_reality_config(&b64_url, Some("not_hex"), None).is_err());
        assert!(parse_reality_config(&b64_url, Some("0123456789abcdef0123"), None).is_err()); // 超过 8 字节
    }
}

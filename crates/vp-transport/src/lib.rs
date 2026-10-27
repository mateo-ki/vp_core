//! vp-transport：传输层（TCP / TLS / WebSocket / HTTP 伪装）。

pub mod grpc;
pub mod http;
pub mod quic;
pub mod tls;
pub mod utls;
pub mod ws;

pub type ProxyStreamBox = Box<dyn vp_core::ProxyStream>;

pub use http::{HttpConfig, HttpStream, http_handshake_client};
pub use tls::{TlsClientConfig, connect_tls, tls_acceptor, tls_connect};
pub use ws::{WsConfig, WsStream, ws_handshake_client, ws_handshake_server};

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use vp_common::Result;
use vp_core::ProxyStream;

static GLOBAL_SO_RCVBUF: AtomicUsize = AtomicUsize::new(0);
static GLOBAL_SO_SNDBUF: AtomicUsize = AtomicUsize::new(0);
static GLOBAL_TCP_NODELAY: AtomicBool = AtomicBool::new(true);
static GLOBAL_TCP_KEEPALIVE_SECS: AtomicU64 = AtomicU64::new(60);

/// 全局配置套接字发送与接收缓冲区及 TCP 调优参数
pub fn set_global_tuning(rcvbuf: usize, sndbuf: usize, tcp_nodelay: bool, tcp_keepalive_secs: u64) {
    GLOBAL_SO_RCVBUF.store(rcvbuf, Ordering::Relaxed);
    GLOBAL_SO_SNDBUF.store(sndbuf, Ordering::Relaxed);
    GLOBAL_TCP_NODELAY.store(tcp_nodelay, Ordering::Relaxed);
    GLOBAL_TCP_KEEPALIVE_SECS.store(
        if tcp_keepalive_secs == 0 {
            60
        } else {
            tcp_keepalive_secs
        },
        Ordering::Relaxed,
    );
}

/// 套接字调优：内核持有的所有 TCP 连接统一设置。
/// - TCP_NODELAY：关闭 Nagle，交互流量不被合并延迟（流畅的关键）
/// - SO_RCVBUF / SO_SNDBUF：高带宽时延积 (BDP) 窗口放大
/// - TCP keepalive：探测对端僵死连接，避免句柄泄漏（稳定的保障）
pub fn tune(stream: &tokio::net::TcpStream) {
    let sock = socket2::SockRef::from(stream);
    let nodelay = GLOBAL_TCP_NODELAY.load(Ordering::Relaxed);
    let _ = sock.set_tcp_nodelay(nodelay);

    let rcv = GLOBAL_SO_RCVBUF.load(Ordering::Relaxed);
    if rcv > 0 {
        let _ = sock.set_recv_buffer_size(rcv);
    }
    let snd = GLOBAL_SO_SNDBUF.load(Ordering::Relaxed);
    if snd > 0 {
        let _ = sock.set_send_buffer_size(snd);
    }

    let keepalive_secs = GLOBAL_TCP_KEEPALIVE_SECS.load(Ordering::Relaxed);
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

/// 传输配置（各协议出站共用）
#[derive(Debug, Clone, Default)]
pub struct TransportConfig {
    pub tls: bool,
    pub server_name: Option<String>,
    pub skip_cert_verify: bool,
    /// uTLS 指纹（"chrome"）：设置时 TLS 走手写指纹客户端
    pub fingerprint: Option<String>,
    /// network: "ws" 时启用 WebSocket
    pub ws: Option<WsConfig>,
    /// network: "http" 时启用 HTTP 伪装传输
    pub http: Option<http::HttpConfig>,
    /// network: "grpc" 时启用 gRPC（要求 TLS + ALPN h2）
    pub grpc: Option<grpc::GrpcConfig>,
    /// REALITY 认证扩展
    pub reality: Option<RealityConfig>,
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
        let tls: Box<dyn ProxyStream> = if cfg.reality.is_some() {
            let fp = cfg.fingerprint.as_deref().unwrap_or("chrome");
            let s = utls::utls_connect(
                stream,
                server_host,
                &utls::UtlsConfig {
                    fingerprint: utls::Fingerprint::parse(fp)?,
                    server_name: cfg.server_name.clone(),
                    alpn: Vec::new(),
                    skip_cert_verify: cfg.skip_cert_verify,
                    reality: cfg.reality.clone(),
                },
            )
            .await?;
            Box::new(s)
        } else {
            let s = tls::tls_connect(
                stream,
                server_host,
                &tls::TlsClientConfig {
                    skip_cert_verify: cfg.skip_cert_verify,
                    server_name: cfg.server_name.clone(),
                    alpn: Vec::new(),
                },
            )
            .await?;
            Box::new(s)
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

/// 拨号：TCP → 传输层封装（wrap_transport）
pub async fn dial(
    server_host: &str,
    server_port: u16,
    cfg: &TransportConfig,
) -> Result<Box<dyn ProxyStream>> {
    let tcp = tokio::time::timeout(
        Duration::from_secs(8),
        tokio::net::TcpStream::connect((server_host, server_port)),
    )
    .await
    .map_err(|_| {
        vp_common::Error::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("连接 {server_host}:{server_port} 超时"),
        ))
    })??;
    tune(&tcp);
    wrap_transport(Box::new(tcp), server_host, cfg).await
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

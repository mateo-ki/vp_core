//! vp-transport：传输层（TCP / TLS / WebSocket）。

pub mod grpc;
pub mod quic;
pub mod tls;
pub mod utls;
pub mod ws;

pub type ProxyStreamBox = Box<dyn vp_core::ProxyStream>;

pub use tls::{connect_tls, tls_acceptor, tls_connect, TlsClientConfig};
pub use ws::{ws_handshake_client, ws_handshake_server, WsConfig, WsStream};

use std::time::Duration;
use vp_common::Result;
use vp_core::ProxyStream;

/// 套接字调优：内核持有的所有 TCP 连接统一设置。
/// - TCP_NODELAY：关闭 Nagle，交互流量不被合并延迟（流畅的关键）
/// - TCP keepalive：探测对端僵死连接，避免句柄泄漏（稳定的保障）
pub fn tune(stream: &tokio::net::TcpStream) {
    let sock = socket2::SockRef::from(stream);
    let _ = sock.set_tcp_nodelay(true);
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(15));
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let ka = ka.with_retries(3);
    let _ = sock.set_tcp_keepalive(&ka);
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
    /// network: "grpc" 时启用 gRPC（要求 TLS + ALPN h2）
    pub grpc: Option<grpc::GrpcConfig>,
}

/// 拨号：TCP →（可选 WS）→（可选 TLS，TLS 在最外层）
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

    if let Some(g) = &cfg.grpc {
        // grpc 生态默认 TLS + ALPN h2
        let tls = tls::tls_connect(
            tcp,
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
    if cfg.tls {
        let tls: Box<dyn ProxyStream> = if let Some(fp) = &cfg.fingerprint {
            let s = utls::utls_connect(
                tcp,
                server_host,
                &utls::UtlsConfig {
                    fingerprint: utls::Fingerprint::parse(fp)?,
                    server_name: cfg.server_name.clone(),
                    alpn: Vec::new(),
                    skip_cert_verify: cfg.skip_cert_verify,
                },
            )
            .await?;
            Box::new(s)
        } else {
            let s = tls::tls_connect(
                tcp,
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
        return Ok(tls);
    }
    if let Some(ws) = &cfg.ws {
        let ws_stream = ws::ws_handshake_client(tcp, server_host, ws).await?;
        return Ok(Box::new(ws_stream));
    }
    Ok(Box::new(tcp))
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
}

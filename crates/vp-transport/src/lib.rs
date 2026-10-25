//! vp-transport：传输层（TCP / TLS / WebSocket）。

pub mod tls;
pub mod ws;

pub type ProxyStreamBox = Box<dyn vp_core::ProxyStream>;

pub use tls::{connect_tls, tls_acceptor, tls_connect, TlsClientConfig};
pub use ws::{ws_handshake_client, ws_handshake_server, WsConfig, WsStream};

use std::time::Duration;
use vp_common::Result;
use vp_core::ProxyStream;

/// 传输配置（各协议出站共用）
#[derive(Debug, Clone, Default)]
pub struct TransportConfig {
    pub tls: bool,
    pub server_name: Option<String>,
    pub skip_cert_verify: bool,
    /// network: "ws" 时启用 WebSocket
    pub ws: Option<WsConfig>,
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

    if cfg.tls {
        let tls = tls::tls_connect(
            tcp,
            server_host,
            &tls::TlsClientConfig {
                skip_cert_verify: cfg.skip_cert_verify,
                server_name: cfg.server_name.clone(),
                alpn: Vec::new(),
            },
        )
        .await?;
        let tls = Box::new(tls) as Box<dyn ProxyStream>;
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

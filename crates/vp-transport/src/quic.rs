//! QUIC 传输（quinn）：客户端/服务端双向流，适配 ProxyStream。

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use vp_common::{Error, Result};

#[derive(Debug, Clone)]
pub struct QuicConfig {
    /// ALPN 协议串（两端一致即可）
    pub alpn: String,
}

impl Default for QuicConfig {
    fn default() -> Self {
        QuicConfig {
            alpn: "vpcore".into(),
        }
    }
}

/// QUIC 双向流（收发半部天然分离）
pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

fn client_config(skip_verify: bool, alpn: &str) -> quinn::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if skip_verify {
        crypto
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerify));
    }
    crypto.alpn_protocols = vec![alpn.as_bytes().to_vec()];
    let mut cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("quic client config"),
    ));
    cfg.transport_config(Arc::new(transport_config()));
    cfg
}

fn transport_config() -> quinn::TransportConfig {
    // 面向代理负载的温和调优：更大的流控窗口
    let mut t = quinn::TransportConfig::default();
    t.initial_mtu(1200);
    t
}

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _e: &rustls::pki_types::CertificateDer<'_>,
        _i: &[rustls::pki_types::CertificateDer<'_>],
        _n: &rustls::pki_types::ServerName<'_>,
        _o: &[u8],
        _t: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

/// 连接到 QUIC 服务器并打开双向流
pub async fn quic_connect(
    addr: SocketAddr,
    server_name: &str,
    skip_verify: bool,
    cfg: &QuicConfig,
) -> Result<QuicStream> {
    let mut ep = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
        .map_err(|e| Error::Io(std::io::Error::other(format!("quic endpoint: {e}"))))?;
    ep.set_default_client_config(client_config(skip_verify, &cfg.alpn));
    let conn = ep
        .connect(addr, server_name)
        .map_err(|e| Error::Addr(format!("quic 连接参数: {e}")))?
        .await
        .map_err(|e| Error::Io(std::io::Error::other(format!("quic 握手失败: {e}"))))?;
    let (send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| Error::Io(std::io::Error::other(format!("quic open_bi: {e}"))))?;
    Ok(QuicStream { send, recv })
}

/// 服务端：证书 + ALPN 配置
pub fn server_config(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    alpn: &str,
) -> Result<quinn::ServerConfig> {
    let cert = rustls::pki_types::CertificateDer::from(cert_der);
    let key = rustls::pki_types::PrivateKeyDer::try_from(key_der)
        .map_err(|e| Error::Config(format!("quic 私钥: {e}")))?;
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| Error::Config(format!("quic 证书: {e}")))?;
    crypto.alpn_protocols = vec![alpn.as_bytes().to_vec()];
    let server = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
            .map_err(|e| Error::Config(format!("quic server config: {e}")))?,
    ));
    Ok(server)
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn quic_loopback() {
        let _ = tracing_subscriber::fmt::try_init();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let sconfig = server_config(
            cert.cert.der().to_vec(),
            cert.key_pair.serialize_der(),
            "vpcore",
        )
        .unwrap();
        let endpoint = quinn::Endpoint::server(sconfig, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();

        // 服务端：accept 连接 → accept_bi → echo
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                if let Ok(conn) = incoming.await {
                    tokio::spawn(async move {
                        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                            let mut b = [0u8; 2048];
                            loop {
                                match recv.read(&mut b).await {
                                    Ok(Some(0)) | Ok(None) | Err(_) => break,
                                    Ok(Some(n)) => {
                                        if send.write_all(&b[..n]).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    });
                }
            }
        });

        let mut c = quic_connect(addr, "localhost", true, &QuicConfig::default())
            .await
            .unwrap();
        c.write_all(b"ping-quic").await.unwrap();
        let mut buf = [0u8; 9];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-quic");

        // 大块
        let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let (mut r, mut w) = tokio::io::split(c);
        let big2 = big.clone();
        tokio::spawn(async move {
            w.write_all(&big2).await.unwrap();
            let _ = w.shutdown().await;
        });
        let mut got = vec![0u8; big.len()];
        r.read_exact(&mut got).await.unwrap();
        assert_eq!(got, big);
    }
}

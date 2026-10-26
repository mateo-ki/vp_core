//! TLS（rustls/ring）：客户端连接器（含 skip-cert-verify、SNI 覆盖）与服务端配置。

use std::sync::Arc;

use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio_rustls::{client::TlsConnector, rustls::ServerConfig, server::TlsAcceptor};
use vp_common::{Error, Result};

/// 允许任意自签/过期证书的验证器
#[derive(Debug)]
struct NoVerify(Arc<RootCertStore>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        WebPkiServerVerifier::builder(self.0.clone())
            .build()
            .unwrap()
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        WebPkiServerVerifier::builder(self.0.clone())
            .build()
            .unwrap()
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
        ]
    }
}

#[derive(Default)]
pub struct TlsClientConfig {
    pub skip_cert_verify: bool,
    pub server_name: Option<String>,
    pub alpn: Vec<String>,
}

fn root_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// 客户端 TCP 包装为 TLS
pub async fn tls_connect(
    tcp: TcpStream,
    host: &str,
    cfg: &TlsClientConfig,
) -> Result<ClientTlsStream<TcpStream>> {
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store())
        .with_no_client_auth();
    if cfg.skip_cert_verify {
        let verifier = WebPkiServerVerifier::builder(Arc::new(root_store()))
            .build()
            .unwrap();
        let _ = verifier; // 仅为 NoVerify 构造签名方案
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerify(Arc::new(root_store()))));
    }
    if !cfg.alpn.is_empty() {
        config.alpn_protocols = cfg.alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    }
    let connector = TlsConnector::from(Arc::new(config));
    let sni = cfg.server_name.clone().unwrap_or_else(|| host.to_string());
    let name =
        ServerName::try_from(sni.clone()).map_err(|_| Error::Addr(format!("非法 SNI: {sni:?}")))?;
    let stream = connector
        .connect(name, tcp)
        .await
        .map_err(|e| Error::Io(std::io::Error::other(format!("TLS 握手失败: {e}"))))?;
    Ok(stream)
}

/// 服务端 TLS（自测与协议服务端用）
pub fn tls_acceptor(cert_pem: &[u8], key_pem: &[u8]) -> Result<TlsAcceptor> {
    let certs: Vec<CertificateDer<'_>> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| Error::Config(format!("证书解析失败: {e}")))?;
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| Error::Config(format!("私钥解析失败: {e}")))?
        .ok_or(Error::Config("未找到私钥".into()))?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::Config(format!("服务端 TLS 配置失败: {e}")))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// 统一签名：连接到 server（host:port 会被解析），按需叠加 TLS
pub async fn connect_tls(
    tcp: TcpStream,
    host: &str,
    skip_cert_verify: bool,
    server_name: Option<&str>,
) -> Result<Box<dyn vp_core::ProxyStream>> {
    let cfg = TlsClientConfig {
        skip_cert_verify,
        server_name: server_name.map(|s| s.to_string()),
        alpn: Vec::new(),
    };
    let s = tls_connect(tcp, host, &cfg).await?;
    Ok(Box::new(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tls_loopback_self_signed() {
        // rcgen 自签证书 + skip-verify 客户端自环
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem().into_bytes();
        let key_pem = cert.key_pair.serialize_pem().into_bytes();
        let acceptor = tls_acceptor(&cert_pem, &key_pem).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).await.unwrap();
            tls.write_all(b"pong!").await.unwrap();
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut client = tls_connect(
            tcp,
            "localhost",
            &TlsClientConfig {
                skip_cert_verify: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client.write_all(b"ping!").await.unwrap();
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong!");
        server.await.unwrap();
    }
}

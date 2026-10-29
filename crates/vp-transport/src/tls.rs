//! TLS（rustls/ring）：客户端连接器（含 skip-cert-verify、SNI 覆盖）与服务端配置。

use std::sync::Arc;

use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio_rustls::{client::TlsConnector, rustls::ServerConfig, server::TlsAcceptor};
use vp_common::{Error, Result};

/// 允许任意自签/过期证书的验证器
#[derive(Debug)]
struct NoVerify;

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
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
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

#[derive(Default, Clone)]
pub struct TlsClientConfig {
    pub skip_cert_verify: bool,
    pub server_name: Option<String>,
    pub alpn: Vec<String>,
    /// ECHConfigList 字节（来自 DNS HTTPS 记录或 ech-opts.config）；
    /// Some 时握手走 rustls ECH（TLS1.3-only），被服务端拒绝则自动回退普通 TLS
    pub ech_config: Option<Arc<Vec<u8>>>,
}

/// 全局 DNS 解析器钩子（vp_app 启动时注入），供 ECH 配置的 HTTPS(type65) 记录查询使用
static GLOBAL_RESOLVER: std::sync::RwLock<Option<Arc<vp_dns::Resolver>>> =
    std::sync::RwLock::new(None);

pub fn set_global_resolver(res: Arc<vp_dns::Resolver>) {
    *GLOBAL_RESOLVER.write().unwrap() = Some(res);
}

pub fn global_resolver() -> Option<Arc<vp_dns::Resolver>> {
    GLOBAL_RESOLVER.read().unwrap().clone()
}

/// ECH 被服务端拒绝过的主机：后续连接跳过 ECH 直接走普通 TLS（重拨后生效）
fn ech_rejected_hosts() -> &'static std::sync::Mutex<std::collections::HashSet<String>> {
    static S: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    S.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}

pub fn note_ech_rejected(host: &str) {
    ech_rejected_hosts()
        .lock()
        .unwrap()
        .insert(host.to_string());
}

fn ech_rejected(host: &str) -> bool {
    ech_rejected_hosts().lock().unwrap().contains(host)
}

fn ech_undelete(host: &str) {
    ech_rejected_hosts().lock().unwrap().remove(host);
}

/// 服务端拒绝 ECH 时随 alert 下发的 retry config（按主机缓存）。
/// Cloudflare 等会轮换 ECH 密钥：DNS 拿到的配置过旧即被拒，此时服务端会给出
/// 最新 retry config —— 用它重连是标准 ECH 流程，成功率远高于回退明文 TLS。
fn ech_retry_configs() -> &'static std::sync::Mutex<std::collections::HashMap<String, Arc<Vec<u8>>>>
{
    static S: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, Arc<Vec<u8>>>>,
    > = std::sync::OnceLock::new();
    S.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn note_ech_retry_config(host: &str, list: Arc<Vec<u8>>) {
    ech_retry_configs()
        .lock()
        .unwrap()
        .insert(host.to_string(), list);
}

fn take_ech_retry_config(host: &str) -> Option<Arc<Vec<u8>>> {
    ech_retry_configs().lock().unwrap().remove(host)
}

/// 从 tokio-rustls 握手错误中提取服务端下发的 ECHConfigList（重编码回 wire 格式）
fn ech_retry_list_from(err: &std::io::Error) -> Option<Arc<Vec<u8>>> {
    use tokio_rustls::rustls::Error;
    use tokio_rustls::rustls::internal::msgs::codec::Codec as _;

    let rl = err.get_ref()?.downcast_ref::<Error>()?;
    let Error::PeerIncompatible(
        tokio_rustls::rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(Some(list)),
    ) = rl
    else {
        return None;
    };
    if list.is_empty() {
        return None;
    }
    // Vec<EchConfigPayload> 的 TLS 列表编码 = u16 总长 + 各配置（版本+长度+内容）
    let wire = list.get_encoding();
    Some(Arc::new(wire))
}

/// 全局共享根证书库：避免每次 TLS 握手重复解析 140+ 根证书
pub fn global_root_store() -> &'static Arc<RootCertStore> {
    static ROOT_STORE: std::sync::OnceLock<Arc<RootCertStore>> = std::sync::OnceLock::new();
    ROOT_STORE.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(roots)
    })
}

/// 全局客户端连接器缓存：高频配置直接走无锁 OnceLock，消除海量 ClientConfig 分配
pub fn get_tls_connector(skip_cert_verify: bool, alpn: &[String]) -> TlsConnector {
    static DEFAULT_CONNECTOR: std::sync::OnceLock<TlsConnector> = std::sync::OnceLock::new();
    static NO_VERIFY_CONNECTOR: std::sync::OnceLock<TlsConnector> = std::sync::OnceLock::new();
    static H2_CONNECTOR: std::sync::OnceLock<TlsConnector> = std::sync::OnceLock::new();
    static H2_NO_VERIFY_CONNECTOR: std::sync::OnceLock<TlsConnector> = std::sync::OnceLock::new();

    if alpn.is_empty() {
        if skip_cert_verify {
            return NO_VERIFY_CONNECTOR
                .get_or_init(|| build_connector(true, &[]))
                .clone();
        } else {
            return DEFAULT_CONNECTOR
                .get_or_init(|| build_connector(false, &[]))
                .clone();
        }
    }

    if alpn.len() == 2 && alpn[0] == "h2" && alpn[1] == "http/1.1" {
        if skip_cert_verify {
            return H2_NO_VERIFY_CONNECTOR
                .get_or_init(|| build_connector(true, &["h2".into(), "http/1.1".into()]))
                .clone();
        } else {
            return H2_CONNECTOR
                .get_or_init(|| build_connector(false, &["h2".into(), "http/1.1".into()]))
                .clone();
        }
    }

    type TlsCache = std::sync::RwLock<std::collections::HashMap<(bool, Vec<String>), TlsConnector>>;
    static CACHE: std::sync::OnceLock<TlsCache> = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::RwLock::new(std::collections::HashMap::new()));
    let key = (skip_cert_verify, alpn.to_vec());
    {
        let r = cache.read().unwrap();
        if let Some(conn) = r.get(&key) {
            return conn.clone();
        }
    }
    let conn = build_connector(skip_cert_verify, alpn);
    let mut w = cache.write().unwrap();
    w.entry(key).or_insert_with(|| conn.clone()).clone()
}

fn build_connector(skip_cert_verify: bool, alpn: &[String]) -> TlsConnector {
    let mut config = ClientConfig::builder()
        .with_root_certificates(global_root_store().clone())
        .with_no_client_auth();
    if skip_cert_verify {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerify));
    }
    if !alpn.is_empty() {
        config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    }
    TlsConnector::from(Arc::new(config))
}

/// ECH 专用连接器：with_ech 强制 TLS1.3，密码学套件用自实现的 X25519+HKDF-SHA256+AES-GCM。
/// 以 (skip, alpn, ECH 配置字节) 为键缓存（ECH 配置同一域名长期不变）。
fn get_ech_connector(
    skip_cert_verify: bool,
    alpn: &[String],
    ech_list: &[u8],
) -> Result<TlsConnector> {
    type EchCache =
        std::sync::Mutex<std::collections::HashMap<(bool, Vec<String>, u64), Option<TlsConnector>>>;
    static CACHE: std::sync::OnceLock<EchCache> = std::sync::OnceLock::new();
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in ech_list {
        hash = (hash ^ b as u64).wrapping_mul(0x100000001b3);
    }
    let key = (skip_cert_verify, alpn.to_vec(), hash);
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    if let Some(hit) = cache.lock().unwrap().get(&key) {
        return match hit {
            Some(c) => Ok(c.clone()),
            None => Err(Error::Config("ECH 配置解析失败（缓存）".into())),
        };
    }
    let built = build_ech_connector(skip_cert_verify, alpn, ech_list);
    let cached = match &built {
        Ok(c) => Some(c.clone()),
        Err(_) => None,
    };
    cache.lock().unwrap().insert(key, cached);
    built
}

fn build_ech_connector(
    skip_cert_verify: bool,
    alpn: &[String],
    ech_list: &[u8],
) -> Result<TlsConnector> {
    let ech = rustls::client::EchConfig::new(ech_list.into(), super::hpke::ECH_HPKE_SUITES)
        .map_err(|e| Error::Config(format!("ECH 配置解析失败: {e}")))?;
    // builder_with_provider 才能到达 WantsVersions 阶段（with_ech 所在）。
    // 进程默认 provider 可能尚未安装（普通 TLS 的 builder() 会懒安装），这里显式兜底 ring。
    let provider = match rustls::crypto::CryptoProvider::get_default().cloned() {
        Some(p) => p,
        None => Arc::new(rustls::crypto::ring::default_provider()),
    };
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_ech(rustls::client::EchMode::Enable(ech))
        .map_err(|e| Error::Config(format!("ECH 客户端配置失败: {e}")))?
        .with_root_certificates(global_root_store().clone())
        .with_no_client_auth();
    if skip_cert_verify {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerify));
    }
    if !alpn.is_empty() {
        config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    }
    Ok(TlsConnector::from(Arc::new(config)))
}

/// 客户端流包装为 TLS
pub async fn tls_connect<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: S,
    host: &str,
    cfg: &TlsClientConfig,
) -> Result<ClientTlsStream<S>> {
    // 订阅源可能写入非法 SNI（如 "t.me/FuckTheWall" 这类频道链接）。rustls 的 ServerName
    // 强校验 DNS 名，直接报错会让节点整体不可用；此时回退到服务器域名（Mihomo 等内核
    // 不校验 SNI 格式，因此同一节点在 Mihomo 下可用）。
    let sni = cfg.server_name.clone().unwrap_or_else(|| host.to_string());
    let name = ServerName::try_from(sni.clone()).or_else(|_| {
        tracing::warn!("配置的 SNI {sni:?} 不是合法域名，已回退为服务器域名 {host:?}");
        ServerName::try_from(host.to_string())
            .map_err(|_| Error::Addr(format!("非法 SNI: {sni:?}")))
    })?;

    // ECH：ECHConfigList 由 wrap_transport 预解析（ech-opts.config 或 DNS HTTPS 记录）。
    // 服务端上次拒绝时下发的 retry config 最新鲜，优先于 DNS 获取的配置；
    // 曾被该主机拒绝过（且无 retry config）则直接跳过，避免每次连接都失败重试一轮。
    let ech_list = match &cfg.ech_config {
        Some(l) if !ech_rejected(host) => Some(l.clone()),
        _ => None,
    };
    let ech_list = take_ech_retry_config(host).or(ech_list);
    if let Some(list) = ech_list {
        tracing::debug!(
            "tls_connect ECH: host={host} sni={:?} alpn={:?} list_len={} list_head={:02x?}",
            cfg.server_name,
            cfg.alpn,
            list.len(),
            &list[..list.len().min(12)]
        );
        match get_ech_connector(cfg.skip_cert_verify, &cfg.alpn, &list) {
            Ok(ech_conn) => match ech_conn.connect(name, stream).await {
                Ok(s) => {
                    tracing::debug!("ECH 握手成功: {host}");
                    // 保留生效配置并解除回退标记：后续连接优先用它直连
                    note_ech_retry_config(host, list);
                    ech_undelete(host);
                    return Ok(s);
                }
                Err(e) => {
                    // 服务端拒绝/不支持 ECH：缓存其下发的 retry config（若有），
                    // 标记主机，由 transport::dial 重拨（有 retry config 则再试 ECH，
                    // 否则回退普通 TLS）
                    if let Some(retry) = ech_retry_list_from(&e) {
                        tracing::info!("ECH 被拒，已缓存服务端 retry config 重试: {host}");
                        note_ech_retry_config(host, retry);
                    }
                    tracing::warn!("ECH 握手失败（{e}），回退普通 TLS: {host}");
                    note_ech_rejected(host);
                    return Err(Error::Io(std::io::Error::other("ECH_REJECTED_FALLBACK")));
                }
            },
            Err(e) => {
                tracing::warn!("{e}，回退普通 TLS: {host}");
            }
        }
    }

    let connector = get_tls_connector(cfg.skip_cert_verify, &cfg.alpn);
    let stream = connector
        .connect(name, stream)
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
pub async fn connect_tls<
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
>(
    stream: S,
    host: &str,
    skip_cert_verify: bool,
    server_name: Option<&str>,
) -> Result<Box<dyn vp_core::ProxyStream>> {
    let cfg = TlsClientConfig {
        skip_cert_verify,
        server_name: server_name.map(|s| s.to_string()),
        alpn: Vec::new(),
        ech_config: None,
    };
    let s = tls_connect(stream, host, &cfg).await?;
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

    #[tokio::test]
    async fn tls_real_node_connect() {
        let node = match std::env::var("VPCORE_DEBUG_TLS_NODE") {
            Ok(v) if !v.trim().is_empty() => v,
            _ => return, // 未提供真实节点调试环境变量，优雅跳过
        };
        let tcp = match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::TcpStream::connect(&node),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => return,
        };
        let host = node.split(':').next().unwrap_or("example.com");
        let client_res = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tls_connect(
                tcp,
                host,
                &TlsClientConfig {
                    skip_cert_verify: true,
                    ..Default::default()
                },
            ),
        )
        .await;

        let mut client = match client_res {
            Ok(Ok(c)) => c,
            _ => return,
        };

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let req = b"CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\n\r\n";
        if client.write_all(req).await.is_err() {
            return;
        }
        let mut resp = [0u8; 100];
        if let Ok(n) = client.read(&mut resp).await {
            let resp_str = String::from_utf8_lossy(&resp[..n]);
            assert!(resp_str.contains("200 Connection established") || resp_str.contains("200"));
        }
    }
}

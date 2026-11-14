//! Juicity 协议（QUIC）。
//!
//! 线格式对齐官方 Go 实现（juicity/juicity + daeuniverse/outbound，与 tuic v5 同源）：
//! - 认证（uni 流，保持打开不 finish）：`VER=0x00 TYPE=0x00 UUID(16) TOKEN(32)`；
//!   TOKEN = TLS exporter（label=UUID 原始字节，context=密码，RFC 5705）
//! - TCP（bi 流）：首写 `NETWORK(1) ADDR PORT(2) 首块数据`，之后裸中继，无响应头
//! - UDP（bi 流，每关联一条）：首包 `NETWORK(0x03) ADDR PORT + ADDR PORT + LEN(2) 载荷`
//!   （连接头与服务端 ReadFrom 各解析一个地址头），后续包 `ADDR PORT + LEN(2) 载荷`；
//!   服务端回包 `ADDR PORT + LEN(2) 载荷`
//! - 地址 trojan 风格：`0x01` IPv4 / `0x03` 域名(len1) / `0x04` IPv6，端口大端
//! - NETWORK：tcp=`0x01` / udp=`0x03`
//! - 证书：ALPN `h3`；自签用 allow_insecure，或 pinned-cert-chain（滚动 SHA-256 链哈希，
//!   hex/base64 均可，与官方 GenerateCertChainHash 一致）

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::Mutex;

use vp_common::{DstAddr, Error, Host, Result};
use vp_core::session::Session;
use vp_core::{Outbound, PacketConn, ProxyStream, UdpPacket};

/// UDP 单包上限（IPv6 UDP 最大载荷 65507 < u16::MAX）
const MAX_UDP_PKT: usize = 65507;

// ---------------------------------------------------------------------------
// 地址编解码（trojan 风格：0x01 v4 / 0x03 域名 / 0x04 v6，端口大端在后）
// ---------------------------------------------------------------------------

fn encode_addr(dst: &DstAddr, out: &mut Vec<u8>) -> Result<()> {
    match &dst.host {
        Host::Domain(d) => {
            if d.len() > 255 {
                return Err(Error::Addr(format!("juicity: 域名过长 {}", d.len())));
            }
            out.push(0x03);
            out.push(d.len() as u8);
            out.extend_from_slice(d.as_bytes());
        }
        Host::Ip(std::net::IpAddr::V4(v4)) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        Host::Ip(std::net::IpAddr::V6(v6)) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&dst.port.to_be_bytes());
    Ok(())
}

fn decode_host_addr(buf: &[u8]) -> Result<(DstAddr, usize)> {
    let atyp = *buf.first().ok_or(Error::Proto("juicity: 地址截断"))?;
    match atyp {
        0x01 => {
            if buf.len() < 7 {
                return Err(Error::Proto("juicity: v4 截断"));
            }
            Ok((
                DstAddr {
                    host: Host::Ip(std::net::IpAddr::V4(
                        [buf[1], buf[2], buf[3], buf[4]].into(),
                    )),
                    port: u16::from_be_bytes([buf[5], buf[6]]),
                },
                7,
            ))
        }
        0x03 => {
            if buf.len() < 2 {
                return Err(Error::Proto("juicity: 域名截断"));
            }
            let n = buf[1] as usize;
            if buf.len() < 2 + n + 2 {
                return Err(Error::Proto("juicity: 域名截断"));
            }
            let d = std::str::from_utf8(&buf[2..2 + n])
                .map_err(|_| Error::Proto("juicity: 域名非 utf8"))?
                .to_ascii_lowercase();
            Ok((
                DstAddr {
                    host: Host::Domain(d),
                    port: u16::from_be_bytes([buf[2 + n], buf[3 + n]]),
                },
                2 + n + 2,
            ))
        }
        0x04 => {
            if buf.len() < 19 {
                return Err(Error::Proto("juicity: v6 截断"));
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[1..17]);
            Ok((
                DstAddr {
                    host: Host::Ip(std::net::IpAddr::V6(o.into())),
                    port: u16::from_be_bytes([buf[17], buf[18]]),
                },
                19,
            ))
        }
        other => Err(Error::ProtoMsg(format!("juicity: 地址类型 {other:#x} 非法"))),
    }
}

// ---------------------------------------------------------------------------
// 证书链哈希（官方 common.GenerateCertChainHash：滚动 SHA-256）
// ---------------------------------------------------------------------------

fn cert_chain_hash(certs: &[rustls::pki_types::CertificateDer<'_>]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut chain_hash: Option<[u8; 32]> = None;
    for c in certs {
        let cert_hash: [u8; 32] = Sha256::digest(c.as_ref()).into();
        chain_hash = Some(match chain_hash {
            None => cert_hash,
            Some(prev) => {
                let mut h = Sha256::new();
                h.update(prev);
                h.update(cert_hash);
                h.finalize().into()
            }
        });
    }
    chain_hash.unwrap_or([0u8; 32])
}

/// pinned-cert-chain 解析：hex（64 位无歧义优先）/ base64（std 与 url，含无填充）
fn decode_pin(s: &str) -> Option<[u8; 32]> {
    use base64::{engine::general_purpose, Engine as _};
    let t = s.trim();
    let bytes = if t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        hex_decode(t)
    } else {
        general_purpose::STANDARD
            .decode(t)
            .or_else(|_| general_purpose::URL_SAFE.decode(t))
            .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(t))
            .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(t))
            .ok()
    }?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[derive(Debug)]
struct JuicityPinVerifier([u8; 32]);

impl rustls::client::danger::ServerCertVerifier for JuicityPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _n: &rustls::pki_types::ServerName<'_>,
        _o: &[u8],
        _t: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let mut chain = Vec::with_capacity(1 + intermediates.len());
        chain.push(end_entity.clone());
        chain.extend(intermediates.iter().cloned());
        if cert_chain_hash(&chain) != self.0 {
            return Err(rustls::Error::General(
                "juicity: 证书链哈希与 pinned-cert-chain 不匹配".into(),
            ));
        }
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

#[derive(Debug)]
struct JuicityNoVerify;

impl rustls::client::danger::ServerCertVerifier for JuicityNoVerify {
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

fn build_client_config(skip_verify: bool, pinned: Option<[u8; 32]>) -> quinn::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if let Some(pin) = pinned {
        crypto
            .dangerous()
            .set_certificate_verifier(Arc::new(JuicityPinVerifier(pin)));
    } else if skip_verify {
        crypto
            .dangerous()
            .set_certificate_verifier(Arc::new(JuicityNoVerify));
    }
    // 官方客户端 TLS NextProtos 固定 ["h3"]
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let mut cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("juicity cfg"),
    ));
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(
        std::time::Duration::from_secs(30)
            .try_into()
            .expect("idle timeout"),
    ));
    t.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    cfg.transport_config(Arc::new(t));
    cfg
}

// ---------------------------------------------------------------------------
// 出站
// ---------------------------------------------------------------------------

pub struct JuicityOutbound {
    name: Arc<str>,
    server: String,
    port: u16,
    uuid: String,
    password: String,
    sni: Option<String>,
    crypto: quinn::ClientConfig,
    _congestion_controller: Option<String>,
    session: Mutex<Option<Arc<JuicitySession>>>,
}

struct JuicitySession {
    conn: quinn::Connection,
    /// 认证 uni 流保持打开（对齐官方客户端：该流后续承载 UnderlayAuth）
    _auth_send: quinn::SendStream,
    _ep: quinn::Endpoint,
}

impl JuicitySession {
    fn is_alive(&self) -> bool {
        self.conn.close_reason().is_none()
    }
}

impl JuicityOutbound {
    pub fn new(cfg: &vp_config::JuicityCfg) -> Result<Self> {
        let pinned = cfg
            .pinned_cert_chain
            .as_deref()
            .and_then(decode_pin);
        if cfg.pinned_cert_chain.as_deref().is_some_and(|s| !s.trim().is_empty()) && pinned.is_none()
        {
            return Err(Error::Config(
                "juicity: pinned-cert-chain 无法解析（应为 32 字节 hex/base64）".into(),
            ));
        }
        Ok(JuicityOutbound {
            name: "juicity".into(),
            server: cfg.server.clone(),
            port: cfg.port,
            uuid: cfg.uuid.clone(),
            password: cfg.password.clone(),
            sni: cfg
                .sni
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .or_else(|| Some(cfg.server.clone())),
            crypto: build_client_config(cfg.skip_cert_verify, pinned),
            _congestion_controller: cfg.congestion_controller.clone(),
            session: Mutex::new(None),
        })
    }

    async fn get_or_connect(&self) -> Result<Arc<JuicitySession>> {
        let mut guard = self.session.lock().await;
        if let Some(ref s) = *guard {
            if s.is_alive() {
                return Ok(s.clone());
            }
        }
        let s = self.dial().await?;
        *guard = Some(s.clone());
        Ok(s)
    }

    /// QUIC 连接 + 认证（认证 uni 流保持打开）
    async fn dial(&self) -> Result<Arc<JuicitySession>> {
        let addrs = vp_transport::resolve_node_addrs(&self.server, self.port).await?;
        let (conn, ep) =
            vp_transport::race_addrs(&addrs, vp_transport::HAPPY_EYEBALLS_DELAY, |addr| {
                self.connect_quic_addr(addr)
            })
            .await?;
        let auth_send = self.authenticate(&conn).await?;
        Ok(Arc::new(JuicitySession {
            conn,
            _auth_send: auth_send,
            _ep: ep,
        }))
    }

    async fn connect_quic_addr(&self, addr: SocketAddr) -> Result<(quinn::Connection, quinn::Endpoint)> {
        let bind: &'static str = if addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let tokio_sock = vp_transport::create_udp_socket(bind.parse().unwrap())?;
        let std_sock = tokio_sock.into_std().map_err(Error::Io)?;
        let mut ep = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            std_sock,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|e| Error::Io(std::io::Error::other(format!("juicity endpoint: {e}"))))?;
        ep.set_default_client_config(self.crypto.clone());
        let server_name = self.sni.as_deref().unwrap_or(&self.server);
        let conn = ep
            .connect(addr, server_name)
            .map_err(|e| Error::Addr(format!("juicity 连接参数: {e}")))?
            .await
            .map_err(|e| Error::Io(std::io::Error::other(format!("juicity QUIC 握手: {e}"))))?;
        Ok((conn, ep))
    }

    /// 认证：uni 流写 `VER=0x00 TYPE=0x00 UUID TOKEN`；流保持打开（对齐官方客户端）
    async fn authenticate(&self, conn: &quinn::Connection) -> Result<quinn::SendStream> {
        let uuid16 = vp_crypto::vmess_kdf::parse_uuid(&self.uuid)?;
        let mut tok = [0u8; 32];
        conn.export_keying_material(&mut tok, &uuid16, self.password.as_bytes())
            .map_err(|_| Error::Proto("juicity: token 导出失败"))?;
        let io = |e: String| Error::Io(std::io::Error::other(e));
        let mut uni = conn
            .open_uni()
            .await
            .map_err(|e| io(format!("juicity open_uni: {e}")))?;
        let mut auth = Vec::with_capacity(2 + 16 + 32);
        auth.extend_from_slice(&[0x00, 0x00]);
        auth.extend_from_slice(&uuid16);
        auth.extend_from_slice(&tok);
        uni.write_all(&auth)
            .await
            .map_err(|e| io(format!("juicity 认证写入: {e}")))?;
        Ok(uni)
    }

    /// TCP：打开 bi 流并立即发出 `0x01 + ADDR` 请求头（空载荷先行，服务端可先应答）
    async fn open_tcp_stream(&self, dst: &DstAddr) -> Result<crate::hysteria2::QuicBiStream> {
        let sess = self.get_or_connect().await?;
        let (mut send, recv) = sess
            .conn
            .open_bi()
            .await
            .map_err(|e| Error::Io(std::io::Error::other(format!("juicity open_bi: {e}"))))?;
        let mut req = vec![0x01];
        encode_addr(dst, &mut req)?;
        send.write_all(&req)
            .await
            .map_err(|e| Error::Io(std::io::Error::other(format!("juicity connect 写入: {e}"))))?;
        Ok(crate::hysteria2::QuicBiStream { send, recv })
    }
}

#[async_trait]
impl Outbound for JuicityOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect_stream(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        Ok(Box::new(self.open_tcp_stream(dst).await?))
    }

    fn support_udp(&self) -> bool {
        true
    }

    async fn connect_packet(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        let sess = self.get_or_connect().await?;
        let (send, recv) = sess
            .conn
            .open_bi()
            .await
            .map_err(|e| Error::Io(std::io::Error::other(format!("juicity udp open_bi: {e}"))))?;
        Ok(Box::new(JuicityPacketConn {
            target: dst.clone(),
            send: Mutex::new(send),
            first_sent: AtomicBool::new(false),
            recv,
        }))
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
}

/// UDP 关联：一条 bi 流上按包寻址（每包 `ADDR PORT + LEN(2) 载荷`；首包前有连接头）
struct JuicityPacketConn {
    target: DstAddr,
    send: Mutex<quinn::SendStream>,
    first_sent: AtomicBool,
    recv: quinn::RecvStream,
}

impl JuicityPacketConn {
    async fn write_pkt(&self, addr: &DstAddr, data: &[u8]) -> Result<()> {
        let io = |e: String| Error::Io(std::io::Error::other(e));
        let mut buf = Vec::with_capacity(2 * 262 + 2 + data.len());
        if !self.first_sent.swap(true, Ordering::Relaxed) {
            // 连接头：NETWORK(0x03) + 地址（服务端 Conn.Read 先消费）；
            // 官方客户端对首个包还会再写一份 WriteTo 元数据，服务端按它路由
            buf.push(0x03);
            encode_addr(addr, &mut buf)?;
        }
        encode_addr(addr, &mut buf)?;
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        buf.extend_from_slice(data);
        let mut send = self.send.lock().await;
        send.write_all(&buf)
            .await
            .map_err(|e| io(format!("juicity udp 写入: {e}")))?;
        Ok(())
    }
}

#[async_trait]
impl PacketConn for JuicityPacketConn {
    async fn send(&self, pkt: &UdpPacket) -> Result<()> {
        if pkt.data.len() > MAX_UDP_PKT {
            return Err(Error::ProtoMsg(format!(
                "juicity: udp 包超长 {}",
                pkt.data.len()
            )));
        }
        // juicity 服务端按每包的地址头路由，直接下发包目标
        let dst = DstAddr {
            host: Host::Ip(pkt.dst.ip()),
            port: pkt.dst.port(),
        };
        self.write_pkt(&dst, &pkt.data).await
    }

    async fn recv(&mut self) -> Result<UdpPacket> {
        let io = |e: String| Error::Io(std::io::Error::other(e));
        // 服务端回包：`ADDR PORT + LEN(2) 载荷`（无 network 字节）
        let mut atyp = [0u8; 1];
        self.recv
            .read_exact(&mut atyp)
            .await
            .map_err(|e| io(format!("juicity udp 读取: {e}")))?;
        let rest = match atyp[0] {
            0x01 => 6,
            0x03 => {
                let mut n = [0u8; 1];
                self.recv
                    .read_exact(&mut n)
                    .await
                    .map_err(|e| io(format!("juicity udp 读取: {e}")))?;
                n[0] as usize + 2
            }
            0x04 => 18,
            other => return Err(Error::ProtoMsg(format!("juicity: 回包地址类型 {other:#x} 非法"))),
        };
        let mut rest_buf = vec![0u8; rest];
        self.recv
            .read_exact(&mut rest_buf)
            .await
            .map_err(|e| io(format!("juicity udp 读取: {e}")))?;
        let mut full = vec![atyp[0]];
        full.extend_from_slice(&rest_buf);
        let (src_addr, _) = decode_host_addr(&full)?;
        let mut len_buf = [0u8; 2];
        self.recv
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| io(format!("juicity udp 读取: {e}")))?;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut data = vec![0u8; len];
        self.recv
            .read_exact(&mut data)
            .await
            .map_err(|e| io(format!("juicity udp 读取: {e}")))?;
        let src = match src_addr.host {
            Host::Ip(ip) => SocketAddr::new(ip, src_addr.port),
            // 域名源地址少见（DNS 应答均为 IP）；回退到关联目标
            Host::Domain(_) => match self.target.host {
                Host::Ip(ip) => SocketAddr::new(ip, self.target.port),
                Host::Domain(_) => {
                    return Err(Error::Proto("juicity: 回包源地址为域名且目标不可解析"))
                }
            },
        };
        Ok(UdpPacket {
            src,
            dst: src,
            data: Bytes::from(data),
        })
    }
}

// ---------------------------------------------------------------------------
// 测试：最小 juicity 服务端 + 回环
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 最小 juicity 服务端：认证校验 + TCP 中继 + UDP（按包寻址）。
    /// 返回（端口，服务端证书链哈希——用于 pinned-cert-chain 测试）
    async fn mini_server(uuid16: [u8; 16], password: &str) -> (u16, [u8; 32]) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let pin = cert_chain_hash(std::slice::from_ref(&cert_der));
        let mut crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                rustls_pemfile::certs(&mut cert.cert.pem().as_bytes())
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .unwrap(),
                rustls_pemfile::private_key(&mut cert.key_pair.serialize_pem().as_bytes())
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        let scfg = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto).unwrap(),
        ));
        let endpoint = quinn::Endpoint::server(scfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let port = endpoint.local_addr().unwrap().port();
        let password = password.to_string();
        tokio::spawn(async move {
            while let Some(conn) = endpoint.accept().await {
                let Ok(conn) = conn.await else { continue };
                let password = password.clone();
                tokio::spawn(async move {
                    serve_conn(conn, uuid16, &password).await;
                });
            }
        });
        (port, pin)
    }

    async fn serve_conn(conn: quinn::Connection, uuid16: [u8; 16], password: &str) {
        // 认证（首个 uni 流）
        let mut auth_uni = match conn.accept_uni().await {
            Ok(u) => u,
            Err(_) => return,
        };
        let mut auth = [0u8; 50];
        if auth_uni.read_exact(&mut auth).await.is_err() {
            return;
        }
        let mut expect = [0u8; 32];
        if conn
            .export_keying_material(&mut expect, &uuid16, password.as_bytes())
            .is_err()
        {
            return;
        }
        if auth[0] != 0x00 || auth[1] != 0x00 || auth[2..18] != uuid16 || auth[18..50] != expect {
            conn.close(quinn::VarInt::from_u32(0xfffffff1), b"auth failed");
            return;
        }
        // bi 流循环：每条流独立处理（TCP 与 UDP 关联并存于同一连接）
        loop {
            let (send, mut recv) = match conn.accept_bi().await {
                Ok(x) => x,
                Err(_) => return,
            };
            let mut network = [0u8; 1];
            if recv.read_exact(&mut network).await.is_err() {
                continue;
            }
            let dst = match read_addr_incremental(&mut recv).await {
                Ok(d) => d,
                Err(_) => continue,
            };
            match network[0] {
                0x01 => {
                    tokio::spawn(async move {
                        let Ok(mut remote) =
                            tokio::net::TcpStream::connect(connect_str(&dst)).await
                        else {
                            return;
                        };
                        let mut client = crate::hysteria2::QuicBiStream { send, recv };
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
                    });
                }
                0x03 => {
                    // 连接头（network + META_conn）已被上方消费；
                    // 其后每包 `META + LEN + 载荷` 由 handle_udp 按包解析
                    tokio::spawn(handle_udp(send, recv));
                }
                _ => continue,
            }
        }
    }

    fn connect_str(dst: &DstAddr) -> String {
        match &dst.host {
            Host::Domain(d) => format!("{}:{}", d, dst.port),
            Host::Ip(std::net::IpAddr::V4(v4)) => format!("{}:{}", v4, dst.port),
            Host::Ip(std::net::IpAddr::V6(v6)) => format!("[{}]:{}", v6, dst.port),
        }
    }

    async fn read_addr_incremental(recv: &mut quinn::RecvStream) -> Result<DstAddr> {
        let mut buf: Vec<u8> = Vec::with_capacity(300);
        loop {
            match decode_host_addr(&buf) {
                Ok((d, _)) => return Ok(d),
                Err(_) => {
                    let mut b = [0u8; 1];
                    if recv.read_exact(&mut b).await.is_err() || buf.len() > 262 {
                        return Err(Error::Proto("juicity: 地址读取失败"));
                    }
                    buf.push(b[0]);
                }
            }
        }
    }

    /// UDP 关联：每包 `ADDR PORT + LEN(2) 载荷` → 转发；回包写 `ADDR PORT + LEN 载荷`
    async fn handle_udp(send: quinn::SendStream, recv: quinn::RecvStream) {
        let sock = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => Arc::new(s),
            Err(_) => return,
        };
        let send = Arc::new(Mutex::new(send));
        let recv = Arc::new(Mutex::new(recv));
        // 上行泵
        let (up_sock, up_recv) = (sock.clone(), recv.clone());
        tokio::spawn(async move {
            loop {
                let mut r = up_recv.lock().await;
                let pkt = read_one_packet(&mut r).await;
                drop(r);
                let Some((addr, data)) = pkt else { return };
                let _ = up_sock.send_to(&data, connect_str(&addr)).await;
            }
        });
        // 下行泵
        let mut buf = [0u8; 65536];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else { return };
            let mut addr = Vec::with_capacity(262);
            if encode_addr(
                &DstAddr {
                    host: Host::Ip(from.ip()),
                    port: from.port(),
                },
                &mut addr,
            )
            .is_err()
            {
                return;
            }
            let mut w = Vec::with_capacity(addr.len() + 2 + n);
            w.extend_from_slice(&addr);
            w.extend_from_slice(&(n as u16).to_be_bytes());
            w.extend_from_slice(&buf[..n]);
            let mut s = send.lock().await;
            if s.write_all(&w).await.is_err() {
                return;
            }
        }
    }

    async fn read_one_packet(recv: &mut quinn::RecvStream) -> Option<(DstAddr, Vec<u8>)> {
        let mut buf: Vec<u8> = Vec::with_capacity(300);
        let addr = loop {
            match decode_host_addr(&buf) {
                Ok((d, _)) => break d,
                Err(_) => {
                    let mut b = [0u8; 1];
                    if recv.read_exact(&mut b).await.is_err() || buf.len() > 262 {
                        return None;
                    }
                    buf.push(b[0]);
                }
            }
        };
        let mut len = [0u8; 2];
        if recv.read_exact(&mut len).await.is_err() {
            return None;
        }
        let mut data = vec![0u8; u16::from_be_bytes(len) as usize];
        if recv.read_exact(&mut data).await.is_err() {
            return None;
        }
        Some((addr, data))
    }

    fn parse_uuid16(s: &str) -> [u8; 16] {
        vp_crypto::vmess_kdf::parse_uuid(s).unwrap()
    }

    #[test]
    fn addr_roundtrip() {
        for d in [
            DstAddr::new("example.com", 443),
            DstAddr::ip("1.2.3.4".parse().unwrap(), 80),
            DstAddr::ip("2001:db8::1".parse().unwrap(), 53),
        ] {
            let mut b = Vec::new();
            encode_addr(&d, &mut b).unwrap();
            let (d2, used) = decode_host_addr(&b).unwrap();
            assert_eq!(used, b.len());
            assert_eq!(d, d2);
        }
    }

    #[test]
    fn pin_decode() {
        use base64::{engine::general_purpose, Engine as _};
        use sha2::{Digest, Sha256};
        let raw: [u8; 32] = Sha256::digest(b"juicity-pin").into();
        let hex_s: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(decode_pin(&hex_s), Some(raw));
        let b64 = general_purpose::STANDARD.encode(raw);
        assert_eq!(decode_pin(&b64), Some(raw));
        let b64u = general_purpose::URL_SAFE_NO_PAD.encode(raw);
        assert_eq!(decode_pin(&b64u), Some(raw));
        assert_eq!(decode_pin("zzz"), None);
        assert_eq!(decode_pin(""), None);
    }

    #[test]
    fn cert_chain_hash_matches_official() {
        // 与官方 GenerateCertChainHash 一致：h1=sha256(c1)；h2=sha256(h1||sha256(c2))
        use sha2::{Digest, Sha256};
        let c1 = [1u8; 16];
        let c2 = [2u8; 16];
        let h1: [u8; 32] = Sha256::digest(c1).into();
        let c2h: [u8; 32] = Sha256::digest(c2).into();
        let mut hh = Sha256::new();
        hh.update(h1);
        hh.update(c2h);
        let expect: [u8; 32] = hh.finalize().into();
        let to_der = |raw: [u8; 16]| rustls::pki_types::CertificateDer::from(raw.to_vec());
        assert_eq!(cert_chain_hash(&[to_der(c1), to_der(c2)]), expect);
        assert_eq!(cert_chain_hash(&[to_der(c1)]), h1);
    }

    fn mk_outbound(port: u16, pin: Option<String>) -> JuicityOutbound {
        JuicityOutbound::new(&vp_config::JuicityCfg {
            server: "127.0.0.1".into(),
            port,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            password: "pw".into(),
            sni: None,
            skip_cert_verify: pin.is_none(),
            congestion_controller: None,
            pinned_cert_chain: pin,
        })
        .unwrap()
    }

    /// 出入站自环：TCP 中继 + UDP 按包寻址往返
    #[tokio::test]
    async fn juicity_loopback() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // TCP echo
        let tcp_echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tcp_echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = tcp_echo.accept().await.unwrap();
            let mut b = [0u8; 1024];
            loop {
                let n = s.read(&mut b).await.unwrap();
                if n == 0 {
                    break;
                }
                s.write_all(&b[..n]).await.unwrap();
            }
        });
        // UDP echo
        let udp_echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp_echo.local_addr().unwrap();
        tokio::spawn(async move {
            let udp_echo = std::sync::Arc::new(udp_echo);
            let mut b = [0u8; 2048];
            loop {
                let Ok((n, from)) = udp_echo.recv_from(&mut b).await else {
                    break;
                };
                let mut r = b"echo:".to_vec();
                r.extend_from_slice(&b[..n]);
                let _ = udp_echo.send_to(&r, from).await;
            }
        });

        let (port, _pin) = mini_server(parse_uuid16("b831381d-6324-4d53-ad4f-8cda48b30811"), "pw")
            .await;
        let out = mk_outbound(port, None);

        // TCP
        let dst = DstAddr::ip("127.0.0.1".parse().unwrap(), tcp_port);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = out.connect_stream(&sess, &dst).await.unwrap();
        s.write_all(b"ping-juicity").await.unwrap();
        let mut buf = [0u8; 12];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-juicity");

        // UDP
        let dst = DstAddr::ip(udp_addr.ip(), udp_addr.port());
        let sess = Session::new_udp("t".into(), None, dst.clone());
        let mut conn = out.connect_packet(&sess, &dst).await.unwrap();
        conn.send(&UdpPacket {
            src: "127.0.0.1:0".parse().unwrap(),
            dst: udp_addr,
            data: b"juicity-udp".to_vec().into(),
        })
        .await
        .unwrap();
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), conn.recv())
            .await
            .expect("udp 超时")
            .unwrap();
        assert_eq!(&resp.data[..], b"echo:juicity-udp");
        assert_eq!(resp.src.port(), udp_addr.port());

        // 第二包（连接头已发，后续包只带地址元数据）
        conn.send(&UdpPacket {
            src: "127.0.0.1:0".parse().unwrap(),
            dst: udp_addr,
            data: b"juicity-udp-2".to_vec().into(),
        })
        .await
        .unwrap();
        let resp2 = tokio::time::timeout(std::time::Duration::from_secs(5), conn.recv())
            .await
            .expect("udp 2 超时")
            .unwrap();
        assert_eq!(&resp2.data[..], b"echo:juicity-udp-2");
    }

    /// pinned-cert-chain：钉扎正确哈希可连；钉扎错误哈希握手失败
    #[tokio::test]
    async fn juicity_pinned_cert_chain() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let tcp_echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tcp_echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = tcp_echo.accept().await.unwrap();
            let mut b = [0u8; 1024];
            loop {
                let n = s.read(&mut b).await.unwrap();
                if n == 0 {
                    break;
                }
                s.write_all(&b[..n]).await.unwrap();
            }
        });
        let (port, pin) =
            mini_server(parse_uuid16("b831381d-6324-4d53-ad4f-8cda48b30811"), "pw").await;

        let wrong = mk_outbound(port, Some("00".repeat(32)));
        let dst = DstAddr::ip("127.0.0.1".parse().unwrap(), tcp_port);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        assert!(
            wrong.connect_stream(&sess, &dst).await.is_err(),
            "错误钉扎应握手失败"
        );

        let right = mk_outbound(port, Some(hex_encode(pin)));
        let mut s = right.connect_stream(&sess, &dst).await.unwrap();
        s.write_all(b"pin-ok").await.unwrap();
        let mut buf = [0u8; 6];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pin-ok");
    }

    fn hex_encode(b: [u8; 32]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}

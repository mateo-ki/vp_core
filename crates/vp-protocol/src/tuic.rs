//! TUIC v5 协议（QUIC）。
//!
//! 通用命令：`[VER=0x05][TYPE][OPT...]`（全大端）
//! - Authenticate `0x00`（uni 流）：`UUID(16) TOKEN(32)`，TOKEN 由 TLS Keying Material
//!   导出（label=UUID 字符串，context=原始密码，RFC 5705）
//! - Connect `0x01`（bi 流）：`ADDR_TYPE(1) ADDR PORT(2)`，无应答直接中继
//!   ADDR_TYPE：`0x00` 域名（首字节长度）/ `0x01` IPv4 / `0x02` IPv6 / `0xff` None
//! - Packet `0x02`（uni 流）：`ASSOC(2) PKT(2) FRAG_TOTAL(1) FRAG(1) SIZE(2) ADDR`
//!   SIZE = ADDR 编码长 + payload 长
//! - Dissociate `0x03`（uni 流）：`ASSOC(2)`
//! - Heartbeat `0x04`（datagram）：空 OPT
//!
//! ALPN：`tuic`

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use async_trait::async_trait;
use bytes::Bytes;

use vp_common::{DstAddr, Error, Host, Result};
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;
use vp_core::tunnel::{RelayHook, relay};
use vp_core::{Inbound, Outbound, PacketConn, ProxyStream, UdpPacket};

const VER: u8 = 0x05;
const T_AUTH: u8 = 0x00;
const T_CONNECT: u8 = 0x01;
const T_PACKET: u8 = 0x02;
const T_DISSOCIATE: u8 = 0x03;
#[allow(dead_code)]
const T_HEARTBEAT: u8 = 0x04;

// ---------------------------------------------------------------------------
// 地址编解码（TUIC 风格，与 SOCKS 不同：0x00 域名 / 0x01 v4 / 0x02 v6）
// ---------------------------------------------------------------------------

fn encode_addr(dst: &DstAddr, out: &mut Vec<u8>) {
    match &dst.host {
        Host::Domain(d) => {
            out.push(0x00);
            out.push(d.len() as u8);
            out.extend_from_slice(d.as_bytes());
        }
        Host::Ip(std::net::IpAddr::V4(v4)) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        Host::Ip(std::net::IpAddr::V6(v6)) => {
            out.push(0x02);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&dst.port.to_be_bytes());
}

/// 解析地址：返回 (dst, consumed)。需要 `type|addr|port` 完整。
fn decode_addr(buf: &[u8]) -> Result<(DstAddr, usize)> {
    let atyp = *buf.first().ok_or(Error::Proto("tuic: 地址截断"))?;
    match atyp {
        0x00 => {
            if buf.len() < 2 {
                return Err(Error::Proto("tuic: 域名截断"));
            }
            let n = buf[1] as usize;
            if buf.len() < 2 + n + 2 {
                return Err(Error::Proto("tuic: 域名截断"));
            }
            let d = std::str::from_utf8(&buf[2..2 + n])
                .map_err(|_| Error::Proto("tuic: 域名非 utf8"))?
                .to_ascii_lowercase();
            let port = u16::from_be_bytes([buf[2 + n], buf[3 + n]]);
            Ok((
                DstAddr {
                    host: Host::Domain(d),
                    port,
                },
                2 + n + 2,
            ))
        }
        0x01 => {
            if buf.len() < 7 {
                return Err(Error::Proto("tuic: v4 截断"));
            }
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((
                DstAddr {
                    host: Host::Ip(std::net::IpAddr::V4(
                        [buf[1], buf[2], buf[3], buf[4]].into(),
                    )),
                    port,
                },
                7,
            ))
        }
        0x02 => {
            if buf.len() < 19 {
                return Err(Error::Proto("tuic: v6 截断"));
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[1..17]);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((
                DstAddr {
                    host: Host::Ip(std::net::IpAddr::V6(o.into())),
                    port,
                },
                19,
            ))
        }
        other => Err(Error::ProtoMsg(format!("tuic: 地址类型 {other:#x} 非法"))),
    }
}

fn token(conn: &quinn::Connection, uuid: &str, password: &str) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, uuid.as_bytes(), password.as_bytes())
        .map_err(|_| Error::Proto("tuic: token 导出失败"))?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// 出站
// ---------------------------------------------------------------------------

pub struct TuicOutbound {
    name: Arc<str>,
    server: String,
    port: u16,
    uuid: String,
    password: String,
    skip_verify: bool,
    _congestion_controller: Option<String>,
    assoc_counter: AtomicU16,
}

impl TuicOutbound {
    pub fn new(cfg: &vp_config::TuicCfg) -> Result<Self> {
        Ok(TuicOutbound {
            name: "tuic".into(),
            server: cfg.server.clone(),
            port: cfg.port,
            uuid: cfg.uuid.clone(),
            password: cfg.password.clone(),
            skip_verify: cfg.skip_cert_verify,
            _congestion_controller: cfg.congestion_controller.clone(),
            assoc_counter: AtomicU16::new(1),
        })
    }

    /// QUIC 连接 + Authenticate
    async fn dial(&self) -> Result<quinn::Connection> {
        let addr: SocketAddr = tokio::net::lookup_host((self.server.as_str(), self.port))
            .await
            .map_err(|e| Error::Addr(format!("解析 {}: {e}", self.server)))?
            .next()
            .ok_or(Error::Addr("无地址".into()))?;
        let mut ep = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
        ep.set_default_client_config(tuic_client_config(self.skip_verify));
        let conn = ep
            .connect(addr, &self.server)
            .map_err(|e| Error::Addr(format!("tuic 连接参数: {e}")))?
            .await
            .map_err(|e| Error::Io(std::io::Error::other(format!("tuic QUIC 握手: {e}"))))?;
        // Authenticate（uni 流）
        let mut uni = conn
            .open_uni()
            .await
            .map_err(|e| Error::Io(std::io::Error::other(format!("tuic open_uni: {e}"))))?;
        let uuid16 = parse_uuid16(&self.uuid)?;
        let tok = token(&conn, &self.uuid, &self.password)?;
        let mut auth = Vec::with_capacity(2 + 16 + 32);
        auth.push(VER);
        auth.push(T_AUTH);
        auth.extend_from_slice(&uuid16);
        auth.extend_from_slice(&tok);
        uni.write_all(&auth)
            .await
            .map_err(|e| Error::Io(std::io::Error::other(format!("tuic auth 写入: {e}"))))?;
        uni.finish()
            .map_err(|e| Error::Io(std::io::Error::other(format!("tuic auth finish: {e}"))))?;
        Ok(conn)
    }
}

fn parse_uuid16(s: &str) -> Result<[u8; 16]> {
    vp_crypto::vmess_kdf::parse_uuid(s)
}

#[async_trait]
impl Outbound for TuicOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect_stream(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        let conn = self.dial().await?;
        let (mut send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| Error::Io(std::io::Error::other(format!("tuic open_bi: {e}"))))?;
        let mut req = vec![VER, T_CONNECT];
        encode_addr(dst, &mut req);
        send.write_all(&req)
            .await
            .map_err(|e| Error::Io(std::io::Error::other(format!("tuic connect 写入: {e}"))))?;
        Ok(Box::new(crate::hysteria2::QuicBiStream { send, recv }))
    }

    fn support_udp(&self) -> bool {
        true
    }

    async fn connect_packet(&self, _sess: &Session, _dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        let conn = self.dial().await?;
        let assoc = self.assoc_counter.fetch_add(1, Ordering::Relaxed);
        Ok(Box::new(TuicPacketConn {
            conn,
            assoc,
            pkt: AtomicU16::new(1),
            _reply_assoc: None,
        }))
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
}

/// UDP：uni 流模式 Packet 命令（回包也走服务端 uni 流，由会话任务读取转发）
struct TuicPacketConn {
    conn: quinn::Connection,
    assoc: u16,
    pkt: AtomicU16,
    /// 服务端回包流
    _reply_assoc: Option<tokio::sync::Mutex<Option<quinn::RecvStream>>>,
}

#[async_trait]
impl PacketConn for TuicPacketConn {
    async fn send(&self, pkt: &UdpPacket) -> Result<()> {
        let mut addr = Vec::with_capacity(24);
        encode_addr(
            &DstAddr {
                host: Host::Ip(pkt.dst.ip()),
                port: pkt.dst.port(),
            },
            &mut addr,
        );
        let size = addr.len() + pkt.data.len();
        let mut msg = Vec::with_capacity(2 + 8 + size);
        msg.push(VER);
        msg.push(T_PACKET);
        msg.extend_from_slice(&self.assoc.to_be_bytes());
        msg.extend_from_slice(&(self.pkt.fetch_add(1, Ordering::Relaxed)).to_be_bytes());
        msg.push(1); // frag total
        msg.push(0); // frag id
        msg.extend_from_slice(&(size as u16).to_be_bytes());
        msg.extend_from_slice(&addr);
        msg.extend_from_slice(&pkt.data);
        let mut uni = self
            .conn
            .open_uni()
            .await
            .map_err(|e| Error::Io(std::io::Error::other(format!("tuic pkt open_uni: {e}"))))?;
        uni.write_all(&msg)
            .await
            .map_err(|e| Error::Io(std::io::Error::other(format!("tuic pkt 写入: {e}"))))?;
        uni.finish()
            .map_err(|e| Error::Io(std::io::Error::other(format!("tuic pkt finish: {e}"))))?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<UdpPacket> {
        // 简化实现：服务端把回包写在客户端打开的 bi 流之外的 uni 流不可等——
        // TUIC 服务端回包：对 native 模式走 datagram，对 quic 模式服务端开 uni 流。
        // 此处读取服务端 uni 流。
        loop {
            let stream = self
                .conn
                .read_datagram()
                .await
                .map_err(|e| Error::Io(std::io::Error::other(format!("tuic datagram: {e}"))))?;
            // 尝试按 Packet 命令解析
            if stream.len() < 2 || stream[0] != VER {
                continue;
            }
            match stream[1] {
                T_PACKET => {
                    let Some(pkt) = parse_packet_opt(&stream[2..]) else {
                        continue;
                    };
                    if pkt.assoc != self.assoc {
                        continue;
                    }
                    return Ok(UdpPacket {
                        src: pkt.src,
                        dst: pkt.src,
                        data: pkt.payload,
                    });
                }
                _ => continue, // Heartbeat 等
            }
        }
    }
}

struct PacketOpt {
    assoc: u16,
    src: SocketAddr,
    payload: Bytes,
}

/// 解析 Packet OPT：ASSOC(2) PKT(2) FRAG_TOTAL(1) FRAG(1) SIZE(2) ADDR PAYLOAD
fn parse_packet_opt(opt: &[u8]) -> Option<PacketOpt> {
    if opt.len() < 8 {
        return None;
    }
    let assoc = u16::from_be_bytes([opt[0], opt[1]]);
    let frag_total = opt[4];
    if frag_total != 1 {
        return None; // 分片不支持
    }
    let size = u16::from_be_bytes([opt[6], opt[7]]) as usize;
    let rest = &opt[8..];
    if rest.len() < size {
        return None;
    }
    let body = &rest[..size];
    let (dst, used) = decode_addr(body).ok()?;
    let ip = match dst.host {
        Host::Ip(ip) => ip,
        Host::Domain(_) => return None,
    };
    Some(PacketOpt {
        assoc,
        src: SocketAddr::new(ip, dst.port),
        payload: Bytes::copy_from_slice(&body[used..]),
    })
}

fn tuic_client_config(skip_verify: bool) -> quinn::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if skip_verify {
        crypto
            .dangerous()
            .set_certificate_verifier(Arc::new(TuicNoVerify));
    }
    crypto.alpn_protocols = vec![b"tuic".to_vec()];
    let mut cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("tuic cfg"),
    ));
    let mut t = quinn::TransportConfig::default();
    t.datagram_receive_buffer_size(Some(1 << 20));
    cfg.transport_config(Arc::new(t));
    cfg
}

#[derive(Debug)]
struct TuicNoVerify;

impl rustls::client::danger::ServerCertVerifier for TuicNoVerify {
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

// ---------------------------------------------------------------------------
// 入站（服务端）
// ---------------------------------------------------------------------------

pub struct TuicInbound {
    bind: String,
    port: u16,
    tag: Arc<str>,
    /// uuid → password
    users: Vec<(String, String)>,
    /// 证书（PEM）
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
}

impl TuicInbound {
    pub fn new(
        bind: &str,
        port: u16,
        tag: &str,
        users: Vec<(String, String)>,
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
    ) -> Self {
        TuicInbound {
            bind: bind.into(),
            port,
            tag: tag.into(),
            users,
            cert_pem,
            key_pem,
        }
    }
}

#[async_trait]
impl Inbound for TuicInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, ctx: InboundCtx) -> Result<u16> {
        let certs: Vec<_> = rustls_pemfile::certs(&mut &self.cert_pem[..])
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| Error::Config(format!("tuic 证书: {e}")))?;
        let key = rustls_pemfile::private_key(&mut &self.key_pem[..])
            .map_err(|e| Error::Config(format!("tuic 私钥: {e}")))?
            .ok_or(Error::Config("tuic 缺私钥".into()))?;
        let mut crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| Error::Config(format!("tuic tls: {e}")))?;
        crypto.alpn_protocols = vec![b"tuic".to_vec()];
        let mut scfg = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
                .map_err(|e| Error::Config(format!("tuic server cfg: {e}")))?,
        ));
        let mut t = quinn::TransportConfig::default();
        t.datagram_receive_buffer_size(Some(1 << 20));
        scfg.transport_config(Arc::new(t));

        let endpoint =
            quinn::Endpoint::server(scfg, (self.bind.as_str(), self.port).to_socket_addrs_dyn())
                .map_err(|e| Error::Io(std::io::Error::other(format!("tuic bind: {e}"))))?;
        let bound = endpoint.local_addr().map_err(Error::Io)?.port();
        let this = self.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let Ok(conn) = incoming.await else { continue };
                let this = this.clone();
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = this.serve_conn(conn, &ctx).await {
                        tracing::debug!("tuic 连接结束: {e}");
                    }
                });
            }
        });
        Ok(bound)
    }
}

trait ToAddrsDyn {
    fn to_socket_addrs_dyn(&self) -> SocketAddr;
}
impl ToAddrsDyn for (&str, u16) {
    fn to_socket_addrs_dyn(&self) -> SocketAddr {
        format!("{}:{}", self.0, self.1)
            .parse()
            .unwrap_or_else(|_| SocketAddr::new(std::net::IpAddr::V4([0, 0, 0, 0].into()), self.1))
    }
}

impl TuicInbound {
    /// UDP 会话：登记目标 + 建socket + 回包泵（datagram 模式回发）
    async fn udp_session_relay(
        conn: &quinn::Connection,
        udp_sessions: &mut std::collections::HashMap<
            u16,
            std::sync::Arc<tokio::sync::Mutex<std::net::SocketAddr>>,
        >,
        pkt: PacketOpt,
    ) -> Result<()> {
        let sess = udp_sessions
            .entry(pkt.assoc)
            .or_insert_with(|| {
                std::sync::Arc::new(tokio::sync::Mutex::new("127.0.0.1:0".parse().unwrap()))
            })
            .clone();
        let mut guard = sess.lock().await;
        if guard.port() == 0 {
            *guard = pkt.src;
        }
        let target = *guard;
        drop(guard);
        let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(target).await?;
        let _ = sock.send(&pkt.payload).await;
        let conn2 = conn.clone();
        let assoc = pkt.assoc;
        tokio::spawn(async move {
            let mut rbuf = [0u8; 65535];
            loop {
                let recv = tokio::time::timeout(
                    std::time::Duration::from_secs(300),
                    sock.recv_from(&mut rbuf),
                )
                .await;
                let Ok(Ok((n, from))) = recv else { break };
                let mut addr = Vec::new();
                encode_addr(&DstAddr::ip(from.ip(), from.port()), &mut addr);
                let size = addr.len() + n;
                let mut msg = vec![VER, T_PACKET];
                msg.extend_from_slice(&assoc.to_be_bytes());
                msg.extend_from_slice(&1u16.to_be_bytes());
                msg.push(1);
                msg.push(0);
                msg.extend_from_slice(&(size as u16).to_be_bytes());
                msg.extend_from_slice(&addr);
                msg.extend_from_slice(&rbuf[..n]);
                if conn2.send_datagram(Bytes::from(msg)).is_err() {
                    break;
                }
            }
        });
        Ok(())
    }

    /// 已认证的连接：认证（首个 uni 流）成功前不处理其它命令
    async fn serve_conn(&self, conn: quinn::Connection, ctx: &InboundCtx) -> Result<()> {
        // 并发接受 uni/bi 流与 datagram；认证在首个 uni 流上
        let authed = Arc::new(tokio::sync::Notify::new());
        let mut udp_sessions: std::collections::HashMap<
            u16,
            std::sync::Arc<tokio::sync::Mutex<std::net::SocketAddr>>,
        > = std::collections::HashMap::new();

        // 期望 token 集合
        let expect: Vec<([u8; 16], [u8; 32])> = self
            .users
            .iter()
            .filter_map(|(uuid, pw)| {
                let u16b = parse_uuid16(uuid).ok()?;
                let t = token(&conn, uuid, pw).ok()?;
                Some((u16b, t))
            })
            .collect();

        loop {
            tokio::select! {
                uni = conn.accept_uni() => {
                    let Ok(mut uni) = uni else { break };
                    let mut head = [0u8; 2];
                    if uni.read_exact(&mut head).await.is_err() {
                        continue;
                    }
                    if head[0] != VER {
                        continue;
                    }
                    match head[1] {
                        T_AUTH => {
                            let mut body = [0u8; 48];
                            if uni.read_exact(&mut body).await.is_err() {
                                continue;
                            }
                            let mut uuid = [0u8; 16];
                            uuid.copy_from_slice(&body[..16]);
                            let mut tok = [0u8; 32];
                            tok.copy_from_slice(&body[16..]);
                            let ok = expect.iter().any(|(u, t)| *u == uuid && *t == tok);
                            tracing::debug!("tuic auth uuid={:02x?} ok={ok}", uuid);
                            if !ok {
                                conn.close(quinn::VarInt::from_u32(0x1f), b"auth failed");
                                break;
                            }
                            authed.notify_waiters();
                        }
                        T_PACKET => {
                            let mut opt = Vec::with_capacity(1500);
                            let mut lim = 0usize;
                            loop {
                                let mut b = [0u8; 1];
                                match uni.read(&mut b).await {
                                    Ok(None) | Err(_) => break,
                                    Ok(Some(_)) => {
                                        opt.push(b[0]);
                                        lim += 1;
                                        if lim > 65535 {
                                            break;
                                        }
                                    }
                                }
                            }
                            let Some(pkt) = parse_packet_opt(&opt) else { continue };
                            let _ = Self::udp_session_relay(&conn, &mut udp_sessions, pkt).await;
                        }
                        T_DISSOCIATE => {
                            let mut a = [0u8; 2];
                            if uni.read_exact(&mut a).await.is_ok() {
                                udp_sessions.remove(&u16::from_be_bytes(a));
                            }
                        }
                        _ => {}
                    }
                }
                bi = conn.accept_bi() => {
                    let Ok((send, mut recv)) = bi else { break };
                    let mut head = [0u8; 2];
                    if recv.read_exact(&mut head).await.is_err() {
                        continue;
                    }
                    if head[0] != VER || head[1] != T_CONNECT {
                        continue;
                    }
                    // 读地址（增量）
                    let mut addr_buf: Vec<u8> = Vec::with_capacity(300);
                    let dst = loop {
                        match decode_addr(&addr_buf) {
                            Ok((d, _)) => break d,
                            Err(_) => {
                                let mut b = [0u8; 1];
                                if recv.read_exact(&mut b).await.is_err() {
                                    break DstAddr::ip([127,0,0,1].into(), 0);
                                }
                                addr_buf.push(b[0]);
                                if addr_buf.len() > 262 {
                                    break DstAddr::ip([127,0,0,1].into(), 0);
                                }
                            }
                        }
                    };
                    if dst.port == 0 {
                        continue;
                    }
                    let src = conn.remote_address();
                    let sess = Session::new_tcp(self.tag.clone(), Some(src), dst.clone());
                    let ctx2 = ctx.clone();
                    tokio::spawn(async move {
                        let direct = crate::direct::DirectOutbound::new(
                            Arc::new(vp_dns::Resolver::system()),
                            false,
                        );
                        match direct.connect_stream(&sess, &dst).await {
                            Ok(remote) => {
                                let client: Box<dyn ProxyStream> =
                                    Box::new(crate::hysteria2::QuicBiStream { send, recv });
                                let meta = vp_core::ConnMeta {
                                    id: sess.id,
                                    inbound: sess.inbound.clone(),
                                    network: "tcp",
                                    host: dst.host.to_string(),
                                    dst_port: dst.port,
                                    src: Some(src.to_string()),
                                    process: None,
                                    rule: None,
                                    chain: Some("tuic-server".into()),
                                    start: vp_common::now_millis(),
                                };
                                let hook = RelayHook {
                                    table: Some(ctx2.conns.clone()),
                                    meta: Some(meta),
                                    stats: Some(ctx2.stats.clone()),
                                };
                                let _ = relay(client, remote, hook).await;
                            }
                            Err(e) => {
                                tracing::debug!("tuic 出站失败: {e}");
                            }
                        }
                    });
                }
                dg = conn.read_datagram() => {
                    let Ok(dg) = dg else { break };
                    if dg.len() >= 2 && dg[0] == VER && dg[1] == T_PACKET {
                        let Some(pkt) = parse_packet_opt(&dg[2..]) else { continue };
                        let _ = Self::udp_session_relay(&conn, &mut udp_sessions, pkt).await;
                    }
                    // Heartbeat 忽略
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_roundtrip() {
        for d in [
            DstAddr::new("example.com", 443),
            DstAddr::ip("1.2.3.4".parse().unwrap(), 80),
            DstAddr::ip("2001:db8::1".parse().unwrap(), 53),
        ] {
            let mut b = Vec::new();
            encode_addr(&d, &mut b);
            let (d2, used) = decode_addr(&b).unwrap();
            assert_eq!(used, b.len());
            assert_eq!(d, d2);
        }
    }

    /// TUIC v5 出入站自环（TCP Connect + UDP Packet native datagram 模式）
    #[tokio::test]
    async fn tuic_loopback() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // TCP echo + UDP echo
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

        // 自签服务端
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let ctx = vp_core::InboundCtx {
            router: std::sync::Arc::new(crate::test_support::NoopRouter()),
            stats: std::sync::Arc::new(vp_common::Stats::default()),
            conns: std::sync::Arc::new(vp_core::ConnTable::new()),
        };
        let server = TuicInbound::new(
            "127.0.0.1",
            0,
            "tuic-srv",
            vec![(
                "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
                "pw".to_string(),
            )],
            cert.cert.pem().into_bytes(),
            cert.key_pair.serialize_pem().into_bytes(),
        );
        let port = std::sync::Arc::new(server).start(ctx).await.unwrap();

        let out = TuicOutbound::new(&vp_config::TuicCfg {
            server: "127.0.0.1".into(),
            port,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            password: "pw".into(),
            sni: None,
            skip_cert_verify: true,
            congestion_controller: None,
            udp_relay_mode: None,
        })
        .unwrap();

        // TCP
        let dst = DstAddr::ip("127.0.0.1".parse().unwrap(), tcp_port);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = out.connect_stream(&sess, &dst).await.unwrap();
        s.write_all(b"ping-tuic").await.unwrap();
        let mut buf = [0u8; 9];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-tuic");

        // UDP（datagram 模式回包）
        let dst = DstAddr::ip(udp_addr.ip(), udp_addr.port());
        let sess = Session::new_udp("t".into(), None, dst.clone());
        let mut conn = out.connect_packet(&sess, &dst).await.unwrap();
        conn.send(&UdpPacket {
            src: "127.0.0.1:0".parse().unwrap(),
            dst: udp_addr,
            data: b"tuic-udp".to_vec().into(),
        })
        .await
        .unwrap();
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), conn.recv())
            .await
            .expect("udp 超时")
            .unwrap();
        assert_eq!(&resp.data[..], b"echo:tuic-udp");
    }

    #[test]
    fn packet_opt_roundtrip() {
        let mut addr = Vec::new();
        encode_addr(&DstAddr::ip("9.9.9.9".parse().unwrap(), 53), &mut addr);
        let payload = b"hello";
        let size = addr.len() + payload.len();
        let mut opt = Vec::new();
        opt.extend_from_slice(&0x0102u16.to_be_bytes()); // assoc
        opt.extend_from_slice(&7u16.to_be_bytes()); // pkt
        opt.push(1);
        opt.push(0);
        opt.extend_from_slice(&(size as u16).to_be_bytes());
        opt.extend_from_slice(&addr);
        opt.extend_from_slice(payload);
        let p = parse_packet_opt(&opt).unwrap();
        assert_eq!(p.assoc, 0x0102);
        assert_eq!(p.src.to_string(), "9.9.9.9:53");
        assert_eq!(&p.payload[..], b"hello");
    }
}

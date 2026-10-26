//! Hysteria2 协议（QUIC + HTTP/3 认证 + QUIC varint 帧）。
//!
//! - 认证：HTTP/3 `POST /auth`，`Hysteria-Auth` 头携带密码，响应状态码 233
//! - TCP：每连接一条 QUIC 双向流，首包 `[varint 0x401][varint |addr|]["host:port"][varint |pad|]`
//!   服务端 TCPResponse `[u8 status][varint |msg|][msg]`
//! - UDP：QUIC unreliable datagram，UDPMessage
//!   `[u32 BE session][u16 BE pkt][u8 frag][u8 frag_total][varint |addr|][addr][payload]`

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};

use vp_common::{DstAddr, Error, Result};
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;
use vp_core::tunnel::{RelayHook, relay};
use vp_core::{Inbound, Outbound, PacketConn, ProxyStream, UdpPacket};

const TCP_REQUEST_ID: u64 = 0x401;

// ---------------------------------------------------------------------------
// QUIC varint
// ---------------------------------------------------------------------------

pub fn write_varint(out: &mut Vec<u8>, v: u64) {
    if v < 0x40 {
        out.push(v as u8);
    } else if v < 0x4000 {
        let n: u16 = 0x4000 | v as u16;
        out.extend_from_slice(&n.to_be_bytes());
    } else if v < 0x4000_0000 {
        let n: u32 = 0x8000_0000 | v as u32;
        out.extend_from_slice(&n.to_be_bytes());
    } else {
        let n: u64 = 0xC000_0000_0000_0000 | v;
        out.extend_from_slice(&n.to_be_bytes());
    }
}

pub fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let b0 = *buf.first()?;
    match b0 >> 6 {
        0 => Some((b0 as u64, 1)),
        1 => {
            if buf.len() < 2 {
                return None;
            }
            Some((((b0 as u64) & 0x3f) << 8 | buf[1] as u64, 2))
        }
        2 => {
            if buf.len() < 4 {
                return None;
            }
            let mut b = [0u8; 4];
            b[0] = b0 & 0x3f;
            b[1..].copy_from_slice(&buf[1..4]);
            Some((u32::from_be_bytes(b) as u64, 4))
        }
        _ => {
            if buf.len() < 8 {
                return None;
            }
            let mut b = [0u8; 8];
            b[0] = b0 & 0x3f;
            b[1..].copy_from_slice(&buf[1..8]);
            Some((u64::from_be_bytes(b), 8))
        }
    }
}

fn addr_text(dst: &DstAddr) -> String {
    dst.to_string()
}

// ---------------------------------------------------------------------------
// 出站
// ---------------------------------------------------------------------------

pub struct Hysteria2Outbound {
    name: Arc<str>,
    server: String,
    port: u16,
    password: String,
    sni: Option<String>,
    skip_verify: bool,
    _up_mbps: u32,
    udp_session: AtomicU32,
}

impl Hysteria2Outbound {
    pub fn new(cfg: &vp_config::Hysteria2Cfg) -> Result<Self> {
        Ok(Hysteria2Outbound {
            name: "hysteria2".into(),
            server: cfg.server.clone(),
            port: cfg.port,
            password: cfg.password.clone(),
            sni: cfg.sni.clone().or(Some(cfg.server.clone())),
            skip_verify: cfg.skip_cert_verify,
            _up_mbps: 0,
            udp_session: AtomicU32::new(1),
        })
    }

    async fn connect_quic(&self) -> Result<(quinn::Connection, quinn::Endpoint)> {
        let addr: SocketAddr = tokio::net::lookup_host((self.server.as_str(), self.port))
            .await
            .map_err(|e| Error::Addr(format!("解析 {}: {e}", self.server)))?
            .next()
            .ok_or(Error::Addr("无地址".into()))?;
        let mut ep = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
        ep.set_default_client_config(hysteria_client_config(
            self.skip_verify,
            self.sni.as_deref(),
        ));
        let conn = ep
            .connect(addr, self.sni.as_deref().unwrap_or(&self.server))
            .map_err(|e| Error::Addr(format!("hy2 连接参数: {e}")))?
            .await
            .map_err(|e| Error::Io(std::io::Error::other(format!("hy2 QUIC 握手: {e}"))))?;
        Ok((conn, ep))
    }

    /// HTTP/3 认证（最小实现，见 h3_min 模块说明）
    async fn auth(&self, conn: &quinn::Connection) -> Result<()> {
        let headers: Vec<(&str, &str)> = vec![
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", "hysteria"),
            (":path", "/auth"),
            ("hysteria-auth", &self.password),
            ("hysteria-cc-rx", "0"),
            ("hysteria-padding", "0000000000000000"),
        ];
        let resp = crate::h3_min::auth_roundtrip(conn, &headers).await?;
        let status = resp
            .iter()
            .find(|(k, _)| k == ":status")
            .map(|(_, v)| v.clone())
            .ok_or(Error::Proto("hy2: 响应缺 :status"))?;
        if status != "233" {
            return Err(Error::ProtoMsg(format!("hy2 认证失败（状态 {status}）")));
        }
        Ok(())
    }
}

#[async_trait]
impl Outbound for Hysteria2Outbound {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect_stream(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        let (conn, _ep) = self.connect_quic().await?;
        self.auth(&conn).await?;
        // TCP 流
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| Error::Io(std::io::Error::other(format!("hy2 open_bi: {e}"))))?;
        let addr = addr_text(dst);
        let mut req = Vec::with_capacity(addr.len() + 12);
        write_varint(&mut req, TCP_REQUEST_ID);
        write_varint(&mut req, addr.len() as u64);
        req.extend_from_slice(addr.as_bytes());
        write_varint(&mut req, 0); // padding
        send.write_all(&req)
            .await
            .map_err(|e| Error::Io(std::io::Error::other(format!("hy2 写请求: {e}"))))?;
        // TCPResponse: [u8 status][varint |msg|][msg][varint |pad|][pad]
        // 本实现两端 msg=pad=空 → 固定 3 字节（status + 两个单字节零 varint）
        let mut head = [0u8; 3];
        recv.read_exact(&mut head)
            .await
            .map_err(|e| Error::Io(std::io::Error::other(format!("hy2 读响应: {e}"))))?;
        if head[0] != 0x00 {
            return Err(Error::ProtoMsg("hy2 TCPResponse 错误".into()));
        }
        let (msg_len, used) = read_varint(&head[1..]).ok_or(Error::Proto("hy2 varint"))?;
        let extra = (used as isize - 2).max(0) as usize;
        if extra > 0 {
            let mut ex = vec![0u8; extra];
            recv.read_exact(&mut ex)
                .await
                .map_err(|e| Error::Io(std::io::Error::other(format!("hy2: {e}"))))?;
        }
        if msg_len > 0 {
            let mut skip = vec![0u8; msg_len as usize];
            recv.read_exact(&mut skip)
                .await
                .map_err(|e| Error::Io(std::io::Error::other(format!("hy2 跳过消息: {e}"))))?;
        }
        Ok(Box::new(QuicBiStream { send, recv }))
    }

    fn support_udp(&self) -> bool {
        true
    }

    async fn connect_packet(&self, _sess: &Session, _dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        let (conn, _ep) = self.connect_quic().await?;
        self.auth(&conn).await?;
        let session = self.udp_session.fetch_add(1, Ordering::Relaxed);
        Ok(Box::new(Hy2UdpConn {
            conn,
            session,
            pkt_id: 1,
        }))
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
}

/// QUIC 双向流包装（tuic 复用）
pub struct QuicBiStream {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}

impl AsyncRead for QuicBiStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        AsyncRead::poll_read(std::pin::Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for QuicBiStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(std::pin::Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.send), cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.send), cx)
    }
}

/// UDP over QUIC datagram
struct Hy2UdpConn {
    conn: quinn::Connection,
    session: u32,
    pkt_id: u16,
}

#[async_trait]
impl PacketConn for Hy2UdpConn {
    async fn send(&self, pkt: &UdpPacket) -> Result<()> {
        let addr = format!("{}:{}", pkt.dst.ip(), pkt.dst.port());
        let mut msg = Vec::with_capacity(pkt.data.len() + addr.len() + 16);
        msg.extend_from_slice(&self.session.to_be_bytes());
        msg.extend_from_slice(&self.pkt_id.to_be_bytes());
        msg.push(0); // frag id
        msg.push(1); // frag total
        write_varint(&mut msg, addr.len() as u64);
        msg.extend_from_slice(addr.as_bytes());
        msg.extend_from_slice(&pkt.data);
        self.conn
            .send_datagram(Bytes::from(msg))
            .map_err(|e| Error::Io(std::io::Error::other(format!("hy2 datagram: {e}"))))?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<UdpPacket> {
        loop {
            let dgram =
                self.conn.read_datagram().await.map_err(|e| {
                    Error::Io(std::io::Error::other(format!("hy2 read_datagram: {e}")))
                })?;
            if dgram.len() < 8 {
                continue;
            }
            let session = u32::from_be_bytes([dgram[0], dgram[1], dgram[2], dgram[3]]);
            if session != self.session {
                continue;
            }
            let _pkt = u16::from_be_bytes([dgram[4], dgram[5]]);
            // frag id/total：未分片实现——分片包直接丢弃
            if dgram[7] != 1 {
                continue;
            }
            let Some((alen, used)) = read_varint(&dgram[8..]) else {
                continue;
            };
            let start = 8 + used;
            let end = start + alen as usize;
            if dgram.len() < end {
                continue;
            }
            let addr = std::str::from_utf8(&dgram[start..end])
                .ok()
                .and_then(|s| s.parse::<SocketAddr>().ok());
            let Some(src) = addr else { continue };
            return Ok(UdpPacket {
                src,
                dst: src,
                data: dgram.slice(end..),
            });
        }
    }
}

fn hysteria_client_config(skip_verify: bool, _sni: Option<&str>) -> quinn::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if skip_verify {
        crypto
            .dangerous()
            .set_certificate_verifier(Arc::new(Hy2NoVerify));
    }
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let mut cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("hy2 client cfg"),
    ));
    let mut t = quinn::TransportConfig::default();
    t.datagram_receive_buffer_size(Some(1 << 20));
    cfg.transport_config(Arc::new(t));
    cfg
}

#[derive(Debug)]
struct Hy2NoVerify;

impl rustls::client::danger::ServerCertVerifier for Hy2NoVerify {
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

pub struct Hysteria2Inbound {
    bind: String,
    port: u16,
    tag: Arc<str>,
    password: String,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
}

impl Hysteria2Inbound {
    pub fn new(
        bind: &str,
        port: u16,
        tag: &str,
        password: &str,
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
    ) -> Self {
        Hysteria2Inbound {
            bind: bind.into(),
            port,
            tag: tag.into(),
            password: password.into(),
            cert_pem,
            key_pem,
        }
    }
}

#[async_trait]
impl Inbound for Hysteria2Inbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, ctx: InboundCtx) -> Result<u16> {
        let certs: Vec<_> = rustls_pemfile::certs(&mut &self.cert_pem[..])
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| Error::Config(format!("hy2 证书: {e}")))?;
        let key = rustls_pemfile::private_key(&mut &self.key_pem[..])
            .map_err(|e| Error::Config(format!("hy2 私钥: {e}")))?
            .ok_or(Error::Config("hy2 缺私钥".into()))?;
        let mut crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| Error::Config(format!("hy2 tls: {e}")))?;
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        let mut scfg = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
                .map_err(|e| Error::Config(format!("hy2 server cfg: {e}")))?,
        ));
        let mut t = quinn::TransportConfig::default();
        t.datagram_receive_buffer_size(Some(1 << 20));
        scfg.transport_config(Arc::new(t));

        let bind_addr: SocketAddr = format!("{}:{}", self.bind, self.port)
            .parse()
            .unwrap_or_else(|_| {
                SocketAddr::new(std::net::IpAddr::V4([0, 0, 0, 0].into()), self.port)
            });
        let endpoint = quinn::Endpoint::server(scfg, bind_addr)?;
        let bound = endpoint.local_addr()?.port();
        let this = self.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let Ok(conn) = incoming.await else { continue };
                let this = this.clone();
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = this.serve_conn(conn, &ctx).await {
                        tracing::debug!("hy2 连接结束: {e}");
                    }
                });
            }
        });
        Ok(bound)
    }
}

impl Hysteria2Inbound {
    async fn serve_conn(&self, conn: quinn::Connection, ctx: &InboundCtx) -> Result<()> {
        let mut udp_sessions: std::collections::HashMap<
            u32,
            std::sync::Arc<tokio::sync::Mutex<std::net::SocketAddr>>,
        > = std::collections::HashMap::new();
        loop {
            tokio::select! {
                uni = conn.accept_uni() => {
                    let Ok(mut s) = uni else { break };
                    let mut tb = [0u8; 1];
                    if s.read_exact(&mut tb).await.is_err() {
                        continue;
                    }
                    let st = read_varint(&tb).map(|(v, _)| v).unwrap_or(u64::MAX);
                    if st == crate::h3_min::STREAM_CONTROL {
                        // 客户端开了控制流：服务端也开一条并回应空 SETTINGS
                        if let Ok(out) = conn.open_uni().await {
                            let _ = crate::h3_min::server_init_stream(out, crate::h3_min::STREAM_CONTROL).await;
                        }
                    }
                }
                bi = conn.accept_bi() => {
                    let Ok((mut send, mut recv)) = bi else { break };
                    // 嗅探首字节：TCP 请求(0x44 0x01) 或 HEADERS 帧(0x01)
                    let mut first: Vec<u8> = Vec::with_capacity(16);
                    let handled = loop {
                        let mut b = [0u8; 1];
                        if recv.read_exact(&mut b).await.is_err() {
                            break false;
                        }
                        first.push(b[0]);
                        if first.len() == 2 && first == [0x44, 0x01] {
                            self.serve_tcp(recv, send, ctx).await;
                            break true;
                        }
                        if first[0] == 0x01 {
                            let mut full = first.clone();
                            match read_h3_headers(&mut recv, &mut full).await {
                                Ok(headers) => {
                                    self.serve_auth(headers, send, &conn, ctx).await;
                                    break true;
                                }
                                Err(e) => {
                                    tracing::debug!("hy2 请求解析失败: {e}");
                                    let _ = send.reset(quinn::VarInt::from_u32(0x8));
                                    break true;
                                }
                            }
                        }
                        if first.len() > 8 {
                            break false;
                        }
                    };
                    let _ = handled;
                }
                dg = conn.read_datagram() => {
                    let Ok(dg) = dg else { break };
                    let Some(pkt) = parse_udp_message(&dg) else { continue };
                    let sess = udp_sessions
                        .entry(pkt.session)
                        .or_insert_with(|| {
                            std::sync::Arc::new(tokio::sync::Mutex::new(
                                "127.0.0.1:0".parse().unwrap(),
                            ))
                        })
                        .clone();
                    let mut g = sess.lock().await;
                    if g.port() == 0 {
                        *g = pkt.src;
                    }
                    let target = *g;
                    drop(g);
                    if target.port() == 0 {
                        continue;
                    }
                    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
                    sock.connect(target).await?;
                    let _ = sock.send(&pkt.payload).await;
                    let conn2 = conn.clone();
                    let session = pkt.session;
                    tokio::spawn(async move {
                        let mut rbuf = [0u8; 65535];
                        loop {
                            let Ok(Ok((n, from))) = tokio::time::timeout(
                                std::time::Duration::from_secs(300),
                                sock.recv_from(&mut rbuf),
                            ).await else { break };
                            let addr = format!("{}:{}", from.ip(), from.port());
                            let mut msg = Vec::with_capacity(n + addr.len() + 16);
                            msg.extend_from_slice(&session.to_be_bytes());
                            msg.extend_from_slice(&0u16.to_be_bytes());
                            msg.push(0);
                            msg.push(1);
                            write_varint(&mut msg, addr.len() as u64);
                            msg.extend_from_slice(addr.as_bytes());
                            msg.extend_from_slice(&rbuf[..n]);
                            if conn2.send_datagram(Bytes::from(msg)).is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
        Ok(())
    }

    /// /auth → 233；其它/密码错 → 伪装 404
    async fn serve_auth(
        &self,
        headers: Vec<(String, String)>,
        mut send: quinn::SendStream,
        conn: &quinn::Connection,
        _ctx: &InboundCtx,
    ) {
        let path = headers
            .iter()
            .find(|(k, _)| k == ":path")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let got = headers
            .iter()
            .find(|(k, _)| k == "hysteria-auth")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        if path != "/auth" || got != self.password {
            let _ = crate::h3_min::write_response_headers(&mut send, &[(":status", "404")]).await;
            let _ = send.finish();
            if path == "/auth" {
                conn.close(quinn::VarInt::from_u32(8), b"auth failed");
            }
            return;
        }
        let _ = crate::h3_min::write_response_headers(
            &mut send,
            &[
                (":status", "233"),
                ("hysteria-udp", "true"),
                ("hysteria-cc-rx", "0"),
            ],
        )
        .await;
        let _ = send.finish();
    }

    /// TCP 请求流（0x44 0x01 已消费）
    async fn serve_tcp(
        &self,
        mut recv: quinn::RecvStream,
        mut send: quinn::SendStream,
        ctx: &InboundCtx,
    ) {
        let mut addr_buf: Vec<u8> = Vec::with_capacity(300);
        let dst = loop {
            match read_varint(&addr_buf) {
                Some((alen, used)) if addr_buf.len() >= used + alen as usize => {
                    let s = std::str::from_utf8(&addr_buf[used..used + alen as usize])
                        .unwrap_or("127.0.0.1:0");
                    let s = s
                        .strip_prefix('[')
                        .map(|x| x.trim_end_matches(']'))
                        .unwrap_or(s);
                    break DstAddr::parse(s)
                        .unwrap_or_else(|_| DstAddr::ip([127, 0, 0, 1].into(), 0));
                }
                _ => {
                    let mut b = [0u8; 1];
                    if recv.read_exact(&mut b).await.is_err() {
                        break DstAddr::ip([127, 0, 0, 1].into(), 0);
                    }
                    addr_buf.push(b[0]);
                    if addr_buf.len() > 300 {
                        break DstAddr::ip([127, 0, 0, 1].into(), 0);
                    }
                }
            }
        };
        if dst.port == 0 {
            let _ = send.reset(quinn::VarInt::from_u32(0x8));
            return;
        }
        // 消费 padding：[varint |pad|][pad bytes]（本实现恒空，读 varint 即可）
        let mut padb: Vec<u8> = Vec::with_capacity(8);
        let pad_len = loop {
            match read_varint(&padb) {
                Some((v, _)) => break v as usize,
                None => {
                    let mut b = [0u8; 1];
                    if recv.read_exact(&mut b).await.is_err() {
                        break 0;
                    }
                    padb.push(b[0]);
                    if padb.len() > 8 {
                        break 0;
                    }
                }
            }
        };
        if pad_len > 0 {
            let mut skip = vec![0u8; pad_len];
            let _ = recv.read_exact(&mut skip).await;
        }
        let sess = Session::new_tcp(self.tag.clone(), None, dst.clone());
        let direct =
            crate::direct::DirectOutbound::new(Arc::new(vp_dns::Resolver::system()), false);
        match direct.connect_stream(&sess, &dst).await {
            Ok(remote) => {
                // TCPResponse: [0x00][varint 0][varint 0]
                let _ = send.write_all(&[0x00, 0x00, 0x00]).await;
                let client: Box<dyn ProxyStream> = Box::new(QuicBiStream { send, recv });
                let meta = vp_core::ConnMeta {
                    id: sess.id,
                    inbound: sess.inbound.clone(),
                    network: "tcp",
                    host: dst.host.to_string(),
                    dst_port: dst.port,
                    src: None,
                    process: None,
                    rule: None,
                    chain: Some("hy2-server".into()),
                    start: vp_common::now_millis(),
                };
                let hook = RelayHook {
                    table: Some(ctx.conns.clone()),
                    meta: Some(meta),
                    stats: Some(ctx.stats.clone()),
                };
                let _ = relay(client, remote, hook).await;
            }
            Err(_) => {
                let _ = send.reset(quinn::VarInt::from_u32(0x8));
            }
        }
    }
}

struct Hy2Packet {
    session: u32,
    src: SocketAddr,
    payload: Bytes,
}

fn parse_udp_message(dg: &[u8]) -> Option<Hy2Packet> {
    if dg.len() < 10 {
        return None;
    }
    let session = u32::from_be_bytes([dg[0], dg[1], dg[2], dg[3]]);
    let _pkt = u16::from_be_bytes([dg[4], dg[5]]);
    if dg[7] != 1 {
        return None;
    }
    let (alen, used) = read_varint(&dg[8..])?;
    let start = 8 + used;
    let end = start + alen as usize;
    if dg.len() < end {
        return None;
    }
    let src = std::str::from_utf8(&dg[start..end]).ok()?.parse().ok()?;
    Some(Hy2Packet {
        session,
        src,
        payload: Bytes::copy_from_slice(&dg[end..]),
    })
}

/// 从流读出完整 HEADERS 帧（buf 含已读前缀）
async fn read_h3_headers(
    recv: &mut quinn::RecvStream,
    buf: &mut Vec<u8>,
) -> Result<Vec<(String, String)>> {
    loop {
        if let Some((ty, payload, _)) = crate::h3_min::parse_frame(buf) {
            if ty != crate::h3_min::FRAME_HEADERS {
                return Err(Error::ProtoMsg(format!("h3min: 期望 HEADERS（{ty}）")));
            }
            return crate::h3_min::decode_header_block(&payload);
        }
        let mut chunk = [0u8; 1024];
        let n = recv
            .read(&mut chunk)
            .await
            .map_err(|e| Error::Io(std::io::Error::other(format!("{e:?}"))))?
            .unwrap_or(0);
        if n == 0 {
            return Err(Error::Proto("h3min: 流中断"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 16 * 1024 {
            return Err(Error::Proto("h3min: 头过大"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for v in [
            0u64,
            1,
            63,
            64,
            0x3fff,
            0x4000,
            0x401,
            u32::MAX as u64,
            0x3fff_ffff_ffff,
        ] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            let (got, used) = read_varint(&buf).unwrap();
            assert_eq!(got, v);
            assert_eq!(used, buf.len());
        }
    }

    #[test]
    fn tcp_request_frame_layout() {
        // [varint 0x401][varint |addr|][addr][varint 0]
        let addr = "example.com:443";
        let mut req = Vec::new();
        write_varint(&mut req, TCP_REQUEST_ID);
        write_varint(&mut req, addr.len() as u64);
        req.extend_from_slice(addr.as_bytes());
        write_varint(&mut req, 0);
        // 0x401 → 2 字节 varint：01 前缀 + 14bit → 0x4401
        assert_eq!(&req[..2], &[0x44, 0x01]);
        // 回读
        let (id, used) = read_varint(&req).unwrap();
        assert_eq!(id, TCP_REQUEST_ID);
        let (alen, used2) = read_varint(&req[used..]).unwrap();
        assert_eq!(alen as usize, addr.len());
        assert_eq!(
            std::str::from_utf8(&req[used + used2..used + used2 + alen as usize]).unwrap(),
            addr
        );
    }

    /// hysteria2 出入站自环：认证 → TCP → UDP（全链路走 h3_min 认证层）
    #[tokio::test]
    async fn hysteria2_loopback() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // echo 源站（TCP + UDP）
        let tcp_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tcp_l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = tcp_l.accept().await.unwrap();
            let mut b = [0u8; 1024];
            loop {
                let n = s.read(&mut b).await.unwrap();
                if n == 0 {
                    break;
                }
                s.write_all(&b[..n]).await.unwrap();
            }
        });
        let udp = std::sync::Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let udp_addr = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            loop {
                let Ok((n, from)) = udp.recv_from(&mut b).await else {
                    break;
                };
                let mut r = b"echo:".to_vec();
                r.extend_from_slice(&b[..n]);
                let _ = udp.send_to(&r, from).await;
            }
        });

        // hy2 服务端（自签）
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let ctx = InboundCtx {
            router: Arc::new(crate::test_support::NoopRouter()),
            stats: Arc::new(vp_common::Stats::default()),
            conns: Arc::new(vp_core::ConnTable::new()),
        };
        let server = Hysteria2Inbound::new(
            "127.0.0.1",
            0,
            "hy2-srv",
            "s3cret",
            cert.cert.pem().into_bytes(),
            cert.key_pair.serialize_pem().into_bytes(),
        );
        let port = Arc::new(server).start(ctx).await.unwrap();

        let out = Hysteria2Outbound::new(&vp_config::Hysteria2Cfg {
            server: "127.0.0.1".into(),
            port,
            password: "s3cret".into(),
            sni: None,
            skip_cert_verify: true,
            up: None,
            down: None,
        })
        .unwrap();

        // TCP
        let dst = DstAddr::ip("127.0.0.1".parse().unwrap(), tcp_port);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = out.connect_stream(&sess, &dst).await.unwrap();
        s.write_all(b"ping-hy2").await.unwrap();
        let mut buf = [0u8; 8];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-hy2");

        // UDP
        let dst = DstAddr::ip(udp_addr.ip(), udp_addr.port());
        let sess = Session::new_udp("t".into(), None, dst.clone());
        let mut conn = out.connect_packet(&sess, &dst).await.unwrap();
        conn.send(&UdpPacket {
            src: "127.0.0.1:0".parse().unwrap(),
            dst: udp_addr,
            data: b"hy2-udp".to_vec().into(),
        })
        .await
        .unwrap();
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), conn.recv())
            .await
            .expect("udp 超时")
            .unwrap();
        assert_eq!(&resp.data[..], b"echo:hy2-udp");

        // 错误密码 → 认证失败
        let bad = Hysteria2Outbound::new(&vp_config::Hysteria2Cfg {
            server: "127.0.0.1".into(),
            port,
            password: "wrong".into(),
            sni: None,
            skip_cert_verify: true,
            up: None,
            down: None,
        })
        .unwrap();
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        assert!(bad.connect_stream(&sess, &dst).await.is_err());
    }

    #[test]
    fn udp_message_layout() {
        // [u32 session][u16 pkt][u8 frag][u8 total][varint |addr|][addr][payload]
        let addr = "8.8.8.8:53";
        let mut msg = Vec::new();
        msg.extend_from_slice(&0xdead_beefu32.to_be_bytes());
        msg.extend_from_slice(&7u16.to_be_bytes());
        msg.push(0);
        msg.push(1);
        write_varint(&mut msg, addr.len() as u64);
        msg.extend_from_slice(addr.as_bytes());
        msg.extend_from_slice(b"");
        // 解析（与 Hy2UdpConn::recv 相同布局）
        assert_eq!(
            u32::from_be_bytes([msg[0], msg[1], msg[2], msg[3]]),
            0xdead_beef
        );
        let (alen, used) = read_varint(&msg[8..]).unwrap();
        assert_eq!(
            std::str::from_utf8(&msg[8 + used..8 + used + alen as usize]).unwrap(),
            addr
        );
        assert_eq!(&msg[8 + used + alen as usize..], b"");
    }
}

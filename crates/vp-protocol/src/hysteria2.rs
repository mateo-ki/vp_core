//! Hysteria2 协议（QUIC + HTTP/3 认证 + QUIC varint 帧）。
//!
//! - 认证：HTTP/3 `POST /auth`，`Hysteria-Auth` 头携带密码，响应状态码 233
//! - TCP：每连接一条 QUIC 双向流，首包 `[varint 0x401][varint |addr|]["host:port"][varint |pad|]`
//!   服务端 TCPResponse `[u8 status][varint |msg|][msg]`
//! - UDP：QUIC unreliable datagram，UDPMessage
//!   `[u32 BE session][u16 BE pkt][u8 frag][u8 frag_total][varint |addr|][addr][payload]`

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use vp_common::{DstAddr, Error, Result};
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;
use vp_core::tunnel::{relay, RelayHook};
use vp_core::{Inbound, Outbound, PacketConn, ProxyStream, UdpPacket};

const TCP_REQUEST_ID: u64 = 0x401;

// ---------------------------------------------------------------------------
// QUIC varint
// ---------------------------------------------------------------------------

fn write_varint(out: &mut Vec<u8>, v: u64) {
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

fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
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
    up_mbps: u32,
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
            up_mbps: 0,
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

    /// HTTP/3 认证
    async fn auth(&self, conn: &quinn::Connection) -> Result<()> {
        let h3conn = h3_quinn::Connection::new(conn.clone());
        let (mut driver, mut send_req) = h3::client::new(h3conn)
            .await
            .map_err(|e| Error::ProtoMsg(format!("hy2 h3 握手: {e}")))?;
        let _ = &mut driver;
        // 单连接单次认证：驱动任务随连接关闭结束
        tokio::spawn(async move {
            let _ = driver.shutdown(0).await;
        });
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("/auth")
            .version(http::Version::HTTP_3)
            .header("host", "hysteria")
            .header("hysteria-auth", &self.password)
            .header("hysteria-cc-rx", self.up_mbps.to_string())
            .header("hysteria-padding", "0".repeat(16))
            .body(())
            .map_err(|e| Error::ProtoMsg(format!("hy2 auth 请求: {e}")))?;
        let mut stream = send_req
            .send_request(req)
            .await
            .map_err(|e| Error::ProtoMsg(format!("hy2 auth 发送: {e}")))?;
        stream
            .finish()
            .await
            .map_err(|e| Error::ProtoMsg(format!("hy2 auth 结束流: {e}")))?;
        let resp = match stream.recv_response().await {
            Ok(r) => r,
            Err(e) => return Err(Error::ProtoMsg(format!("hy2 auth 响应: {e}"))),
        };
        if resp.status().as_u16() != 233 {
            return Err(Error::ProtoMsg(format!(
                "hy2 认证失败（状态 {}）",
                resp.status()
            )));
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
        // TCPResponse: [u8 status][varint len][msg][varint pad]
        let mut head = [0u8; 2];
        recv.read_exact(&mut head)
            .await
            .map_err(|e| Error::Io(std::io::Error::other(format!("hy2 读响应: {e}"))))?;
        if head[0] != 0x00 {
            return Err(Error::ProtoMsg("hy2 TCPResponse 错误".into()));
        }
        let (msg_len, used) = read_varint(&head[1..]).ok_or(Error::Proto("hy2 varint"))?;
        let mut rest = vec![0u8; (msg_len as usize).saturating_sub(head.len() - 1 - used) + 4];
        // 简化：小消息直接吞掉（msg+pad）
        if msg_len > 0 {
            let mut skip = vec![0u8; msg_len as usize];
            recv.read_exact(&mut skip)
                .await
                .map_err(|e| Error::Io(std::io::Error::other(format!("hy2 跳过消息: {e}"))))?;
        }
        let _ = rest;
        Ok(Box::new(QuicBiStream { send, recv }))
    }

    fn support_udp(&self) -> bool {
        true
    }

    async fn connect_packet(&self, _sess: &Session, _dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        let (conn, _ep) = self.connect_quic().await?;
        self.auth(&conn).await?;
        let session = self.udp_session.fetch_add(1, Ordering::Relaxed);
        Ok(Box::new(Hy2UdpConn { conn, session, pkt_id: 1 }))
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
}

/// QUIC 双向流包装（与 vp_transport::quic::QuicStream 同构，供本模块使用）
pub struct QuicBiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
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
            let dgram = self
                .conn
                .read_datagram()
                .await
                .map_err(|e| Error::Io(std::io::Error::other(format!("hy2 read_datagram: {e}"))))?;
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
            let Some((alen, used)) = read_varint(&dgram[8..]) else { continue };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for v in [0u64, 1, 63, 64, 0x3fff, 0x4000, 0x401, u32::MAX as u64, 0x3fff_ffff_ffff] {
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
        assert_eq!(u32::from_be_bytes([msg[0], msg[1], msg[2], msg[3]]), 0xdead_beef);
        let (alen, used) = read_varint(&msg[8..]).unwrap();
        assert_eq!(
            std::str::from_utf8(&msg[8 + used..8 + used + alen as usize]).unwrap(),
            addr
        );
        assert_eq!(&msg[8 + used + alen as usize..], b"");
    }
}

//! SOCKS5 与 Shadowsocks 的 UDP 出站（PacketConn 实现）。

use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

use vp_common::addr::{decode_socks_addr, encode_socks_addr};
use vp_common::{DstAddr, Error, Result};
use vp_core::stream::{PacketConn, UdpPacket};

// ---------------------------------------------------------------------------
// SOCKS5 UDP
// ---------------------------------------------------------------------------

/// SOCKS5 UDP ASSOCIATE 客户端：
/// 控制连接保持存活；数据经中继地址以 socks-udp 报文收发。
pub struct Socks5PacketConn {
    /// 控制连接（drop 即结束关联）
    _ctrl: TcpStream,
    relay: Arc<UdpSocket>,
}

pub async fn socks5_udp_connect(
    server: &str,
    port: u16,
    username: &Option<String>,
    password: &Option<String>,
) -> Result<Socks5PacketConn> {
    let mut ctrl = TcpStream::connect((server, port)).await?;
    vp_transport::tune(&ctrl);
    // 握手（同 TCP 流程，目标为 0.0.0.0:0）
    let has_auth = username.is_some();
    if has_auth {
        ctrl.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        ctrl.write_all(&[0x05, 0x01, 0x00]).await?;
    }
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut b = [0u8; 2];
    ctrl.read_exact(&mut b).await?;
    if b[1] == 0x02 {
        let u = username.as_deref().unwrap_or("");
        let p = password.as_deref().unwrap_or("");
        let mut auth = vec![0x01, u.len() as u8];
        auth.extend_from_slice(u.as_bytes());
        auth.push(p.len() as u8);
        auth.extend_from_slice(p.as_bytes());
        ctrl.write_all(&auth).await?;
        let mut r = [0u8; 2];
        ctrl.read_exact(&mut r).await?;
        if r[1] != 0x00 {
            return Err(Error::Proto("socks5 udp: 认证失败"));
        }
    } else if b[1] != 0x00 {
        return Err(Error::Proto("socks5 udp: 认证方式不支持"));
    }
    // UDP ASSOCIATE 0.0.0.0:0
    let mut req = vec![0x05, 0x03, 0x00];
    encode_socks_addr(&DstAddr::ip([0, 0, 0, 0].into(), 0), &mut req);
    ctrl.write_all(&req).await?;
    let mut head = [0u8; 4];
    ctrl.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        return Err(Error::ProtoMsg(format!("socks5 udp: 关联失败 rep={}", head[1])));
    }
    let skip = match head[3] {
        0x01 => 6,
        0x03 => {
            let mut l = [0u8; 1];
            ctrl.read_exact(&mut l).await?;
            l[0] as usize + 2
        }
        0x04 => 18,
        _ => return Err(Error::Proto("socks5 udp: atyp 非法")),
    };
    let mut rest = vec![0u8; skip];
    ctrl.read_exact(&mut rest).await?;
    // rest = [addr][port]（无 atyp）；重组为完整 socks 地址再解码
    let mut full = vec![head[3]];
    full.extend_from_slice(&rest);
    let mut bound = decode_socks_addr(&full).map(|(d, _)| d)?;
    if matches!(bound.host, vp_common::Host::Ip(ip) if ip.is_unspecified()) {
        bound.host = vp_common::Host::Domain(server.to_string());
    }
    let bind: std::net::SocketAddr = match &bound.host {
        vp_common::Host::Ip(ip) => std::net::SocketAddr::new(*ip, bound.port),
        vp_common::Host::Domain(d) => {
            // 域名：解析（回环场景直接使用）
            match d.parse() {
                Ok(ip) => std::net::SocketAddr::new(ip, bound.port),
                Err(_) => std::net::SocketAddr::new([127, 0, 0, 1].into(), bound.port),
            }
        }
    };
    let relay = UdpSocket::bind("0.0.0.0:0").await?;
    relay.connect(bind).await?;
    Ok(Socks5PacketConn { _ctrl: ctrl, relay: Arc::new(relay) })
}

#[async_trait]
impl PacketConn for Socks5PacketConn {
    async fn send(&self, pkt: &UdpPacket) -> Result<()> {
        let mut dgram = vec![0x00, 0x00, 0x00]; // rsv rsv frag
        encode_socks_addr(
            &DstAddr {
                host: match pkt.dst.ip() {
                    std::net::IpAddr::V4(v4) => vp_common::Host::Ip(std::net::IpAddr::V4(v4)),
                    std::net::IpAddr::V6(v6) => vp_common::Host::Ip(std::net::IpAddr::V6(v6)),
                },
                port: pkt.dst.port(),
            },
            &mut dgram,
        );
        dgram.extend_from_slice(&pkt.data);
        self.relay.send(&dgram).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<UdpPacket> {
        let mut buf = vec![0u8; 65535];
        loop {
            let n = self.relay.recv(&mut buf).await?;
            tracing::debug!("socks5 udp 出站收到 {n}B");
            if n < 4 || buf[2] != 0 {
                continue;
            }
            let Ok((src, used)) = decode_socks_addr(&buf[3..n]) else { continue };
            return Ok(UdpPacket {
                src: std::net::SocketAddr::new(
                    match &src.host {
                        vp_common::Host::Ip(ip) => *ip,
                        vp_common::Host::Domain(_) => [0, 0, 0, 0].into(),
                    },
                    src.port,
                ),
                dst: self.relay.local_addr()?,
                data: buf[3 + used..n].to_vec().into(),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Shadowsocks UDP（每包独立 salt）
// ---------------------------------------------------------------------------

pub struct SsUdpConn {
    sock: Arc<UdpSocket>,
    cipher: vp_crypto::ss::Cipher,
    key: Vec<u8>,
    server: std::net::SocketAddr,
    recv_state: Mutex<()>,
}

impl SsUdpConn {
    pub async fn bind(
        server_host: &str,
        server_port: u16,
        cipher: vp_crypto::ss::Cipher,
        key: Vec<u8>,
    ) -> Result<Self> {
        let server = tokio::net::lookup_host((server_host, server_port))
            .await
            .map_err(|e| Error::Addr(format!("解析 {server_host} 失败: {e}")))?
            .next()
            .ok_or(Error::Addr("无地址".into()))?;
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        Ok(SsUdpConn {
            sock: Arc::new(sock),
            cipher,
            key,
            server,
            recv_state: Mutex::new(()),
        })
    }
}

#[async_trait]
impl PacketConn for SsUdpConn {
    async fn send(&self, pkt: &UdpPacket) -> Result<()> {
        // 明文：[socks addr][payload]，整体一个分块；独立 salt
        let mut plain = Vec::with_capacity(pkt.data.len() + 24);
        encode_socks_addr(
            &DstAddr {
                host: vp_common::Host::Ip(pkt.dst.ip()),
                port: pkt.dst.port(),
            },
            &mut plain,
        );
        plain.extend_from_slice(&pkt.data);

        let mut salt = vec![0u8; self.cipher.salt_len()];
        vp_common::rand_bytes(&mut salt);
        let sub = self.cipher.subkey(&self.key, &salt)?;
        let mut codec = vp_crypto::ss::AeadChunkCodec::new(&self.cipher, &sub)?;
        let chunk = codec.seal_chunk(&plain);

        let mut dgram = salt;
        dgram.extend_from_slice(&chunk);
        self.sock.send_to(&dgram, self.server).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<UdpPacket> {
        let _guard = self.recv_state.lock().await;
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, _) = self.sock.recv_from(&mut buf).await?;
            let salt_len = self.cipher.salt_len();
            if n <= salt_len {
                continue;
            }
            let salt = buf[..salt_len].to_vec();
            let sub = match self.cipher.subkey(&self.key, &salt) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let mut codec = match vp_crypto::ss::AeadChunkCodec::new(&self.cipher, &sub) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let Some(Ok((plain, _))) = codec.try_open_chunk(&buf[salt_len..n]) else {
                continue;
            };
            let Ok((src, used)) = decode_socks_addr(&plain) else { continue };
            return Ok(UdpPacket {
                src: std::net::SocketAddr::new(
                    match &src.host {
                        vp_common::Host::Ip(ip) => *ip,
                        vp_common::Host::Domain(_) => [0, 0, 0, 0].into(),
                    },
                    src.port,
                ),
                dst: self.sock.local_addr()?,
                data: plain[used..].to_vec().into(),
            });
        }
    }
}

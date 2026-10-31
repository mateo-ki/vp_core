//! UDP over TCP（UoT v1）—— 与 Clash.Meta/mihomo/sing-box 互通。
//!
//! 客户端经代理发起一条到魔法地址 `sp.udp-over-tcp.arpa` 的 TCP 流，
//! 随后每一帧自带目标地址（v1 每帧寻址，天然多目标）：
//!
//! ```text
//! [ATYP][addr][port u16be][len u16be][data]
//! ```
//!
//! ATYP 为 UoT 非标准取值：0x00=IPv4、0x01=IPv6、0x02=域名。
//!
//! - 出站侧：`UotOutbound` 包装任意流型出站（vmess/vless/trojan/ss…），
//!   配置 `udp-over-tcp: true` 时其 PacketConn 建立在该魔法流上。
//! - 入站侧：分发层识别魔法地址后进入 `serve_client`，把帧解包为
//!   UDP 数据报按目标路由，回包以帧写回（地址为数据报源地址）。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use vp_common::{DstAddr, Error, Host, Result};
use vp_core::Outbound;
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;
use vp_core::stream::{PacketConn, ProxyStream, UdpPacket};

pub const MAGIC_HOST_V1: &str = "sp.udp-over-tcp.arpa";
pub const MAGIC_HOST_V2: &str = "sp.v2.udp-over-tcp.arpa";

/// UoT v1 魔法目标（端口任意，惯例 443）
pub fn magic_dst() -> DstAddr {
    DstAddr::new(MAGIC_HOST_V1, 443)
}

/// 是否 UoT 魔法地址（v1 服务端中继；v2 帧格式不同，明确拒绝）
pub fn is_magic(dst: &DstAddr) -> bool {
    matches!(&dst.host, Host::Domain(d) if d == MAGIC_HOST_V1 || d == MAGIC_HOST_V2)
}

const ATYP_V4: u8 = 0x00;
const ATYP_V6: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;

// ---------------------------------------------------------------------------
// 帧编解码
// ---------------------------------------------------------------------------

fn encode_addr(dst: &DstAddr, out: &mut Vec<u8>) {
    match &dst.host {
        Host::Ip(IpAddr::V4(v4)) => {
            out.push(ATYP_V4);
            out.extend_from_slice(&v4.octets());
        }
        Host::Ip(IpAddr::V6(v6)) => {
            out.push(ATYP_V6);
            out.extend_from_slice(&v6.octets());
        }
        Host::Domain(d) => {
            out.push(ATYP_DOMAIN);
            out.push(d.len() as u8);
            out.extend_from_slice(d.as_bytes());
        }
    }
    out.extend_from_slice(&dst.port.to_be_bytes());
}

/// 编码一帧：地址 + 长度 + 数据
pub fn encode_frame(addr: &DstAddr, data: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(data.len() + 28);
    encode_addr(addr, &mut f);
    f.extend_from_slice(&(data.len() as u16).to_be_bytes());
    f.extend_from_slice(data);
    f
}

async fn read_n<R: AsyncRead + Unpin>(r: &mut R, n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await.map_err(Error::Io)?;
    Ok(buf)
}

/// 读一帧：返回 (地址, 数据)
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<(DstAddr, Bytes)> {
    let atyp = read_n(r, 1).await?[0];
    let (host, port) = match atyp {
        ATYP_V4 => {
            let b = read_n(r, 6).await?;
            let oct: [u8; 4] = b[0..4].try_into().unwrap();
            (
                Host::Ip(IpAddr::V4(oct.into())),
                u16::from_be_bytes([b[4], b[5]]),
            )
        }
        ATYP_V6 => {
            let b = read_n(r, 18).await?;
            let oct: [u8; 16] = b[0..16].try_into().unwrap();
            (
                Host::Ip(IpAddr::V6(oct.into())),
                u16::from_be_bytes([b[16], b[17]]),
            )
        }
        ATYP_DOMAIN => {
            let n = read_n(r, 1).await?[0] as usize;
            if n == 0 {
                return Err(Error::Proto("uot: 空域名"));
            }
            let b = read_n(r, n + 2).await?;
            (
                Host::Domain(String::from_utf8_lossy(&b[..n]).into_owned()),
                u16::from_be_bytes([b[n], b[n + 1]]),
            )
        }
        a => return Err(Error::ProtoMsg(format!("uot: 非法 ATYP {a:#04x}"))),
    };
    let len = u16::from_be_bytes(read_n(r, 2).await?.try_into().unwrap()) as usize;
    let data = read_n(r, len).await?;
    Ok((DstAddr { host, port }, Bytes::from(data)))
}

fn dst_to_socket(dst: &DstAddr) -> Result<SocketAddr> {
    match &dst.host {
        Host::Ip(ip) => Ok(SocketAddr::new(*ip, dst.port)),
        Host::Domain(_) => Ok(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            dst.port,
        )),
    }
}

async fn resolve_dst_socket(dst: &DstAddr) -> Result<SocketAddr> {
    match &dst.host {
        Host::Ip(ip) => Ok(SocketAddr::new(*ip, dst.port)),
        Host::Domain(d) => {
            if let Some((resolver, ipv6)) = vp_transport::global_node_resolver() {
                if let Ok(ips) = resolver.resolve_domain(d, ipv6).await {
                    if let Some(ip) = ips.first() {
                        return Ok(SocketAddr::new(*ip, dst.port));
                    }
                }
            }
            if let Ok(mut it) = tokio::net::lookup_host((d.as_str(), dst.port)).await {
                if let Some(addr) = it.next() {
                    return Ok(addr);
                }
            }
            Ok(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                dst.port,
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// 客户端（出站包装层）
// ---------------------------------------------------------------------------

/// UoT 客户端 PacketConn：代理流上的数据报通道（v1 每帧自带地址，天然多目标）
pub struct UotClientConn<S> {
    stream: Mutex<S>,
    default_dst: SocketAddr,
}

impl<S: ProxyStream> UotClientConn<S> {
    pub fn new(stream: S, default_dst: SocketAddr) -> Self {
        UotClientConn {
            stream: Mutex::new(stream),
            default_dst,
        }
    }
}

#[async_trait::async_trait]
impl<S: ProxyStream> PacketConn for UotClientConn<S> {
    async fn send(&self, pkt: &UdpPacket) -> Result<()> {
        let dst = DstAddr {
            host: Host::Ip(pkt.dst.ip()),
            port: pkt.dst.port(),
        };
        let frame = encode_frame(&dst, &pkt.data);
        self.stream
            .lock()
            .await
            .write_all(&frame)
            .await
            .map_err(Error::Io)
    }

    async fn recv(&mut self) -> Result<UdpPacket> {
        let mut s = self.stream.lock().await;
        let (src_addr, data) = read_frame(&mut *s).await?;
        drop(s);
        let src = dst_to_socket(&src_addr).unwrap_or_else(|_| {
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), src_addr.port)
        });
        Ok(UdpPacket {
            src,
            dst: self.default_dst,
            data,
        })
    }
}

/// 出站包装层：为任意流型出站提供 UDP over TCP（配置 udp-over-tcp: true 时启用）
pub struct UotOutbound {
    inner: Arc<dyn Outbound>,
}

impl UotOutbound {
    pub fn new(inner: Arc<dyn Outbound>) -> Self {
        UotOutbound { inner }
    }
}

#[async_trait::async_trait]
impl Outbound for UotOutbound {
    fn name(&self) -> &str {
        self.inner.name()
    }

    async fn connect_stream(&self, sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        self.inner.connect_stream(sess, dst).await
    }

    async fn connect_over(
        &self,
        sess: &Session,
        dst: &DstAddr,
        underlying: Box<dyn ProxyStream>,
    ) -> Result<Box<dyn ProxyStream>> {
        self.inner.connect_over(sess, dst, underlying).await
    }

    fn support_udp(&self) -> bool {
        true
    }

    async fn connect_packet(&self, sess: &Session, dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        // 魔法地址流；回包 dst 用调用方目标（仅展示用，实际按帧源地址）
        let stream = self.inner.connect_stream(sess, &magic_dst()).await?;
        let default_dst = dst_to_socket(dst).unwrap_or_else(|_| {
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), dst.port)
        });
        Ok(Box::new(UotClientConn::new(stream, default_dst)))
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        self.inner.remote_addr()
    }
}

// ---------------------------------------------------------------------------
// 服务端（入站分发层）
// ---------------------------------------------------------------------------

/// 入站侧 UoT 中继：客户端流上的帧 → 按目标路由 → 出站 UDP；
/// 回包以帧（源地址）写回。流结束（EOF/错帧）即回收全部会话。
pub async fn serve_client(
    ctx: &InboundCtx,
    mut sess: Session,
    client: Box<dyn ProxyStream>,
) -> Result<()> {
    let (mut rd, wr) = tokio::io::split(client);
    let wr = Arc::new(Mutex::new(wr));
    // 目标 → 发送队列（会话存活标志）
    let mut sessions: HashMap<DstAddr, tokio::sync::mpsc::Sender<UdpPacket>> = HashMap::new();

    loop {
        let (dst, data) = match read_frame(&mut rd).await {
            Ok(x) => x,
            Err(_) => break, // EOF 或错帧：结束
        };
        let tx = match sessions.get(&dst) {
            Some(tx) => tx.clone(),
            None => {
                let tx = spawn_session(ctx, &mut sess, &dst, wr.clone()).await?;
                sessions.insert(dst.clone(), tx.clone());
                tx
            }
        };
        let dst_sock = resolve_dst_socket(&dst).await?;
        let _ = tx
            .send(UdpPacket {
                src: SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
                dst: dst_sock,
                data,
            })
            .await;
    }
    Ok(())
}

async fn spawn_session(
    ctx: &InboundCtx,
    sess: &mut Session,
    dst: &DstAddr,
    wr: Arc<Mutex<tokio::io::WriteHalf<Box<dyn ProxyStream>>>>,
) -> Result<tokio::sync::mpsc::Sender<UdpPacket>> {
    sess.dst = dst.clone();
    sess.network = vp_core::session::Network::Udp;
    let res = ctx.router.pick(sess).await;
    if !res.outbound.support_udp() {
        return Err(Error::Unsupported(format!(
            "uot: 出站 {} 不支持 UDP",
            res.outbound.name()
        )));
    }
    let mut conn = res.outbound.connect_packet(sess, dst).await?;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<UdpPacket>(64);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                // 出站 → 客户端（帧化，地址为数据报源地址）
                r = conn.recv() => {
                    match r {
                        Ok(pkt) => {
                            let frame = encode_frame(
                                &DstAddr {
                                    host: Host::Ip(pkt.src.ip()),
                                    port: pkt.src.port(),
                                },
                                &pkt.data,
                            );
                            if wr.lock().await.write_all(&frame).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                // 客户端 → 出站
                out = rx.recv() => {
                    match out {
                        Some(pkt) => {
                            if conn.send(&pkt).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    });
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dst4(a: [u8; 4], port: u16) -> DstAddr {
        DstAddr::ip(IpAddr::V4(a.into()), port)
    }

    #[tokio::test]
    async fn frame_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let frame = encode_frame(&dst4([10, 0, 0, 1], 5353), b"hello");
        a.write_all(&frame).await.unwrap();
        a.flush().await.unwrap();
        let (addr, data) = read_frame(&mut b).await.unwrap();
        assert_eq!(addr, dst4([10, 0, 0, 1], 5353));
        assert_eq!(&data[..], b"hello");
    }

    #[tokio::test]
    async fn frame_domain_roundtrip() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let frame = encode_frame(&DstAddr::new("dns.example.com", 53), b"q");
        let h = tokio::spawn(async move {
            client.write_all(&frame).await.unwrap();
        });
        let (addr, data) = read_frame(&mut server).await.unwrap();
        h.await.unwrap();
        assert_eq!(addr.host, Host::Domain("dns.example.com".into()));
        assert_eq!(addr.port, 53);
        assert_eq!(&data[..], b"q");
    }

    #[test]
    fn magic_detection() {
        assert!(is_magic(&DstAddr::new(MAGIC_HOST_V1, 443)));
        assert!(is_magic(&DstAddr::new(MAGIC_HOST_V2, 443)));
        assert!(!is_magic(&DstAddr::new("example.com", 443)));
        assert!(!is_magic(&dst4([1, 2, 3, 4], 443)));
    }

    #[test]
    fn frame_layout_v4() {
        // [0x00][10.0.0.1][5353][len][data]
        let f = encode_frame(&dst4([10, 0, 0, 1], 5353), b"ab");
        assert_eq!(
            f,
            vec![0x00, 10, 0, 0, 1, 0x14, 0xE9, 0x00, 0x02, b'a', b'b']
        );
    }
}

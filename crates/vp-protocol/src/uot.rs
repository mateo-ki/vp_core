//! UDP over TCP（UoT）—— 与 Clash.Meta/mihomo/sing-box 互通，v1 / v2 两个版本。
//!
//! 客户端经代理发起一条到魔法地址的 TCP 流，随后在流上收发数据报：
//!
//! - v1（`sp.udp-over-tcp.arpa`）：每帧自带地址 `[ATYP][addr][port u16be][len u16be][data]`
//! - v2（`sp.v2.udp-over-tcp.arpa`）：先发一次请求头 `[isConnect u8][SOCKS 地址]`；
//!   isConnect=0 时帧同 v1，isConnect=1（连接模式）时帧为 `[len u16be][data]`、目标恒为请求头地址
//!
//! 帧内 ATYP 为 UoT 非标准取值：0x00=IPv4、0x01=IPv6、0x02=域名；v2 请求头用标准 SOCKS 取值。
//!
//! - 出站侧：`UotOutbound` 包装任意流型出站；v2 一律用非连接模式（同 anytls-go）。
//! - 服务侧：[`serve_client`]。帧读写抽象为 [`PacketFraming`]，VLESS / Trojan / VMess 的原生 UDP
//!   复用同一套客户端（[`StreamPacketConn`]）与服务侧中继（[`serve_packets`]）。入站分发（socks5 / http / redir / tproxy）按路由逐目标转发；
//!   协议服务端监听器（ss / vless / trojan / anytls / naive …）经 DIRECT 拨号魔法地址时由
//!   DIRECT 在本地承接、直连收发（见 direct.rs）。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

use vp_common::{DstAddr, Error, Host, Result};
use vp_core::Outbound;
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;
use vp_core::stream::{PacketConn, ProxyStream, UdpPacket};

pub const MAGIC_HOST_V1: &str = "sp.udp-over-tcp.arpa";
pub const MAGIC_HOST_V2: &str = "sp.v2.udp-over-tcp.arpa";

/// UoT 魔法目标（端口任意，惯例 443）
pub fn magic_dst(version: u8) -> DstAddr {
    let host = if version >= 2 {
        MAGIC_HOST_V2
    } else {
        MAGIC_HOST_V1
    };
    DstAddr::new(host, 443)
}

/// 魔法地址对应的 UoT 版本；非魔法地址为 None
pub fn magic_version(dst: &DstAddr) -> Option<u8> {
    match &dst.host {
        Host::Domain(d) if d.eq_ignore_ascii_case(MAGIC_HOST_V1) => Some(1),
        Host::Domain(d) if d.eq_ignore_ascii_case(MAGIC_HOST_V2) => Some(2),
        _ => None,
    }
}

pub fn is_magic(dst: &DstAddr) -> bool {
    magic_version(dst).is_some()
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

/// 解析 buf 开头的 UoT 帧地址，返回 (地址, 地址之后的偏移)；数据不全时 Ok(None)
fn parse_uot_addr(buf: &[u8]) -> Result<Option<(DstAddr, usize)>> {
    let Some(&atyp) = buf.first() else {
        return Ok(None);
    };
    let (host, addr_len) = match atyp {
        ATYP_V4 => {
            let Some(b) = buf.get(1..5) else {
                return Ok(None);
            };
            let o: [u8; 4] = b.try_into().unwrap();
            (Host::Ip(IpAddr::V4(o.into())), 4)
        }
        ATYP_V6 => {
            let Some(b) = buf.get(1..17) else {
                return Ok(None);
            };
            let o: [u8; 16] = b.try_into().unwrap();
            (Host::Ip(IpAddr::V6(o.into())), 16)
        }
        ATYP_DOMAIN => {
            let Some(&n) = buf.get(1) else {
                return Ok(None);
            };
            if n == 0 {
                return Err(Error::Proto("uot: 空域名"));
            }
            let Some(b) = buf.get(2..2 + n as usize) else {
                return Ok(None);
            };
            (
                Host::Domain(String::from_utf8_lossy(b).into_owned()),
                1 + n as usize,
            )
        }
        a => return Err(Error::ProtoMsg(format!("uot: 非法 ATYP {a:#04x}"))),
    };
    let p = 1 + addr_len;
    let Some(b) = buf.get(p..p + 2) else {
        return Ok(None);
    };
    let port = u16::from_be_bytes([b[0], b[1]]);
    Ok(Some((DstAddr { host, port }, p + 2)))
}

/// packetaddr（v2ray 5+）魔法目标：VLESS / VMess UDP 请求发往它时，每个数据报自带 IP 目标
pub const PACKET_ADDR_MAGIC: &str = "sp.packet-addr.v2fly.arpa";

/// XUDP 请求在日志 / 会话里显示的目标（线上不携带地址）
pub fn xudp_dst() -> DstAddr {
    DstAddr::new("v1.mux.cool", 666)
}

/// VLESS / VMess 的 UDP 编码（mihomo 语义：packet-encoding 优先，其次 xudp / packet-addr
/// 布尔开关；都没配时为原始编码，每个目标一条连接）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpEncoding {
    Raw,
    /// Xray XUDP：一条连接承载多目标（full-cone），Mux.Cool 帧
    Xudp,
    /// v2ray packetaddr：一条连接承载多目标，目标只能是 IP
    PacketAddr,
}

impl UdpEncoding {
    pub fn from_cfg(packet_encoding: Option<&str>, xudp: bool, packet_addr: bool) -> Result<Self> {
        match packet_encoding.map(str::trim).unwrap_or_default() {
            "xudp" => Ok(UdpEncoding::Xudp),
            "packetaddr" | "packet" => Ok(UdpEncoding::PacketAddr),
            "" | "none" if xudp => Ok(UdpEncoding::Xudp),
            "" | "none" if packet_addr => Ok(UdpEncoding::PacketAddr),
            "" | "none" => Ok(UdpEncoding::Raw),
            other => Err(Error::Config(format!("未知的 packet-encoding: {other:?}"))),
        }
    }
}

/// 代理流上承载数据报的帧格式（UoT 与 VLESS / Trojan / VMess 原生 UDP 共用）
#[derive(Clone, Debug)]
pub enum PacketFraming {
    /// UoT v1 / v2 非连接模式：`[UoT 地址][len][data]`
    Uot,
    /// `[len][data]`，地址恒为给定目标：UoT v2 连接模式、VLESS 原始编码
    Len(DstAddr),
    /// Trojan：`[SOCKS 地址][len][CRLF][data]`
    Trojan,
    /// VMess：一个数据报占一个 body 分块。写方向由 VmessStream 按每次写入分块（这里不加长度）；
    /// 读方向由包模式的 VmessStream 给每个分块补上 `[len]`，因此按 Len 解析
    Vmess(DstAddr),
    /// packetaddr：外层同 Len（vmess = false）/ Vmess（vmess = true），载荷前加
    /// `[1=IPv4 / 2=IPv6][ip][port]`（不支持域名）
    PacketAddr { vmess: bool },
    /// XUDP：Mux.Cool 帧 `[metaLen][sid=0][status][opt][net=UDP][V2Ray 地址]` + `[len][data]`。
    /// 客户端首帧为 New、其后 Keep；服务端回包一律为带来源地址的 Keep。
    /// target：对端的 Keep 帧不带地址时的缺省目标（服务端为 None，这种帧丢弃）
    Xudp {
        new_pending: Arc<AtomicBool>,
        target: Option<DstAddr>,
    },
}

/// 一帧的解析结果
enum Frame {
    /// (地址, 数据起点, 帧终点)
    Packet(DstAddr, usize, usize),
    /// 不含数据报的控制帧（XUDP 保活等）：跳过前 n 字节
    Skip(usize),
}

/// buf[pos..] 处的 `[len u16be][data]`：(数据起点, 帧终点)；不全时 None
fn len_prefixed(buf: &[u8], pos: usize) -> Option<(usize, usize)> {
    let h = buf.get(pos..pos + 2)?;
    let start = pos + 2;
    let end = start + u16::from_be_bytes([h[0], h[1]]) as usize;
    (buf.len() >= end).then_some((start, end))
}

/// VMess 一个分块即一个数据报：空包会被对端当成流结束，超过单块上限（0x3FFF）会被
/// VmessStream 拆成多块、对端当成多个数据报——两者都只能丢弃
fn vmess_chunk(c: Vec<u8>) -> Option<Vec<u8>> {
    (!c.is_empty() && c.len() <= 0x3FFF).then_some(c)
}

/// packetaddr 载荷头 `[1=IPv4 / 2=IPv6][ip][port]`：(地址, 头长度)
fn parse_packet_addr(p: &[u8]) -> Result<(DstAddr, usize)> {
    match p.first() {
        Some(1) if p.len() >= 7 => {
            let ip = IpAddr::from([p[1], p[2], p[3], p[4]]);
            Ok((DstAddr::ip(ip, u16::from_be_bytes([p[5], p[6]])), 7))
        }
        Some(2) if p.len() >= 19 => {
            let o: [u8; 16] = p[1..17].try_into().unwrap();
            Ok((
                DstAddr::ip(IpAddr::from(o), u16::from_be_bytes([p[17], p[18]])),
                19,
            ))
        }
        _ => Err(Error::Proto("packetaddr: 地址非法")),
    }
}

/// 解析一个 XUDP（Mux.Cool）帧
fn parse_xudp(buf: &[u8], target: Option<&DstAddr>) -> Result<Option<Frame>> {
    let Some(h) = buf.get(..2) else {
        return Ok(None);
    };
    let l = u16::from_be_bytes([h[0], h[1]]) as usize;
    if l < 4 {
        return Err(Error::Proto("xudp: 帧头过短"));
    }
    let Some(meta) = buf.get(2..2 + l) else {
        return Ok(None);
    };
    let (status, opt) = (meta[2], meta[3]);
    let mut end = 2 + l;
    let data = if opt & 0x01 != 0 {
        let Some(r) = len_prefixed(buf, end) else {
            return Ok(None);
        };
        end = r.1;
        Some(r)
    } else {
        None
    };
    if opt & 0x02 != 0 {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "xudp: 对端报错关闭",
        )));
    }
    match status {
        // New / Keep：带 UDP 网络字节时紧跟目标地址（其后可能有 8 字节 GlobalID，忽略）
        0x01 | 0x02 => {
            let addr = if l > 4 && meta[4] == 0x02 {
                Some(vp_common::addr::decode_v2ray_addr(&meta[5..])?.0)
            } else if status == 0x01 {
                return Err(Error::Unsupported(
                    "Mux.Cool TCP 子连接未实现（仅支持 XUDP）".into(),
                ));
            } else {
                // ponytail: 服务端收到不带地址的 Keep 帧直接丢弃；Xray / sing-box 客户端的
                // UDP 帧总带地址，需要兼容别的实现时再记下 New 帧的目标
                target.cloned()
            };
            Ok(Some(match (addr, data) {
                (Some(a), Some((s, e))) => Frame::Packet(a, s, e),
                _ => Frame::Skip(end),
            }))
        }
        0x03 => Err(Error::Io(std::io::ErrorKind::UnexpectedEof.into())),
        0x04 => Ok(Some(Frame::Skip(end))),
        s => Err(Error::ProtoMsg(format!("xudp: 未知帧类型 {s}"))),
    }
}

impl PacketFraming {
    pub fn xudp_client(target: &DstAddr) -> Self {
        PacketFraming::Xudp {
            new_pending: Arc::new(AtomicBool::new(true)),
            target: Some(target.clone()),
        }
    }

    pub fn xudp_server() -> Self {
        PacketFraming::Xudp {
            new_pending: Arc::new(AtomicBool::new(false)),
            target: None,
        }
    }

    /// 编码一个数据报；addr 只有自带地址的格式才用。
    /// None = 该格式承载不了这个数据报，只能丢弃（见 vmess_chunk；packetaddr 不能带域名）
    pub fn encode(&self, addr: &DstAddr, data: &[u8]) -> Option<Vec<u8>> {
        let mut f = Vec::with_capacity(data.len() + 32);
        match self {
            PacketFraming::Uot => return Some(encode_frame(addr, data)),
            PacketFraming::Vmess(_) => return vmess_chunk(data.to_vec()),
            PacketFraming::Len(_) => {}
            PacketFraming::Trojan => {
                vp_common::addr::encode_socks_addr(addr, &mut f);
                f.extend_from_slice(&(data.len() as u16).to_be_bytes());
                f.extend_from_slice(b"\r\n");
                f.extend_from_slice(data);
                return Some(f);
            }
            PacketFraming::PacketAddr { vmess } => {
                let mut inner = Vec::with_capacity(data.len() + 19);
                match &addr.host {
                    Host::Ip(IpAddr::V4(v4)) => {
                        inner.push(1);
                        inner.extend_from_slice(&v4.octets());
                    }
                    Host::Ip(IpAddr::V6(v6)) => {
                        inner.push(2);
                        inner.extend_from_slice(&v6.octets());
                    }
                    Host::Domain(_) => return None,
                }
                inner.extend_from_slice(&addr.port.to_be_bytes());
                inner.extend_from_slice(data);
                if *vmess {
                    return vmess_chunk(inner);
                }
                f.extend_from_slice(&(inner.len() as u16).to_be_bytes());
                f.extend_from_slice(&inner);
                return Some(f);
            }
            PacketFraming::Xudp { new_pending, .. } => {
                let new = new_pending.swap(false, Ordering::Relaxed);
                // [sid 0][New=1 / Keep=2][opt=Data][net=UDP][地址]
                let mut meta = vec![0, 0, if new { 0x01 } else { 0x02 }, 0x01, 0x02];
                vp_common::addr::encode_v2ray_addr(addr, &mut meta);
                f.extend_from_slice(&(meta.len() as u16).to_be_bytes());
                f.extend_from_slice(&meta);
            }
        }
        f.extend_from_slice(&(data.len() as u16).to_be_bytes());
        f.extend_from_slice(data);
        Some(f)
    }

    /// 从 buf 开头解析一帧；数据不全时 Ok(None)
    fn parse(&self, buf: &[u8]) -> Result<Option<Frame>> {
        let (addr, pos) = match self {
            PacketFraming::Uot => match parse_uot_addr(buf)? {
                Some(x) => x,
                None => return Ok(None),
            },
            PacketFraming::Len(dst) | PacketFraming::Vmess(dst) => (dst.clone(), 0),
            PacketFraming::Trojan => match vp_common::addr::decode_socks_addr(buf) {
                Ok(x) => x,
                Err(Error::Proto("address truncated")) => return Ok(None),
                Err(e) => return Err(e),
            },
            PacketFraming::PacketAddr { .. } => {
                let Some((start, end)) = len_prefixed(buf, 0) else {
                    return Ok(None);
                };
                let (addr, used) = parse_packet_addr(&buf[start..end])?;
                return Ok(Some(Frame::Packet(addr, start + used, end)));
            }
            PacketFraming::Xudp { target, .. } => return parse_xudp(buf, target.as_ref()),
        };
        if matches!(self, PacketFraming::Trojan) {
            let Some(crlf) = buf.get(pos + 2..pos + 4) else {
                return Ok(None);
            };
            if crlf != b"\r\n" {
                return Err(Error::Proto("trojan: UDP 包缺少 CRLF"));
            }
            let len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
            let (start, end) = (pos + 4, pos + 4 + len);
            return Ok((buf.len() >= end).then_some(Frame::Packet(addr, start, end)));
        }
        Ok(len_prefixed(buf, pos).map(|(start, end)| Frame::Packet(addr, start, end)))
    }
}

/// 缓冲帧读取。每个 await 点只有一次 read_buf（可取消、不丢字节），
/// 所以放进 select! 里被别的分支打断也不会丢掉读到一半的帧，后续帧不会错位。
pub struct FrameReader<R> {
    rd: R,
    buf: BytesMut,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub fn new(rd: R) -> Self {
        FrameReader {
            rd,
            buf: BytesMut::new(),
        }
    }

    async fn fill(&mut self) -> Result<()> {
        self.buf.reserve(4096);
        if self.rd.read_buf(&mut self.buf).await? == 0 {
            return Err(Error::Io(std::io::ErrorKind::UnexpectedEof.into()));
        }
        Ok(())
    }

    /// 读一帧：(地址, 数据)
    pub async fn next(&mut self, framing: &PacketFraming) -> Result<(DstAddr, Bytes)> {
        loop {
            match framing.parse(&self.buf)? {
                Some(Frame::Packet(addr, start, end)) => {
                    let data = self.buf.split_to(end).freeze().slice(start..);
                    return Ok((addr, data));
                }
                Some(Frame::Skip(n)) => self.buf.advance(n),
                None => self.fill().await?,
            }
        }
    }

    /// v2 请求头：(isConnect, 目标)
    async fn request(&mut self) -> Result<(bool, DstAddr)> {
        loop {
            if let Some(&flag) = self.buf.first() {
                match vp_common::addr::decode_socks_addr(&self.buf[1..]) {
                    Ok((dst, used)) => {
                        self.buf.advance(1 + used);
                        return Ok((flag == 1, dst));
                    }
                    Err(Error::Proto("address truncated")) => {}
                    Err(e) => return Err(e),
                }
            }
            self.fill().await?;
        }
    }
}

fn dst_to_socket(dst: &DstAddr) -> SocketAddr {
    match &dst.host {
        Host::Ip(ip) => SocketAddr::new(*ip, dst.port),
        Host::Domain(_) => SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), dst.port),
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

/// 代理流上的数据报通道（UoT、VLESS / Trojan / VMess 原生 UDP 共用，按 framing 分帧）。
/// 读写分半：recv 等数据时不占写锁，不会卡住 send。
pub struct StreamPacketConn<S> {
    /// Mutex 只为让本结构 Sync（send 经 &self 调用，ReadHalf<S> 在 S 非 Sync 时不 Sync）；
    /// recv 持 &mut self，经 get_mut 访问，从不加锁
    rd: Mutex<FrameReader<ReadHalf<S>>>,
    wr: Mutex<WriteHalf<S>>,
    /// connect_packet 的目标（可能是域名）
    target: DstAddr,
    framing: PacketFraming,
}

impl<S: ProxyStream> StreamPacketConn<S> {
    /// stream 为已完成协议握手（或懒握手）的代理流
    pub fn new(stream: S, dst: &DstAddr, framing: PacketFraming) -> Self {
        let (rd, wr) = tokio::io::split(stream);
        StreamPacketConn {
            rd: Mutex::new(FrameReader::new(rd)),
            wr: Mutex::new(wr),
            target: dst.clone(),
            framing,
        }
    }

    /// UoT：stream 为已连到魔法地址的代理流；version >= 2 时先写 v2 请求头（非连接模式）
    pub async fn uot(mut stream: S, dst: &DstAddr, version: u8) -> Result<Self> {
        if version >= 2 {
            let mut req = vec![0u8]; // isConnect = 0：帧自带地址
            vp_common::addr::encode_socks_addr(dst, &mut req);
            stream.write_all(&req).await?;
            stream.flush().await?;
        }
        Ok(Self::new(stream, dst, PacketFraming::Uot))
    }
}

#[async_trait::async_trait]
impl<S: ProxyStream> PacketConn for StreamPacketConn<S> {
    async fn send(&self, pkt: &UdpPacket) -> Result<()> {
        // 目标是域名时帧里写域名，由远端解析：TUN + Fake-IP 下 pkt.dst 是 198.18.x.x 这类
        // 只在本机有意义的地址，原样发给远端就是黑洞（同 hysteria2 的处理）。
        // pkt.dst 为占位（未指定 / 回环）时也用会话目标；但会话目标本身就是回环时，
        // 发往别的回环端口是真实的多目标（XUDP / packetaddr full-cone），不能替换
        let use_target = match &self.target.host {
            Host::Domain(_) => true,
            Host::Ip(t) => {
                pkt.dst.ip().is_unspecified() || (pkt.dst.ip().is_loopback() && !t.is_loopback())
            }
        };
        let mut dst = if use_target {
            self.target.clone()
        } else {
            DstAddr::ip(pkt.dst.ip(), pkt.dst.port())
        };
        // packetaddr 只能带 IP：域名目标先在本地解析
        if matches!(self.framing, PacketFraming::PacketAddr { .. })
            && matches!(dst.host, Host::Domain(_))
        {
            let s = resolve_dst_socket(&dst).await?;
            if s.ip().is_unspecified() {
                return Ok(());
            }
            dst = DstAddr::ip(s.ip(), s.port());
        }
        // 编码放在写锁内：XUDP 首帧必须是 New，并发 send 时不能让 Keep 帧抢先写出
        let mut w = self.wr.lock().await;
        let Some(frame) = self.framing.encode(&dst, &pkt.data) else {
            return Ok(()); // 承载不了：同 UDP 语义静默丢弃
        };
        w.write_all(&frame).await?;
        w.flush().await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<UdpPacket> {
        let (src, data) = self.rd.get_mut().next(&self.framing).await?;
        Ok(UdpPacket {
            src: dst_to_socket(&src),
            dst: dst_to_socket(&self.target),
            data,
        })
    }
}

/// 出站包装层：为任意流型出站提供 UDP over TCP
pub struct UotOutbound {
    inner: Arc<dyn Outbound>,
    version: u8,
}

impl UotOutbound {
    pub fn new(inner: Arc<dyn Outbound>, version: u8) -> Self {
        UotOutbound { inner, version }
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
        let stream = self
            .inner
            .connect_stream(sess, &magic_dst(self.version))
            .await?;
        Ok(Box::new(
            StreamPacketConn::uot(stream, dst, self.version).await?,
        ))
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        self.inner.remote_addr()
    }
}

// ---------------------------------------------------------------------------
// 服务侧
// ---------------------------------------------------------------------------

/// 服务侧数据报出站：入站分发按路由逐目标选择；协议服务端监听器固定直连
pub enum UdpEgress<'a> {
    Route(&'a InboundCtx),
    Fixed(Arc<dyn Outbound>),
}

type ClientWriter = Arc<Mutex<WriteHalf<Box<dyn ProxyStream>>>>;

/// 服务侧 UoT 中继：客户端流上的帧 → 出站 UDP；回包按帧写回。
/// sess.dst 为魔法地址（决定 v1 / v2）；流结束（EOF / 错帧）即回收全部会话。
pub async fn serve_client(
    egress: UdpEgress<'_>,
    sess: Session,
    client: Box<dyn ProxyStream>,
) -> Result<()> {
    let version = magic_version(&sess.dst).unwrap_or(1);
    let (rd, wr) = tokio::io::split(client);
    let mut rd = FrameReader::new(rd);
    // v2 先读请求头；连接模式下帧不带地址，目标恒为请求头里的地址
    let framing = if version >= 2 {
        match rd.request().await? {
            (true, dst) => PacketFraming::Len(dst),
            (false, _) => PacketFraming::Uot,
        }
    } else {
        PacketFraming::Uot
    };
    relay_packets(egress, sess, rd, wr, framing).await
}

/// 协议服务端（vless / trojan / vmess 入站）收到 UDP 请求：按该协议的帧格式中继
pub async fn serve_packets(
    egress: UdpEgress<'_>,
    sess: Session,
    client: Box<dyn ProxyStream>,
    framing: PacketFraming,
) -> Result<()> {
    let (rd, wr) = tokio::io::split(client);
    relay_packets(egress, sess, FrameReader::new(rd), wr, framing).await
}

async fn relay_packets(
    egress: UdpEgress<'_>,
    mut sess: Session,
    mut rd: FrameReader<ReadHalf<Box<dyn ProxyStream>>>,
    wr: WriteHalf<Box<dyn ProxyStream>>,
    framing: PacketFraming,
) -> Result<()> {
    let wr = Arc::new(Mutex::new(wr));
    // 目标 → 发送队列（会话存活标志）
    let mut sessions: HashMap<DstAddr, tokio::sync::mpsc::Sender<UdpPacket>> = HashMap::new();
    while let Ok((dst, data)) = rd.next(&framing).await {
        let tx = match sessions.get(&dst) {
            Some(tx) => tx.clone(),
            None => {
                // 单个目标建会话失败（解析失败 / 出站不支持 UDP）只丢这个包，不断开整条流
                match spawn_session(&egress, &mut sess, &dst, wr.clone(), framing.clone()).await {
                    Ok(tx) => {
                        sessions.insert(dst.clone(), tx.clone());
                        tx
                    }
                    Err(e) => {
                        tracing::debug!("udp 中继: 目标 {dst} 建立会话失败，丢弃数据报: {e}");
                        continue;
                    }
                }
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
    egress: &UdpEgress<'_>,
    sess: &mut Session,
    dst: &DstAddr,
    wr: ClientWriter,
    framing: PacketFraming,
) -> Result<tokio::sync::mpsc::Sender<UdpPacket>> {
    sess.dst = dst.clone();
    sess.network = vp_core::session::Network::Udp;
    let outbound = match egress {
        UdpEgress::Route(ctx) => ctx.router.pick(sess).await.outbound,
        UdpEgress::Fixed(o) => o.clone(),
    };
    if !outbound.support_udp() {
        return Err(Error::Unsupported(format!(
            "出站 {} 不支持 UDP",
            outbound.name()
        )));
    }
    let mut conn = outbound.connect_packet(sess, dst).await?;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<UdpPacket>(64);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                // 出站 → 客户端（按帧格式封装；自带地址的格式写上数据报源地址）
                r = conn.recv() => {
                    let Ok(pkt) = r else { break };
                    let src = DstAddr::ip(pkt.src.ip(), pkt.src.port());
                    let Some(frame) = framing.encode(&src, &pkt.data) else { continue };
                    let mut w = wr.lock().await;
                    if w.write_all(&frame).await.is_err() || w.flush().await.is_err() {
                        break;
                    }
                }
                // 客户端 → 出站
                out = rx.recv() => {
                    let Some(pkt) = out else { break };
                    if conn.send(&pkt).await.is_err() {
                        break;
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
        let (mut a, b) = tokio::io::duplex(1024);
        a.write_all(&encode_frame(&dst4([10, 0, 0, 1], 5353), b"hello"))
            .await
            .unwrap();
        a.write_all(&encode_frame(&DstAddr::new("dns.example.com", 53), b"q"))
            .await
            .unwrap();
        let mut r = FrameReader::new(b);
        let (addr, data) = r.next(&PacketFraming::Uot).await.unwrap();
        assert_eq!(addr, dst4([10, 0, 0, 1], 5353));
        assert_eq!(&data[..], b"hello");
        let (addr, data) = r.next(&PacketFraming::Uot).await.unwrap();
        assert_eq!(addr.host, Host::Domain("dns.example.com".into()));
        assert_eq!(addr.port, 53);
        assert_eq!(&data[..], b"q");
    }

    /// XUDP 线格式对齐 Xray xudp.go：首帧 New、其后 Keep，均带 UDP 网络字节与 V2Ray 地址
    #[test]
    fn xudp_frame_layout() {
        let to = dst4([8, 8, 8, 8], 53);
        let f = PacketFraming::xudp_client(&to);
        let first = f.encode(&to, b"q").unwrap();
        // [metaLen=12][sid 0 0][New][Data][UDP][port 53][atyp 1][8.8.8.8][len 1]["q"]
        assert_eq!(
            first,
            vec![0, 12, 0, 0, 1, 1, 2, 0, 53, 1, 8, 8, 8, 8, 0, 1, b'q']
        );
        let second = f.encode(&to, b"q").unwrap();
        assert_eq!(second[4], 0x02, "第二帧应为 Keep");
        // 服务端回的 Keep 帧解析出来源地址；保活帧被跳过
        let mut buf = vec![0, 4, 0, 0, 4, 0]; // KeepAlive，无数据
        buf.extend_from_slice(&second);
        assert!(matches!(
            PacketFraming::xudp_server().parse(&buf).unwrap(),
            Some(Frame::Skip(6))
        ));
        match PacketFraming::xudp_server().parse(&buf[6..]).unwrap() {
            Some(Frame::Packet(a, s, e)) => {
                assert_eq!(a, to);
                assert_eq!(&buf[6 + s..6 + e], b"q");
            }
            _ => panic!("应解析出数据帧"),
        }
        // End 帧 → EOF
        assert!(
            PacketFraming::xudp_server()
                .parse(&[0, 4, 0, 0, 3, 0])
                .is_err()
        );
    }

    #[test]
    fn udp_encoding_from_cfg_like_mihomo() {
        assert_eq!(
            UdpEncoding::from_cfg(None, false, false).unwrap(),
            UdpEncoding::Raw
        );
        assert_eq!(
            UdpEncoding::from_cfg(None, true, false).unwrap(),
            UdpEncoding::Xudp
        );
        assert_eq!(
            UdpEncoding::from_cfg(Some("packetaddr"), true, false).unwrap(),
            UdpEncoding::PacketAddr,
            "packet-encoding 优先于布尔开关"
        );
        assert!(UdpEncoding::from_cfg(Some("bogus"), false, false).is_err());
    }

    #[test]
    fn magic_detection() {
        assert_eq!(magic_version(&magic_dst(1)), Some(1));
        assert_eq!(magic_version(&magic_dst(2)), Some(2));
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

    /// 回归：recv 放在 select! 里被打断时，读到一半的帧不能丢（否则后续帧全部错位）
    #[tokio::test]
    async fn recv_is_cancel_safe_mid_frame() {
        let (near, mut far) = tokio::io::duplex(1024);
        let mut conn = StreamPacketConn::uot(near, &dst4([10, 0, 0, 1], 53), 1)
            .await
            .unwrap();
        let frame = encode_frame(&dst4([8, 8, 8, 8], 53), b"0123456789");
        far.write_all(&frame[..6]).await.unwrap();
        let r = tokio::time::timeout(std::time::Duration::from_millis(50), conn.recv()).await;
        assert!(r.is_err(), "半帧时应当还在等待");
        far.write_all(&frame[6..]).await.unwrap();
        let pkt = conn.recv().await.unwrap();
        assert_eq!(&pkt.data[..], b"0123456789");
        assert_eq!(pkt.src, "8.8.8.8:53".parse().unwrap());
    }

    /// v1 / v2 客户端 ↔ 服务侧直连中继 ↔ UDP echo 全链路
    #[tokio::test]
    async fn client_server_roundtrip_v1_and_v2() {
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            while let Ok((n, from)) = echo.recv_from(&mut b).await {
                let _ = echo.send_to(&b[..n], from).await;
            }
        });
        let direct: Arc<dyn Outbound> = Arc::new(crate::DirectOutbound::new(
            Arc::new(vp_dns::Resolver::system()),
            false,
        ));
        for version in [1u8, 2] {
            let (near, far) = tokio::io::duplex(64 * 1024);
            let sess = Session::new_tcp("t".into(), None, magic_dst(version));
            let egress = UdpEgress::Fixed(direct.clone());
            tokio::spawn(async move {
                let _ = serve_client(egress, sess, Box::new(far)).await;
            });
            let target = DstAddr::ip(echo_addr.ip(), echo_addr.port());
            let mut conn = StreamPacketConn::uot(near, &target, version).await.unwrap();
            for payload in [&b"first"[..], b"second"] {
                conn.send(&UdpPacket {
                    src: "0.0.0.0:0".parse().unwrap(),
                    dst: echo_addr,
                    data: Bytes::copy_from_slice(payload),
                })
                .await
                .unwrap();
                let pkt = tokio::time::timeout(std::time::Duration::from_secs(5), conn.recv())
                    .await
                    .expect("回包超时")
                    .unwrap();
                assert_eq!(&pkt.data[..], payload, "v{version}");
                assert_eq!(pkt.src, echo_addr, "v{version}");
            }
        }
    }

    /// v2 连接模式（sing-box 客户端会用）：帧不带地址
    #[tokio::test]
    async fn server_accepts_v2_connect_mode() {
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            while let Ok((n, from)) = echo.recv_from(&mut b).await {
                let _ = echo.send_to(&b[..n], from).await;
            }
        });
        let direct: Arc<dyn Outbound> = Arc::new(crate::DirectOutbound::new(
            Arc::new(vp_dns::Resolver::system()),
            false,
        ));
        let (mut near, far) = tokio::io::duplex(64 * 1024);
        let sess = Session::new_tcp("t".into(), None, magic_dst(2));
        tokio::spawn(async move {
            let _ = serve_client(UdpEgress::Fixed(direct), sess, Box::new(far)).await;
        });
        let mut req = vec![1u8]; // isConnect = 1
        vp_common::addr::encode_socks_addr(
            &DstAddr::ip(echo_addr.ip(), echo_addr.port()),
            &mut req,
        );
        req.extend_from_slice(&[0, 4]);
        req.extend_from_slice(b"ping");
        near.write_all(&req).await.unwrap();
        let mut resp = [0u8; 6];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            near.read_exact(&mut resp),
        )
        .await
        .expect("回包超时")
        .unwrap();
        assert_eq!(&resp, b"\x00\x04ping", "连接模式回包也不带地址");
    }
}

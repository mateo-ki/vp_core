//! VLESS 出入站（version 0，port-then-address，atyp 1/2/3）。

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use vp_common::{DstAddr, Error, Result};
use vp_config::VlessCfg;
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;
use vp_core::tunnel::{RelayHook, relay};
use vp_core::{Inbound, Outbound, PacketConn, ProxyStream};
use vp_crypto::vmess_kdf::parse_uuid;

use crate::uot::{
    PACKET_ADDR_MAGIC, PacketFraming, StreamPacketConn, UdpEgress, UdpEncoding, xudp_dst,
};

use crate::direct::DirectOutbound;
use crate::vless_vision::{VISION_FLOW_BYTES, VisionStream};
use vp_dns::Resolver;
use vp_transport as transport;

pub(crate) const VERSION: u8 = 0x00;
pub(crate) const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x02;

const CMD_MUX: u8 = 0x03;

fn encode_addr(dst: &DstAddr, cmd: u8, is_vision: bool, out: &mut Vec<u8>) {
    // [addons len][cmd][port][atyp][addr]（版本与 UUID 由调用方前置；Mux 命令不带地址）
    if is_vision {
        out.push(VISION_FLOW_BYTES.len() as u8);
        out.extend_from_slice(VISION_FLOW_BYTES);
    } else {
        out.push(0); // addons len
    }
    out.push(cmd);
    if cmd != CMD_MUX {
        vp_common::addr::encode_v2ray_addr(dst, out);
    }
}

/// 解析请求头：(uuid, 目标, 是否 vision, 命令, 头长度)。Mux 命令（XUDP）不带地址
pub(crate) fn decode_request(buf: &[u8]) -> Result<([u8; 16], DstAddr, bool, u8, usize)> {
    if buf.len() < 1 + 16 + 1 + 1 {
        return Err(Error::Proto("vless 请求头过短"));
    }
    if buf[0] != VERSION {
        return Err(Error::Proto("vless 版本不支持"));
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&buf[1..17]);
    let addons_len = buf[17] as usize;
    let mut i = 18;
    if buf.len() < i + addons_len + 1 {
        return Err(Error::Proto("vless 请求头截断"));
    }
    let is_vision = addons_len > 0 && &buf[i..i + addons_len] == VISION_FLOW_BYTES;
    i += addons_len;
    let cmd = buf[i];
    i += 1;
    let dst = match cmd {
        CMD_MUX => crate::uot::xudp_dst(),
        CMD_TCP | CMD_UDP => match vp_common::addr::decode_v2ray_addr(&buf[i..]) {
            Ok((dst, used)) => {
                i += used;
                dst
            }
            Err(Error::Proto("address truncated")) => return Err(Error::Proto("vless 地址截断")),
            Err(_) => return Err(Error::Proto("vless atyp 非法")),
        },
        _ => {
            return Err(Error::Unsupported(format!(
                "vless 入站: 不支持的命令 {cmd}"
            )));
        }
    };
    Ok((uuid, dst, is_vision, cmd, i))
}

// ---------------------------------------------------------------------------
// 出站
// ---------------------------------------------------------------------------

pub struct VlessOutbound {
    name: Arc<str>,
    server: String,
    port: u16,
    uuid: [u8; 16],
    flow: Option<String>,
    transport: transport::TransportConfig,
    udp: bool,
    udp_encoding: UdpEncoding,
}

impl VlessOutbound {
    pub fn new(cfg: &VlessCfg) -> Result<Self> {
        Self::internal_new(None, cfg)
    }

    pub fn new_named(name: &str, cfg: &VlessCfg) -> Result<Self> {
        Self::internal_new(Some(name), cfg)
    }

    fn internal_new(name: Option<&str>, cfg: &VlessCfg) -> Result<Self> {
        let uuid = parse_uuid(&cfg.uuid)?;
        let mut t = crate::transport_of_full(
            cfg.tls,
            &cfg.server_name,
            cfg.skip_cert_verify,
            &cfg.network,
            &cfg.ws_opts,
            &cfg.grpc_opts,
            &cfg.client_fingerprint,
            &cfg.reality_opts,
            &cfg.http_opts,
            &cfg.ech_opts,
            &cfg.xhttp_opts,
            &cfg.shadowtls_opts,
        )?;
        t.alpn = cfg.alpn.clone().unwrap_or_default();
        Ok(VlessOutbound {
            name: name.unwrap_or("vless").into(),
            server: cfg.server.clone(),
            port: cfg.port,
            uuid,
            flow: cfg.flow.clone(),
            transport: t,
            udp: cfg.udp,
            udp_encoding: UdpEncoding::from_cfg(
                cfg.packet_encoding.as_deref(),
                cfg.xudp,
                cfg.packet_addr,
            )?,
        })
    }

    async fn handshake<S>(&self, io: S, dst: &DstAddr, cmd: u8) -> Result<Box<dyn ProxyStream>>
    where
        S: ProxyStream,
    {
        // UDP / XUDP（Mux）不走 vision：Xray 服务端拒绝 vision + UDP 命令，但接受 flow 为空的
        // UDP / Mux 请求，即使该用户配置了 vision（真实 Xray 节点实测 XUDP 可用）
        let is_vision = cmd == CMD_TCP
            && self
                .flow
                .as_deref()
                .map(|f| f.eq_ignore_ascii_case("xtls-rprx-vision"))
                .unwrap_or(false);

        let mut req = Vec::with_capacity(48);
        encode_addr(dst, cmd, is_vision, &mut req);
        let mut full = Vec::with_capacity(1 + 16 + req.len());
        full.push(VERSION);
        full.extend_from_slice(&self.uuid);
        full.extend_from_slice(&req);
        // 只记长度：请求里含 UUID（认证凭据），整段打印会在用户贴出的 debug 日志里泄露
        tracing::debug!("vless 请求 {} 字节 -> {dst}", full.len());

        // 懒握手：vless 请求不单独成帧、也不阻塞等响应头，而是与消费方的首个载荷
        // （vision 时即首个填充帧）合并同一帧写出；响应侧的 [ver][addon_len][addon]
        // 头由 VlessStream 读取时透明剥离。
        // - Xray 服务端只在目标首包回来时才连同响应头一起发出：先等响应头，HTTP 这类
        //   "客户端先说话"的协议就会互等到超时
        // - Cloudflare Worker 型服务端只在首条消息里同时拿到 vless 头+初始载荷才建立
        //   上游；空的 vless 首帧会让其对端静默等待（mihomo 的中继同样把早数据并入首帧）
        let stream = VlessStream {
            inner: io,
            request: Some(full),
            out: BytesMut::new(),
            strip: RespStrip::default(),
            decoded: BytesMut::new(),
        };
        let out: Box<dyn ProxyStream> = if is_vision {
            Box::new(VisionStream::new(stream, self.uuid))
        } else {
            Box::new(stream)
        };
        Ok(out)
    }
}

/// vless 响应头剥离状态：先吃 [ver][addon_len]，再吃 addon_len 字节 addon
#[derive(Default)]
struct RespStrip {
    /// 0 = 读 ver/addon_len 两字节；1 = 吃 addon；2 = 完成
    phase: u8,
    /// phase 0 中已读的头字节数（0=ver 待读，1=addon_len 待读）
    header_idx: usize,
    addon_left: usize,
}

impl RespStrip {
    /// 从 data 头部剥离响应头，返回剩余透传字节
    fn strip<'a>(&mut self, mut data: &'a [u8]) -> &'a [u8] {
        while self.phase < 2 && !data.is_empty() {
            match self.phase {
                0 => {
                    let b = data[0];
                    data = &data[1..];
                    if self.header_idx == 0 {
                        // ver 字节（校验留给首连接——CF Worker 等兼容实现也回 0）
                        self.header_idx = 1;
                    } else {
                        self.addon_left = b as usize;
                        self.phase = if self.addon_left > 0 { 1 } else { 2 };
                        self.header_idx = 0;
                    }
                }
                1 => {
                    let take = data.len().min(self.addon_left);
                    data = &data[take..];
                    self.addon_left -= take;
                    if self.addon_left == 0 {
                        self.phase = 2;
                    }
                }
                _ => break,
            }
        }
        data
    }
}

/// 非 vision 的 vless 数据流（懒握手 + 响应头剥离）
pub struct VlessStream<S> {
    inner: S,
    /// 待发送的 vless 请求（与首个载荷合并同帧）
    request: Option<Vec<u8>>,
    /// 已合并（请求头 + 首个载荷）但底层尚未写完的字节：底层返回 Pending 或只写一部分时，
    /// 不能丢（否则请求头没发出去，整条连接作废）
    out: BytesMut,
    strip: RespStrip,
    /// 剥离后待交付的明文余量
    decoded: BytesMut,
}

impl<S: vp_core::ProxyStream> vp_core::ProxyStream for VlessStream<S> {
    /// decoded 里已读出的余量照常先交付（poll_read 先吐 decoded），切换只影响其后的 inner 读取
    fn switch_to_raw_read(&mut self) -> bool {
        self.inner.switch_to_raw_read()
    }
}

impl<S> VlessStream<S> {
    /// 若请求仍未发出（消费方先读后写），以独立帧发出（标准 vless 语义；
    /// 写前读的协议极少见，正常代理流量总是先发载荷）
    fn ensure_request_sent(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>>
    where
        S: AsyncWrite + Unpin,
    {
        if let Some(req) = self.request.take() {
            self.out.extend_from_slice(&req);
        }
        std::task::ready!(self.poll_drain(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    /// 把 out 里积压的字节写进底层
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>>
    where
        S: AsyncWrite + Unpin,
    {
        while !self.out.is_empty() {
            let n = std::task::ready!(Pin::new(&mut self.inner).poll_write(cx, &self.out))?;
            if n == 0 {
                return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
            }
            self.out.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VlessStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.request.is_some() || !this.out.is_empty() {
            std::task::ready!(this.ensure_request_sent(cx))?;
        }
        // 头未剥离完：经内部缓冲剥离（可能连带读入其后的载荷）
        while this.strip.phase < 2 && this.decoded.is_empty() {
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
            let filled = rb.filled();
            if filled.is_empty() {
                return Poll::Ready(Ok(())); // EOF
            }
            let rest = this.strip.strip(filled);
            this.decoded.extend_from_slice(rest);
        }
        // 剥离时连带读入的载荷必须先交付完：调用方读缓冲小于余量时（如 vision 逐 5 字节读帧头），
        // 若此处只看"头已剥完"就转去直读 inner，余量会被静默丢弃
        if !this.decoded.is_empty() {
            let n = this.decoded.len().min(buf.remaining());
            buf.put_slice(&this.decoded[..n]);
            this.decoded.advance(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VlessStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        std::task::ready!(this.poll_drain(cx))?;
        if let Some(req) = this.request.take() {
            // 首写：vless 请求 + 载荷同帧；写不完的留在 out，由后续 write / flush 续写
            this.out.extend_from_slice(&req);
            this.out.extend_from_slice(buf);
            if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
                return Poll::Ready(Err(e));
            }
            return Poll::Ready(Ok(buf.len()));
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[async_trait]
impl Outbound for VlessOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect_stream(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        let io = crate::dial_transport(&self.server, self.port, &self.transport).await?;
        self.handshake(io, dst, CMD_TCP).await
    }

    async fn connect_over(
        &self,
        _sess: &Session,
        dst: &DstAddr,
        underlying: Box<dyn ProxyStream>,
    ) -> Result<Box<dyn ProxyStream>> {
        let io = crate::wrap_transport_over(underlying, &self.server, &self.transport).await?;
        self.handshake(io, dst, CMD_TCP).await
    }

    fn support_udp(&self) -> bool {
        self.udp
    }

    /// 原生 UDP，按 packet-encoding：
    /// - 原始编码：命令 0x02，每个目标一条流，帧为 `[len][data]`
    /// - xudp：命令 0x03（Mux.Cool，不带地址），一条流承载多目标（Xray full-cone）
    /// - packetaddr：命令 0x02 发往魔法地址，每个数据报自带 IP 目标（v2ray 5+）
    async fn connect_packet(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        let io = crate::dial_transport(&self.server, self.port, &self.transport).await?;
        let (cmd, req_dst, framing) = match self.udp_encoding {
            UdpEncoding::Raw => (CMD_UDP, dst.clone(), PacketFraming::Len(dst.clone())),
            UdpEncoding::Xudp => (CMD_MUX, xudp_dst(), PacketFraming::xudp_client(dst)),
            UdpEncoding::PacketAddr => (
                CMD_UDP,
                DstAddr::new(PACKET_ADDR_MAGIC, 0),
                PacketFraming::PacketAddr { vmess: false },
            ),
        };
        let stream = self.handshake(io, &req_dst, cmd).await?;
        Ok(Box::new(StreamPacketConn::new(stream, dst, framing)))
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
}

// ---------------------------------------------------------------------------
// 入站
// ---------------------------------------------------------------------------

pub struct VlessInbound {
    bind: String,
    port: u16,
    tag: Arc<str>,
    uuids: Vec<[u8; 16]>,
    fallback: Option<String>,
    users_by_uuid: std::collections::HashMap<[u8; 16], Arc<vp_core::UserAccount>>,
    user_mgr: Option<Arc<vp_core::UserManager>>,
    gate: Option<Arc<vp_core::InboundGate>>,
    direct: Arc<DirectOutbound>,
}

impl VlessInbound {
    pub fn new(bind: &str, port: u16, tag: &str, uuids: &[String]) -> Result<Self> {
        Self::with_options(bind, port, tag, uuids, None, None)
    }

    pub fn with_options(
        bind: &str,
        port: u16,
        tag: &str,
        uuids: &[String],
        fallback: Option<String>,
        user_mgr: Option<Arc<vp_core::UserManager>>,
    ) -> Result<Self> {
        Self::with_gate(bind, port, tag, uuids, fallback, user_mgr, None)
    }

    pub fn with_gate(
        bind: &str,
        port: u16,
        tag: &str,
        uuids: &[String],
        fallback: Option<String>,
        user_mgr: Option<Arc<vp_core::UserManager>>,
        gate: Option<Arc<vp_core::InboundGate>>,
    ) -> Result<Self> {
        let mut ids = Vec::new();
        let mut users_by_uuid = std::collections::HashMap::new();

        for u in uuids {
            let id = parse_uuid(u)?;
            ids.push(id);
            if let Some(mgr) = &user_mgr {
                if let Some(user) = mgr.get_user(u) {
                    users_by_uuid.insert(id, user);
                }
            }
        }
        if let Some(mgr) = &user_mgr {
            for user in mgr.all_users() {
                if let Ok(id) = parse_uuid(&user.secret) {
                    if !ids.contains(&id) {
                        ids.push(id);
                    }
                    users_by_uuid.insert(id, user);
                }
            }
        }
        if ids.is_empty() && fallback.is_none() {
            return Err(Error::Config("vless 入站需要至少一个用户或回落目标".into()));
        }
        Ok(VlessInbound {
            bind: bind.to_string(),
            port,
            tag: tag.into(),
            uuids: ids,
            fallback,
            users_by_uuid,
            user_mgr,
            gate,
            direct: Arc::new(DirectOutbound::new(Arc::new(Resolver::system()), false)),
        })
    }

    async fn handle_fallback_or_err(
        &self,
        stream: Box<dyn ProxyStream>,
        peeked: &[u8],
        err: Error,
    ) -> Result<()> {
        if let Some(fb_target) = &self.fallback {
            tracing::debug!(fallback = %fb_target, "VLESS 认证失败或探测流量，执行 Fallback 回落: {err}");
            match tokio::net::TcpStream::connect(fb_target).await {
                Ok(fb_stream) => {
                    vp_transport::tune(&fb_stream);
                    let client: Box<dyn ProxyStream> =
                        Box::new(vp_core::PeekedStream::new(stream, peeked.to_vec()));
                    let remote: Box<dyn ProxyStream> = Box::new(fb_stream);
                    tokio::spawn(async move {
                        let _ = relay(client, remote, RelayHook::default()).await;
                    });
                    Ok(())
                }
                Err(conn_err) => {
                    tracing::warn!("VLESS 连接回落目标 {fb_target} 失败: {conn_err}");
                    Err(err)
                }
            }
        } else {
            Err(err)
        }
    }

    async fn serve(
        self: &Arc<Self>,
        stream: tokio::net::TcpStream,
        src: std::net::SocketAddr,
        ctx: &InboundCtx,
    ) -> Result<()> {
        let mut peek = [0u8; 512];
        let is_ws = match stream.peek(&mut peek).await {
            Ok(n) if n >= 4 => {
                let s = String::from_utf8_lossy(&peek[..n]).to_ascii_lowercase();
                s.contains("upgrade: websocket")
            }
            _ => false,
        };
        if is_ws {
            let ws = vp_transport::ws_handshake_server(stream).await?;
            return self.serve_stream(Box::new(ws), src, ctx).await;
        }
        self.serve_stream(Box::new(stream), src, ctx).await
    }

    async fn serve_stream(
        self: &Arc<Self>,
        mut stream: Box<dyn ProxyStream>,
        src: std::net::SocketAddr,
        ctx: &InboundCtx,
    ) -> Result<()> {
        // 头部最长：1+16+1+1+2+1+255
        let mut buf = vec![0u8; 19 + 256];
        let mut filled = 0;
        loop {
            if filled >= buf.len() {
                return self
                    .handle_fallback_or_err(
                        stream,
                        &buf[..filled],
                        Error::Proto("vless 请求头过长"),
                    )
                    .await;
            }
            let n = stream.read(&mut buf[filled..]).await?;
            if n == 0 {
                return Err(Error::Proto("vless 请求头中断"));
            }
            filled += n;
            match decode_request(&buf[..filled]) {
                Ok((uuid, dst, is_vision, cmd, used)) => {
                    let (matched, user) = if let Some(mgr) = &self.user_mgr {
                        if let Some(u) = mgr.get_user_by_uuid(&uuid) {
                            if u.is_quota_exceeded() {
                                return self
                                    .handle_fallback_or_err(
                                        stream,
                                        &buf[..filled],
                                        Error::Proto("vless: 用户配额已超限"),
                                    )
                                    .await;
                            }
                            (true, Some(u))
                        } else {
                            (self.uuids.contains(&uuid), None)
                        }
                    } else {
                        let m = self.uuids.contains(&uuid);
                        let u = if let Some(u) = self.users_by_uuid.get(&uuid) {
                            if u.is_quota_exceeded() {
                                return self
                                    .handle_fallback_or_err(
                                        stream,
                                        &buf[..filled],
                                        Error::Proto("vless: 用户配额已超限"),
                                    )
                                    .await;
                            }
                            Some(u.clone())
                        } else {
                            None
                        };
                        (m, u)
                    };
                    if !matched {
                        return self
                            .handle_fallback_or_err(
                                stream,
                                &buf[..filled],
                                Error::Proto("vless: 用户认证失败"),
                            )
                            .await;
                    }
                    if let Some(ref g) = self.gate {
                        g.mark_authenticated(src.ip());
                    }
                    if cmd != CMD_TCP {
                        // UDP：回响应头后流上是数据报帧（请求头后的早数据即首帧）。
                        // 帧格式：Mux → XUDP；发往 packetaddr 魔法地址 → packetaddr；否则 [len][data]
                        stream.write_all(&[VERSION, 0]).await?;
                        let stream = vp_core::PeekedStream::new(stream, buf[used..filled].to_vec());
                        // Xray 客户端 vision + XUDP 时 Mux 流也走 vision 填充
                        let client: Box<dyn ProxyStream> = if is_vision {
                            Box::new(VisionStream::new(stream, uuid))
                        } else {
                            Box::new(stream)
                        };
                        let framing = if cmd == CMD_MUX {
                            PacketFraming::xudp_server()
                        } else if dst.host.as_domain() == Some(PACKET_ADDR_MAGIC) {
                            PacketFraming::PacketAddr { vmess: false }
                        } else {
                            PacketFraming::Len(dst.clone())
                        };
                        let sess = Session::new_udp(self.tag.clone(), Some(src), dst);
                        let egress = UdpEgress::Fixed(self.direct.clone());
                        tokio::spawn(async move {
                            let _ = crate::uot::serve_packets(egress, sess, client, framing, user)
                                .await;
                        });
                        return Ok(());
                    }
                    let sess = Session::new_tcp(self.tag.clone(), Some(src), dst.clone());
                    let remote = self.direct.connect_stream(&sess, &dst).await?;
                    // 响应：如果启用了 vision，回送 [VERSION, 18, VISION_FLOW_BYTES]
                    if is_vision {
                        stream
                            .write_all(&[VERSION, VISION_FLOW_BYTES.len() as u8])
                            .await?;
                        stream.write_all(VISION_FLOW_BYTES).await?;
                    } else {
                        stream.write_all(&[VERSION, 0]).await?;
                    }
                    // 请求头之后已读入的早数据属于上行载荷（Xray / mihomo 客户端会把它与
                    // 请求头合并发出），放回读取侧随后续数据一起转发——不能回写给客户端
                    let stream = vp_core::PeekedStream::new(stream, buf[used..filled].to_vec());
                    let meta = vp_core::conn_table::ConnMeta {
                        id: sess.id,
                        inbound: self.tag.clone(),
                        network: "tcp",
                        host: dst.host.to_string(),
                        dst_port: dst.port,
                        src: Some(src.to_string()),
                        process: None,
                        user: user.as_ref().map(|u| u.username.clone()),
                        rule: None,
                        chain: Some("vless-server".into()),
                        start: vp_common::now_millis(),
                    };
                    let hook = RelayHook {
                        table: Some(ctx.conns.clone()),
                        meta: Some(meta),
                        stats: Some(ctx.stats.clone()),
                        user,
                        limiter: None,
                        brutal: None,
                    };
                    let client: Box<dyn ProxyStream> = if is_vision {
                        Box::new(VisionStream::new(stream, uuid))
                    } else {
                        Box::new(stream)
                    };
                    tokio::spawn(async move {
                        let _ = relay(client, remote, hook).await;
                    });
                    return Ok(());
                }
                Err(Error::Proto("vless 请求头过短" | "vless 请求头截断" | "vless 地址截断")) =>
                {
                    continue;
                }
                Err(e) => {
                    return self.handle_fallback_or_err(stream, &buf[..filled], e).await;
                }
            }
        }
    }
}

#[async_trait]
impl Inbound for VlessInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, ctx: InboundCtx) -> Result<u16> {
        use std::net::ToSocketAddrs;
        let addr = match (self.bind.as_str(), self.port).to_socket_addrs() {
            Ok(mut it) => it.next().ok_or_else(|| {
                Error::Config(format!("无法解析绑定地址 {}:{}", self.bind, self.port))
            })?,
            Err(e) => {
                return Err(Error::Config(format!(
                    "无法解析绑定地址 {}:{}: {e}",
                    self.bind, self.port
                )));
            }
        };
        let listener = vp_transport::bind_tcp_listener(addr)?;
        let bound = listener.local_addr()?.port();
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, src)) => {
                        if let Some(ref g) = this.gate {
                            if !g.check_accept(src.ip()) {
                                continue;
                            }
                        }
                        vp_transport::tune(&stream);
                        let this = this.clone();
                        let ctx = ctx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = this.serve(stream, src, &ctx).await {
                                tracing::debug!("vless 入站会话结束: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("vless 入站 accept 失败: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        });
        Ok(bound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn vless_loopback() {
        // 目标服务回 "echo:" + 收到的数据：区分"真正经目标往返"与"服务端把早数据回写给客户端"
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut b = [0u8; 1024];
            loop {
                let n = s.read(&mut b).await.unwrap();
                if n == 0 {
                    break;
                }
                s.write_all(b"echo:").await.unwrap();
                s.write_all(&b[..n]).await.unwrap();
            }
        });
        let ctx = InboundCtx {
            router: Arc::new(crate::test_support::NoopRouter()),
            stats: Arc::new(vp_common::Stats::default()),
            conns: Arc::new(vp_core::ConnTable::new()),
        };
        let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811".to_string();
        let server =
            VlessInbound::new("127.0.0.1", 0, "vl-srv", std::slice::from_ref(&uuid)).unwrap();
        let port = Arc::new(server).start(ctx).await.unwrap();

        let out = VlessOutbound::new(&VlessCfg {
            xhttp_opts: None,
            shadowtls_opts: None,
            server: "127.0.0.1".into(),
            port,
            uuid,
            flow: None,
            tls: false,
            server_name: None,
            skip_cert_verify: false,
            client_fingerprint: None,
            alpn: None,
            network: None,
            ws_opts: None,
            grpc_opts: None,
            http_opts: None,
            reality_opts: None,
            ech_opts: None,
            udp: false,
            packet_encoding: None,
            xudp: false,
            packet_addr: false,
        })
        .unwrap();
        let dst = DstAddr::new("127.0.0.1", echo_addr.port());
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = out.connect_stream(&sess, &dst).await.unwrap();
        s.write_all(b"ping-vless").await.unwrap();
        let mut buf = [0u8; 15];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"echo:ping-vless", "请求头后的早数据必须转发给目标");
    }

    /// UDP：出站 connect_packet ↔ 本地 vless 入站 ↔ UDP echo，三种编码。
    /// 配了 vision 也要能走 UDP（UDP 请求不带 flow，同 Xray）；xudp / packetaddr 单连接多目标
    #[tokio::test]
    async fn vless_udp_roundtrip() {
        for enc in [None, Some("xudp"), Some("packetaddr")] {
            vless_udp_roundtrip_with(enc).await;
        }
    }

    async fn vless_udp_roundtrip_with(enc: Option<&str>) {
        let echo = crate::test_support::udp_echo().await;
        let ctx = InboundCtx {
            router: Arc::new(crate::test_support::NoopRouter()),
            stats: Arc::new(vp_common::Stats::default()),
            conns: Arc::new(vp_core::ConnTable::new()),
        };
        let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811".to_string();
        let server =
            VlessInbound::new("127.0.0.1", 0, "vl-udp", std::slice::from_ref(&uuid)).unwrap();
        let port = Arc::new(server).start(ctx).await.unwrap();
        let out = VlessOutbound::new(&VlessCfg {
            xhttp_opts: None,
            shadowtls_opts: None,
            server: "127.0.0.1".into(),
            port,
            uuid,
            flow: Some("xtls-rprx-vision".into()),
            tls: false,
            server_name: None,
            skip_cert_verify: false,
            client_fingerprint: None,
            alpn: None,
            network: None,
            ws_opts: None,
            grpc_opts: None,
            http_opts: None,
            reality_opts: None,
            ech_opts: None,
            udp: true,
            packet_encoding: enc.map(Into::into),
            xudp: false,
            packet_addr: false,
        })
        .unwrap();
        assert!(out.support_udp());
        let dst = DstAddr::ip(echo.ip(), echo.port());
        let sess = Session::new_udp("t".into(), None, dst.clone());
        let mut conn = out.connect_packet(&sess, &dst).await.unwrap();
        crate::test_support::assert_udp_roundtrip(&mut conn, echo).await;
        if enc.is_some() {
            crate::test_support::assert_udp_second_target(&mut conn).await;
        }
    }

    #[tokio::test]
    async fn vless_ws_inbound_outbound_e2e() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut b = [0u8; 1024];
            loop {
                let n = s.read(&mut b).await.unwrap();
                if n == 0 {
                    break;
                }
                s.write_all(&b[..n]).await.unwrap();
            }
        });

        let ctx = InboundCtx {
            router: Arc::new(crate::test_support::NoopRouter()),
            stats: Arc::new(vp_common::Stats::default()),
            conns: Arc::new(vp_core::ConnTable::new()),
        };
        let uuid = "4a4cb40d-d1a7-493e-a54d-5f154534cd93".to_string();
        let server =
            VlessInbound::new("127.0.0.1", 0, "vl-ws-srv", std::slice::from_ref(&uuid)).unwrap();
        let port = Arc::new(server).start(ctx).await.unwrap();

        let out = VlessOutbound::new(&VlessCfg {
            xhttp_opts: None,
            shadowtls_opts: None,
            server: "127.0.0.1".into(),
            port,
            uuid,
            flow: None,
            tls: false,
            server_name: None,
            skip_cert_verify: false,
            client_fingerprint: None,
            alpn: None,
            network: Some("ws".into()),
            ws_opts: Some(vp_config::WsOpts {
                path: Some("/vpcore-tunnel".into()),
                headers: None,
                max_early_data: None,
                v2ray_http_upgrade: false,
            }),
            grpc_opts: None,
            http_opts: None,
            reality_opts: None,
            ech_opts: None,
            udp: false,
            packet_encoding: None,
            xudp: false,
            packet_addr: false,
        })
        .unwrap();
        let dst = DstAddr::new("127.0.0.1", echo_addr.port());
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = out.connect_stream(&sess, &dst).await.unwrap();
        s.write_all(b"ping-vless-ws").await.unwrap();
        let mut buf = [0u8; 13];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-vless-ws");
    }

    #[tokio::test]
    async fn vless_vision_handshake_and_direct_splice() {
        // echo 回显服务器
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut b = [0u8; 8192];
            loop {
                let n = s.read(&mut b).await.unwrap();
                if n == 0 {
                    break;
                }
                s.write_all(&b[..n]).await.unwrap();
            }
        });

        let ctx = InboundCtx {
            router: Arc::new(crate::test_support::NoopRouter()),
            stats: Arc::new(vp_common::Stats::default()),
            conns: Arc::new(vp_core::ConnTable::new()),
        };
        let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811".to_string();
        let server =
            VlessInbound::new("127.0.0.1", 0, "vl-vision-srv", std::slice::from_ref(&uuid))
                .unwrap();
        let port = Arc::new(server).start(ctx).await.unwrap();

        // 构造配置了 flow: xtls-rprx-vision 的出站
        let out = VlessOutbound::new(&VlessCfg {
            xhttp_opts: None,
            shadowtls_opts: None,
            server: "127.0.0.1".into(),
            port,
            uuid,
            flow: Some("xtls-rprx-vision".into()),
            tls: false,
            server_name: None,
            skip_cert_verify: false,
            client_fingerprint: None,
            alpn: None,
            network: None,
            ws_opts: None,
            grpc_opts: None,
            http_opts: None,
            reality_opts: None,
            ech_opts: None,
            udp: false,
            packet_encoding: None,
            xudp: false,
            packet_addr: false,
        })
        .unwrap();

        let dst = DstAddr::new("127.0.0.1", echo_addr.port());
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = out.connect_stream(&sess, &dst).await.unwrap();

        // 1. 发送伪造的内层 TLS 1.3 ClientHello（触发布局伪装与填充）
        let mut client_hello = vec![0x16, 0x03, 0x03, 0x01, 0x00, 0x01, 0x00, 0x00, 0xfc];
        client_hello.resize(256, 0xaa);
        s.write_all(&client_hello).await.unwrap();

        let mut recv_ch = vec![0u8; client_hello.len()];
        s.read_exact(&mut recv_ch).await.unwrap();
        assert_eq!(
            recv_ch, client_hello,
            "ClientHello 内容经 Vision 填充/剥离后应完全一致"
        );

        // 2. 发送 ApplicationData（0x17），触发 PaddingEnd 并切换到裸流直通
        let mut app_data = vec![0x17, 0x03, 0x03, 0x00, 0x20];
        app_data.extend_from_slice(b"secret-application-data-content!");
        s.write_all(&app_data).await.unwrap();

        let mut recv_ad = vec![0u8; app_data.len()];
        s.read_exact(&mut recv_ad).await.unwrap();
        assert_eq!(recv_ad, app_data);

        // 3. 大流量（128 KB）直通传输测试（验证 Splice / Direct 状态零分帧损耗）
        let large_payload = vec![0x42u8; 128 * 1024];
        let mut recv_large = vec![0u8; large_payload.len()];
        let (mut rh, mut wh) = tokio::io::split(s);
        let write_fut = async move {
            wh.write_all(&large_payload).await.unwrap();
        };
        let read_fut = async {
            rh.read_exact(&mut recv_large).await.unwrap();
        };
        tokio::join!(write_fut, read_fut);
        assert_eq!(recv_large, vec![0x42u8; 128 * 1024]);
    }
}

//! VLESS 出入站（version 0，port-then-address，atyp 1/2/3）。

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use vp_common::{DstAddr, Error, Host, Result};
use vp_config::VlessCfg;
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;
use vp_core::tunnel::{RelayHook, relay};
use vp_core::{Inbound, Outbound, ProxyStream};
use vp_crypto::vmess_kdf::parse_uuid;

use crate::direct::DirectOutbound;
use crate::vless_vision::{VISION_FLOW_BYTES, VisionStream};
use vp_dns::Resolver;
use vp_transport as transport;

const VERSION: u8 = 0x00;
const CMD_TCP: u8 = 0x01;

fn encode_addr(dst: &DstAddr, is_vision: bool, out: &mut Vec<u8>) {
    // [addons len][cmd][port][atyp][addr]（版本与 UUID 由调用方前置）
    if is_vision {
        out.push(VISION_FLOW_BYTES.len() as u8);
        out.extend_from_slice(VISION_FLOW_BYTES);
    } else {
        out.push(0); // addons len
    }
    out.push(CMD_TCP);
    out.extend_from_slice(&dst.port.to_be_bytes());
    match &dst.host {
        Host::Ip(std::net::IpAddr::V4(v4)) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        Host::Ip(std::net::IpAddr::V6(v6)) => {
            out.push(0x03);
            out.extend_from_slice(&v6.octets());
        }
        Host::Domain(d) => {
            out.push(0x02);
            out.push(d.len() as u8);
            out.extend_from_slice(d.as_bytes());
        }
    }
}

fn decode_request(buf: &[u8]) -> Result<([u8; 16], DstAddr, bool, usize)> {
    if buf.len() < 3 + 16 + 1 + 1 + 2 + 1 {
        return Err(Error::Proto("vless 请求头过短"));
    }
    if buf[0] != VERSION {
        return Err(Error::Proto("vless 版本不支持"));
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&buf[1..17]);
    let addons_len = buf[17] as usize;
    let mut i = 18;
    let mut is_vision = false;
    if addons_len > 0 {
        if buf.len() < i + addons_len {
            return Err(Error::Proto("vless 请求头截断"));
        }
        if &buf[i..i + addons_len] == VISION_FLOW_BYTES {
            is_vision = true;
        }
        i += addons_len;
    }
    if buf.len() < i + 4 {
        return Err(Error::Proto("vless 请求头截断"));
    }
    let cmd = buf[i];
    i += 1;
    if cmd != CMD_TCP {
        return Err(Error::Unsupported("vless 入站仅支持 TCP".into()));
    }
    let port = u16::from_be_bytes([buf[i], buf[i + 1]]);
    i += 2;
    let atyp = buf[i];
    i += 1;
    let host = match atyp {
        0x01 => {
            if buf.len() < i + 4 {
                return Err(Error::Proto("vless 地址截断"));
            }
            let o: [u8; 4] = buf[i..i + 4].try_into().unwrap();
            i += 4;
            Host::Ip(std::net::IpAddr::V4(o.into()))
        }
        0x02 => {
            if buf.len() < i + 1 {
                return Err(Error::Proto("vless 地址截断"));
            }
            let n = buf[i] as usize;
            i += 1;
            if buf.len() < i + n {
                return Err(Error::Proto("vless 地址截断"));
            }
            let d = std::str::from_utf8(&buf[i..i + n])
                .map_err(|_| Error::Proto("域名非 utf-8"))?
                .to_ascii_lowercase();
            i += n;
            Host::Domain(d)
        }
        0x03 => {
            if buf.len() < i + 16 {
                return Err(Error::Proto("vless 地址截断"));
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[i..i + 16]);
            i += 16;
            Host::Ip(std::net::IpAddr::V6(o.into()))
        }
        _ => return Err(Error::Proto("vless atyp 非法")),
    };
    Ok((uuid, DstAddr { host, port }, is_vision, i))
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
        )?;
        t.alpn = cfg.alpn.clone().unwrap_or_default();
        Ok(VlessOutbound {
            name: name.unwrap_or("vless").into(),
            server: cfg.server.clone(),
            port: cfg.port,
            uuid,
            flow: cfg.flow.clone(),
            transport: t,
        })
    }

    async fn handshake<S>(&self, mut io: S, dst: &DstAddr) -> Result<Box<dyn ProxyStream>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let is_vision = self
            .flow
            .as_deref()
            .map(|f| f.eq_ignore_ascii_case("xtls-rprx-vision"))
            .unwrap_or(false);

        let mut req = Vec::with_capacity(48);
        encode_addr(dst, is_vision, &mut req);
        let mut full = Vec::with_capacity(1 + 16 + req.len());
        full.push(VERSION);
        full.extend_from_slice(&self.uuid);
        full.extend_from_slice(&req);
        tracing::debug!(
            "vless 请求 {} 字节: {}",
            full.len(),
            full.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );

        if is_vision {
            io.write_all(&full).await?;
            // 响应头：[ver][addon_len]
            let mut resp = [0u8; 2];
            io.read_exact(&mut resp).await?;
            if resp[0] != VERSION {
                return Err(Error::Proto("vless 响应版本不匹配"));
            }
            let addon_len = resp[1] as usize;
            if addon_len > 0 {
                let mut skip = vec![0u8; addon_len];
                io.read_exact(&mut skip).await?;
            }
            Ok(Box::new(VisionStream::new(io)))
        } else {
            // 懒握手：vless 请求不单独成帧、也不阻塞等响应头，而是与消费方的
            // 首个载荷合并同一帧写出。Cloudflare Worker 型服务端只在首条消息里
            // 同时拿到 vless 头+初始载荷才建立上游；空的 vless 首帧会让其对端
            // 静默等待（mihomo 的中继同样把早数据并入首帧）。响应侧的
            // [ver][addon_len][addon] 头由 VlessStream 读取时透明剥离。
            Ok(Box::new(VlessStream {
                inner: io,
                request: Some(full),
                strip: RespStrip::default(),
                decoded: BytesMut::new(),
            }))
        }
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
    strip: RespStrip,
    /// 剥离后待交付的明文余量
    decoded: BytesMut,
}

impl<S> vp_core::ProxyStream for VlessStream<S> where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
}

impl<S> VlessStream<S> {
    /// 若请求仍未发出（消费方先读后写），以独立帧发出（标准 vless 语义；
    /// 写前读的协议极少见，正常代理流量总是先发载荷）
    fn ensure_request_sent(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>>
    where
        S: AsyncWrite + Unpin,
    {
        if let Some(req) = self.request.take() {
            let mut inner = Pin::new(&mut self.inner);
            std::task::ready!(inner.as_mut().poll_write(cx, &req))?;
            std::task::ready!(inner.as_mut().poll_flush(cx))?;
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
        if this.request.is_some() {
            std::task::ready!(this.ensure_request_sent(cx))?;
        }
        if this.strip.phase < 2 {
            // 头未剥离完：经内部缓冲
            while this.decoded.is_empty() {
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
        if let Some(mut req) = this.request.take() {
            // 首写：vless 请求 + 载荷同帧
            req.extend_from_slice(buf);
            Pin::new(&mut this.inner)
                .poll_write(cx, &req)
                .map(|p| p.map(|_| buf.len()))
        } else {
            Pin::new(&mut this.inner).poll_write(cx, buf)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[async_trait]
impl Outbound for VlessOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect_stream(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        let io = transport::dial(&self.server, self.port, &self.transport).await?;
        self.handshake(io, dst).await
    }

    async fn connect_over(
        &self,
        _sess: &Session,
        dst: &DstAddr,
        underlying: Box<dyn ProxyStream>,
    ) -> Result<Box<dyn ProxyStream>> {
        let io = transport::wrap_transport(underlying, &self.server, &self.transport).await?;
        self.handshake(io, dst).await
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
    direct: Arc<DirectOutbound>,
}

impl VlessInbound {
    pub fn new(bind: &str, port: u16, tag: &str, uuids: &[String]) -> Result<Self> {
        let mut ids = Vec::new();
        for u in uuids {
            ids.push(parse_uuid(u)?);
        }
        if ids.is_empty() {
            return Err(Error::Config("vless 入站需要至少一个用户".into()));
        }
        Ok(VlessInbound {
            bind: bind.to_string(),
            port,
            tag: tag.into(),
            uuids: ids,
            direct: Arc::new(DirectOutbound::new(Arc::new(Resolver::system()), false)),
        })
    }

    async fn serve(
        self: &Arc<Self>,
        mut stream: tokio::net::TcpStream,
        src: std::net::SocketAddr,
        ctx: &InboundCtx,
    ) -> Result<()> {
        // 头部最长：1+16+1+1+2+1+255
        let mut buf = vec![0u8; 19 + 256];
        let mut filled = 0;
        loop {
            if filled >= buf.len() {
                return Err(Error::Proto("vless 请求头过长"));
            }
            let n = stream.read(&mut buf[filled..]).await?;
            if n == 0 {
                return Err(Error::Proto("vless 请求头中断"));
            }
            filled += n;
            match decode_request(&buf[..filled]) {
                Ok((uuid, dst, is_vision, used)) => {
                    if !self.uuids.contains(&uuid) {
                        return Err(Error::Proto("vless: 用户认证失败"));
                    }
                    let extra = filled - used;
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
                    if extra > 0 {
                        stream.write_all(&buf[used..filled]).await?;
                    }
                    let meta = vp_core::conn_table::ConnMeta {
                        id: sess.id,
                        inbound: self.tag.clone(),
                        network: "tcp",
                        host: dst.host.to_string(),
                        dst_port: dst.port,
                        src: Some(src.to_string()),
                        process: None,
                        rule: None,
                        chain: Some("vless-server".into()),
                        start: vp_common::now_millis(),
                    };
                    let hook = RelayHook {
                        table: Some(ctx.conns.clone()),
                        meta: Some(meta),
                        stats: Some(ctx.stats.clone()),
                    };
                    let client: Box<dyn ProxyStream> = if is_vision {
                        Box::new(VisionStream::new_server(stream))
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
                Err(e) => return Err(e),
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
        let listener = tokio::net::TcpListener::bind((self.bind.as_str(), self.port)).await?;
        let bound = listener.local_addr()?.port();
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, src)) => {
                        vp_transport::tune(&stream);
                        let this = this.clone();
                        let ctx = ctx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = this.serve(stream, src, &ctx).await {
                                tracing::warn!("vless 入站会话结束: {e}");
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
        let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811".to_string();
        let server =
            VlessInbound::new("127.0.0.1", 0, "vl-srv", std::slice::from_ref(&uuid)).unwrap();
        let port = Arc::new(server).start(ctx).await.unwrap();

        let out = VlessOutbound::new(&VlessCfg {
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
        })
        .unwrap();
        let dst = DstAddr::new("127.0.0.1", echo_addr.port());
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = out.connect_stream(&sess, &dst).await.unwrap();
        s.write_all(b"ping-vless").await.unwrap();
        let mut buf = [0u8; 10];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-vless");
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

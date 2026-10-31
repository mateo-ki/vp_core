//! naive（NaiveProxy）：基于 HTTP/2 CONNECT + 8 包 Padding 的隧道协议。
//!
//! 线格式（对标 klzgrad/naiveproxy 与 Caddy forwardproxy 参考实现）：
//! - 传输层：TLS 流上协商 ALPN `["h2"]`（可选 Chrome uTLS 指纹），亦支持明文 HTTP/2；
//! - 握手：发送 HTTP/2 `CONNECT` 请求：
//!   - `:method = CONNECT`
//!   - `:authority = <dst_host>:<dst_port>`
//!   - `proxy-authorization = Basic <base64(username:password)>`
//!   - `padding = <30..61 字符伪随机串，首 16 字节选自 "!#$()+<>?@[]^{}"，余部填 '~'>`
//! - 服务端校验凭据后回 HTTP 200，并带 `Padding: <随机串>` 头部；
//! - 数据流（8 包 Padding 机制，两端完全对称）：
//!   - 前 8 个写入数据包包裹为：`[u16be data_len][u8 padding_len][data][padding_len 字节零]`；
//!   - 前 8 个读取数据包解析 3 字节头，提取 `data_len` 数据并丢弃 `padding_len` 填充；
//!   - 8 包之后两端均收发裸数据，无任何包装开销；
//! - UDP：通过 UoT（`sp.udp-over-tcp.arpa`）在 CONNECT 隧道内传输。

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use vp_common::{DstAddr, Error, Result};
use vp_config::NaiveCfg;
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;
use vp_core::{Inbound, Outbound, ProxyStream};
use vp_transport as transport;

use crate::direct::DirectOutbound;
use vp_dns::Resolver;

/// 前 8 包进行长度混淆填充
const NUM_FIRST_PADDINGS: usize = 8;
const MAX_CHUNK_DATA: usize = 65535 - 3 - 255;

/// 生成 NaiveProxy 标准 Padding 请求/响应头
fn generate_padding_header() -> String {
    let mut rng_buf = [0u8; 8];
    vp_common::rand_bytes(&mut rng_buf);
    let mut bits = u64::from_le_bytes(rng_buf);
    let pad_chars = b"!#$()+<>?@[]^`{}";
    let mut len_buf = [0u8; 1];
    vp_common::rand_bytes(&mut len_buf);
    let pad_len = 30 + (len_buf[0] as usize % 32);
    let mut s = Vec::with_capacity(pad_len);
    for _ in 0..16 {
        s.push(pad_chars[(bits & 15) as usize]);
        bits >>= 4;
    }
    s.resize(pad_len, b'~');
    String::from_utf8(s).unwrap()
}

// ---------------------------------------------------------------------------
// NaiveStream：双向 HTTP/2 流 + 8 包 Padding 流控
// ---------------------------------------------------------------------------

pub struct NaiveStream {
    recv: h2::RecvStream,
    send: h2::SendStream<Bytes>,
    // 读侧状态
    read_pending: BytesMut,
    read_buf: VecDeque<u8>,
    read_paddings_left: usize,
    read_eof: bool,
    // 写侧状态
    send_buf: BytesMut,
    write_paddings_left: usize,
    closed: bool,
}

impl vp_core::ProxyStream for NaiveStream {}

impl NaiveStream {
    pub fn new(recv: h2::RecvStream, send: h2::SendStream<Bytes>, padding: bool) -> Self {
        let paddings = if padding { NUM_FIRST_PADDINGS } else { 0 };
        NaiveStream {
            recv,
            send,
            read_pending: BytesMut::new(),
            read_buf: VecDeque::new(),
            read_paddings_left: paddings,
            read_eof: false,
            send_buf: BytesMut::new(),
            write_paddings_left: paddings,
            closed: false,
        }
    }

    fn release_capacity(&mut self, n: usize) {
        let _ = self.recv.flow_control().release_capacity(n);
    }

    /// 解析并消费 read_pending 中的数据（解包前 8 个 Padding 帧）
    fn process_incoming(&mut self) -> io::Result<()> {
        while !self.read_pending.is_empty() {
            if self.read_paddings_left > 0 {
                if self.read_pending.len() < 3 {
                    break;
                }
                let data_len =
                    u16::from_be_bytes([self.read_pending[0], self.read_pending[1]]) as usize;
                let pad_len = self.read_pending[2] as usize;
                let total = 3 + data_len + pad_len;
                if self.read_pending.len() < total {
                    break;
                }
                let _ = self.read_pending.split_to(3);
                let data = self.read_pending.split_to(data_len);
                let _ = self.read_pending.split_to(pad_len);
                self.read_buf.extend(data);
                self.read_paddings_left -= 1;
            } else {
                // 8 包已过，后续均为裸数据
                let all = self.read_pending.split();
                self.read_buf.extend(all);
            }
        }
        Ok(())
    }

    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.send_buf.is_empty() {
            self.send.reserve_capacity(self.send_buf.len());
            match self.send.poll_capacity(cx) {
                Poll::Ready(Some(Ok(cap))) => {
                    let n = cap.min(self.send_buf.len());
                    let chunk = Bytes::copy_from_slice(&self.send_buf[..n]);
                    let _ = self.send_buf.split_to(n);
                    match self.send.send_data(chunk, false) {
                        Ok(()) => {}
                        Err(e) => {
                            return Poll::Ready(Err(io::Error::other(format!("naive send: {e}"))));
                        }
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::other(format!("naive capacity: {e}"))));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "naive: 发送流已关闭",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for NaiveStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        rb: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.read_buf.is_empty() {
                let n = self.read_buf.len().min(rb.remaining());
                let (front, back) = self.read_buf.as_slices();
                if front.len() >= n {
                    rb.put_slice(&front[..n]);
                } else {
                    rb.put_slice(front);
                    rb.put_slice(&back[..n - front.len()]);
                }
                self.read_buf.drain(..n);
                return Poll::Ready(Ok(()));
            }
            if self.read_eof {
                return Poll::Ready(Ok(()));
            }

            match Pin::new(&mut self.recv).poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    let n = chunk.len();
                    self.release_capacity(n);
                    self.read_pending.extend_from_slice(&chunk);
                    self.process_incoming()?;
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::other(format!("naive recv: {e}"))));
                }
                Poll::Ready(None) => {
                    self.read_eof = true;
                    // 流关闭后若有残留未完整帧尽量处理
                    self.process_incoming()?;
                    if self.read_buf.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for NaiveStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "naive: 已关闭",
            )));
        }
        ready!(self.flush_pending(cx))?;

        if self.write_paddings_left > 0 {
            let n = data.len().min(MAX_CHUNK_DATA);
            let slice = &data[..n];
            let mut rand_b = [0u8; 1];
            vp_common::rand_bytes(&mut rand_b);
            let pad_len = rand_b[0] as usize;

            self.send_buf.put_u16(n as u16);
            self.send_buf.put_u8(pad_len as u8);
            self.send_buf.put_slice(slice);
            let target_len = self.send_buf.len() + pad_len;
            self.send_buf.resize(target_len, 0);
            self.write_paddings_left -= 1;

            let _ = self.flush_pending(cx);
            Poll::Ready(Ok(n))
        } else {
            self.send_buf.extend_from_slice(data);
            let _ = self.flush_pending(cx);
            Poll::Ready(Ok(data.len()))
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.flush_pending(cx))?;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closed {
            ready!(self.flush_pending(cx))?;
            let _ = self.send.send_trailers(http::HeaderMap::new());
            self.closed = true;
        }
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// NaiveOutbound：HTTP/2 CONNECT 客户端
// ---------------------------------------------------------------------------

pub struct NaiveOutbound {
    name: Arc<str>,
    server: String,
    port: u16,
    auth_header: Option<String>,
    transport: transport::TransportConfig,
    udp: bool,
}

impl NaiveOutbound {
    pub fn new(cfg: &NaiveCfg) -> Result<Self> {
        Self::new_named("naive", cfg)
    }

    pub fn new_named(name: &str, cfg: &NaiveCfg) -> Result<Self> {
        let auth_header = if !cfg.username.is_empty() || !cfg.password.is_empty() {
            let raw = format!("{}:{}", cfg.username, cfg.password);
            Some(format!("Basic {}", BASE64.encode(raw)))
        } else {
            None
        };
        Ok(NaiveOutbound {
            name: name.into(),
            server: cfg.server.clone(),
            port: cfg.port,
            auth_header,
            transport: transport::TransportConfig {
                tls: cfg.tls,
                server_name: cfg.server_name.clone(),
                skip_cert_verify: cfg.skip_cert_verify,
                fingerprint: cfg.client_fingerprint.clone(),
                alpn: cfg
                    .alpn
                    .clone()
                    .filter(|a| !a.is_empty())
                    .unwrap_or_else(|| vec!["h2".into()]),
                ws: None,
                http: None,
                grpc: None,
                reality: None,
                ech: None,
                socket_opts: None,
            },
            udp: cfg.udp,
        })
    }

    async fn connect_h2<S>(&self, io: S, dst: &DstAddr) -> Result<NaiveStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut client, conn) = h2::client::handshake(io)
            .await
            .map_err(|e| Error::Io(io::Error::other(format!("naive h2 握手失败: {e}"))))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let target_authority = format!("{}:{}", dst.host, dst.port);
        let padding_val = generate_padding_header();

        let mut req_builder = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(format!("https://{target_authority}"))
            .header("padding", padding_val);

        if let Some(auth) = &self.auth_header {
            req_builder = req_builder.header("proxy-authorization", auth);
        }

        let req = req_builder
            .body(())
            .map_err(|e| Error::ProtoMsg(format!("naive 请求构造失败: {e}")))?;

        let (resp_fut, send_stream) = client
            .send_request(req, false)
            .map_err(|e| Error::ProtoMsg(format!("naive 请求发送失败: {e}")))?;

        let resp = resp_fut
            .await
            .map_err(|e| Error::ProtoMsg(format!("naive 握手响应失败: {e}")))?;

        if resp.status() != http::StatusCode::OK {
            return Err(Error::ProtoMsg(format!(
                "naive 代理拒绝: 状态码 {}",
                resp.status()
            )));
        }

        let recv_stream = resp.into_body();
        Ok(NaiveStream::new(recv_stream, send_stream, true))
    }
}

#[async_trait]
impl Outbound for NaiveOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect_stream(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        let tcfg = self.transport.clone();
        let io = transport::dial(&self.server, self.port, &tcfg).await?;
        let stream = self.connect_h2(io, dst).await?;
        Ok(Box::new(stream))
    }

    fn support_udp(&self) -> bool {
        self.udp
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
}

// ---------------------------------------------------------------------------
// NaiveInbound：HTTP/2 CONNECT 服务端（兼容 Caddy forwardproxy / NaiveProxy）
// ---------------------------------------------------------------------------

pub struct NaiveInbound {
    bind: String,
    port: u16,
    tag: Arc<str>,
    /// 用户凭据列表：base64(username:password) 集合
    auth_credentials: Vec<String>,
    direct: Arc<DirectOutbound>,
}

impl NaiveInbound {
    pub fn new(bind: &str, port: u16, tag: &str, users: &[String]) -> Result<Self> {
        let mut creds = Vec::new();
        for u in users {
            let encoded = format!("Basic {}", BASE64.encode(u.as_bytes()));
            creds.push(encoded);
        }
        Ok(NaiveInbound {
            bind: bind.to_string(),
            port,
            tag: tag.into(),
            auth_credentials: creds,
            direct: Arc::new(DirectOutbound::new(Arc::new(Resolver::system()), false)),
        })
    }

    async fn handle_connection<S>(&self, io: S, src: SocketAddr) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut server = h2::server::handshake(io)
            .await
            .map_err(|e| Error::Io(io::Error::other(format!("naive 服务端 h2 握手失败: {e}"))))?;

        while let Some(res) = server.accept().await {
            let (req, mut respond) =
                res.map_err(|e| Error::ProtoMsg(format!("naive accept 失败: {e}")))?;

            if req.method() != http::Method::CONNECT {
                let resp = http::Response::builder()
                    .status(http::StatusCode::BAD_REQUEST)
                    .body(())
                    .unwrap();
                let _ = respond.send_response(resp, true);
                continue;
            }

            // 认证校验
            if !self.auth_credentials.is_empty() {
                let auth_ok = req
                    .headers()
                    .get("proxy-authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| self.auth_credentials.iter().any(|c| c == v))
                    .unwrap_or(false);

                if !auth_ok {
                    let resp = http::Response::builder()
                        .status(http::StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                        .body(())
                        .unwrap();
                    let _ = respond.send_response(resp, true);
                    continue;
                }
            }

            // NaiveProxy 要求必须携带 Padding 头部防止指纹被探测
            if !req.headers().contains_key("padding") {
                let resp = http::Response::builder()
                    .status(http::StatusCode::BAD_REQUEST)
                    .body(())
                    .unwrap();
                let _ = respond.send_response(resp, true);
                continue;
            }

            let padding_enabled = true;

            // 目标地址提取
            let target_str = req
                .headers()
                .get("-connect-authority")
                .and_then(|v| v.to_str().ok())
                .or_else(|| req.uri().authority().map(|a| a.as_str()))
                .or_else(|| req.headers().get("host").and_then(|v| v.to_str().ok()))
                .ok_or(Error::Proto("naive: 缺少目标地址"))?;

            let (host, port_str) = target_str
                .rsplit_once(':')
                .ok_or(Error::Proto("naive: 目标地址缺少端口"))?;
            let port = port_str
                .parse::<u16>()
                .map_err(|_| Error::Proto("naive: 目标端口非法"))?;
            let dst = DstAddr::new(host, port);

            // 回复 200 OK
            let mut resp_builder = http::Response::builder().status(http::StatusCode::OK);
            if padding_enabled {
                resp_builder = resp_builder.header("padding", generate_padding_header());
            }
            let resp = resp_builder.body(()).unwrap();
            let send_stream = match respond.send_response(resp, false) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("naive 回送响应失败: {e}");
                    continue;
                }
            };

            let recv_stream = req.into_body();
            let client_stream = NaiveStream::new(recv_stream, send_stream, padding_enabled);

            let direct = self.direct.clone();
            let tag = self.tag.clone();
            tokio::spawn(async move {
                let sess = Session::new_tcp(tag, Some(src), dst.clone());
                match direct.connect_stream(&sess, &dst).await {
                    Ok(remote) => {
                        let (mut cr, mut cw) = tokio::io::split(client_stream);
                        let (mut rr, mut rw) = tokio::io::split(remote);
                        let _ = tokio::select! {
                            r1 = tokio::io::copy(&mut cr, &mut rw) => r1,
                            r2 = tokio::io::copy(&mut rr, &mut cw) => r2,
                        };
                    }
                    Err(e) => {
                        tracing::warn!("naive 目标连接失败: {e}");
                    }
                }
            });
        }
        Ok(())
    }
}

#[async_trait]
impl Inbound for NaiveInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, _ctx: InboundCtx) -> Result<u16> {
        let listener = tokio::net::TcpListener::bind((self.bind.as_str(), self.port)).await?;
        let bound = listener.local_addr()?.port();
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, src)) => {
                        transport::tune(&stream);
                        let this = this.clone();
                        tokio::spawn(async move {
                            if let Err(e) = this.handle_connection(stream, src).await {
                                tracing::debug!("naive 会话结束: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("naive 入站 accept 失败: {e}");
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
    use tokio::time::{Duration, timeout};

    fn test_ctx() -> InboundCtx {
        InboundCtx {
            router: Arc::new(crate::test_support::NoopRouter()),
            stats: Arc::new(vp_common::Stats::default()),
            conns: Arc::new(vp_core::ConnTable::new()),
        }
    }

    async fn echo_server() -> std::sync::Arc<tokio::net::TcpListener> {
        let l = std::sync::Arc::new(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap());
        let l2 = l.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l2.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut b = vec![0u8; 65536];
                    loop {
                        match s.read(&mut b).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&b[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        l
    }

    #[test]
    fn padding_header_format() {
        let p = generate_padding_header();
        assert!((30..=61).contains(&p.len()), "len={}", p.len());
        let valid_chars = b"!#$()+<>?@[]^`{}~";
        for c in p.bytes() {
            assert!(valid_chars.contains(&c), "invalid char {c}");
        }
        // 后半段恒为 ~
        assert!(p[16..].chars().all(|c| c == '~'));
    }

    #[tokio::test]
    async fn naive_loopback() {
        let echo = echo_server().await;
        let echo_port = echo.local_addr().unwrap().port();

        // 启动 Naive 服务端（支持 Padding + Basic Auth）
        let server = Arc::new(
            NaiveInbound::new("127.0.0.1", 0, "naive-srv", &["user1:pass1".to_string()]).unwrap(),
        );
        let srv_port = server.clone().start(test_ctx()).await.unwrap();

        // 构造明文 HTTP/2 Naive 客户端出站
        let cfg = NaiveCfg {
            server: "127.0.0.1".into(),
            port: srv_port,
            username: "user1".into(),
            password: "pass1".into(),
            server_name: None,
            skip_cert_verify: false,
            client_fingerprint: None,
            alpn: None,
            tls: false,
            udp: false,
        };
        let out = NaiveOutbound::new(&cfg).unwrap();

        let dst = DstAddr::new("127.0.0.1", echo_port);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = timeout(Duration::from_secs(5), out.connect_stream(&sess, &dst))
            .await
            .unwrap()
            .unwrap();

        // 小包往返（触发前 8 包 padding 流程）
        for i in 0..10 {
            let msg = format!("ping-naive-{i}");
            s.write_all(msg.as_bytes()).await.unwrap();
            s.flush().await.unwrap();
            let mut buf = vec![0u8; msg.len()];
            timeout(Duration::from_secs(5), s.read_exact(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(buf, msg.as_bytes());
        }

        // 大流量回显（跨越 8 包 Padding 边界，进入纯裸数据阶段，300KB）
        let big: Vec<u8> = (0..300_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 3) as u8)
            .collect();
        let mut rb = vec![0u8; big.len()];
        let (mut rr, mut rw) = tokio::io::split(s);
        let big2 = big.clone();
        let wtask = tokio::spawn(async move {
            rw.write_all(&big2).await.unwrap();
            rw.flush().await.unwrap();
        });
        timeout(Duration::from_secs(20), rr.read_exact(&mut rb))
            .await
            .unwrap()
            .unwrap();
        wtask.await.unwrap();
        assert_eq!(rb, big, "大回显逐字节不一致");
    }

    #[tokio::test]
    async fn naive_wrong_password() {
        let echo = echo_server().await;
        let echo_port = echo.local_addr().unwrap().port();

        let server = Arc::new(
            NaiveInbound::new("127.0.0.1", 0, "naive-srv", &["user1:pass1".to_string()]).unwrap(),
        );
        let srv_port = server.clone().start(test_ctx()).await.unwrap();

        let cfg = NaiveCfg {
            server: "127.0.0.1".into(),
            port: srv_port,
            username: "user1".into(),
            password: "wrong-password".into(),
            server_name: None,
            skip_cert_verify: false,
            client_fingerprint: None,
            alpn: None,
            tls: false,
            udp: false,
        };
        let out = NaiveOutbound::new(&cfg).unwrap();

        let dst = DstAddr::new("127.0.0.1", echo_port);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let res = timeout(Duration::from_secs(5), out.connect_stream(&sess, &dst))
            .await
            .unwrap();
        assert!(res.is_err(), "错误密码应被拒绝: {:?}", res.as_ref().err());
    }

    #[tokio::test]
    async fn naive_missing_padding_rejected() {
        let server = Arc::new(
            NaiveInbound::new("127.0.0.1", 0, "naive-srv", &["user1:pass1".to_string()]).unwrap(),
        );
        let srv_port = server.clone().start(test_ctx()).await.unwrap();

        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", srv_port))
            .await
            .unwrap();
        let (mut client, conn) = h2::client::handshake(tcp).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        // 故意不带 padding 头
        let req = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("https://127.0.0.1:80")
            .header(
                "proxy-authorization",
                format!("Basic {}", BASE64.encode("user1:pass1")),
            )
            .body(())
            .unwrap();

        let (resp_fut, _) = client.send_request(req, false).unwrap();
        let resp = resp_fut.await.unwrap();
        assert_eq!(
            resp.status(),
            http::StatusCode::BAD_REQUEST,
            "缺少 padding 必须返回 400"
        );
    }
}

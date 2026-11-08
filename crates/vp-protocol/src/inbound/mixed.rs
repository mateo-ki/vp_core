//! MIXED 入站：同一端口自动识别 SOCKS5 / HTTP。

use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use tracing::{debug, warn};

use vp_common::{Error, Result};
use vp_core::inbound::InboundCtx;

use super::http_in::serve_http;
use super::socks5_in::serve_socks5;

pub struct MixedInbound {
    bind: String,
    port: u16,
    tag: Arc<str>,
    gate: Option<Arc<vp_core::InboundGate>>,
}

impl MixedInbound {
    pub fn new(bind: String, port: u16, tag: &str) -> Self {
        Self::with_gate(bind, port, tag, None)
    }

    pub fn with_gate(
        bind: String,
        port: u16,
        tag: &str,
        gate: Option<Arc<vp_core::InboundGate>>,
    ) -> Self {
        MixedInbound {
            bind,
            port,
            tag: tag.into(),
            gate,
        }
    }
}

#[async_trait]
impl vp_core::Inbound for MixedInbound {
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
        // SO_REUSEPORT 多监听器：多核 Linux 下每 accept 循环持独立 listener，
        // 内核按四元组哈希把新连接硬分流到不同接收队列，打散单套接字 accept 互斥与 epoll 惊群
        let listeners =
            vp_transport::bind_tcp_listener_many(addr, vp_transport::inbound_listener_count())?;
        let bound = listeners[0].local_addr()?.port();
        let tag = self.tag.clone();
        let this = self.clone();
        for listener in listeners {
            let ctx = ctx.clone();
            let tag = tag.clone();
            let this = this.clone();
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
                            let ctx = ctx.clone();
                            let tag = tag.clone();
                            tokio::spawn(async move {
                                if let Err(e) = serve_mixed(stream, src, tag, &ctx).await {
                                    debug!("mixed 入站会话结束: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            warn!("mixed 入站 accept 失败: {e}");
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        }
                    }
                }
            });
        }
        Ok(bound)
    }
}

const HTTP_METHODS: &[&[u8]] = &[
    b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE",
];

async fn serve_mixed(
    mut stream: tokio::net::TcpStream,
    src: std::net::SocketAddr,
    tag: Arc<str>,
    ctx: &InboundCtx,
) -> Result<()> {
    // 预读大块缓冲（彻底消除单字节 read 系统调用与 IOCP/epoll 线程唤醒风暴）
    let mut temp = [0u8; 1024];
    let n = stream.read(&mut temp).await?;
    if n == 0 {
        return Ok(());
    }
    let first = temp[0];
    let stream = PrefixedStream {
        inner: stream,
        prefix: temp[..n].to_vec(),
        pos: 0,
    };

    if first == 0x05 {
        serve_socks5(stream, src, tag, ctx).await
    } else {
        let looks_http = HTTP_METHODS.iter().any(|m| m[0] == first);
        if looks_http {
            serve_http(stream, src, tag, ctx).await
        } else {
            Err(vp_common::Error::Proto("mixed 入站: 无法识别的协议"))
        }
    }
}

/// 把预读的多字节缓冲注回流的高性能包装器
pub struct PrefixedStream<S> {
    inner: S,
    prefix: Vec<u8>,
    pos: usize,
}

impl<S> vp_core::ProxyStream for PrefixedStream<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static + vp_core::ProxyStream,
{
    // 透传底层裸 socket：mixed 是 Linux 主力入站，缺失本委托会导致
    // 整条 mixed 链路被 splice 零拷贝快速路径排除
    fn raw_socket(&self) -> Option<&tokio::net::TcpStream> {
        if self.pos < self.prefix.len() {
            // 前缀字节尚未排空时绝不能暴露裸 socket：旁路直拷会丢失已读出的前缀
            return None;
        }
        self.inner.raw_socket()
    }

    fn unconsumed_peek(&self) -> Option<&[u8]> {
        if self.pos < self.prefix.len() {
            Some(&self.prefix[self.pos..])
        } else {
            self.inner.unconsumed_peek()
        }
    }

    fn consume_peek(&mut self, len: usize) {
        if self.pos < self.prefix.len() {
            let avail = self.prefix.len() - self.pos;
            let take = avail.min(len);
            self.pos += take;
            let rem = len - take;
            if rem > 0 {
                self.inner.consume_peek(rem);
            }
        } else {
            self.inner.consume_peek(len);
        }
    }

    /// 预读前缀在本层之上照常先交付，切换只影响其后从 inner 读取的部分
    fn switch_to_raw_read(&mut self) -> bool {
        self.inner.switch_to_raw_read()
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let available = self.prefix.len() - self.pos;
            let to_copy = available.min(buf.remaining());
            buf.put_slice(&self.prefix[self.pos..self.pos + to_copy]);
            self.pos += to_copy;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

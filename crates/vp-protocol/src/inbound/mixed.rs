//! MIXED 入站：同一端口自动识别 SOCKS5 / HTTP。

use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tracing::{debug, warn};

use vp_common::Result;
use vp_core::inbound::InboundCtx;

use super::http_in::serve_http;
use super::socks5_in::serve_socks5;

pub struct MixedInbound {
    bind: String,
    port: u16,
    tag: Arc<str>,
}

impl MixedInbound {
    pub fn new(bind: String, port: u16, tag: &str) -> Self {
        MixedInbound { bind, port, tag: tag.into() }
    }
}

#[async_trait]
impl vp_core::Inbound for MixedInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, ctx: InboundCtx) -> Result<u16> {
        let listener = TcpListener::bind((self.bind.as_str(), self.port)).await?;
        let bound = listener.local_addr()?.port();
        let tag = self.tag.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, src)) => {
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
    // 预读首字节判断协议
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await?;
    // 回填：包装流
    let stream = PrefixedStream { inner: stream, prefix: first[0], consumed: false };

    if first[0] == 0x05 {
        serve_socks5(stream, src, tag, ctx).await
    } else {
        let c = first[0];
        let looks_http = HTTP_METHODS.iter().any(|m| m[0] == c);
        if looks_http {
            serve_http(stream, src, tag, ctx).await
        } else {
            Err(vp_common::Error::Proto("mixed 入站: 无法识别的协议"))
        }
    }
}

/// 把预读的一个字节注回流的包装器
pub struct PrefixedStream<S> {
    inner: S,
    prefix: u8,
    consumed: bool,
}

impl<S> PrefixedStream<S> {
    #[allow(dead_code)]
    pub fn new(inner: S, prefix: u8) -> Self {
        PrefixedStream { inner, prefix, consumed: false }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.consumed {
            if buf.remaining() == 0 {
                return std::task::Poll::Ready(Ok(()));
            }
            buf.put_slice(&[self.prefix]);
            self.consumed = true;
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



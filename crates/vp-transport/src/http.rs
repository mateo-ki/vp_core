//! HTTP 伪装传输（Xray / mihomo `network: "http"`）。
//!
//! 客户端把协议载荷作为 HTTP/1.1 请求体发出：首段 write 前插请求头；
//! 首段 read 先解析并剥离响应头（要求 200），其后字节即双向裸流。
//! 与 mihomo transport/vmess/http.go 的 HTTPConn 行为对齐。

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use vp_common::Result;

const MAX_HEADER_BUF: usize = 16 * 1024;

#[derive(Debug, Clone, Default)]
pub struct HttpConfig {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
}

/// 客户端握手：不发网络包，仅构造请求头（首段写时随载荷一并发出，
/// 与 mihomo 的惰性写头一致——部分服务端在收到请求体前不回响应）。
pub fn http_handshake_client<S>(io: S, host: &str, cfg: &HttpConfig) -> Result<HttpStream<S>> {
    let method = if cfg.method.trim().is_empty() {
        "GET"
    } else {
        cfg.method.trim()
    };
    let path = if cfg.path.trim().is_empty() {
        "/"
    } else {
        cfg.path.trim()
    };
    let host_header = cfg
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| host.to_string());
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {host_header}\r\n");
    for (k, v) in &cfg.headers {
        if k.eq_ignore_ascii_case("host") {
            continue;
        }
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    // 兜底伪装头：Xray 默认请求亦带 UA
    if !cfg
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
    {
        head.push_str("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n");
    }
    head.push_str("Connection: keep-alive\r\n\r\n");
    Ok(HttpStream {
        inner: io,
        pending_head: Some(head.into_bytes()),
        resp_head_parsed: false,
        buf: BytesMut::new(),
        out: BytesMut::new(),
    })
}

/// HTTP 伪装流：写方向首段前插请求头；读方向首段剥离响应头。
pub struct HttpStream<S> {
    inner: S,
    pending_head: Option<Vec<u8>>,
    resp_head_parsed: bool,
    buf: BytesMut,
    out: BytesMut,
}

impl<S> vp_core::ProxyStream for HttpStream<S> where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static
{
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HttpStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(head) = self.pending_head.take() {
            // 先把请求头整段写出，再写载荷；头没写完时保持 Pending
            let this = &mut *self;
            match Pin::new(&mut this.inner).poll_write(cx, &head) {
                Poll::Ready(Ok(n)) if n >= head.len() => {}
                Poll::Ready(Ok(n)) => {
                    // 头只写了一部分：剩下的下次续写
                    this.pending_head = Some(head[n..].to_vec());
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    this.pending_head = Some(head);
                    return Poll::Pending;
                }
            }
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(head) = self.pending_head.take() {
            let this = &mut *self;
            match Pin::new(&mut this.inner).poll_write(cx, &head) {
                Poll::Ready(Ok(n)) if n < head.len() => {
                    this.pending_head = Some(head[n..].to_vec());
                }
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    this.pending_head = Some(head);
                }
            }
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for HttpStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        rbuf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.out.is_empty() {
            let n = self.out.len().min(rbuf.remaining());
            let data = self.out.split_to(n);
            rbuf.put_slice(&data);
            return Poll::Ready(Ok(()));
        }
        let this = &mut *self;
        if !this.resp_head_parsed {
            // 读到响应头结束为止
            loop {
                let mut tmp = [0u8; 512];
                let mut read = ReadBuf::new(&mut tmp);
                match Pin::new(&mut this.inner).poll_read(cx, &mut read) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
                let n = read.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "http: 响应头未收到即被对端关闭",
                    )));
                }
                this.buf.extend_from_slice(read.filled());
                if let Some(pos) = find_head_end(&this.buf) {
                    let head = String::from_utf8_lossy(&this.buf[..pos]).to_string();
                    let status_line = head.lines().next().unwrap_or_default();
                    if !status_line.contains("200") {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("http: 响应异常 {status_line}"),
                        )));
                    }
                    let rest = this.buf.split_off(pos + 4);
                    this.buf.clear();
                    this.out = rest;
                    this.resp_head_parsed = true;
                    break;
                }
                if this.buf.len() > MAX_HEADER_BUF {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "http: 响应头过长",
                    )));
                }
            }
        } else {
            // 头已剥离：透传底层
            let mut tmp = [0u8; 2048];
            let mut read = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read) {
                Poll::Ready(Ok(())) => {
                    let filled = read.filled().len();
                    if filled == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    this.out.extend_from_slice(read.filled());
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if this.out.is_empty() {
            // 本轮只拿到了响应头，继续等数据
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let n = this.out.len().min(rbuf.remaining());
        let data = this.out.split_to(n);
        rbuf.put_slice(&data);
        Poll::Ready(Ok(()))
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 环回自测：服务端读请求头 → 回 200 + 响应体；客户端读到的应是裸载荷
    #[tokio::test]
    async fn http_transport_roundtrip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt as _;
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                s.read_exact(&mut byte).await.unwrap();
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&buf);
            assert!(head.starts_with("GET /fake HTTP/1.1"));
            assert!(head.contains("Host: fake.example.com"));
            s.write_all(b"HTTP/1.1 200 OK\r\nServer: xray\r\n\r\nhello-body")
                .await
                .unwrap();
            let mut payload = Vec::new();
            s.read_to_end(&mut payload).await.unwrap();
            assert_eq!(payload, b"ping-payload");
        });
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut st = http_handshake_client(
            tcp,
            "1.2.3.4",
            &HttpConfig {
                method: "GET".into(),
                path: "/fake".into(),
                headers: vec![("Host".into(), "fake.example.com".into())],
            },
        )
        .unwrap();
        st.write_all(b"ping-payload").await.unwrap();
        st.flush().await.unwrap();
        // 半关闭：让服务端 read_to_end 收到 EOF，避免双端互等死锁
        st.shutdown().await.unwrap();
        let mut got = Vec::new();
        st.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello-body");
        server.await.unwrap();
    }

    /// 请求头惰性发送：握手本身不应发包（对齐 mihomo 行为）
    #[tokio::test]
    async fn head_is_lazy() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut b = [0u8; 1];
            // 若客户端握手即发头，这里会立刻读到字节 —— 等待超时即符合预期
            let r =
                tokio::time::timeout(std::time::Duration::from_millis(300), s.read(&mut b)).await;
            assert!(r.is_err(), "握手不应立即发送请求头");
        });
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _st = http_handshake_client(tcp, "h", &HttpConfig::default()).unwrap();
        server.await.unwrap();
    }
}

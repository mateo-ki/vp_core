//! gRPC 传输（Xray 生态风格）：HTTP/2 + 长双向流。
//!
//! - 客户端：POST /{service}/Tun，响应 200 后 DATA 帧承载载荷
//! - 服务端：接受任意 gRPC 请求路径的流
//! - 双向流适配为 ProxyStream（发送=DATA 帧，接收=poll_data）

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use vp_common::{Error, Result};

/// gRPC 服务名（默认 Turbo）
#[derive(Debug, Clone)]
pub struct GrpcConfig {
    pub service_name: String,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        GrpcConfig {
            service_name: "Turbo".into(),
        }
    }
}

/// 双向 gRPC 流（收发共用一条 h2 stream）
pub struct GrpcStream {
    recv: h2::RecvStream,
    send: h2::SendStream<Bytes>,
    /// 接收缓冲（h2 的 poll_data 以 chunk 为单位，需展平）
    pending: bytes::BytesMut,
    send_buf: bytes::BytesMut,
    released: bool,
}

// ---------------------------------------------------------------------------
// 客户端
// ---------------------------------------------------------------------------

/// 在 TLS 流上建立 gRPC（要求 alpn=h2 已协商）
pub async fn grpc_connect<S>(io: S, host: &str, cfg: &GrpcConfig) -> Result<GrpcStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut client, conn) = h2::client::handshake(io)
        .await
        .map_err(|e| Error::Io(std::io::Error::other(format!("h2 握手失败: {e}"))))?;
    // 连接驱动任务
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let uri: http::Uri = format!("https://{host}/{}/Tun", cfg.service_name)
        .parse()
        .map_err(|e| Error::Addr(format!("grpc uri 非法: {e}")))?;
    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .map_err(|e| Error::ProtoMsg(format!("grpc 请求构造失败: {e}")))?;

    let (response, send) = client
        .send_request(req, false)
        .map_err(|e| Error::ProtoMsg(format!("grpc 发送失败: {e}")))?;
    let resp = response
        .await
        .map_err(|e| Error::ProtoMsg(format!("grpc 响应失败: {e}")))?;
    if resp.status() != http::StatusCode::OK {
        return Err(Error::ProtoMsg(format!("grpc 状态 {}", resp.status())));
    }
    let recv = resp.into_body();
    Ok(GrpcStream {
        recv,
        send,
        pending: bytes::BytesMut::new(),
        send_buf: bytes::BytesMut::new(),
        released: true,
    })
}

// ---------------------------------------------------------------------------
// 服务端
// ---------------------------------------------------------------------------

/// 服务端：接受第一个 gRPC 请求并回 200（单连接单流，自测/自建场景）
pub async fn grpc_accept<S>(io: S) -> Result<GrpcStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut server = h2::server::handshake(io)
        .await
        .map_err(|e| Error::Io(std::io::Error::other(format!("h2 服务端握手失败: {e}"))))?;
    let (req, mut respond) = server
        .accept()
        .await
        .ok_or(Error::Proto("grpc: 无请求"))?
        .map_err(|e| Error::ProtoMsg(format!("grpc accept 失败: {e}")))?;
    // 连接驱动：继续 accept（忽略后续请求）以维持 h2 连接存活
    tokio::spawn(async move { while server.accept().await.is_some() {} });
    let recv = req.into_body();
    let resp = http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(())
        .map_err(|e| Error::ProtoMsg(format!("grpc 响应构造失败: {e}")))?;
    let send = respond
        .send_response(resp, false)
        .map_err(|e| Error::ProtoMsg(format!("grpc 回响应失败: {e}")))?;
    Ok(GrpcStream {
        recv,
        send,
        pending: bytes::BytesMut::new(),
        send_buf: bytes::BytesMut::new(),
        released: true,
    })
}

// ---------------------------------------------------------------------------
// 双向流适配
// ---------------------------------------------------------------------------

impl GrpcStream {
    fn release_capacity(&mut self, n: usize) {
        if self.released {
            let _ = self.recv.flow_control().release_capacity(n);
        }
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if !self.pending.is_empty() {
                let n = self.pending.len().min(buf.remaining());
                buf.put_slice(&self.pending[..n]);
                let _ = self.pending.split_to(n);
                return Poll::Ready(Ok(()));
            }
            match std::pin::Pin::new(&mut self.recv).poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    let n = chunk.len();
                    self.release_capacity(n);
                    self.pending.extend_from_slice(&chunk);
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::other(format!("grpc recv: {e}"))));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())), // 流结束
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // 先冲刷积压
        std::task::ready!(self.flush_pending(cx))?;
        self.send_buf.extend_from_slice(buf);
        std::task::ready!(self.flush_pending(cx))?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        std::task::ready!(self.flush_pending(cx))?;
        // h2 SendStream 无显式 flush：数据已在发送缓冲，直接就绪
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        std::task::ready!(self.flush_pending(cx))?;
        self.send
            .send_trailers(http::HeaderMap::new())
            .map_err(|e| std::io::Error::other(format!("grpc shutdown: {e}")))?;
        Poll::Ready(Ok(()))
    }
}

impl GrpcStream {
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while !self.send_buf.is_empty() {
            // h2 语义：先 reserve 再 poll（否则永远 Pending）
            self.send.reserve_capacity(self.send_buf.len());
            match self.send.poll_capacity(cx) {
                Poll::Ready(Some(Ok(cap))) => {
                    let n = cap.min(self.send_buf.len());
                    let chunk: Bytes = Bytes::from(self.send_buf.split_to(n).to_vec());
                    match self.send.send_data(chunk, false) {
                        Ok(()) => {}
                        Err(e) => {
                            return Poll::Ready(Err(std::io::Error::other(format!(
                                "grpc send: {e}"
                            ))));
                        }
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::other(format!("grpc capacity: {e}"))));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "grpc 发送侧关闭",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// gRPC 双向流自环：TLS(h2 ALPN) 之上 client↔server
    #[tokio::test]
    async fn grpc_loopback() {
        use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use tokio_rustls::{TlsAcceptor, rustls::ServerConfig};

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
        let mut sconfig = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        sconfig.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(sconfig));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // 服务端：grpc accept → echo
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            let mut s = grpc_accept(tls).await.unwrap();
            let mut b = [0u8; 1024];
            loop {
                let n = s.read(&mut b).await.unwrap();
                if n == 0 {
                    break;
                }
                s.write_all(&b[..n]).await.unwrap();
            }
        });

        // 客户端
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let cfg = crate::tls::TlsClientConfig {
            ech_config: None,
            skip_cert_verify: true,
            server_name: None,
            alpn: vec!["h2".into()],
        };
        let tls = crate::tls::tls_connect(tcp, "localhost", &cfg)
            .await
            .unwrap();
        let mut c = grpc_connect(tls, "localhost", &GrpcConfig::default())
            .await
            .unwrap();

        c.write_all(b"ping-grpc").await.unwrap();
        let mut buf = [0u8; 9];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-grpc");

        // 大块数据（触发流量控制多轮）：拆半双向
        let big: Vec<u8> = (0..100_000u32).map(|i| (i % 253) as u8).collect();
        let (mut c_r, mut c_w) = tokio::io::split(c);
        let big2 = big.clone();
        tokio::spawn(async move {
            c_w.write_all(&big2).await.unwrap();
            let _ = c_w.shutdown().await;
        });
        let mut got = vec![0u8; big.len()];
        let mut off = 0;
        while off < got.len() {
            let n = c_r.read(&mut got[off..]).await.unwrap();
            if n == 0 {
                break;
            }
            off += n;
        }
        assert_eq!(off, big.len());
    }
}

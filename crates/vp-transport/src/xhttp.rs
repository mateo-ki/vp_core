//! XHTTP 传输（Xray SplitHTTP 后继，RFC 无正式编号，参考 Xray-core 实现约定）：
//! HTTP/2 承载，一条 h2 连接上复用上行与下行请求。
//!
//! - 下行：`GET {path}/{session}` 长响应流，响应体即服务端下发数据；
//!   兼容服务端 `X-Padding` 响应头（跳过等量填充字节）
//! - 上行 `packet-up`（默认，`auto` 同）：每次写入一条
//!   `POST {path}/{session}/{seq}`，body 为整包数据（`content-type: application/grpc`
//!   伪装成 gRPC 流以规避 CDN 缓冲）
//! - 上行 `stream-up`：单条流式 `POST {path}/{session}`，body 即上行流；
//! - 上行 `stream-one`：单条双向 POST——请求体为上行流，响应体为下行流
//!
//! 请求侧不主动填充 X-Padding（服务端可选支持，不发送即最大兼容）；
//! 响应侧必须容忍服务端填充。

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use vp_common::{Error, Result};

/// XHTTP 传输配置
#[derive(Debug, Clone, Default)]
pub struct XhttpConfig {
    /// 伪装路径（默认 "/"）。可携带查询串（如 `?ed=2048`），会话路径插在查询串之前
    pub path: String,
    /// 伪装 Host（:authority）；缺省沿用连接目标
    pub host: Option<String>,
    /// auto / packet-up / stream-up / stream-one；空值按 auto（H2 下即 packet-up）
    pub mode: Option<String>,
    /// 额外伪装请求头（附加到上行与下行请求）
    pub headers: Vec<(String, String)>,
}

/// 上行模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XhttpMode {
    /// 逐包 POST（默认 / auto）
    PacketUp,
    /// 单条流式 POST 上行 + GET 长响应下行
    StreamUp,
    /// 单条双向 POST：请求体上行、响应体下行
    StreamOne,
}

impl XhttpMode {
    fn resolve(mode: Option<&str>) -> XhttpMode {
        match mode.unwrap_or("auto") {
            "stream-up" => XhttpMode::StreamUp,
            "stream-one" => XhttpMode::StreamOne,
            // auto / packet-up / 未知值一律回退 packet-up（H2 最广泛兼容）
            _ => XhttpMode::PacketUp,
        }
    }
}

/// 拆分伪装路径与查询串：`/xhttp?ed=2048` -> (`/xhttp`, `?ed=2048`)
fn split_path_query(path: &str) -> (String, String) {
    match path.split_once('?') {
        Some((p, q)) => (p.trim_end_matches('/').to_string(), format!("?{q}")),
        None => (path.trim_end_matches('/').to_string(), String::new()),
    }
}

/// 生成 RFC 4122 v4 会话 ID（Xray 服务端以 UUID 标识会话）
fn uuid_v4() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

/// 双向 XHTTP 流（下行 = GET/POST 响应体；上行按模式区分）
pub struct XhttpStream {
    recv: h2::RecvStream,
    /// 接收缓冲（h2 poll_data 以 chunk 为单位，需展平）
    pending: BytesMut,
    /// 服务端响应 X-Padding 声明的待跳过填充字节数
    pad_remaining: u64,
    upload: UploadSide,
}

enum UploadSide {
    /// 逐包 POST：每次 poll_write 一条完整请求
    Packet {
        client: h2::client::SendRequest<Bytes>,
        /// URI 前缀（含 authority），形如 `https://host`
        uri_prefix: String,
        /// 会话请求路径（不含 seq），形如 `/xhttp/{session}`
        session_path: String,
        query: String,
        seq: u64,
    },
    /// 流式 POST：body 即上行流（stream-up / stream-one 共用）
    Stream {
        send: h2::SendStream<Bytes>,
        send_buf: BytesMut,
        /// stream-one：关闭时应发送 EOS 而非 trailers（CDN 兼容）
        is_stream_one: bool,
    },
}

impl vp_core::ProxyStream for XhttpStream {}

// ---------------------------------------------------------------------------
// 客户端
// ---------------------------------------------------------------------------

/// 在（TLS）流上建立 XHTTP 会话（要求 ALPN 已协商 h2）
pub async fn xhttp_connect<S>(io: S, server_host: &str, cfg: &XhttpConfig) -> Result<XhttpStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut client, conn) = h2::client::handshake(io)
        .await
        .map_err(|e| Error::Io(std::io::Error::other(format!("h2 握手失败: {e}"))))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let authority = cfg.host.clone().unwrap_or_else(|| server_host.to_string());
    let (base, query) = split_path_query(&cfg.path);
    let session = uuid_v4();
    let mode = XhttpMode::resolve(cfg.mode.as_deref());

    // 通用请求头构造器（伪装 Host 由 URI authority 承载）。
    // 注意：HTTP/2 规范（RFC 9113 §8.1.1）禁止请求携带 Host 头——携带即 malformed，
    // 服务端必须回 400。h2 模式下 Host 头一律跳过，authority 已由 cfg.host / 连接目标给出。
    let apply_headers = |mut b: http::request::Builder| {
        for (k, v) in &cfg.headers {
            if k.eq_ignore_ascii_case("host") {
                continue;
            }
            b = b.header(k.as_str(), v.as_str());
        }
        b
    };

    // stream-one：单条双向 POST——请求体上行、响应体下行（不发独立 GET）
    if mode == XhttpMode::StreamOne {
        let up_path = format!("https://{authority}{base}/{session}{query}");
        let up_req = apply_headers(
            http::Request::builder()
                .method(http::Method::POST)
                .uri(up_path)
                .header("content-type", "application/grpc"),
        )
        .body(())
        .map_err(|e| Error::ProtoMsg(format!("xhttp 上行请求构造失败: {e}")))?;
        let (resp_fut, send) = client
            .send_request(up_req, false)
            .map_err(|e| Error::ProtoMsg(format!("xhttp 上行请求发送失败: {e}")))?;
        let resp = resp_fut
            .await
            .map_err(|e| Error::ProtoMsg(format!("xhttp 双向响应失败: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::ProtoMsg(format!(
                "xhttp 双向响应状态 {}",
                resp.status()
            )));
        }
        let pad_remaining: u64 = resp
            .headers()
            .get("x-padding")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let recv = resp.into_body();
        return Ok(XhttpStream {
            recv,
            pending: BytesMut::new(),
            pad_remaining,
            upload: UploadSide::Stream {
                send,
                send_buf: BytesMut::new(),
                is_stream_one: true,
            },
        });
    }

    // packet-up / stream-up：独立 GET 长响应作下行
    let download_path = format!("https://{authority}{base}/{session}{query}");
    let dl_req = apply_headers(
        http::Request::builder()
            .method(http::Method::GET)
            .uri(download_path)
            .header("x-acc", "0"),
    )
    .body(())
    .map_err(|e| Error::ProtoMsg(format!("xhttp 下行请求构造失败: {e}")))?;
    let dl_resp = client
        .send_request(dl_req, true)
        .map_err(|e| Error::ProtoMsg(format!("xhttp 下行请求发送失败: {e}")))?
        .0
        .await
        .map_err(|e| Error::ProtoMsg(format!("xhttp 下行响应失败: {e}")))?;
    if !dl_resp.status().is_success() {
        let hdrs: Vec<String> = dl_resp
            .headers()
            .iter()
            .map(|(k, v)| format!("{k}: {}", v.to_str().unwrap_or("")))
            .collect();
        return Err(Error::ProtoMsg(format!(
            "xhttp 下行响应状态 {}，响应头: [{}]",
            dl_resp.status(),
            hdrs.join("; ")
        )));
    }
    let pad_remaining: u64 = dl_resp
        .headers()
        .get("x-padding")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let recv = dl_resp.into_body();

    let upload = match mode {
        XhttpMode::PacketUp => UploadSide::Packet {
            client,
            uri_prefix: format!("https://{authority}"),
            session_path: format!("{base}/{session}"),
            query,
            seq: 0,
        },
        XhttpMode::StreamOne => unreachable!("stream-one 已在函数前段提前返回"),
        XhttpMode::StreamUp => {
            let up_path = format!("https://{authority}{base}/{session}{query}");
            let up_req = apply_headers(
                http::Request::builder()
                    .method(http::Method::POST)
                    .uri(up_path)
                    .header("content-type", "application/grpc"),
            )
            .body(())
            .map_err(|e| Error::ProtoMsg(format!("xhttp 上行请求构造失败: {e}")))?;
            let (resp_fut, send) = client
                .send_request(up_req, false)
                .map_err(|e| Error::ProtoMsg(format!("xhttp 上行请求发送失败: {e}")))?;
            // stream-up：响应在后台排空（服务端可能立即回 200 或延迟回复）
            tokio::spawn(async move {
                if let Ok(resp) = resp_fut.await {
                    let mut body = resp.into_body();
                    while let Some(chunk) = body.data().await {
                        match chunk {
                            Ok(c) => {
                                let _ = body.flow_control().release_capacity(c.len());
                            }
                            Err(_) => break,
                        }
                    }
                }
            });
            UploadSide::Stream {
                send,
                send_buf: BytesMut::new(),
                is_stream_one: false,
            }
        }
    };

    Ok(XhttpStream {
        recv,
        pending: BytesMut::new(),
        pad_remaining,
        upload,
    })
}

// ---------------------------------------------------------------------------
// 双向流适配
// ---------------------------------------------------------------------------

impl XhttpStream {
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let UploadSide::Stream { send, send_buf, .. } = &mut self.upload else {
            // packet 模式：每条 write 已是完整请求，无积压
            return Poll::Ready(Ok(()));
        };
        while !send_buf.is_empty() {
            send.reserve_capacity(send_buf.len());
            match send.poll_capacity(cx) {
                Poll::Ready(Some(Ok(cap))) => {
                    let n = cap.min(send_buf.len());
                    let chunk: Bytes = Bytes::from(send_buf.split_to(n).to_vec());
                    send.send_data(chunk, false)
                        .map_err(|e| std::io::Error::other(format!("xhttp send: {e}")))?;
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::other(format!("xhttp capacity: {e}"))));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "xhttp 发送侧关闭",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for XhttpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            // 先消费服务端声明的填充字节
            if this.pad_remaining > 0 && !this.pending.is_empty() {
                let take = (this.pending.len() as u64).min(this.pad_remaining) as usize;
                let _ = this.pending.split_to(take);
                this.pad_remaining -= take as u64;
                continue;
            }
            if !this.pending.is_empty() {
                let n = this.pending.len().min(buf.remaining());
                buf.put_slice(&this.pending[..n]);
                let _ = this.pending.split_to(n);
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut this.recv).poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    let n = chunk.len();
                    let _ = this.recv.flow_control().release_capacity(n);
                    this.pending.extend_from_slice(&chunk);
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::other(format!("xhttp recv: {e}"))));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())), // 下行流结束
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for XhttpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match &mut this.upload {
            UploadSide::Packet {
                client,
                uri_prefix,
                session_path,
                query,
                seq,
            } => {
                std::task::ready!(
                    client
                        .poll_ready(cx)
                        .map_err(|e| std::io::Error::other(format!("xhttp ready: {e}")))
                )?;
                let up_path = format!("{uri_prefix}{session_path}/{seq}{query}");
                let req = http::Request::builder()
                    .method(http::Method::POST)
                    .uri(up_path)
                    .header("content-type", "application/grpc")
                    .body(())
                    .map_err(|e| std::io::Error::other(format!("xhttp 上行请求构造失败: {e}")))?;
                let (resp_fut, mut send) = client
                    .send_request(req, false)
                    .map_err(|e| std::io::Error::other(format!("xhttp send: {e}")))?;
                // 整包数据一次写入并 EOS 关闭
                send.send_data(Bytes::copy_from_slice(buf), true)
                    .map_err(|e| std::io::Error::other(format!("xhttp send: {e}")))?;
                // 后台排空响应（服务端回 200 空体），避免 h2 连接流控窗口堆积
                tokio::spawn(async move {
                    if let Ok(resp) = resp_fut.await {
                        let mut body = resp.into_body();
                        while let Some(chunk) = body.data().await {
                            match chunk {
                                Ok(c) => {
                                    let _ = body.flow_control().release_capacity(c.len());
                                }
                                Err(_) => break,
                            }
                        }
                    }
                });
                *seq += 1;
                Poll::Ready(Ok(buf.len()))
            }
            UploadSide::Stream { .. } => {
                // 注意 poll_write 重入语义：若 flush 返回 Pending，数据已入 send_buf，
                // 调用方会以同一 buf 重轮询——绝不能再追加。此处接受写入后即使冲刷
                // 挂起也上报完成，由 poll_flush / poll_shutdown 保证最终投递。
                std::task::ready!(this.flush_pending(cx))?;
                let UploadSide::Stream { send_buf, .. } = &mut this.upload else {
                    unreachable!()
                };
                send_buf.extend_from_slice(buf);
                match this.flush_pending(cx) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Ready(Ok(buf.len())),
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.flush_pending(cx))?;
        // h2 SendStream 无显式 flush：数据已在发送缓冲
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.flush_pending(cx))?;
        match &mut this.upload {
            UploadSide::Packet { .. } => Poll::Ready(Ok(())),
            UploadSide::Stream {
                send,
                is_stream_one,
                ..
            } => {
                if *is_stream_one {
                    // 单条双向：以空 DATA 帧 + EOS 关闭上传半边（CDN 不接受 trailers）
                    send.send_data(Bytes::new(), true)
                        .map_err(|e| std::io::Error::other(format!("xhttp shutdown: {e}")))?;
                } else {
                    send.send_trailers(http::HeaderMap::new())
                        .map_err(|e| std::io::Error::other(format!("xhttp shutdown: {e}")))?;
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 单元测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_split_path_query() {
        assert_eq!(
            split_path_query("/xhttp?ed=2048"),
            ("/xhttp".to_string(), "?ed=2048".to_string())
        );
        assert_eq!(
            split_path_query("/xhttp/"),
            ("/xhttp".to_string(), String::new())
        );
        assert_eq!(split_path_query("/"), (String::new(), String::new()));
        assert_eq!(
            split_path_query("/a/b"),
            ("/a/b".to_string(), String::new())
        );
    }

    #[test]
    fn test_uuid_v4_shape() {
        let u = uuid_v4();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
        let v = u.as_bytes()[19] as char;
        assert!(matches!(v, '8' | '9' | 'a' | 'b'));
    }

    #[test]
    fn test_mode_resolve() {
        assert_eq!(XhttpMode::resolve(None), XhttpMode::PacketUp);
        assert_eq!(XhttpMode::resolve(Some("auto")), XhttpMode::PacketUp);
        assert_eq!(XhttpMode::resolve(Some("packet-up")), XhttpMode::PacketUp);
        assert_eq!(XhttpMode::resolve(Some("stream-up")), XhttpMode::StreamUp);
        assert_eq!(XhttpMode::resolve(Some("stream-one")), XhttpMode::StreamOne);
        assert_eq!(XhttpMode::resolve(Some("future-mode")), XhttpMode::PacketUp);
    }

    /// XHTTP 回环：TLS(h2) 之上 client ↔ 参考实现 server。
    /// 服务端语义（对齐 Xray）：按路径深度分类——
    /// - GET `{base}/{session}`：下行长响应（200 + X-Padding 声明 + 填充字节 + 会话数据回放）
    /// - POST `{base}/{session}/{seq}`：packet-up 上行（读整包 → 追加会话缓冲 → 回 200 空体）
    /// - POST `{base}/{session}`：双向流（读请求体上行 + 响应体下行回放，stream-up/stream-one 同形）
    async fn spawn_reference_server() -> std::net::SocketAddr {
        use std::collections::HashMap as StdHashMap;
        use std::sync::Arc as StdArc;
        use tokio::sync::Mutex;
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

        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            let mut server = h2::server::handshake(tls).await.unwrap();
            // 会话缓冲：session -> 已收到的上行数据
            let sessions: StdArc<Mutex<StdHashMap<String, Vec<u8>>>> =
                StdArc::new(Mutex::new(StdHashMap::new()));
            loop {
                let Some(Ok((req, mut respond))) = server.accept().await else {
                    break;
                };
                let sessions = sessions.clone();
                tokio::spawn(async move {
                    let method = req.method().clone();
                    let path = req.uri().path().to_string();
                    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
                    let depth = parts.len();
                    let mut body = req.into_body();

                    if method == http::Method::GET {
                        // 下行：GET {base}/{session} → 200 + 填充 + 回放
                        let session = parts.last().copied().unwrap_or("").to_string();
                        download_respond(respond, sessions, session).await;
                    } else if depth >= 3 {
                        // packet-up 上行：读整包 → 入会话缓冲 → 200 空体
                        let session = parts.get(depth - 2).copied().unwrap_or("").to_string();
                        while let Some(chunk) = body.data().await {
                            match chunk {
                                Ok(c) => {
                                    let _ = body.flow_control().release_capacity(c.len());
                                    sessions
                                        .lock()
                                        .await
                                        .entry(session.clone())
                                        .or_default()
                                        .extend_from_slice(&c);
                                }
                                Err(_) => break,
                            }
                        }
                        let resp = http::Response::builder().status(200).body(()).unwrap();
                        let _ = respond.send_response(resp, true);
                    } else {
                        // 双向流 POST {base}/{session}：响应即下行，请求体并发读入会话缓冲
                        let session = parts.last().copied().unwrap_or("").to_string();
                        let reader_session = session.clone();
                        let buf = sessions.clone();
                        let reader = tokio::spawn(async move {
                            while let Some(chunk) = body.data().await {
                                match chunk {
                                    Ok(c) => {
                                        let _ = body.flow_control().release_capacity(c.len());
                                        buf.lock()
                                            .await
                                            .entry(reader_session.clone())
                                            .or_default()
                                            .extend_from_slice(&c);
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                        download_respond(respond, sessions, session).await;
                        let _ = reader.await;
                    }
                });
            }
        });
        addr
    }

    /// 下行响应：200 + `X-Padding: 3` + 3 填充字节 + 会话缓冲增量回放（静默 100ms 后结束）
    async fn download_respond(
        mut respond: h2::server::SendResponse<Bytes>,
        sessions: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>>,
        session: String,
    ) {
        let resp = http::Response::builder()
            .status(200)
            .header("x-padding", "3")
            .body(())
            .unwrap();
        let Ok(mut send) = respond.send_response(resp, false) else {
            return;
        };
        let _ = send.send_data(Bytes::from_static(b"abc"), false);
        let mut sent = 0usize;
        let mut quiet = 0u32;
        for _ in 0..300 {
            let cur = sessions
                .lock()
                .await
                .entry(session.clone())
                .or_default()
                .clone();
            if cur.len() > sent {
                if send
                    .send_data(Bytes::from(cur[sent..].to_vec()), false)
                    .is_err()
                {
                    return;
                }
                sent = cur.len();
                quiet = 0;
            } else if sent > 0 {
                quiet += 1;
                if quiet >= 5 {
                    break; // 100ms 无新增：认为上行结束
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let _ = send.send_data(Bytes::new(), true);
    }

    async fn client_connect(addr: std::net::SocketAddr, mode: Option<&str>) -> XhttpStream {
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
        xhttp_connect(
            tls,
            "localhost",
            &XhttpConfig {
                path: "/xhttp".into(),
                host: None,
                mode: mode.map(String::from),
                headers: Vec::new(),
            },
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn xhttp_packet_up_loopback() {
        let addr = spawn_reference_server().await;
        let mut c = client_connect(addr, None).await;
        c.write_all(b"ping-xhttp").await.unwrap();
        let mut buf = [0u8; 10];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-xhttp");
    }

    #[tokio::test]
    async fn xhttp_stream_up_loopback() {
        let addr = spawn_reference_server().await;
        let mut c = client_connect(addr, Some("stream-up")).await;
        c.write_all(b"stream-hello").await.unwrap();
        let _ = c.flush().await;
        let _ = c.shutdown().await;
        let mut buf = Vec::new();
        c.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"stream-hello");
    }

    #[tokio::test]
    async fn xhttp_stream_one_loopback() {
        let addr = spawn_reference_server().await;
        let mut c = client_connect(addr, Some("stream-one")).await;
        c.write_all(b"one-hello").await.unwrap();
        let _ = c.flush().await;
        let _ = c.shutdown().await;
        let mut buf = Vec::new();
        c.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"one-hello");
    }

    /// packet-up 吞吐基准：4 MB 双向回环（本机 h2 上下行，可观测传输层开销）
    #[tokio::test]
    async fn xhttp_packet_up_throughput() {
        use std::time::Instant;
        let addr = spawn_reference_server().await;
        let mut c = client_connect(addr, None).await;

        // 4 MB 随机载荷分 64 KB 块上行
        let total = 4 * 1024 * 1024usize;
        let chunk = vec![0xABu8; 64 * 1024];
        let start = Instant::now();
        let mut sent = 0usize;
        while sent < total {
            c.write_all(&chunk).await.unwrap();
            sent += chunk.len();
        }
        c.flush().await.unwrap();

        // 下行读回等量数据
        let mut got = 0usize;
        let mut buf = [0u8; 64 * 1024];
        while got < total {
            let n = c.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            got += n;
        }
        let secs = start.elapsed().as_secs_f64();
        assert_eq!(got, total, "回环数据量应守恒");
        let mbps = (total as f64 / 1024.0 / 1024.0) / secs;
        println!("xhttp packet-up loopback: 4 MB in {secs:.3}s = {mbps:.1} MB/s");
        assert!(
            mbps > 10.0,
            "本机回环吞吐不应低于 10 MB/s（实测 {mbps:.1}）"
        );
    }
}

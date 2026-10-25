//! HTTP 代理入站：CONNECT 隧道 + absolute-form 请求改写转发。

use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, warn};

use vp_common::{DstAddr, Result};
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;

use super::dispatch::{dispatch_stream, ClientReply};

pub struct HttpInbound {
    bind: String,
    port: u16,
    tag: Arc<str>,
}

impl HttpInbound {
    pub fn new(bind: String, port: u16, tag: &str) -> Self {
        HttpInbound { bind, port, tag: tag.into() }
    }
}

#[async_trait]
impl vp_core::Inbound for HttpInbound {
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
                            if let Err(e) = serve_http(stream, src, tag, &ctx).await {
                                debug!("http 入站会话结束: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        warn!("http 入站 accept 失败: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        });
        Ok(bound)
    }
}

pub async fn serve_http<S>(
    mut stream: S,
    src: std::net::SocketAddr,
    tag: Arc<str>,
    ctx: &InboundCtx,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // 读请求头
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(vp_common::Error::Proto("http 入站: 请求中断"));
        }
        buf.push(byte[0]);
        if buf.len() > 32 * 1024 {
            return Err(vp_common::Error::Proto("http 入站: 请求头过长"));
        }
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    if method.eq_ignore_ascii_case("CONNECT") {
        // CONNECT host:port
        let dst = DstAddr::parse(target)?;
        let sess = Session::new_tcp(tag, Some(src), dst);
        dispatch_stream(ctx, sess, Box::new(stream), ClientReply::Http("200 Connection established"))
            .await;
        return Ok(());
    }

    // absolute-form: GET http://host/path → 转发时改写为相对路径
    let (host, rewritten) = match target.strip_prefix("http://").or_else(|| target.strip_prefix("https://")) {
        Some(rest) => {
            let (h, path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => (rest, "/"),
            };
            (h.to_string(), path.to_string())
        }
        None => {
            // origin-form：从 Host 头取目标
            let host = lines
                .find_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).filter(|(k, _)| k == "host"))
                .and_then(|(_, v)| Some(v))
                .ok_or(vp_common::Error::Proto("http 入站: 缺少 Host"))?;
            (host, target.to_string())
        }
    };
    let dst = DstAddr::new(host.clone(), 80);
    // 改写请求行（absolute-form → origin-form）
    let new_first_line = format!("{method} {rewritten} HTTP/1.1");
    let mut new_req = new_first_line.into_bytes();
    if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
        new_req.extend_from_slice(&buf[pos + 2..]);
    }

    // absolute-form：响应由远端直接透传，不做本地应答
    let sess = Session::new_tcp(tag, Some(src), dst);
    let outbound = ctx.router.pick(&sess).await;
    match outbound.outbound.connect_stream(&sess, &sess.dst).await {
        Ok(mut remote) => {
            remote.write_all(&new_req).await?;
            let client: Box<dyn vp_core::ProxyStream> = Box::new(stream);
            let hook = vp_core::tunnel::RelayHook {
                table: Some(ctx.conns.clone()),
                meta: Some(vp_core::conn_table::ConnMeta {
                    id: sess.id,
                    inbound: sess.inbound.clone(),
                    network: "tcp",
                    host: sess.dst.host.to_string(),
                    dst_port: sess.dst.port,
                    src: sess.src.map(|s| s.to_string()),
                    process: sess.process.clone(),
                    rule: outbound.rule.as_ref().map(|r| format!("{} => {}", r.rule, r.target)),
                    chain: Some(outbound.via.clone()),
                    start: vp_common::now_millis(),
                }),
                stats: Some(ctx.stats.clone()),
            };
            let _ = vp_core::tunnel::relay(client, remote, hook).await;
            Ok(())
        }
        Err(e) => {
            warn!("http 入站出站失败: {e}");
            stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok(())
        }
    }
}

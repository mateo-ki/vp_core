//! HTTP 代理入站：CONNECT 隧道 + absolute-form 请求改写转发。

use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, warn};

use vp_common::{DstAddr, Error, Result};
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;

use super::dispatch::{ClientReply, dispatch_stream};

pub struct HttpInbound {
    bind: String,
    port: u16,
    tag: Arc<str>,
    gate: Option<Arc<vp_core::InboundGate>>,
}

impl HttpInbound {
    pub fn new(bind: String, port: u16, tag: &str) -> Self {
        Self::with_gate(bind, port, tag, None)
    }

    pub fn with_gate(
        bind: String,
        port: u16,
        tag: &str,
        gate: Option<Arc<vp_core::InboundGate>>,
    ) -> Self {
        HttpInbound {
            bind,
            port,
            tag: tag.into(),
            gate,
        }
    }
}

#[async_trait]
impl vp_core::Inbound for HttpInbound {
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
        }
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
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static + vp_core::ProxyStream,
{
    // 读请求头：大块批量读取，避免逐字节 read 引发的 Windows IOCP 线程风暴与高 CPU 消耗
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut temp = [0u8; 2048];
    let header_len = loop {
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            return Err(vp_common::Error::Proto("http 入站: 请求中断"));
        }
        buf.extend_from_slice(&temp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 32 * 1024 {
            return Err(vp_common::Error::Proto("http 入站: 请求头过长"));
        }
    };
    let body_prefix = buf.split_off(header_len);

    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    let mut user = None;
    for l in text.split("\r\n") {
        if let Some((k, v)) = l.split_once(':') {
            if k.trim().eq_ignore_ascii_case("proxy-authorization") {
                if let Some(rest) = v.trim().strip_prefix("Basic ") {
                    use base64::Engine;
                    if let Ok(decoded) =
                        base64::engine::general_purpose::STANDARD.decode(rest.trim())
                    {
                        if let Ok(cred) = String::from_utf8(decoded) {
                            if let Some((u, _)) = cred.split_once(':') {
                                user = Some(u.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        // CONNECT host:port
        let dst = DstAddr::parse(target)?;
        let mut sess = Session::new_tcp(tag, Some(src), dst);
        if let Some(u) = user {
            sess = sess.with_inbound_user(u);
        }
        let client: Box<dyn vp_core::ProxyStream> = if body_prefix.is_empty() {
            Box::new(stream)
        } else {
            Box::new(vp_core::PeekedStream::new(stream, body_prefix))
        };
        dispatch_stream(
            ctx,
            sess,
            client,
            ClientReply::Http("200 Connection established"),
        )
        .await;
        return Ok(());
    }

    // absolute-form: GET http://host[:port]/path → 转发时改写为相对路径
    let (target_host, target_port, rewritten) = match target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
    {
        Some(rest) => {
            let is_https = target.starts_with("https://");
            let default_port = if is_https { 443 } else { 80 };
            let (hp, path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => (rest, "/"),
            };
            let (h, p) = match hp.rsplit_once(':') {
                Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
                    (h, p.parse().unwrap_or(default_port))
                }
                _ => (hp, default_port),
            };
            (h, p, path)
        }
        None => {
            // origin-form：从 Host 头取目标
            let host_header = lines
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    if k.trim().eq_ignore_ascii_case("host") {
                        Some(v.trim())
                    } else {
                        None
                    }
                })
                .ok_or(vp_common::Error::Proto("http 入站: 缺少 Host"))?;
            let (h, p) = match host_header.rsplit_once(':') {
                Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
                    (h, p.parse().unwrap_or(80))
                }
                _ => (host_header, 80),
            };
            (h, p, target)
        }
    };
    let dst = match target_host.parse::<std::net::IpAddr>() {
        Ok(ip) => DstAddr::ip(ip, target_port),
        Err(_) => DstAddr::new(target_host, target_port),
    };
    // 改写请求行（absolute-form → origin-form），剥离代理逐跳头并强制 Connection: close
    //（单次请求模型下避免上游保持 keep-alive 导致连接池复用时被误 reset）。
    let mut new_req = rewrite_http_proxy_request(method, rewritten, &buf);
    if !body_prefix.is_empty() {
        new_req.extend_from_slice(&body_prefix);
    }

    // absolute-form：响应由远端直接透传，不做本地应答
    let mut sess = Session::new_tcp(tag, Some(src), dst);
    if let Some(u) = user {
        sess = sess.with_inbound_user(u);
    }
    let outbound = ctx.router.pick(&sess).await;
    let connect_res = if outbound.outbound.name() == crate::consts::OUTBOUND_DIRECT {
        match tokio::time::timeout(
            std::time::Duration::from_millis(crate::consts::DIRECT_CONNECT_TIMEOUT_MS),
            outbound.outbound.connect_stream(&sess, &sess.dst),
        )
        .await
        {
            Ok(res) => res,
            Err(_) => Err(vp_common::Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "DIRECT 直连超时 ({}ms)",
                    crate::consts::DIRECT_CONNECT_TIMEOUT_MS
                ),
            ))),
        }
    } else {
        outbound.outbound.connect_stream(&sess, &sess.dst).await
    };
    let (mut remote, effective_via) = match connect_res {
        Ok(rem) => (rem, outbound.via.clone()),
        Err(e) if outbound.outbound.name() == crate::consts::OUTBOUND_DIRECT => {
            if let Some(host_str) = sess.dst.host.as_domain() {
                vp_core::adaptive::record_block(host_str);
            }
            if let Some(fallback) = ctx.router.fallback_proxy_outbound() {
                match fallback.connect_stream(&sess, &sess.dst).await {
                    Ok(rem) => (rem, Arc::from(format!("Adaptive > {}", fallback.name()))),
                    Err(proxy_err) => {
                        warn!(
                            "[HTTP] {} 自适应重试代理 {} 亦失败: {}",
                            sess.dst,
                            fallback.name(),
                            proxy_err
                        );
                        send_http_reply(
                            &mut stream,
                            b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                        )
                        .await;
                        return Ok(());
                    }
                }
            } else {
                warn!("http 入站 DIRECT 出站失败且无可用代理: {e}");
                send_http_reply(
                    &mut stream,
                    b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                )
                .await;
                return Ok(());
            }
        }
        Err(e) => {
            if outbound.outbound.name() == "REJECT" || e.to_string().contains("REJECT") {
                tracing::info!("[HTTP] {} 出站 REJECT 阻断", sess.dst);
                send_http_reply(
                    &mut stream,
                    b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                )
                .await;
                return Ok(());
            }
            warn!("http 入站出站失败: {e}");
            send_http_reply(
                &mut stream,
                b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            )
            .await;
            return Ok(());
        }
    };
    if let Err(e) = remote.write_all(&new_req).await {
        warn!("http 入站写入上游请求失败: {e}");
        send_http_reply(
            &mut stream,
            b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        return Ok(());
    }
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
            user: None,
            rule: outbound
                .rule
                .as_ref()
                .map(|r| format!("{} => {}", r.rule, r.target)),
            chain: Some(effective_via),
            start: vp_common::now_millis(),
        }),
        stats: Some(ctx.stats.clone()),
        ..Default::default()
    };
    let _ = vp_core::tunnel::relay(client, remote, hook).await;
    Ok(())
}

async fn send_http_reply<S: AsyncWrite + Unpin>(stream: &mut S, reply: &[u8]) {
    let _ = stream.write_all(reply).await;
    let _ = stream.shutdown().await;
}

/// 改写发往上游的 HTTP/1.1 请求头：
/// - 替换请求目标为 origin-form；
/// - 剥离 `Proxy-Connection` / `Proxy-Authorization` 等代理逐跳头；
/// - 强制 `Connection: close`，防止上游保持 keep-alive 导致无循环转发在复用时重置。
fn rewrite_http_proxy_request(method: &str, rewritten_target: &str, raw_head: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(raw_head);
    let mut lines = text.split("\r\n");
    let _req_line = lines.next();

    let mut out = Vec::with_capacity(raw_head.len() + 32);
    out.extend_from_slice(method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(rewritten_target.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");

    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, _)) = line.split_once(':') {
            let key = name.trim();
            if key.eq_ignore_ascii_case("proxy-connection")
                || key.eq_ignore_ascii_case("proxy-authorization")
                || key.eq_ignore_ascii_case("connection")
            {
                continue;
            }
        }
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_proxy_headers_to_origin_close() {
        let raw = b"POST http://api.example.com/v1/messages HTTP/1.1\r\nHost: api.example.com\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic abc\r\nConnection: keep-alive\r\nContent-Length: 2\r\n\r\n";
        let got = rewrite_http_proxy_request("POST", "/v1/messages", raw);
        let text = String::from_utf8(got).unwrap();
        assert!(text.starts_with("POST /v1/messages HTTP/1.1\r\n"));
        assert!(text.contains("Host: api.example.com\r\n"));
        assert!(text.contains("Content-Length: 2\r\n"));
        assert!(!text.to_ascii_lowercase().contains("proxy-connection:"));
        assert!(!text.to_ascii_lowercase().contains("proxy-authorization:"));
        assert_eq!(text.matches("Connection: close\r\n").count(), 1);
        assert!(text.ends_with("\r\n\r\n"));
    }
}

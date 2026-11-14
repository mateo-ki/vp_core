//! HTTPUpgrade 传输（Xray / mihomo `network: "httpupgrade"`）：
//! 标准 HTTP/1.1 Upgrade 握手，101 Switching Protocols 之后进入**裸流**双向隧道
//! （区别于 WebSocket 的帧封装：无掩码、无分帧，语义等同一条直连 TCP 流）。
//!
//! 握手请求对齐 Xray 实现：携带 `Upgrade: websocket` 与 `Sec-WebSocket-Key`/
//! `Sec-WebSocket-Version`（服务端/CDN 只校验请求头形状，不进行帧编解码）。

use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use vp_common::{Error, Result};

const MAX_HEADER_BUF: usize = 8192;

/// HTTPUpgrade 传输配置（路径与伪装头复用 ws-opts 语义，与 mihomo 一致）
#[derive(Debug, Clone, Default)]
pub struct HttpUpgradeConfig {
    pub path: String,
    pub headers: Vec<(String, String)>,
}

/// 在（可选 TLS）流上执行 HTTPUpgrade 握手；成功后返回裸流。
pub async fn httpupgrade_connect<S>(mut io: S, host: &str, cfg: &HttpUpgradeConfig) -> Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut key_bytes = [0u8; 16];
    vp_common::rand_bytes(&mut key_bytes);
    let key = base64::engine::general_purpose::STANDARD.encode(key_bytes);
    let path = if cfg.path.is_empty() { "/" } else { &cfg.path };
    // Host 覆盖支持（部分服务按 Host 分流）
    let host_header = cfg
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| host.to_string());
    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
    );
    let mut has_ua = false;
    for (k, v) in &cfg.headers {
        if !k.eq_ignore_ascii_case("host") {
            if k.eq_ignore_ascii_case("user-agent") {
                has_ua = true;
            }
            req.push_str(&format!("{k}: {v}\r\n"));
        }
    }
    if !has_ua {
        req.push_str("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\n");
    }
    req.push_str("\r\n");
    io.write_all(req.as_bytes()).await?;

    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        let n = io.read(&mut byte).await?;
        if n == 0 {
            return Err(Error::Proto("httpupgrade: 握手响应中断"));
        }
        buf.push(byte[0]);
        if buf.len() > MAX_HEADER_BUF {
            return Err(Error::Proto("httpupgrade: 响应头过长"));
        }
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let status_line = head.lines().next().unwrap_or_default();
    if !status_line.contains("101") {
        return Err(Error::ProtoMsg(format!(
            "httpupgrade: 握手失败 {status_line}"
        )));
    }
    tracing::debug!("httpupgrade: 握手完成（101），进入裸流隧道");
    Ok(io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
    use vp_common::Result;

    /// 参考服务端：校验升级请求形状 → 回 101 → 之后原样回显（裸流）
    async fn spawn_reference_server() -> DuplexStream {
        let (client_io, mut server_io) = duplex(4096);
        tokio::spawn(async move {
            // 读取请求头
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                let n = server_io.read(&mut byte).await.unwrap();
                if n == 0 {
                    return;
                }
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&buf);
            let head_lower = head.to_ascii_lowercase();
            assert!(
                head_lower.starts_with("get /upgrade HTTP/1.1".to_ascii_lowercase().as_str())
                    || head.starts_with("GET /upgrade HTTP/1.1")
            );
            assert!(head_lower.contains("upgrade: websocket"));
            assert!(head_lower.contains("connection: upgrade"));
            assert!(head_lower.contains("sec-websocket-key:"));
            server_io
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                )
                .await
                .unwrap();
            // 裸流回显
            let (mut r, mut w) = tokio::io::split(server_io);
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        client_io
    }

    #[tokio::test]
    async fn httpupgrade_loopback() -> Result<()> {
        let server = spawn_reference_server().await;
        let cfg = HttpUpgradeConfig {
            path: "/upgrade".into(),
            headers: vec![("x-test".into(), "1".into())],
        };
        let mut s = httpupgrade_connect(server, "localhost", &cfg).await?;
        s.write_all(b"hello-upgrade").await?;
        let mut buf = [0u8; 13];
        s.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"hello-upgrade");
        Ok(())
    }

    #[tokio::test]
    async fn rejects_non_101() {
        let (client_io, mut server_io) = duplex(4096);
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                let n = server_io.read(&mut byte).await.unwrap();
                if n == 0 {
                    return;
                }
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let _ = server_io
                .write_all(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n")
                .await;
        });
        let cfg = HttpUpgradeConfig::default();
        let r = httpupgrade_connect(client_io, "localhost", &cfg).await;
        assert!(r.is_err());
    }
}

//! 流量嗅探（Sniffing）：在建立出站连接前无损窥探首包数据，
//! 提取 TLS SNI 或 HTTP Host 域名，以精准激活域名分流规则。

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use crate::stream::ProxyStream;

/// 带有预读缓冲区的包装流：
/// 首先排空已预读但未消耗的 `buffer` 字节，随后完全直通底层 `inner`。
pub struct PeekedStream<S> {
    inner: S,
    buffer: Vec<u8>,
    offset: usize,
}

impl<S> PeekedStream<S> {
    pub fn new(inner: S, buffer: Vec<u8>) -> Self {
        Self {
            inner,
            buffer,
            offset: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PeekedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.offset < self.buffer.len() {
            let available = &self.buffer[self.offset..];
            let to_copy = available.len().min(buf.remaining());
            buf.put_slice(&available[..to_copy]);
            self.offset += to_copy;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PeekedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// 解析 TLS ClientHello 中的 Server Name Indication (SNI) 扩展
pub fn parse_tls_sni(buf: &[u8]) -> Option<String> {
    // 检查 TLS Record Header (至少 9 字节)
    if buf.len() < 9 {
        return None;
    }
    // ContentType == 0x16 (Handshake)
    if buf[0] != 0x16 {
        return None;
    }
    // Major version 3 (SSL 3.0 / TLS 1.0..1.3)
    if buf[1] != 0x03 {
        return None;
    }
    // Handshake Type == 0x01 (ClientHello)
    if buf[5] != 0x01 {
        return None;
    }

    let mut pos = 9; // 跳过 RecordHeader(5) + HandshakeType(1) + HandshakeLength(3)

    // 跳过 ClientVersion(2) + Random(32)
    pos += 2 + 32;
    if pos >= buf.len() {
        return None;
    }

    // Session ID
    let sid_len = buf[pos] as usize;
    pos += 1 + sid_len;
    if pos + 2 > buf.len() {
        return None;
    }

    // Cipher Suites
    let cs_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2 + cs_len;
    if pos >= buf.len() {
        return None;
    }

    // Compression Methods
    let comp_len = buf[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > buf.len() {
        return None;
    }

    // Extensions
    let ext_total_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total_len).min(buf.len());

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > buf.len() {
            break;
        }

        // Extension 0x0000: server_name
        if ext_type == 0x0000 {
            if ext_len < 2 {
                break;
            }
            let list_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
            let mut sn_pos = pos + 2;
            let sn_end = (pos + 2 + list_len).min(pos + ext_len);
            while sn_pos + 3 <= sn_end {
                let name_type = buf[sn_pos];
                let name_len = u16::from_be_bytes([buf[sn_pos + 1], buf[sn_pos + 2]]) as usize;
                sn_pos += 3;
                if sn_pos + name_len <= sn_end && name_type == 0x00 {
                    // 0x00 = host_name
                    if let Ok(sni) = std::str::from_utf8(&buf[sn_pos..sn_pos + name_len]) {
                        let clean = sni.trim().to_ascii_lowercase();
                        if !clean.is_empty() {
                            return Some(clean);
                        }
                    }
                }
                sn_pos += name_len;
            }
        }
        pos += ext_len;
    }

    None
}

/// 解析 HTTP 1.x 报头中的 Host 字段
pub fn parse_http_host(buf: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(buf).ok()?;
    let first_line = text.lines().next()?;
    let first_upper = first_line.to_ascii_uppercase();
    let is_http_verb = first_upper.starts_with("GET ")
        || first_upper.starts_with("POST ")
        || first_upper.starts_with("HEAD ")
        || first_upper.starts_with("PUT ")
        || first_upper.starts_with("DELETE ")
        || first_upper.starts_with("OPTIONS ")
        || first_upper.starts_with("CONNECT ")
        || first_upper.starts_with("TRACE ")
        || first_upper.starts_with("PATCH ");

    if !is_http_verb {
        return None;
    }

    for line in text.lines().skip(1) {
        if line.is_empty() || line == "\r" {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("host:") {
            let host_part = line[5..].trim();
            // 剥离端口号 (如 example.com:8080 -> example.com)
            let host_clean = if let Some((h, _)) = host_part.split_once(':') {
                h.trim()
            } else {
                host_part
            };
            if !host_clean.is_empty() && !host_clean.contains(' ') {
                return Some(host_clean.to_ascii_lowercase());
            }
        }
    }

    None
}

/// 异步窥探流首包：读取至多 1KB 数据并在限定超时时间内解析 SNI / Host；
/// 无论是否匹配成功，均返回还原后的无损 `Box<dyn ProxyStream>`。
pub async fn sniff_stream(
    mut stream: Box<dyn ProxyStream>,
    timeout: Duration,
) -> (Option<String>, Box<dyn ProxyStream>) {
    let mut buf = vec![0u8; 1024];
    let n = match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return (None, stream),
    };
    buf.truncate(n);
    let domain = parse_tls_sni(&buf).or_else(|| parse_http_host(&buf));
    let peeked = PeekedStream::new(stream, buf);
    (domain, Box::new(peeked))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_parse_http_host() {
        let req =
            b"GET /index.html HTTP/1.1\r\nHost: www.google.com:443\r\nUser-Agent: curl\r\n\r\n";
        assert_eq!(parse_http_host(req), Some("www.google.com".to_string()));

        let req_lower = b"post /api HTTP/1.1\r\nhost: api.github.com\r\n\r\n";
        assert_eq!(
            parse_http_host(req_lower),
            Some("api.github.com".to_string())
        );

        let non_http = b"SSH-2.0-OpenSSH_8.9\r\n";
        assert_eq!(parse_http_host(non_http), None);
    }

    #[tokio::test]
    async fn test_peeked_stream_lossless() {
        let (mut client, server) = tokio::io::duplex(1024);
        let write_task = tokio::spawn(async move {
            client
                .write_all(b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\nrest-data")
                .await
                .unwrap();
        });

        let (domain, mut peeked) = sniff_stream(Box::new(server), Duration::from_secs(1)).await;
        write_task.await.unwrap();
        assert_eq!(domain, Some("example.org".to_string()));

        let mut read_all = Vec::new();
        peeked.read_to_end(&mut read_all).await.unwrap();
        assert_eq!(
            &read_all,
            b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\nrest-data"
        );
    }

    #[test]
    fn test_parse_tls_sni() {
        // 构造简易合法的 TLS ClientHello，携带 SNI "rust-lang.org"
        let host = b"rust-lang.org";
        let mut extensions = Vec::new();
        // Extension: server_name (0x0000)
        extensions.extend_from_slice(&[0x00, 0x00]); // ext type
        let list_len = (3 + host.len()) as u16;
        let ext_len = list_len + 2;
        extensions.extend_from_slice(&ext_len.to_be_bytes());
        extensions.extend_from_slice(&list_len.to_be_bytes());
        extensions.push(0x00); // name_type = host_name
        extensions.extend_from_slice(&(host.len() as u16).to_be_bytes());
        extensions.extend_from_slice(host);

        let mut ch_body = Vec::new();
        ch_body.extend_from_slice(&[0x03, 0x03]); // ClientVersion
        ch_body.extend_from_slice(&[0u8; 32]); // Random
        ch_body.push(0x00); // SessionID len = 0
        ch_body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // CipherSuites (len 2)
        ch_body.extend_from_slice(&[0x01, 0x00]); // Compression methods (len 1)
        ch_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        ch_body.extend_from_slice(&extensions);

        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // Legacy TLS 1.0 version
        let ch_len = (4 + ch_body.len()) as u16;
        record.extend_from_slice(&ch_len.to_be_bytes());
        // Handshake header
        record.push(0x01); // ClientHello
        record.push(0x00);
        record.extend_from_slice(&(ch_body.len() as u16).to_be_bytes());
        record.extend_from_slice(&ch_body);

        let sni = parse_tls_sni(&record);
        assert_eq!(sni, Some("rust-lang.org".to_string()));
    }
}

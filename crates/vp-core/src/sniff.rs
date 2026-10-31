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

impl<S: ProxyStream> ProxyStream for PeekedStream<S> {
    fn raw_socket(&self) -> Option<&tokio::net::TcpStream> {
        self.inner.raw_socket()
    }

    fn unconsumed_peek(&self) -> Option<&[u8]> {
        if self.offset < self.buffer.len() {
            Some(&self.buffer[self.offset..])
        } else {
            self.inner.unconsumed_peek()
        }
    }

    fn consume_peek(&mut self, len: usize) {
        if self.offset < self.buffer.len() {
            let avail = self.buffer.len() - self.offset;
            let take = avail.min(len);
            self.offset += take;
            let rem = len - take;
            if rem > 0 {
                self.inner.consume_peek(rem);
            }
        } else {
            self.inner.consume_peek(len);
        }
    }
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

/// 判断目标端口是否为适合触发主动嗅探的常见 HTTP/HTTPS 端口（含 Cloudflare 及常见自建 Web 端口）
pub fn is_sniffable_port(port: u16) -> bool {
    matches!(
        port,
        80 | 443
            | 8080
            | 8443
            | 8444
            | 9443
            | 2052
            | 2053
            | 2082
            | 2083
            | 2086
            | 2087
            | 2095
            | 2096
            | 8880
    )
}

/// 解析 TLS Record (0x16 Handshake) 中的 Server Name Indication (SNI) 扩展
pub fn parse_tls_sni(buf: &[u8]) -> Option<String> {
    // 检查 TLS Record Header (至少 9 字节)
    if buf.len() < 9 {
        return None;
    }
    // ContentType == 0x16 (Handshake) && Major version 3 (SSL 3.0 / TLS 1.0..1.3)
    if buf[0] != 0x16 || buf[1] != 0x03 {
        return None;
    }
    parse_tls_client_hello_sni(&buf[5..])
}

/// 解析裸 TLS Handshake ClientHello 消息（不含 5 字节 TLS Record 头，供 TCP TLS 与 QUIC CRYPTO 帧共用）
pub fn parse_tls_client_hello_sni(hs: &[u8]) -> Option<String> {
    if hs.len() < 4 || hs[0] != 0x01 {
        return None;
    }
    let mut pos = 4; // 跳过 HandshakeType(1) + HandshakeLength(3)

    // 跳过 ClientVersion(2) + Random(32)
    pos += 2 + 32;
    if pos >= hs.len() {
        return None;
    }

    // Session ID
    let sid_len = hs[pos] as usize;
    pos += 1 + sid_len;
    if pos + 2 > hs.len() {
        return None;
    }

    // Cipher Suites
    let cs_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2 + cs_len;
    if pos >= hs.len() {
        return None;
    }

    // Compression Methods
    let comp_len = hs[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > hs.len() {
        return None;
    }

    // Extensions
    let ext_total_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total_len).min(hs.len());

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
        let ext_len = u16::from_be_bytes([hs[pos + 2], hs[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > hs.len() {
            break;
        }

        // Extension 0x0000: server_name
        if ext_type == 0x0000 {
            if ext_len < 2 {
                break;
            }
            let list_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
            let mut sn_pos = pos + 2;
            let sn_end = (pos + 2 + list_len).min(pos + ext_len);
            while sn_pos + 3 <= sn_end {
                let name_type = hs[sn_pos];
                let name_len = u16::from_be_bytes([hs[sn_pos + 1], hs[sn_pos + 2]]) as usize;
                sn_pos += 3;
                if sn_pos + name_len <= sn_end && name_type == 0x00 {
                    // 0x00 = host_name
                    if let Ok(sni) = std::str::from_utf8(&hs[sn_pos..sn_pos + name_len]) {
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

/// QUIC 变长整数解码（RFC 9000 §16），返回 `(value, bytes_consumed)`
fn read_quic_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let tag = first >> 6;
    let len = 1usize << tag;
    if buf.len() < len {
        return None;
    }
    let mut val = (first & 0x3f) as u64;
    for &b in &buf[1..len] {
        val = (val << 8) | (b as u64);
    }
    Some((val, len))
}

/// HKDF-Expand-Label (RFC 8446 §7.1 / RFC 9001 §5.1)
fn quic_hkdf_expand_label(prk: &hkdf::Hkdf<sha2::Sha256>, label: &[u8], out: &mut [u8]) -> bool {
    let full_label_len = 6 + label.len();
    let mut info = Vec::with_capacity(2 + 1 + full_label_len + 1);
    let len_be = (out.len() as u16).to_be_bytes();
    info.push(len_be[0]);
    info.push(len_be[1]);
    info.push(full_label_len as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0); // empty context
    prk.expand(&info, out).is_ok()
}

/// 窥探 UDP QUIC Initial 数据报（RFC 9000 / RFC 9001 / RFC 9369），
/// 解密首包保护头与 CRYPTO 帧载荷，提取内部 TLS 1.3 ClientHello 的 SNI 域名。
pub fn sniff_quic_sni(pkt: &[u8]) -> Option<String> {
    use aes::Aes128;
    use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit, generic_array::GenericArray};
    use aes_gcm::Aes128Gcm;
    use aes_gcm::aead::{Aead, Payload};

    // Long Header (bit 7 == 1) & Fixed Bit (bit 6 == 1)
    if pkt.len() < 64 || (pkt[0] & 0xc0) != 0xc0 {
        return None;
    }
    let version = u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]);
    let pkt_type = (pkt[0] & 0x30) >> 4;

    // QUIC v1 (0x00000001, Initial type = 0) 或 QUIC v2 (0x6b3343cf, Initial type = 1)
    let (salt, key_label, iv_label, hp_label): ([u8; 20], &[u8], &[u8], &[u8]) = match version {
        0x0000_0001 if pkt_type == 0x00 => (
            [
                0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
            ],
            b"quic key",
            b"quic iv",
            b"quic hp",
        ),
        0x6b33_43cf if pkt_type == 0x01 => (
            [
                0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26,
                0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
            ],
            b"quicv2 key",
            b"quicv2 iv",
            b"quicv2 hp",
        ),
        _ => return None,
    };

    let mut pos = 5;
    let dcid_len = *pkt.get(pos)? as usize;
    pos += 1;
    if pos + dcid_len > pkt.len() {
        return None;
    }
    let dcid = &pkt[pos..pos + dcid_len];
    pos += dcid_len;

    let scid_len = *pkt.get(pos)? as usize;
    pos += 1 + scid_len;
    if pos >= pkt.len() {
        return None;
    }

    // Token Length & Token
    let (token_len, n_tok) = read_quic_varint(&pkt[pos..])?;
    pos += n_tok + (token_len as usize);
    if pos >= pkt.len() {
        return None;
    }

    // Length (PN + Payload + 16B GCM Tag)
    let (rem_len, n_len) = read_quic_varint(&pkt[pos..])?;
    pos += n_len;
    let pn_offset = pos;
    let pkt_end = (pn_offset + rem_len as usize).min(pkt.len());
    if pn_offset + 20 > pkt_end {
        return None;
    }

    // 1. 派生 QUIC Initial 密钥
    let initial_hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), dcid);
    let mut client_in_secret = [0u8; 32];
    if !quic_hkdf_expand_label(&initial_hkdf, b"client in", &mut client_in_secret) {
        return None;
    }
    let client_hkdf = hkdf::Hkdf::<sha2::Sha256>::from_prk(&client_in_secret).ok()?;
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    let mut hp = [0u8; 16];
    if !quic_hkdf_expand_label(&client_hkdf, key_label, &mut key)
        || !quic_hkdf_expand_label(&client_hkdf, iv_label, &mut iv)
        || !quic_hkdf_expand_label(&client_hkdf, hp_label, &mut hp)
    {
        return None;
    }

    // 2. 移除 Header Protection (AES-128-ECB sample at pn_offset + 4)
    let sample_offset = pn_offset + 4;
    if sample_offset + 16 > pkt_end {
        return None;
    }
    let hp_cipher = Aes128::new_from_slice(&hp).ok()?;
    let mut mask = GenericArray::clone_from_slice(&pkt[sample_offset..sample_offset + 16]);
    hp_cipher.encrypt_block(&mut mask);

    let first_byte = pkt[0] ^ (mask[0] & 0x0f);
    let pn_len = ((first_byte & 0x03) + 1) as usize;
    if pn_offset + pn_len + 16 > pkt_end {
        return None;
    }

    let mut hdr = pkt[..pn_offset + pn_len].to_vec();
    hdr[0] = first_byte;
    let mut pn: u64 = 0;
    for i in 0..pn_len {
        hdr[pn_offset + i] ^= mask[1 + i];
        pn = (pn << 8) | (hdr[pn_offset + i] as u64);
    }

    let mut nonce = iv;
    let pn_bytes = pn.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= pn_bytes[i];
    }

    // 3. AES-128-GCM 解密 Initial 载荷
    let aead = Aes128Gcm::new_from_slice(&key).ok()?;
    let ciphertext = &pkt[pn_offset + pn_len..pkt_end];
    let plain = aead
        .decrypt(
            GenericArray::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &hdr,
            },
        )
        .ok()?;

    // 4. 重组 CRYPTO 帧 (Frame Type = 0x06)
    let mut crypto_buf = vec![0u8; 4096];
    let mut max_crypto_end = 0usize;
    let mut fpos = 0usize;
    while fpos < plain.len() {
        let ftype = plain[fpos];
        fpos += 1;
        if ftype == 0x00 || ftype == 0x01 {
            // PADDING (0x00) or PING (0x01)
            continue;
        }
        if ftype == 0x06 {
            let (offset, n1) = read_quic_varint(&plain[fpos..])?;
            fpos += n1;
            let (length, n2) = read_quic_varint(&plain[fpos..])?;
            fpos += n2;
            let length = length as usize;
            let offset = offset as usize;
            if fpos + length > plain.len() {
                break;
            }
            if offset + length <= crypto_buf.len() {
                crypto_buf[offset..offset + length].copy_from_slice(&plain[fpos..fpos + length]);
                max_crypto_end = max_crypto_end.max(offset + length);
            }
            fpos += length;
        } else {
            // Initial 包内遇到未知帧则停止遍历
            break;
        }
    }

    if max_crypto_end == 0 {
        return None;
    }
    parse_tls_client_hello_sni(&crypto_buf[..max_crypto_end])
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

/// 异步窥探流首包：读取至多 4KB 数据并在限定超时时间内解析 SNI / Host；
/// 扩容至 4KB 可无损容纳现代 Chrome 124+ 携带后量子（Post-Quantum Kyber / ML-KEM-768）与 ECH 的膨胀 ClientHello。
/// 无论是否匹配成功，均返回还原后的无损 `Box<dyn ProxyStream>`。
pub async fn sniff_stream(
    mut stream: Box<dyn ProxyStream>,
    timeout: Duration,
) -> (Option<String>, Box<dyn ProxyStream>) {
    let mut buf = vec![0u8; 4096];
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

    #[tokio::test]
    async fn test_peeked_stream_unconsumed_peek() {
        let (mut client, server) = tokio::io::duplex(1024);
        let write_task = tokio::spawn(async move {
            client
                .write_all(b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n")
                .await
                .unwrap();
        });

        let (_, mut peeked) = sniff_stream(Box::new(server), Duration::from_secs(1)).await;
        write_task.await.unwrap();

        assert!(peeked.unconsumed_peek().is_some());
        let peek_len = peeked.unconsumed_peek().unwrap().len();
        assert!(peek_len > 0);

        // 消费全部未读首包
        peeked.consume_peek(peek_len);
        assert!(peeked.unconsumed_peek().is_none());
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

    #[test]
    fn test_sniff_quic_sni() {
        use aes::Aes128;
        use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit, generic_array::GenericArray};
        use aes_gcm::Aes128Gcm;
        use aes_gcm::aead::{Aead, Payload};

        // 1. 构造携带 SNI "quic.cloudflare.com" 的裸 TLS ClientHello 握手消息
        let host = b"quic.cloudflare.com";
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&[0x00, 0x00]); // server_name
        let list_len = (3 + host.len()) as u16;
        let ext_len = list_len + 2;
        extensions.extend_from_slice(&ext_len.to_be_bytes());
        extensions.extend_from_slice(&list_len.to_be_bytes());
        extensions.push(0x00);
        extensions.extend_from_slice(&(host.len() as u16).to_be_bytes());
        extensions.extend_from_slice(host);

        let mut ch_body = Vec::new();
        ch_body.extend_from_slice(&[0x03, 0x03]);
        ch_body.extend_from_slice(&[0x42u8; 32]);
        ch_body.push(0x00);
        ch_body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        ch_body.extend_from_slice(&[0x01, 0x00]);
        ch_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        ch_body.extend_from_slice(&extensions);

        let mut ch_hs = vec![0x01, 0x00];
        ch_hs.extend_from_slice(&(ch_body.len() as u16).to_be_bytes());
        ch_hs.extend_from_slice(&ch_body);

        // 2. 封装进 QUIC CRYPTO 帧 (type=0x06, offset=0, length=varint(len))
        let mut plain = vec![0x06, 0x00];
        let hs_len = ch_hs.len() as u16;
        plain.extend_from_slice(&((0x4000 | hs_len).to_be_bytes()));
        plain.extend_from_slice(&ch_hs);
        plain.resize(plain.len() + 32, 0x00); // PADDING

        // 3. 构造 QUIC v1 Initial Header 并加密
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let salt = [
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
            0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
        ];
        let initial_hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), &dcid);
        let mut client_in = [0u8; 32];
        assert!(quic_hkdf_expand_label(
            &initial_hkdf,
            b"client in",
            &mut client_in
        ));
        let client_hkdf = hkdf::Hkdf::<sha2::Sha256>::from_prk(&client_in).unwrap();
        let mut key = [0u8; 16];
        let mut iv = [0u8; 12];
        let mut hp = [0u8; 16];
        assert!(quic_hkdf_expand_label(&client_hkdf, b"quic key", &mut key));
        assert!(quic_hkdf_expand_label(&client_hkdf, b"quic iv", &mut iv));
        assert!(quic_hkdf_expand_label(&client_hkdf, b"quic hp", &mut hp));

        let mut hdr = Vec::new();
        hdr.push(0xc1); // Long Header + Initial + 2-byte PN (0x01)
        hdr.extend_from_slice(&0x0000_0001u32.to_be_bytes());
        hdr.push(dcid.len() as u8);
        hdr.extend_from_slice(&dcid);
        hdr.push(0); // scid len = 0
        hdr.push(0); // token len = 0
        let rem_len = (2 + plain.len() + 16) as u16;
        hdr.extend_from_slice(&((0x4000 | rem_len).to_be_bytes()));
        let pn_offset = hdr.len();
        hdr.extend_from_slice(&[0x00, 0x02]); // PN = 2

        let mut nonce = iv;
        nonce[11] ^= 0x02;
        let aead = Aes128Gcm::new_from_slice(&key).unwrap();
        let ct = aead
            .encrypt(
                GenericArray::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &hdr,
                },
            )
            .unwrap();

        let mut pkt = hdr;
        pkt.extend_from_slice(&ct);

        // 施加 Header Protection
        let sample_offset = pn_offset + 4;
        let hp_cipher = Aes128::new_from_slice(&hp).unwrap();
        let mut mask = GenericArray::clone_from_slice(&pkt[sample_offset..sample_offset + 16]);
        hp_cipher.encrypt_block(&mut mask);
        pkt[0] ^= mask[0] & 0x0f;
        pkt[pn_offset] ^= mask[1];
        pkt[pn_offset + 1] ^= mask[2];

        assert_eq!(
            sniff_quic_sni(&pkt),
            Some("quic.cloudflare.com".to_string())
        );
    }
}

//! WebSocket 传输（RFC 6455）：客户端/服务端握手 + 帧编解码流。

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use base64::Engine;
use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use vp_common::{Error, Result};

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_FRAME: usize = 4 * 1024 * 1024;
const MAX_HEADER_BUF: usize = 8192;

#[derive(Debug, Clone, Default)]
pub struct WsConfig {
    pub path: String,
    pub headers: Vec<(String, String)>,
}

/// 客户端握手
pub async fn ws_handshake_client<S>(mut io: S, host: &str, cfg: &WsConfig) -> Result<WsStream<S>>
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
    for (k, v) in &cfg.headers {
        if !k.eq_ignore_ascii_case("host") {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
    }
    req.push_str("\r\n");
    io.write_all(req.as_bytes()).await?;

    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        let n = io.read(&mut byte).await?;
        if n == 0 {
            return Err(Error::Proto("ws: 握手响应中断"));
        }
        buf.push(byte[0]);
        if buf.len() > MAX_HEADER_BUF {
            return Err(Error::Proto("ws: 响应头过长"));
        }
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let status_line = head.lines().next().unwrap_or_default();
    if !status_line.contains("101") {
        return Err(Error::ProtoMsg(format!("ws: 握手失败 {status_line}")));
    }
    Ok(WsStream::new(io, true))
}

/// 服务端握手（协议服务端/自测用）
pub async fn ws_handshake_server<S>(mut io: S) -> Result<WsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let buf = read_until_header_end(&mut io).await?;
    let head = String::from_utf8_lossy(&buf).to_ascii_lowercase();
    if !head.contains("upgrade: websocket") {
        return Err(Error::Proto("ws: 非 websocket 升级请求"));
    }
    let key = extract_header(&head, "sec-websocket-key")
        .ok_or(Error::Proto("ws: 缺少 Sec-WebSocket-Key"))?;
    let mut hasher = sha1::Sha1::new();
    use sha1::Digest;
    hasher.update(key.as_bytes());
    hasher.update(GUID.as_bytes());
    let accept = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
    io.write_all(
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .as_bytes(),
    )
    .await?;
    Ok(WsStream::new(io, false))
}

/// 101 已发送后的服务端流：直接进入帧模式
pub async fn ws_handshake_after_101<S>(io: S) -> Result<WsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    Ok(WsStream::new(io, false))
}

async fn read_until_header_end<S: AsyncRead + Unpin>(io: &mut S) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        let n = io.read(&mut byte).await?;
        if n == 0 {
            return Err(Error::Proto("ws: 对端中断"));
        }
        buf.push(byte[0]);
        if buf.len() > MAX_HEADER_BUF {
            return Err(Error::Proto("ws: 头过长"));
        }
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(buf);
        }
    }
}

fn extract_header(head_lower: &str, name: &str) -> Option<String> {
    for line in head_lower.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim() == name {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// 帧流
// ---------------------------------------------------------------------------

enum ReadState {
    Header,
    Data { remaining: usize },
}

pub struct WsStream<S> {
    inner: S,
    is_client: bool,
    raw: BytesMut,
    pending: BytesMut,
    state: ReadState,
    mask_key: [u8; 4],
    mask_offset: usize,
    opcode: u8,
    pong_pending: bool,
    write_out: BytesMut,
    closed: bool,
}

impl<S> WsStream<S> {
    pub fn new(inner: S, is_client: bool) -> Self {
        WsStream {
            inner,
            is_client,
            raw: BytesMut::with_capacity(16 * 1024),
            pending: BytesMut::with_capacity(16 * 1024),
            state: ReadState::Header,
            mask_key: [0; 4],
            mask_offset: 0,
            opcode: 0,
            pong_pending: false,
            write_out: BytesMut::new(),
            closed: false,
        }
    }
}

impl<S: AsyncRead + Unpin> WsStream<S> {
    /// 从 raw 解析并消费数据；返回是否有新数据进入 pending
    fn try_progress(&mut self) -> bool {
        loop {
            match &mut self.state {
                ReadState::Header => {
                    let Some((_fin, opcode, masked, len, header_len)) = parse_header(&self.raw)
                    else {
                        return false;
                    };
                    if len > MAX_FRAME {
                        self.closed = true;
                        return false;
                    }
                    if masked {
                        if self.raw.len() < header_len + 4 {
                            return false;
                        }
                        self.mask_key
                            .copy_from_slice(&self.raw[header_len..header_len + 4]);
                        self.raw.advance(header_len + 4);
                    } else {
                        self.raw.advance(header_len);
                    }
                    self.mask_offset = 0;
                    match opcode {
                        0x8 => {
                            self.closed = true;
                            return false;
                        }
                        op @ (0x9 | 0xA) => {
                            self.opcode = op;
                            self.state = ReadState::Data { remaining: len };
                        }
                        op => {
                            self.opcode = op;
                            self.state = ReadState::Data { remaining: len };
                        }
                    }
                }
                ReadState::Data { remaining } => {
                    if self.raw.is_empty() && *remaining > 0 {
                        return false;
                    }
                    let take = (*remaining).min(self.raw.len());
                    let mut chunk = self.raw.split_to(take);
                    for (i, b) in chunk.iter_mut().enumerate() {
                        *b ^= self.mask_key[(self.mask_offset + i) % 4];
                    }
                    self.mask_offset += take;
                    *remaining -= take;
                    let data_frame = self.opcode == 0x2 || self.opcode == 0x0;
                    if data_frame {
                        self.pending.extend_from_slice(&chunk);
                    }
                    if *remaining == 0 {
                        if self.opcode == 0x9 {
                            self.pong_pending = true;
                        }
                        self.state = ReadState::Header;
                    }
                    if data_frame && take > 0 {
                        return true;
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> WsStream<S> {
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.write_out.is_empty() {
            let mut inner = Pin::new(&mut self.inner);
            match inner.as_mut().poll_write(cx, &self.write_out)? {
                Poll::Ready(0) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "ws: 写入 0 字节",
                    )));
                }
                Poll::Ready(n) => {
                    self.write_out.advance(n);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    /// 编码一个完整二进制帧（fin=1）
    fn encode_frame(&mut self, buf: &[u8], opcode: u8) {
        let mut header = [0u8; 10];
        let mut hlen = 2;
        header[0] = 0x80 | opcode;
        let mask_bit = if self.is_client { 0x80 } else { 0 };
        if buf.len() < 126 {
            header[1] = mask_bit | buf.len() as u8;
        } else if buf.len() <= 0xFFFF {
            header[1] = mask_bit | 126;
            header[2..4].copy_from_slice(&(buf.len() as u16).to_be_bytes());
            hlen = 4;
        } else {
            header[1] = mask_bit | 127;
            header[2..10].copy_from_slice(&(buf.len() as u64).to_be_bytes());
            hlen = 10;
        }
        self.write_out.extend_from_slice(&header[..hlen]);
        if self.is_client {
            let mut key = [0u8; 4];
            vp_common::rand_bytes(&mut key);
            self.write_out.extend_from_slice(&key);
            let masked: Vec<u8> = buf
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ key[i % 4])
                .collect();
            self.write_out.extend_from_slice(&masked);
        } else {
            self.write_out.extend_from_slice(buf);
        }
    }

    fn maybe_send_pong(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pong_pending {
            self.pong_pending = false;
            self.encode_frame(&[], 0xA);
        }
        self.flush_pending(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        loop {
            if !this.pending.is_empty() {
                let n = this.pending.len().min(buf.remaining());
                buf.put_slice(&this.pending[..n]);
                this.pending.advance(n);
                return Poll::Ready(Ok(()));
            }
            if this.closed {
                return Poll::Ready(Ok(()));
            }
            this.try_progress();
            if !this.pending.is_empty() {
                continue;
            }
            if this.closed {
                return Poll::Ready(Ok(()));
            }
            // 从底层读原始字节
            this.raw.reserve(16 * 1024);
            let spare = this.raw.spare_capacity_mut();
            let mut rb = ReadBuf::uninit(spare);
            std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
            let filled = rb.filled().len();
            if filled == 0 {
                this.closed = true;
                return Poll::Ready(Ok(()));
            }
            // SAFETY: filled 字节刚被 poll_read 初始化
            unsafe { this.raw.advance_mut(filled) };
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        std::task::ready!(this.maybe_send_pong(cx))?;
        if !this.write_out.is_empty() {
            std::task::ready!(this.flush_pending(cx))?;
        }
        if this.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "ws: 已关闭",
            )));
        }
        // 16KB 分帧，每帧独立 fin
        let mut offset = 0;
        while offset < buf.len() {
            let end = (offset + 16 * 1024).min(buf.len());
            this.encode_frame(&buf[offset..end], 0x2);
            offset = end;
        }
        if buf.is_empty() {
            this.encode_frame(&[], 0x2);
        }
        std::task::ready!(this.flush_pending(cx))?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        std::task::ready!(this.flush_pending(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if !this.closed {
            this.encode_frame(&[], 0x8);
            this.closed = true;
            let _ = this.flush_pending(cx);
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// 解析帧头：返回 (fin, opcode, masked, payload_len, header_len)
fn parse_header(raw: &[u8]) -> Option<(bool, u8, bool, usize, usize)> {
    if raw.len() < 2 {
        return None;
    }
    let b0 = raw[0];
    let b1 = raw[1];
    let fin = b0 & 0x80 != 0;
    let opcode = b0 & 0x0f;
    let masked = b1 & 0x80 != 0;
    let len7 = (b1 & 0x7f) as usize;
    let (len, header_len) = match len7 {
        126 => {
            if raw.len() < 4 {
                return None;
            }
            (u16::from_be_bytes([raw[2], raw[3]]) as usize, 4)
        }
        127 => {
            if raw.len() < 10 {
                return None;
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&raw[2..10]);
            (u64::from_be_bytes(b) as usize, 10)
        }
        n => (n, 2),
    };
    Some((fin, opcode, masked, len, header_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn echo_pair() -> (
        WsStream<tokio::io::DuplexStream>,
        WsStream<tokio::io::DuplexStream>,
    ) {
        let (a, b) = tokio::io::duplex(8192);
        let cfg = WsConfig {
            path: "/ws".into(),
            headers: vec![("Host".into(), "example.com".into())],
        };
        let server = tokio::spawn(async move { ws_handshake_server(b).await.unwrap() });
        let client = ws_handshake_client(a, "example.com", &cfg).await.unwrap();
        let server = server.await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn handshake_and_roundtrip() {
        let (mut c, mut s) = echo_pair().await;
        c.write_all(b"hello-ws").await.unwrap();
        let mut buf = [0u8; 8];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello-ws");
        s.write_all(b"ok!").await.unwrap();
        let mut buf = [0u8; 3];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ok!");
    }

    #[tokio::test]
    async fn large_frame_roundtrip() {
        let (mut c, mut s) = echo_pair().await;
        let payload: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
        let payload2 = payload.clone();
        tokio::spawn(async move {
            c.write_all(&payload2).await.unwrap();
        });
        let mut got = vec![0u8; payload.len()];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn half_close() {
        let (mut c, mut s) = echo_pair().await;
        c.write_all(b"x").await.unwrap();
        c.shutdown().await.unwrap();
        let mut buf = [0u8; 1];
        use tokio::io::AsyncReadExt;
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], b'x');
    }
}

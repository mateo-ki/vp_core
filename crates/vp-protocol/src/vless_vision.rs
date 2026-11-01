//! XTLS-rprx-vision 流控（线格式与行为对齐 Xray-core / sing-box）。
//!
//! 1. VLESS Addons 线格式：`0x0A 0x10 xtls-rprx-vision`（18 字节 protobuf 编码）。
//! 2. 填充帧：`[UUID 16B，仅每个方向的第一帧][Command 1B][ContentLen 2B be][PaddingLen 2B be][Content][Padding]`。
//!    - 0x00 PaddingContinue：后面还有填充帧
//!    - 0x01 PaddingEnd：此后经外层 TLS 裸流直通
//!    - 0x02 PaddingDirect：此后发送方绕过外层 TLS，直接在底层 TCP 上收发（XTLS 直拷）
//! 3. 内层 TLS ClientHello 长填充（补到 900~1399 字节），隐藏长度特征。
//! 4. 读方向首帧不以本连接 UUID 开头：对端没做填充，原样透传（同 Xray）。
//! 5. 写方向只发 PaddingEnd、不发 PaddingDirect（上行始终走外层 TLS，Xray 照样接受）；
//!    读方向收到 PaddingDirect 时经 `ProxyStream::switch_to_raw_read` 切到底层直读——
//!    内层是 TLS 1.3 时（几乎所有 HTTPS）Xray 服务端都会这样切。

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use vp_core::ProxyStream;

pub const VISION_FLOW_BYTES: &[u8] = b"\x0a\x10xtls-rprx-vision";

pub const CMD_PADDING_CONTINUE: u8 = 0x00;
pub const CMD_PADDING_END: u8 = 0x01;
pub const CMD_PADDING_DIRECT: u8 = 0x02;

/// 单帧内容上限（ContentLen 为 u16）
const MAX_FRAME_CONTENT: usize = u16::MAX as usize;

/// 判断载荷是否为 TLS 握手层 ClientHello（内层 TLS）
pub fn is_tls_client_hello(buf: &[u8]) -> bool {
    // 至少 9 字节：Record Header(5B: [0x16, 0x03, 0x01..0x03, len(2B)]) + Handshake Header(4B: [0x01, len(3B)])
    if buf.len() < 9 {
        return false;
    }
    buf[0] == 0x16 && buf[1] == 0x03 && buf[2] <= 0x04 && buf[5] == 0x01
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum WriteState {
    /// 尚未发送过任何帧
    Initial,
    /// 已发送 ClientHello 填充帧，下一次写发 PaddingEnd
    HandshakeSent,
    /// 已发送 PaddingEnd，裸流直通
    Direct,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum ReadState {
    /// 首帧前的 UUID：对上才按填充帧解析
    Uuid { buf: [u8; 16], filled: usize },
    /// 正在读取 5 字节帧头 [cmd, content_len(2B), pad_len(2B)]
    Header { buf: [u8; 5], filled: usize },
    /// 正在向调用方输出帧内容数据
    Content {
        cmd: u8,
        remaining_content: usize,
        pad_len: usize,
    },
    /// 正在丢弃尾部填充字节
    Padding { cmd: u8, remaining_pad: usize },
    /// 填充结束，裸流直通
    Direct,
}

pub struct VisionStream<S> {
    io: S,
    uuid: [u8; 16],
    /// 写方向的第一帧尚未带出 UUID
    write_uuid: bool,
    write_state: WriteState,
    write_buf: Vec<u8>,
    write_offset: usize,
    read_state: ReadState,
    /// 首帧不是 UUID 开头时已读入的字节，进入直通后先原样交付
    leftover: Vec<u8>,
    scratch: [u8; 2048],
}

impl<S: ProxyStream> ProxyStream for VisionStream<S> {}

impl<S> VisionStream<S> {
    /// 客户端与服务端行为一致：uuid 为本连接的 VLESS 用户 ID
    pub fn new(io: S, uuid: [u8; 16]) -> Self {
        Self {
            io,
            uuid,
            write_uuid: true,
            write_state: WriteState::Initial,
            write_buf: Vec::new(),
            write_offset: 0,
            read_state: ReadState::Uuid {
                buf: [0u8; 16],
                filled: 0,
            },
            leftover: Vec::new(),
            scratch: [0u8; 2048],
        }
    }

    /// 组一帧追加到 write_buf（每个方向的第一帧带 UUID）
    fn push_frame(&mut self, cmd: u8, content: &[u8], pad_len: usize) {
        if std::mem::take(&mut self.write_uuid) {
            self.write_buf.extend_from_slice(&self.uuid);
        }
        self.write_buf.push(cmd);
        self.write_buf
            .extend_from_slice(&(content.len() as u16).to_be_bytes());
        self.write_buf
            .extend_from_slice(&(pad_len as u16).to_be_bytes());
        self.write_buf.extend_from_slice(content);
        self.write_buf.resize(self.write_buf.len() + pad_len, 0);
    }
}

impl<S: ProxyStream> VisionStream<S> {
    /// 一帧（内容 + 填充）读完后按命令切换状态
    fn finish_frame(&mut self, cmd: u8) -> io::Result<()> {
        self.read_state = match cmd {
            CMD_PADDING_CONTINUE => ReadState::Header {
                buf: [0u8; 5],
                filled: 0,
            },
            CMD_PADDING_END => ReadState::Direct,
            CMD_PADDING_DIRECT => {
                if !self.io.switch_to_raw_read() {
                    return Err(io::Error::other(
                        "vision: 对端切换到 XTLS 直拷，但底层连接不支持绕过外层 TLS 直读",
                    ));
                }
                tracing::debug!(
                    "vision: 对端切换到 XTLS 直拷（PaddingDirect），下行改为直读底层连接"
                );
                ReadState::Direct
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("vision: 未知命令 {other}"),
                ));
            }
        };
        Ok(())
    }
}

impl<S: ProxyStream> AsyncRead for VisionStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match this.read_state {
                ReadState::Direct => {
                    if !this.leftover.is_empty() {
                        let n = this.leftover.len().min(buf.remaining());
                        buf.put_slice(&this.leftover[..n]);
                        this.leftover.drain(..n);
                        return Poll::Ready(Ok(()));
                    }
                    return Pin::new(&mut this.io).poll_read(cx, buf);
                }
                ReadState::Uuid {
                    buf: mut id,
                    mut filled,
                } => {
                    while filled < id.len() {
                        let mut rb = ReadBuf::new(&mut id[filled..]);
                        match Pin::new(&mut this.io).poll_read(cx, &mut rb) {
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n == 0 {
                                    break; // EOF：已读字节按非填充流交付
                                }
                                filled += n;
                            }
                            Poll::Pending => {
                                this.read_state = ReadState::Uuid { buf: id, filled };
                                return Poll::Pending;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        }
                    }
                    if filled == id.len() && id == this.uuid {
                        this.read_state = ReadState::Header {
                            buf: [0u8; 5],
                            filled: 0,
                        };
                    } else {
                        this.leftover = id[..filled].to_vec();
                        this.read_state = ReadState::Direct;
                        if this.leftover.is_empty() {
                            return Poll::Ready(Ok(())); // 一个字节都没有就 EOF
                        }
                    }
                }
                ReadState::Header {
                    buf: mut hdr_buf,
                    mut filled,
                } => {
                    while filled < 5 {
                        let mut temp_buf = ReadBuf::new(&mut hdr_buf[filled..]);
                        match Pin::new(&mut this.io).poll_read(cx, &mut temp_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = temp_buf.filled().len();
                                if n == 0 {
                                    if filled == 0 {
                                        return Poll::Ready(Ok(())); // EOF
                                    }
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "Vision 帧头读取中断",
                                    )));
                                }
                                filled += n;
                            }
                            Poll::Pending => {
                                this.read_state = ReadState::Header {
                                    buf: hdr_buf,
                                    filled,
                                };
                                return Poll::Pending;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        }
                    }

                    let cmd = hdr_buf[0];
                    let content_len = u16::from_be_bytes([hdr_buf[1], hdr_buf[2]]) as usize;
                    let pad_len = u16::from_be_bytes([hdr_buf[3], hdr_buf[4]]) as usize;

                    if content_len > 0 {
                        this.read_state = ReadState::Content {
                            cmd,
                            remaining_content: content_len,
                            pad_len,
                        };
                    } else if pad_len > 0 {
                        this.read_state = ReadState::Padding {
                            cmd,
                            remaining_pad: pad_len,
                        };
                    } else if let Err(e) = this.finish_frame(cmd) {
                        return Poll::Ready(Err(e));
                    }
                }
                ReadState::Content {
                    cmd,
                    mut remaining_content,
                    pad_len,
                } => {
                    let to_read = remaining_content.min(buf.remaining());
                    if to_read == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    let chunk = to_read.min(this.scratch.len());
                    let mut temp = ReadBuf::new(&mut this.scratch[..chunk]);
                    match Pin::new(&mut this.io).poll_read(cx, &mut temp) {
                        Poll::Ready(Ok(())) => {
                            let n = temp.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "Vision 帧内容读取中断",
                                )));
                            }
                            buf.put_slice(temp.filled());
                            remaining_content -= n;
                            if remaining_content > 0 {
                                this.read_state = ReadState::Content {
                                    cmd,
                                    remaining_content,
                                    pad_len,
                                };
                            } else if pad_len > 0 {
                                this.read_state = ReadState::Padding {
                                    cmd,
                                    remaining_pad: pad_len,
                                };
                            } else {
                                // 已交付的内容在调用方缓冲里；切换只影响其后的读取
                                this.finish_frame(cmd)?;
                            }
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Pending => {
                            this.read_state = ReadState::Content {
                                cmd,
                                remaining_content,
                                pad_len,
                            };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    }
                }
                ReadState::Padding {
                    cmd,
                    mut remaining_pad,
                } => {
                    while remaining_pad > 0 {
                        let to_discard = remaining_pad.min(this.scratch.len());
                        let mut temp_buf = ReadBuf::new(&mut this.scratch[..to_discard]);
                        match Pin::new(&mut this.io).poll_read(cx, &mut temp_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = temp_buf.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "Vision 填充丢弃读取中断",
                                    )));
                                }
                                remaining_pad -= n;
                            }
                            Poll::Pending => {
                                this.read_state = ReadState::Padding { cmd, remaining_pad };
                                return Poll::Pending;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        }
                    }
                    if let Err(e) = this.finish_frame(cmd) {
                        return Poll::Ready(Err(e));
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // 先排空已有 write_buf
        while this.write_offset < this.write_buf.len() {
            let offset = this.write_offset;
            match Pin::new(&mut this.io).poll_write(cx, &this.write_buf[offset..]) {
                Poll::Ready(Ok(n)) => {
                    this.write_offset += n;
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
        this.write_buf.clear();
        this.write_offset = 0;

        if this.write_state == WriteState::Direct {
            return Pin::new(&mut this.io).poll_write(cx, buf);
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // 一帧最多 64KB 内容；只报告实际封装的字节数，其余由调用方下次再写
        let content = &buf[..buf.len().min(MAX_FRAME_CONTENT)];
        if this.write_state == WriteState::Initial && is_tls_client_hello(content) {
            // 内层 ClientHello 长填充（对齐 Xray：不足 900 字节时补到 900~1399）
            let jitter = rand::random::<u16>() as usize;
            let pad_len = if content.len() < 900 {
                900 - content.len() + jitter % 500
            } else {
                jitter % 256
            }
            .min(MAX_FRAME_CONTENT);
            this.push_frame(CMD_PADDING_CONTINUE, content, pad_len);
            this.write_state = WriteState::HandshakeSent;
        } else {
            // 非 TLS 首包，或 ClientHello 之后的下一包（握手收尾）：结束填充，此后直通
            this.push_frame(CMD_PADDING_END, content, 0);
            this.write_state = WriteState::Direct;
        }

        // 立即尝试发送新组装的帧（写不完留在 write_buf，由后续 poll_write / poll_flush 继续）
        while this.write_offset < this.write_buf.len() {
            let offset = this.write_offset;
            match Pin::new(&mut this.io).poll_write(cx, &this.write_buf[offset..]) {
                Poll::Ready(Ok(n)) => {
                    this.write_offset += n;
                }
                Poll::Pending => break,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
        Poll::Ready(Ok(content.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.write_offset < this.write_buf.len() {
            let offset = this.write_offset;
            match Pin::new(&mut this.io).poll_write(cx, &this.write_buf[offset..]) {
                Poll::Ready(Ok(n)) => {
                    this.write_offset += n;
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
        this.write_buf.clear();
        this.write_offset = 0;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const UUID: [u8; 16] = *b"0123456789abcdef";

    /// 模拟"外层 TLS + 底层 TCP"：switch_to_raw_read 之后改读 raw 半边；写入全部记录下来
    struct FakeTls {
        tls: std::io::Cursor<Vec<u8>>,
        raw: std::io::Cursor<Vec<u8>>,
        switched: bool,
        written: Vec<u8>,
    }

    impl FakeTls {
        fn new(tls: Vec<u8>, raw: Vec<u8>) -> Self {
            FakeTls {
                tls: std::io::Cursor::new(tls),
                raw: std::io::Cursor::new(raw),
                switched: false,
                written: Vec::new(),
            }
        }
    }

    impl AsyncRead for FakeTls {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let src = if this.switched {
                &mut this.raw
            } else {
                &mut this.tls
            };
            let n = std::io::Read::read(src, buf.initialize_unfilled())?;
            buf.advance(n);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for FakeTls {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.get_mut().written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl ProxyStream for FakeTls {
        fn switch_to_raw_read(&mut self) -> bool {
            self.switched = true;
            true
        }
    }

    fn frame(uuid: bool, cmd: u8, content: &[u8], pad: usize) -> Vec<u8> {
        let mut v = Vec::new();
        if uuid {
            v.extend_from_slice(&UUID);
        }
        v.push(cmd);
        v.extend_from_slice(&(content.len() as u16).to_be_bytes());
        v.extend_from_slice(&(pad as u16).to_be_bytes());
        v.extend_from_slice(content);
        v.resize(v.len() + pad, 0);
        v
    }

    #[tokio::test]
    async fn uuid_prefixed_frames_then_padding_direct_switches_to_raw() {
        // Xray 服务端：首帧带 UUID；内层 TLS 1.3 时以 PaddingDirect 结束并改走底层 TCP
        let mut tls = frame(true, CMD_PADDING_CONTINUE, b"server-hello", 300);
        tls.extend(frame(false, CMD_PADDING_DIRECT, b"app-data", 7));
        let mut s = VisionStream::new(FakeTls::new(tls, b"|raw-after-direct".to_vec()), UUID);
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"server-helloapp-data|raw-after-direct");
        assert!(s.io.switched, "PaddingDirect 必须切到底层直读");
    }

    #[tokio::test]
    async fn stream_without_uuid_is_passed_through() {
        // 首 16 字节不是本连接 UUID：对端没做填充，原样交付（同 Xray）
        let data = b"plain-bytes-longer-than-sixteen".to_vec();
        let mut s = VisionStream::new(FakeTls::new(data.clone(), Vec::new()), UUID);
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, data);
    }

    #[tokio::test]
    async fn first_written_frame_carries_uuid() {
        let mut s = VisionStream::new(FakeTls::new(Vec::new(), Vec::new()), UUID);
        let mut ch = vec![0x16, 0x03, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0xfc];
        ch.resize(256, 0xaa);
        s.write_all(&ch).await.unwrap();
        s.write_all(b"finished").await.unwrap();
        s.write_all(b"raw").await.unwrap();
        s.flush().await.unwrap();
        let w = &s.io.written;
        assert_eq!(&w[..16], &UUID, "首帧必须带 UUID");
        assert_eq!(w[16], CMD_PADDING_CONTINUE);
        let content_len = u16::from_be_bytes([w[17], w[18]]) as usize;
        let pad_len = u16::from_be_bytes([w[19], w[20]]) as usize;
        assert_eq!(content_len, ch.len());
        assert!(
            (900..1400).contains(&(content_len + pad_len)),
            "ClientHello 长填充"
        );
        let second = 21 + content_len + pad_len;
        assert_eq!(
            &w[second..second + 5],
            &[CMD_PADDING_END, 0, 8, 0, 0],
            "第二帧不再带 UUID"
        );
        assert_eq!(&w[second + 5..], b"finishedraw");
    }
}

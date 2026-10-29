//! XTLS-rprx-vision 真实流控（Vision 握手填充与帧化直通）。
//!
//! 规范对标 Xray-core / sing-box：
//! 1. VLESS Addons 线格式：`0x0A 0x10 xtls-rprx-vision`（18 字节 protobuf 编码）。
//! 2. 握手阶段 5 字节帧结构：`[Command: 1B][ContentLen: 2B be][PaddingLen: 2B be][Content][Padding]`。
//!    - Command 0x00: PaddingContinue
//!    - Command 0x01: PaddingEnd
//! 3. 内层 TLS 1.3 ClientHello 嗅探与特征区间填充（900~1200 字节随机平滑）。
//! 4. 握手完成后双方发送 PaddingEnd，退出帧化状态机，进入裸流直通（Direct Copy）。

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub const VISION_FLOW_BYTES: &[u8] = b"\x0a\x10xtls-rprx-vision";

pub const CMD_PADDING_CONTINUE: u8 = 0x00;
pub const CMD_PADDING_END: u8 = 0x01;

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
    /// 尚未发送过 ClientHello
    Initial,
    /// 已发送过 ClientHello 填充帧，等待发送 PaddingEnd
    HandshakeSent,
    /// 已完成 PaddingEnd，进入裸流直通阶段
    Direct,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum ReadState {
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
    /// 已接收到 PaddingEnd，进入裸流直通阶段
    Direct,
}

pub struct VisionStream<S> {
    io: S,
    write_state: WriteState,
    write_buf: Vec<u8>,
    write_offset: usize,
    read_state: ReadState,
    scratch: [u8; 2048],
}

impl<S> vp_core::ProxyStream for VisionStream<S> where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static
{
}

impl<S> VisionStream<S> {
    pub fn new(io: S) -> Self {
        Self {
            io,
            write_state: WriteState::Initial,
            write_buf: Vec::new(),
            write_offset: 0,
            read_state: ReadState::Header {
                buf: [0u8; 5],
                filled: 0,
            },
            scratch: [0u8; 2048],
        }
    }

    /// 服务端视角的 VisionStream：收到客户端首包后回送 ServerHello 帧
    pub fn new_server(io: S) -> Self {
        Self {
            io,
            write_state: WriteState::Initial,
            write_buf: Vec::new(),
            write_offset: 0,
            read_state: ReadState::Header {
                buf: [0u8; 5],
                filled: 0,
            },
            scratch: [0u8; 2048],
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match this.read_state {
                ReadState::Direct => {
                    return Pin::new(&mut this.io).poll_read(cx, buf);
                }
                ReadState::Header {
                    buf: mut hdr_buf,
                    mut filled,
                } => {
                    while filled < 5 {
                        let mut read_slice = [0u8; 5];
                        let mut temp_buf = ReadBuf::new(&mut read_slice[..5 - filled]);
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
                                hdr_buf[filled..filled + n].copy_from_slice(temp_buf.filled());
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
                    } else {
                        // 0 内容 0 填充
                        this.read_state = if cmd == CMD_PADDING_END {
                            ReadState::Direct
                        } else {
                            ReadState::Header {
                                buf: [0u8; 5],
                                filled: 0,
                            }
                        };
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
                            remaining_content = remaining_content.saturating_sub(n);
                            if remaining_content == 0 {
                                if pad_len > 0 {
                                    this.read_state = ReadState::Padding {
                                        cmd,
                                        remaining_pad: pad_len,
                                    };
                                } else if cmd == CMD_PADDING_END {
                                    this.read_state = ReadState::Direct;
                                } else {
                                    this.read_state = ReadState::Header {
                                        buf: [0u8; 5],
                                        filled: 0,
                                    };
                                }
                            } else {
                                this.read_state = ReadState::Content {
                                    cmd,
                                    remaining_content,
                                    pad_len,
                                };
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
                                remaining_pad = remaining_pad.saturating_sub(n);
                            }
                            Poll::Pending => {
                                this.read_state = ReadState::Padding { cmd, remaining_pad };
                                return Poll::Pending;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        }
                    }

                    this.read_state = if cmd == CMD_PADDING_END {
                        ReadState::Direct
                    } else {
                        ReadState::Header {
                            buf: [0u8; 5],
                            filled: 0,
                        }
                    };
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
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

        match this.write_state {
            WriteState::Direct => Pin::new(&mut this.io).poll_write(cx, buf),
            WriteState::Initial => {
                if buf.is_empty() {
                    return Poll::Ready(Ok(0));
                }
                let is_tls = is_tls_client_hello(buf);
                if is_tls {
                    // 内层 TLS ClientHello 长度伪装
                    // 目标区间：900 ~ 1200 字节，平滑消除特征
                    let jitter = (rand::random::<u16>() % 200) as usize;
                    let target_len = if buf.len() < 900 {
                        900 + jitter
                    } else if buf.len() < 1300 {
                        buf.len() + (jitter % 100)
                    } else {
                        buf.len()
                    };
                    let pad_len = (target_len.saturating_sub(buf.len())).min(u16::MAX as usize);

                    let content_len = buf.len() as u16;
                    let pad_len_u16 = pad_len as u16;

                    this.write_buf.reserve(5 + buf.len() + pad_len);
                    this.write_buf.push(CMD_PADDING_CONTINUE);
                    this.write_buf.extend_from_slice(&content_len.to_be_bytes());
                    this.write_buf.extend_from_slice(&pad_len_u16.to_be_bytes());
                    this.write_buf.extend_from_slice(buf);
                    this.write_buf.resize(this.write_buf.len() + pad_len, 0);

                    this.write_state = WriteState::HandshakeSent;
                } else {
                    // 非 TLS 握手流量，直接发送 PaddingEnd 帧后退出分帧
                    let content_len = buf.len().min(u16::MAX as usize) as u16;
                    this.write_buf.reserve(5 + content_len as usize);
                    this.write_buf.push(CMD_PADDING_END);
                    this.write_buf.extend_from_slice(&content_len.to_be_bytes());
                    this.write_buf.extend_from_slice(&[0, 0]); // pad_len = 0
                    this.write_buf
                        .extend_from_slice(&buf[..content_len as usize]);

                    this.write_state = WriteState::Direct;
                }

                // 立即尝试发送新组装的帧
                let written = buf.len();
                while this.write_offset < this.write_buf.len() {
                    let offset = this.write_offset;
                    match Pin::new(&mut this.io).poll_write(cx, &this.write_buf[offset..]) {
                        Poll::Ready(Ok(n)) => {
                            this.write_offset += n;
                        }
                        Poll::Pending => return Poll::Ready(Ok(written)),
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    }
                }
                Poll::Ready(Ok(written))
            }
            WriteState::HandshakeSent => {
                if buf.is_empty() {
                    return Poll::Ready(Ok(0));
                }
                // 第二阶段（握手收尾 / ApplicationData 首包），发送 PaddingEnd 并切入 Direct
                let content_len = buf.len().min(u16::MAX as usize) as u16;
                this.write_buf.reserve(5 + content_len as usize);
                this.write_buf.push(CMD_PADDING_END);
                this.write_buf.extend_from_slice(&content_len.to_be_bytes());
                this.write_buf.extend_from_slice(&[0, 0]); // pad_len = 0
                this.write_buf
                    .extend_from_slice(&buf[..content_len as usize]);

                this.write_state = WriteState::Direct;

                let written = content_len as usize;
                while this.write_offset < this.write_buf.len() {
                    let offset = this.write_offset;
                    match Pin::new(&mut this.io).poll_write(cx, &this.write_buf[offset..]) {
                        Poll::Ready(Ok(n)) => {
                            this.write_offset += n;
                        }
                        Poll::Pending => return Poll::Ready(Ok(written)),
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    }
                }
                Poll::Ready(Ok(written))
            }
        }
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

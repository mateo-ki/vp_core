//! smux (Simple MUltipleXing) v1 协议实现与出站多路复用装饰器。
//!
//! 帧头（8 字节）：
//! `[version: 1B][cmd: 1B][length: 2B be][sid: 4B be][payload]`
//! - CMD_SYN (0x00)：开启新流
//! - CMD_FIN (0x01)：关闭流
//! - CMD_PSH (0x02)：数据推送
//! - CMD_NOP (0x03)：心跳保持

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, warn};

use vp_common::addr::encode_socks_addr;
use vp_common::{DstAddr, Error, Result};
use vp_config::SmuxConfig;
use vp_core::outbound::Outbound;
use vp_core::session::Session;
use vp_core::stream::{PacketConn, ProxyStream};

pub const SMUX_VERSION: u8 = 1;
pub const CMD_SYN: u8 = 0;
pub const CMD_FIN: u8 = 1;
pub const CMD_PSH: u8 = 2;
pub const CMD_NOP: u8 = 3;

pub struct SmuxFrame {
    pub cmd: u8,
    pub sid: u32,
    pub data: Vec<u8>,
}

/// smux 虚拟子流
pub struct SmuxStream {
    sid: u32,
    rx: mpsc::Receiver<Vec<u8>>,
    curr: Option<(Vec<u8>, usize)>,
    tx_frame: mpsc::Sender<SmuxFrame>,
    closed: bool,
    active_counter: Arc<AtomicUsize>,
}

impl AsyncRead for SmuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        loop {
            if let Some((data, offset)) = &mut this.curr {
                if *offset < data.len() {
                    let avail = &data[*offset..];
                    let to_copy = avail.len().min(buf.remaining());
                    buf.put_slice(&avail[..to_copy]);
                    *offset += to_copy;
                    return Poll::Ready(Ok(()));
                }
                this.curr = None;
            }

            match this.rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    this.curr = Some((chunk, 0));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())), // EOF
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for SmuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if this.closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "smux stream closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let take = buf.len().min(32 * 1024);
        let frame = SmuxFrame {
            cmd: CMD_PSH,
            sid: this.sid,
            data: buf[..take].to_vec(),
        };
        match this.tx_frame.try_send(frame) {
            Ok(()) => Poll::Ready(Ok(take)),
            Err(mpsc::error::TrySendError::Full(_)) => {
                // 通道拥塞时触发稍微等待
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "smux session closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        if !this.closed {
            this.closed = true;
            let _ = this.tx_frame.try_send(SmuxFrame {
                cmd: CMD_FIN,
                sid: this.sid,
                data: Vec::new(),
            });
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for SmuxStream {
    fn drop(&mut self) {
        if !this_closed(self.closed) {
            let _ = self.tx_frame.try_send(SmuxFrame {
                cmd: CMD_FIN,
                sid: self.sid,
                data: Vec::new(),
            });
        }
        self.active_counter.fetch_sub(1, Ordering::SeqCst);
    }
}

fn this_closed(c: bool) -> bool {
    c
}

/// 承载于单条底层连接之上的 smux 会话
pub struct SmuxSession {
    next_sid: AtomicU32,
    tx_frame: mpsc::Sender<SmuxFrame>,
    streams: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
    active_streams: Arc<AtomicUsize>,
    is_closed: Arc<AtomicBool>,
}

impl SmuxSession {
    pub fn new(underlying: Box<dyn ProxyStream>) -> Arc<Self> {
        let (tx_frame, mut rx_frame) = mpsc::channel::<SmuxFrame>(256);
        let active_streams = Arc::new(AtomicUsize::new(0));
        let is_closed = Arc::new(AtomicBool::new(false));

        let streams: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let (mut r_stream, mut w_stream) = tokio::io::split(underlying);

        // 写任务
        let is_closed_writer = is_closed.clone();
        tokio::spawn(async move {
            while let Some(frame) = rx_frame.recv().await {
                let mut head = [0u8; 8];
                head[0] = SMUX_VERSION;
                head[1] = frame.cmd;
                let len = frame.data.len() as u16;
                head[2..4].copy_from_slice(&len.to_be_bytes());
                head[4..8].copy_from_slice(&frame.sid.to_be_bytes());

                if w_stream.write_all(&head).await.is_err() {
                    break;
                }
                if !frame.data.is_empty() && w_stream.write_all(&frame.data).await.is_err() {
                    break;
                }
                if w_stream.flush().await.is_err() {
                    break;
                }
            }
            is_closed_writer.store(true, Ordering::SeqCst);
        });

        // 读任务
        let streams_reader = streams.clone();
        let is_closed_reader = is_closed.clone();
        tokio::spawn(async move {
            let mut head = [0u8; 8];
            loop {
                if r_stream.read_exact(&mut head).await.is_err() {
                    break;
                }
                let ver = head[0];
                if ver != SMUX_VERSION {
                    warn!("smux: 未知版本 {ver}");
                    break;
                }
                let cmd = head[1];
                let len = u16::from_be_bytes([head[2], head[3]]) as usize;
                let sid = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);

                let mut body = vec![0u8; len];
                if len > 0 && r_stream.read_exact(&mut body).await.is_err() {
                    break;
                }

                match cmd {
                    CMD_PSH => {
                        let sender = {
                            let map = streams_reader.lock().await;
                            map.get(&sid).cloned()
                        };
                        if let Some(s) = sender {
                            let _ = s.send(body).await;
                        }
                    }
                    CMD_FIN => {
                        let mut map = streams_reader.lock().await;
                        map.remove(&sid);
                    }
                    CMD_NOP => {}
                    _ => {}
                }
            }
            is_closed_reader.store(true, Ordering::SeqCst);
        });

        Arc::new(Self {
            next_sid: AtomicU32::new(1),
            tx_frame,
            streams,
            active_streams,
            is_closed,
        })
    }

    pub fn is_alive(&self) -> bool {
        !self.is_closed.load(Ordering::SeqCst)
    }

    pub fn active_count(&self) -> usize {
        self.active_streams.load(Ordering::SeqCst)
    }

    pub async fn open_stream(&self) -> Result<Box<dyn ProxyStream>> {
        if !self.is_alive() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "smux session is closed",
            )));
        }
        let sid = self.next_sid.fetch_add(2, Ordering::SeqCst); // 客户端奇数
        let (tx, rx) = mpsc::channel(64);
        self.streams.lock().await.insert(sid, tx);

        // 发送 SYN 帧
        self.tx_frame
            .send(SmuxFrame {
                cmd: CMD_SYN,
                sid,
                data: Vec::new(),
            })
            .await
            .map_err(|_| Error::Io(std::io::Error::other("发送 smux SYN 失败")))?;

        self.active_streams.fetch_add(1, Ordering::SeqCst);

        let stream = SmuxStream {
            sid,
            rx,
            curr: None,
            tx_frame: self.tx_frame.clone(),
            closed: false,
            active_counter: self.active_streams.clone(),
        };

        Ok(Box::new(stream))
    }
}

/// smux 多路复用出站包装器（装饰器）
pub struct SmuxOutbound {
    inner: Arc<dyn Outbound>,
    cfg: SmuxConfig,
    sessions: Arc<Mutex<Vec<Arc<SmuxSession>>>>,
}

impl SmuxOutbound {
    pub fn new(inner: Arc<dyn Outbound>, cfg: SmuxConfig) -> Self {
        Self {
            inner,
            cfg,
            sessions: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl Outbound for SmuxOutbound {
    fn name(&self) -> &str {
        self.inner.name()
    }

    async fn connect_stream(&self, sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        let max_conns = self.cfg.max_connections.unwrap_or(4).max(1);
        let max_streams = self.cfg.max_streams.unwrap_or(16).max(1);

        let mut sessions = self.sessions.lock().await;
        // 清理死会话
        sessions.retain(|s| s.is_alive());

        // 寻找未达到并发上限的会话
        let chosen_session = sessions
            .iter()
            .find(|s| s.active_count() < max_streams)
            .cloned();

        let session = match chosen_session {
            Some(s) => s,
            None => {
                if sessions.len() < max_conns {
                    // 新建底层物理连接
                    let underlying = self.inner.connect_stream(sess, dst).await?;
                    let new_session = SmuxSession::new(underlying);
                    sessions.push(new_session.clone());
                    new_session
                } else {
                    // 已达最大连接数，选用负载最低的会话
                    sessions
                        .iter()
                        .min_by_key(|s| s.active_count())
                        .cloned()
                        .ok_or(Error::Proto("无可用的 smux 会话"))?
                }
            }
        };

        // 打开子流并在流头写入 SOCKS5 目标地址
        let mut sub_stream = session.open_stream().await?;
        let mut addr_buf = Vec::with_capacity(32);
        encode_socks_addr(dst, &mut addr_buf);
        sub_stream.write_all(&addr_buf).await.map_err(Error::Io)?;
        sub_stream.flush().await.map_err(Error::Io)?;

        debug!("smux: 复用建立子流 -> {dst}");
        Ok(sub_stream)
    }

    async fn connect_over(
        &self,
        sess: &Session,
        dst: &DstAddr,
        underlying: Box<dyn ProxyStream>,
    ) -> Result<Box<dyn ProxyStream>> {
        self.inner.connect_over(sess, dst, underlying).await
    }

    fn support_udp(&self) -> bool {
        self.inner.support_udp()
    }

    async fn connect_packet(&self, sess: &Session, dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        self.inner.connect_packet(sess, dst).await
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        self.inner.remote_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_smux_stream_multiplexing_roundtrip() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let client_session = SmuxSession::new(Box::new(client_io));

        // 模拟服务端收到子流并回显
        tokio::spawn(async move {
            let mut s = server_io;
            let mut head = [0u8; 8];
            // 读 SYN
            s.read_exact(&mut head).await.unwrap();
            assert_eq!(head[1], CMD_SYN);
            let sid = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);

            // 读 PSH
            s.read_exact(&mut head).await.unwrap();
            assert_eq!(head[1], CMD_PSH);
            let len = u16::from_be_bytes([head[2], head[3]]) as usize;
            let mut data = vec![0u8; len];
            s.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"hello-smux");

            // 回送 PSH: "echo:hello-smux"
            let resp = b"echo:hello-smux";
            let mut resp_head = [0u8; 8];
            resp_head[0] = SMUX_VERSION;
            resp_head[1] = CMD_PSH;
            resp_head[2..4].copy_from_slice(&(resp.len() as u16).to_be_bytes());
            resp_head[4..8].copy_from_slice(&sid.to_be_bytes());

            s.write_all(&resp_head).await.unwrap();
            s.write_all(resp).await.unwrap();
            s.flush().await.unwrap();
        });

        let mut stream = client_session.open_stream().await.unwrap();
        stream.write_all(b"hello-smux").await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = [0u8; 15];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"echo:hello-smux");
    }
}

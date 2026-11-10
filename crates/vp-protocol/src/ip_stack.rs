//! 用户态 TCP/UDP IP 栈抽象（smoltcp）。
//! 供 WireGuard、MASQUE (CONNECT-IP) 等 IP 隧道协议复用。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tracing::warn;

use vp_common::{Error, Result};
use vp_core::PacketConn;
use vp_core::stream::UdpPacket;

pub const MTU: u32 = 1420;
pub const SOCK_BUF: usize = 256 * 1024;
pub const TICK: std::time::Duration = std::time::Duration::from_millis(1);
pub const CHAN_CAP: usize = 256;

static LOCAL_PORT_SEQ: AtomicU64 = AtomicU64::new(0);

pub fn next_local_port() -> u16 {
    (20000 + LOCAL_PORT_SEQ.fetch_add(1, Ordering::Relaxed) % 40000) as u16
}

// ---------------------------------------------------------------------------
// smoltcp 队列设备
// ---------------------------------------------------------------------------

pub struct SharedQueues {
    /// 隧道接收后待栈处理的 IP 包
    pub rx: std::sync::Mutex<std::collections::VecDeque<Vec<u8>>>,
    /// 栈发出待注入隧道的 IP 包
    pub tx: std::sync::Mutex<std::collections::VecDeque<Vec<u8>>>,
    /// 栈产生新发包事件通知（通知底层隧道立即发送，杜绝 1ms 空转轮询）
    pub notify_tx: Arc<tokio::sync::Notify>,
}

impl Default for SharedQueues {
    fn default() -> Self {
        Self {
            rx: std::sync::Mutex::new(std::collections::VecDeque::new()),
            tx: std::sync::Mutex::new(std::collections::VecDeque::new()),
            notify_tx: Arc::new(tokio::sync::Notify::new()),
        }
    }
}

impl SharedQueues {
    pub fn new() -> Self {
        Self::default()
    }
}

pub struct QueueDevice {
    pub q: Arc<SharedQueues>,
}

pub struct StackRxToken(Vec<u8>);
impl RxToken for StackRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.0)
    }
}

pub struct StackTxToken<'a>(&'a Arc<SharedQueues>);
impl TxToken for StackTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.tx.lock().unwrap().push_back(buf);
        self.0.notify_tx.notify_one();
        r
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = StackRxToken;
    type TxToken<'a> = StackTxToken<'a>;

    fn receive(&mut self, _t: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.q.rx.lock().unwrap().pop_front()?;
        Some((StackRxToken(pkt), StackTxToken(&self.q)))
    }

    fn transmit(&mut self, _t: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(StackTxToken(&self.q))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU as usize;
        caps.checksum = smoltcp::phy::ChecksumCapabilities::ignored();
        caps
    }
}

// ---------------------------------------------------------------------------
// 会话控制
// ---------------------------------------------------------------------------

pub type SessionInner = Result<(mpsc::Receiver<UpMsg>, mpsc::Sender<DownMsg>)>;
pub type SessionReply = tokio::sync::oneshot::Sender<SessionInner>;

pub enum Cmd {
    Connect {
        dst: SocketAddr,
        reply: SessionReply,
    },
    ConnectUdp {
        reply: tokio::sync::oneshot::Sender<SessionInner>,
    },
}

/// 栈→应用消息（TCP 数据流 / UDP 数据报）
pub enum UpMsg {
    Tcp(Bytes),
    Udp { src: SocketAddr, data: Bytes },
}

/// 应用→栈消息
pub enum DownMsg {
    Tcp(Vec<u8>),
    Udp { dst: SocketAddr, data: Vec<u8> },
}

enum SessKind {
    Tcp {
        handle: SocketHandle,
        pending: Option<Vec<u8>>,
    },
    Udp {
        handle: SocketHandle,
    },
}

struct Sess {
    kind: SessKind,
    up_tx: mpsc::Sender<UpMsg>,
    down_rx: mpsc::Receiver<DownMsg>,
    closed: bool,
}

// ---------------------------------------------------------------------------
// 栈轮询任务
// ---------------------------------------------------------------------------

pub async fn stack_task(
    mut cmd_rx: mpsc::Receiver<Cmd>,
    q: Arc<SharedQueues>,
    local_v4: Ipv4Addr,
    local_v6: Option<Ipv6Addr>,
) {
    let iface_v4 = IpCidr::Ipv4(smoltcp::wire::Ipv4Cidr::new(local_v4.into(), 32));
    let mut config = IfaceConfig::new(smoltcp::wire::HardwareAddress::Ip);
    config.random_seed = vp_common::now_millis();
    let mut device = QueueDevice { q: q.clone() };
    let mut iface = Interface::new(config, &mut device, SmolInstant::from_millis(0));
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(iface_v4);
        if let Some(v6) = local_v6 {
            let _ = addrs.push(IpCidr::Ipv6(smoltcp::wire::Ipv6Cidr::new(v6.into(), 128)));
        }
    });
    let mut sockets = SocketSet::new(vec![]);
    let mut sessions: HashMap<u64, Sess> = HashMap::new();
    let mut next_sess_id: u64 = 1;
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break };
                match cmd {
                    Cmd::Connect { dst, reply } => {
                        let r = connect_session(
                            &mut iface, &mut sockets, &mut sessions,
                            &mut next_sess_id, local_v4, local_v6, dst,
                        );
                        let _ = reply.send(r);
                    }
                    Cmd::ConnectUdp { reply } => {
                        let r = connect_udp_session(&mut sockets, &mut sessions, &mut next_sess_id);
                        let _ = reply.send(r);
                    }
                }
            }
            _ = tick.tick() => {
                let ts = SmolInstant::from_millis(vp_common::now_millis() as i64);
                let _ = iface.poll(ts, &mut device, &mut sockets);
                pump_sessions(&mut iface, &mut sockets, &mut sessions);
            }
        }
    }
}

type SessionPair = (mpsc::Receiver<UpMsg>, mpsc::Sender<DownMsg>);

fn connect_session(
    iface: &mut Interface,
    sockets: &mut SocketSet<'_>,
    sessions: &mut HashMap<u64, Sess>,
    next_sess_id: &mut u64,
    local_v4: Ipv4Addr,
    local_v6: Option<Ipv6Addr>,
    dst: SocketAddr,
) -> Result<SessionPair> {
    match dst.ip() {
        IpAddr::V4(v4) => {
            iface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Address(v4.octets()))
                .ok();
        }
        IpAddr::V6(v6) => {
            iface
                .routes_mut()
                .add_default_ipv6_route(Ipv6Address(v6.octets()))
                .ok();
        }
    }

    let local_ip: IpAddress = match dst.ip() {
        IpAddr::V4(_) => local_v4.into(),
        IpAddr::V6(_) => {
            let Some(v6) = local_v6 else {
                return Err(Error::Config("未配置 ipv6 隧道地址".into()));
            };
            v6.into()
        }
    };
    let local = IpEndpoint::new(local_ip, next_local_port());
    let remote = IpEndpoint::from(dst);

    let rx_buf = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
    let tx_buf = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
    let mut sock = tcp::Socket::new(rx_buf, tx_buf);
    sock.set_nagle_enabled(false);
    if let Err(e) = sock.connect(iface.context(), remote, local) {
        return Err(Error::ProtoMsg(format!("smoltcp 栈 connect: {:?}", e)));
    }
    let handle = sockets.add(sock);

    let (up_tx, up_rx) = mpsc::channel::<UpMsg>(CHAN_CAP);
    let (down_tx, down_rx) = mpsc::channel::<DownMsg>(CHAN_CAP);
    let id = *next_sess_id;
    *next_sess_id += 1;
    sessions.insert(
        id,
        Sess {
            kind: SessKind::Tcp {
                handle,
                pending: None,
            },
            up_tx,
            down_rx,
            closed: false,
        },
    );

    Ok((up_rx, down_tx))
}

fn connect_udp_session(
    sockets: &mut SocketSet<'_>,
    sessions: &mut HashMap<u64, Sess>,
    next_sess_id: &mut u64,
) -> Result<(mpsc::Receiver<UpMsg>, mpsc::Sender<DownMsg>)> {
    let rx_buf = smoltcp::socket::udp::PacketBuffer::new(
        vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 64],
        vec![0u8; SOCK_BUF],
    );
    let tx_buf = smoltcp::socket::udp::PacketBuffer::new(
        vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 64],
        vec![0u8; SOCK_BUF],
    );
    let mut sock = smoltcp::socket::udp::Socket::new(rx_buf, tx_buf);
    let local_port = next_local_port();
    if let Err(e) = sock.bind(local_port) {
        return Err(Error::ProtoMsg(format!("smoltcp 栈 udp bind: {:?}", e)));
    }
    let handle = sockets.add(sock);

    let (up_tx, up_rx) = mpsc::channel::<UpMsg>(CHAN_CAP);
    let (down_tx, down_rx) = mpsc::channel::<DownMsg>(CHAN_CAP);
    let id = *next_sess_id;
    *next_sess_id += 1;
    sessions.insert(
        id,
        Sess {
            kind: SessKind::Udp { handle },
            up_tx,
            down_rx,
            closed: false,
        },
    );

    Ok((up_rx, down_tx))
}

fn pump_sessions(
    _iface: &mut Interface,
    sockets: &mut SocketSet<'_>,
    sessions: &mut HashMap<u64, Sess>,
) {
    let mut reaped: Vec<u64> = Vec::new();
    for (id, sess) in sessions.iter_mut() {
        match &mut sess.kind {
            SessKind::Udp { handle } => {
                let sock = sockets.get_mut::<smoltcp::socket::udp::Socket>(*handle);
                // 应用 → 栈
                loop {
                    if !sock.can_send() {
                        break;
                    }
                    match sess.down_rx.try_recv() {
                        Ok(DownMsg::Udp { dst, data }) => {
                            let remote = IpEndpoint::from(dst);
                            if let Err(e) = sock.send_slice(&data, remote) {
                                warn!("smoltcp udp send_slice: {e:?}");
                            }
                        }
                        _ => break,
                    }
                }
                // 栈 → 应用
                loop {
                    if !sock.can_recv() {
                        break;
                    }
                    if sess.up_tx.capacity() == 0 {
                        break;
                    }
                    let mut buf = [0u8; 64 * 1024];
                    match sock.recv_slice(&mut buf) {
                        Ok((n, meta)) => {
                            let src = endpoint_to_std(meta.endpoint);
                            let msg = UpMsg::Udp {
                                src,
                                data: Bytes::copy_from_slice(&buf[..n]),
                            };
                            if sess.up_tx.try_send(msg).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                continue;
            }
            SessKind::Tcp { handle, pending } => {
                let sock = sockets.get_mut::<tcp::Socket>(*handle);
                // 应用 → 栈
                while sock.can_send() {
                    if let Some(p) = pending.take() {
                        match sock.send_slice(&p) {
                            Ok(n) if n == p.len() => continue,
                            Ok(n) => {
                                *pending = Some(p[n..].to_vec());
                                break;
                            }
                            Err(e) => {
                                warn!("smoltcp pump pending err: {e:?}");
                                sess.closed = true;
                                break;
                            }
                        }
                    }
                    match sess.down_rx.try_recv() {
                        Ok(DownMsg::Tcp(data)) => match sock.send_slice(&data) {
                            Ok(n) if n == data.len() => {}
                            Ok(n) => {
                                *pending = Some(data[n..].to_vec());
                                break;
                            }
                            Err(e) => {
                                warn!("smoltcp pump send err: {e:?}");
                                sess.closed = true;
                                break;
                            }
                        },
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            sock.close();
                            break;
                        }
                        Ok(_) => {}
                    }
                }
                // 栈 → 应用
                loop {
                    if !sock.may_recv() {
                        if sock.state() == tcp::State::Closed {
                            sess.closed = true;
                        }
                        break;
                    }
                    if sess.up_tx.capacity() == 0 {
                        break;
                    }
                    let mut buf = [0u8; 64 * 1024];
                    match sock.recv_slice(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            match sess
                                .up_tx
                                .try_send(UpMsg::Tcp(Bytes::copy_from_slice(&buf[..n])))
                            {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => break,
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    sess.closed = true;
                                    break;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                if sess.closed {
                    reaped.push(*id);
                }
            }
        }
    }
    for id in reaped {
        if let Some(s) = sessions.remove(&id) {
            match s.kind {
                SessKind::Tcp { handle, .. } | SessKind::Udp { handle } => {
                    sockets.remove(handle);
                }
            }
        }
    }
}

fn endpoint_to_std(ep: smoltcp::wire::IpEndpoint) -> SocketAddr {
    match ep.addr {
        IpAddress::Ipv4(v4) => SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(v4.0)),
            ep.port,
        ),
        IpAddress::Ipv6(v6) => SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(v6.0)),
            ep.port,
        ),
    }
}

// ---------------------------------------------------------------------------
// UDP 会话包装
// ---------------------------------------------------------------------------

pub struct IpStackPacketConn {
    up_rx: mpsc::Receiver<UpMsg>,
    down_tx: mpsc::Sender<DownMsg>,
    local: SocketAddr,
}

impl IpStackPacketConn {
    pub fn new(
        up_rx: mpsc::Receiver<UpMsg>,
        down_tx: mpsc::Sender<DownMsg>,
        local: SocketAddr,
    ) -> Self {
        Self {
            up_rx,
            down_tx,
            local,
        }
    }
}

#[async_trait::async_trait]
impl PacketConn for IpStackPacketConn {
    async fn send(&self, pkt: &UdpPacket) -> Result<()> {
        self.down_tx
            .send(DownMsg::Udp {
                dst: pkt.dst,
                data: pkt.data.to_vec(),
            })
            .await
            .map_err(|_| Error::ProtoMsg("smoltcp UDP 会话已关闭".into()))
    }

    async fn recv(&mut self) -> Result<UdpPacket> {
        loop {
            match self.up_rx.recv().await {
                Some(UpMsg::Udp { src, data }) => {
                    return Ok(UdpPacket {
                        src,
                        dst: self.local,
                        data,
                    });
                }
                Some(UpMsg::Tcp(_)) => continue,
                None => return Err(Error::ProtoMsg("smoltcp UDP 会话已关闭".into())),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TCP 会话流包装
// ---------------------------------------------------------------------------

pub struct IpStackTcpStream {
    up_rx: Pin<Box<mpsc::Receiver<UpMsg>>>,
    down_tx: Pin<Box<mpsc::Sender<DownMsg>>>,
    cur: Option<Bytes>,
    eof: bool,
    err: Option<std::io::Error>,
}

impl vp_core::ProxyStream for IpStackTcpStream {}

impl IpStackTcpStream {
    pub fn new(up_rx: mpsc::Receiver<UpMsg>, down_tx: mpsc::Sender<DownMsg>) -> Self {
        IpStackTcpStream {
            up_rx: Box::pin(up_rx),
            down_tx: Box::pin(down_tx),
            cur: None,
            eof: false,
            err: None,
        }
    }
}

impl AsyncRead for IpStackTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        if let Some(e) = this.err.take() {
            return Poll::Ready(Err(e));
        }
        loop {
            if let Some(cur) = this.cur.as_mut() {
                let n = cur.len().min(buf.remaining());
                buf.put_slice(&cur[..n]);
                cur.advance(n);
                if cur.is_empty() {
                    this.cur = None;
                }
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            match this.up_rx.as_mut().poll_recv(cx) {
                Poll::Ready(Some(UpMsg::Tcp(b))) => {
                    this.cur = Some(b);
                }
                Poll::Ready(Some(UpMsg::Udp { .. })) => continue,
                Poll::Ready(None) => {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for IpStackTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        // 快路径 try_send；满时唤醒重试（栈任务 ≤1ms 后泵走数据）
        match this.down_tx.try_send(DownMsg::Tcp(buf.to_vec())) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "smoltcp 会话已关闭",
                )));
            }
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

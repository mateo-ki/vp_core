//! WireGuard 出站：boringtun 噪声协议 + smoltcp 用户态 TCP/UDP 栈。
//!
//! 架构：一个 WgCore 对应一条 WireGuard 隧道（UDP socket + Tunn 噪声状态机），
//! 后台任务负责握手维护、encapsulate/decapsulate 与 smoltcp Interface 轮询；
//! 每条应用层连接映射为隧道内一个 TCP 会话（栈内 connect，数据经 mpsc 交换）。
//! UDP 会话同理（栈内 UDP socket + 回包地址 NAT）。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::task::{Context, Poll};

use base64::Engine;
use bytes::{Buf, Bytes};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tracing::warn;

use vp_common::{DstAddr, Error, Result};
use vp_config::WgCfg;
use vp_core::stream::UdpPacket;
use vp_core::{Outbound, PacketConn, ProxyStream, Session};

use crate::direct::DirectOutbound;
use vp_dns::Resolver;

const MTU: u32 = 1420;
/// 栈内 TCP 收发缓冲
const SOCK_BUF: usize = 256 * 1024;
/// 栈任务轮询周期
const TICK: std::time::Duration = std::time::Duration::from_millis(1);
/// 握手完成判定：自握手起 5 分钟内有效，超期重协商
const SESSION_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(120);
/// 应用→栈 与 栈→应用 通道容量
const CHAN_CAP: usize = 256;

/// WG 包类型字节（boringtun wire 格式首 4 字节前缀）
#[allow(dead_code)]
const WG_TYPE_DATA: u32 = 4;

static WG_INDEX_SEQ: AtomicU32 = AtomicU32::new(1);
static LOCAL_PORT_SEQ: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// smoltcp 队列设备
// ---------------------------------------------------------------------------

struct SharedQueues {
    /// 解封后待栈处理的 IP 包
    rx: std::sync::Mutex<std::collections::VecDeque<Vec<u8>>>,
    /// 栈发出待 encapsulate 的 IP 包
    tx: std::sync::Mutex<std::collections::VecDeque<Vec<u8>>>,
}

struct QueueDevice {
    q: Arc<SharedQueues>,
}

struct WgRxToken(Vec<u8>);
impl RxToken for WgRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.0)
    }
}

struct WgTxToken<'a>(&'a Arc<SharedQueues>);
impl TxToken for WgTxToken<'_> {
    // smoltcp 约定：len 即最终包长，闭包负责填满
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.tx.lock().unwrap().push_back(buf);
        r
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = WgRxToken;
    type TxToken<'a> = WgTxToken<'a>;

    fn receive(&mut self, _t: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.q.rx.lock().unwrap().pop_front()?;
        Some((WgRxToken(pkt), WgTxToken(&self.q)))
    }

    fn transmit(&mut self, _t: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(WgTxToken(&self.q))
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
// 会话
// ---------------------------------------------------------------------------

type SessionInner = Result<(mpsc::Receiver<UpMsg>, mpsc::Sender<DownMsg>)>;
type SessionReply = tokio::sync::oneshot::Sender<SessionInner>;

enum Cmd {
    Connect {
        dst: SocketAddr,
        reply: SessionReply,
    },
    ConnectUdp {
        reply: tokio::sync::oneshot::Sender<Result<(mpsc::Receiver<UpMsg>, mpsc::Sender<DownMsg>)>>,
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
    /// 栈→应用数据
    up_tx: mpsc::Sender<UpMsg>,
    /// 应用→栈数据
    down_rx: mpsc::Receiver<DownMsg>,
    /// 栈侧已读满/关闭标志
    closed: bool,
}

// ---------------------------------------------------------------------------
// 栈任务主体
// ---------------------------------------------------------------------------

/// WireGuard 隧道核心（一条隧道一个实例，可被多个出站引用）。
pub struct WgCore {
    cmd_tx: mpsc::Sender<Cmd>,
    local_v4: Ipv4Addr,
    #[allow(dead_code)]
    local_v6: Option<Ipv6Addr>,
    server: String,
    port: u16,
}

impl WgCore {
    /// 建立隧道（同步签名：UDP 绑定/连接与握手均在后台任务内完成，
    /// 以便在非 async 的 build_outbound 中调用）。
    #[allow(clippy::too_many_arguments)]
    pub fn connect_udp(
        server: &str,
        port: u16,
        private_key_b64: &str,
        peer_public_key_b64: &str,
        preshared_key_b64: Option<&str>,
        persistent_keepalive: Option<u16>,
        local_v4: Ipv4Addr,
        local_v6: Option<Ipv6Addr>,
    ) -> Result<Arc<WgCore>> {
        use boringtun::noise::Tunn;
        use boringtun::x25519::{PublicKey, StaticSecret};

        let decode32 = |s: &str, what: &str| -> Result<[u8; 32]> {
            let v = base64::engine::general_purpose::STANDARD
                .decode(s.trim())
                .map_err(|e| Error::Config(format!("wireguard {what} base64: {e}")))?;
            let n = v.len();
            v.try_into()
                .map_err(|_| Error::Config(format!("wireguard {what} 长度应为 32 字节，得到 {n}")))
        };
        let sk = StaticSecret::from(decode32(private_key_b64, "private-key")?);
        let peer = PublicKey::from(decode32(peer_public_key_b64, "public-key")?);
        let psk = match preshared_key_b64 {
            Some(k) => Some(decode32(k, "pre-shared-key")?),
            None => None,
        };
        let index = WG_INDEX_SEQ.fetch_add(1, Ordering::Relaxed);
        let tunn = Tunn::new(sk, peer, psk, persistent_keepalive, index, None)
            .map_err(|e| Error::Config(format!("wireguard 初始化: {e}")))?;

        let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>(16);
        let core = Arc::new(WgCore {
            cmd_tx,
            local_v4,
            local_v6,
            server: server.to_string(),
            port,
        });

        let server_owned = server.to_string();
        let q = Arc::new(SharedQueues {
            rx: std::sync::Mutex::new(std::collections::VecDeque::new()),
            tx: std::sync::Mutex::new(std::collections::VecDeque::new()),
        });
        let tunn = Arc::new(std::sync::Mutex::new(tunn));
        tokio::spawn(async move {
            match async {
                let udp = vp_transport::create_udp_socket("0.0.0.0:0".parse().unwrap())?;
                udp.connect((server_owned.as_str(), port)).await?;
                Ok::<tokio::net::UdpSocket, std::io::Error>(udp)
            }
            .await
            {
                Ok(udp) => {
                    let udp = Arc::new(udp);
                    tokio::spawn(wire_task(udp, tunn.clone(), q.clone()));
                    stack_task(cmd_rx, q, local_v4, local_v6).await;
                }
                Err(e) => warn!("wireguard 隧道初始化失败: {e}"),
            }
        });
        Ok(core)
    }

    fn next_local_port() -> u16 {
        (20000 + LOCAL_PORT_SEQ.fetch_add(1, Ordering::Relaxed) % 40000) as u16
    }
}

/// UDP IO 任务：recv → decapsulate → rx 队列；tx 队列 → encapsulate → send；握手维护。
async fn wire_task(
    udp: Arc<tokio::net::UdpSocket>,
    tunn: Arc<std::sync::Mutex<boringtun::noise::Tunn>>,
    q: Arc<SharedQueues>,
) {
    use boringtun::noise::TunnResult;
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(2));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut handshake_at: Option<std::time::Instant> = None;
    let mut udp_buf = vec![0u8; 65535];
    let mut enc_buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            r = udp.recv(&mut udp_buf) => {
                match r {
                    Ok(n) => {
                        let src = udp.peer_addr().ok().map(|a| a.ip());
                        // 锁内完成解包，产出待发送/待入栈的包；发送在锁外 await
                        let (mut to_net, mut to_stack) = (Vec::new(), Vec::new());
                        {
                            let mut tunn = tunn.lock().unwrap();
                            let mut res = tunn.decapsulate(src, &udp_buf[..n], &mut enc_buf);
                            loop {
                                match res {
                                    TunnResult::WriteToNetwork(packet) => {
                                        to_net.push(packet.to_vec());
                                    }
                                    TunnResult::WriteToTunnelV4(packet, _) => {
                                        to_stack.push(packet.to_vec());
                                    }
                                    TunnResult::WriteToTunnelV6(packet, _) => {
                                        to_stack.push(packet.to_vec());
                                    }
                                    TunnResult::Done => break,
                                    TunnResult::Err(e) => {
                                        warn!("wireguard decapsulate: {e:?}");
                                        break;
                                    }
                                }
                                // WriteToNetwork 后需以空包续调（cookie/排队包），直至 Done
                                res = tunn.decapsulate(None, &[], &mut enc_buf);
                            }
                        }
                        for p in to_net {
                            let _ = udp.send(&p).await;
                        }
                        {
                            let mut rx = q.rx.lock().unwrap();
                            for p in to_stack {
                                rx.push_back(p);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("wireguard udp recv: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
            _ = tick.tick() => {
                let now = std::time::Instant::now();
                // 握手维护
                let needs_hs = handshake_at.is_none_or(|t| now.duration_since(t) > SESSION_MAX_AGE);
                if needs_hs {
                    let mut buf = [0u8; 148];
                    let to_send = {
                        let mut tunn = tunn.lock().unwrap();
                        match tunn.format_handshake_initiation(&mut buf, false) {
                            TunnResult::WriteToNetwork(pkt) => Some(pkt.to_vec()),
                            TunnResult::Done => {
                                if let Some(hs) = tunn.stats().0 {
                                    handshake_at = Some(now - hs);
                                }
                                None
                            }
                            _ => None,
                        }
                    };
                    if let Some(pkt) = to_send {
                        if udp.send(&pkt).await.is_ok() && handshake_at.is_none() {
                            handshake_at = Some(now);
                        }
                    }
                }
                // tx 队列 → encapsulate → UDP（每包一次；encapsulate 不像
                // decapsulate 那样需要空包续调——空 src 会被当作 keepalive 无限产出）
                let to_send = {
                    let mut tunn = tunn.lock().unwrap();
                    let mut enc = vec![0u8; 65535];
                    let mut to_send = Vec::new();
                    let mut txq = q.tx.lock().unwrap();
                    while let Some(pkt) = txq.pop_front() {
                        match tunn.encapsulate(&pkt, &mut enc) {
                            TunnResult::WriteToNetwork(p) => to_send.push(p.to_vec()),
                            TunnResult::Done => {}
                            TunnResult::Err(e) => {
                                warn!("wireguard encapsulate: {e:?}");
                            }
                            _ => {}
                        }
                    }
                    to_send
                };
                for p in to_send {
                    let _ = udp.send(&p).await;
                }
            }
        }
    }
}

/// 栈轮询任务（1ms tick）：poll + 会话泵 + 连接命令。
async fn stack_task(
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
    // 默认路由指向目标（点对点隧道，gateway 仅形式用途）
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
                return Err(Error::Config("wireguard 未配置 ipv6 隧道地址".into()));
            };
            v6.into()
        }
    };
    let local = IpEndpoint::new(local_ip, WgCore::next_local_port());
    let remote = IpEndpoint::from(dst);

    let rx_buf = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
    let tx_buf = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
    let mut sock = tcp::Socket::new(rx_buf, tx_buf);
    sock.set_nagle_enabled(false);
    if let Err(e) = sock.connect(iface.context(), remote, local) {
        return Err(Error::ProtoMsg(format!("wireguard 栈 connect: {:?}", e)));
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

/// 新建栈内 UDP 会话（connect_packet 的 dst 在 send 时动态携带）。
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
    let local_port = WgCore::next_local_port();
    if let Err(e) = sock.bind(local_port) {
        return Err(Error::ProtoMsg(format!("wireguard 栈 udp bind: {:?}", e)));
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

/// 会话泵：应用下行 → socket 缓冲；socket 上行 → 应用通道。
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
                                warn!("wireguard udp send_slice: {e:?}");
                            }
                        }
                        _ => break,
                    }
                }
                // 栈 → 应用
                if sess.up_tx.capacity() > 0 {
                    let mut buf = [0u8; 64 * 1024];
                    loop {
                        match sock.recv_slice(&mut buf) {
                            Ok((0, _)) => break,
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
                }
                continue;
            }
            SessKind::Tcp { handle, pending } => {
                let sock = sockets.get_mut::<tcp::Socket>(*handle);
                // 应用 → 栈（先冲上轮部分写入的残留）
                while sock.can_send() {
                    if let Some(p) = pending.take() {
                        match sock.send_slice(&p) {
                            Ok(n) if n == p.len() => continue,
                            Ok(n) => {
                                *pending = Some(p[n..].to_vec());
                                break;
                            }
                            Err(e) => {
                                warn!("wireguard pump pending err: {e:?}");
                                sess.closed = true;
                                break;
                            }
                        }
                    }
                    match sess.down_rx.try_recv() {
                        Ok(DownMsg::Tcp(data)) => {
                            match sock.send_slice(&data) {
                                Ok(n) if n == data.len() => {}
                                Ok(n) => {
                                    // 部分写入（缓冲满）：未发部分暂存，下轮续写
                                    *pending = Some(data[n..].to_vec());
                                    break;
                                }
                                Err(e) => {
                                    warn!("wireguard pump send err: {e:?}");
                                    sess.closed = true;
                                    break;
                                }
                            }
                        }
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            // 应用侧写完：半关闭（发 FIN）
                            sock.close();
                            break;
                        }
                        Ok(_) => {}
                    }
                }
                // 栈 → 应用（通道满时不取，数据留在 socket 缓冲待下轮）
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
                    // 尽量搬空
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

/// smoltcp IpEndpoint → std SocketAddr
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

/// UDP 会话连接：数据报直达栈内 UDP socket，dst 动态携带（多点目标）。
pub struct WgUdpConn {
    up_rx: mpsc::Receiver<UpMsg>,
    down_tx: mpsc::Sender<DownMsg>,
    /// 隧道内本机地址（回包 UdpPacket.dst 填充）
    local: SocketAddr,
}

#[async_trait::async_trait]
impl PacketConn for WgUdpConn {
    async fn send(&self, pkt: &UdpPacket) -> Result<()> {
        self.down_tx
            .send(DownMsg::Udp {
                dst: pkt.dst,
                data: pkt.data.to_vec(),
            })
            .await
            .map_err(|_| Error::ProtoMsg("wireguard UDP 会话已关闭".into()))
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
                None => return Err(Error::ProtoMsg("wireguard UDP 会话已关闭".into())),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 会话流（AsyncRead/AsyncWrite）
// ---------------------------------------------------------------------------

pub struct WgTcpStream {
    up_rx: Pin<Box<mpsc::Receiver<UpMsg>>>,
    down_tx: Pin<Box<mpsc::Sender<DownMsg>>>,
    /// 满时的 reserve future（慢路径缓存）
    cur: Option<Bytes>,
    eof: bool,
    err: Option<std::io::Error>,
}

impl vp_core::ProxyStream for WgTcpStream {}

impl WgTcpStream {
    fn new(up_rx: mpsc::Receiver<UpMsg>, down_tx: mpsc::Sender<DownMsg>) -> Self {
        WgTcpStream {
            up_rx: Box::pin(up_rx),
            down_tx: Box::pin(down_tx),
            cur: None,
            eof: false,
            err: None,
        }
    }
}

impl AsyncRead for WgTcpStream {
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
            match Pin::new(&mut this.up_rx).poll_recv(cx) {
                Poll::Ready(Some(UpMsg::Tcp(b))) => {
                    if b.is_empty() {
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }
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

impl AsyncWrite for WgTcpStream {
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
                    "wireguard 会话已关闭",
                )));
            }
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // drop 时 sender 关闭，pump 侧发 FIN
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// 出站
// ---------------------------------------------------------------------------

pub struct WgOutbound {
    name: Arc<str>,
    core: Arc<WgCore>,
    #[allow(dead_code)]
    resolver: Arc<Resolver>,
    direct: Arc<DirectOutbound>,
    udp: bool,
}

impl WgOutbound {
    pub fn new_named(name: &str, cfg: &WgCfg, resolver: Arc<Resolver>) -> Result<Self> {
        let _ = tokio::runtime::Handle::try_current()
            .map_err(|_| Error::Config("wireguard 出站必须在 tokio 运行时内构建".to_string()))?;
        let core = WgCore::connect_udp(
            &cfg.server,
            cfg.port,
            &cfg.private_key,
            &cfg.public_key,
            cfg.pre_shared_key.as_deref(),
            cfg.persistent_keepalive,
            cfg.local_v4()
                .ok_or_else(|| Error::Config("wireguard ip 字段必须是合法 IPv4".into()))?,
            cfg.local_v6(),
        )?;
        Ok(WgOutbound {
            name: name.into(),
            core,
            direct: Arc::new(DirectOutbound::new(resolver.clone(), false)),
            resolver,
            udp: cfg.udp,
        })
    }

    async fn resolve(&self, dst: &DstAddr) -> Result<SocketAddr> {
        self.direct
            .resolve(dst)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| Error::Addr(format!("wireguard 解析 {dst} 无结果")))
    }
}

#[async_trait::async_trait]
impl Outbound for WgOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect_stream(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        let saddr = self.resolve(dst).await?;
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel::<SessionInner>();
        self.core
            .cmd_tx
            .send(Cmd::Connect {
                dst: saddr,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Error::Proto("wireguard 隧道任务已退出"))?;
        let (up_rx, down_tx) = reply_rx
            .await
            .map_err(|_| Error::Proto("wireguard 隧道任务已退出"))??;
        Ok(Box::new(WgTcpStream::new(up_rx, down_tx)))
    }

    async fn connect_packet(&self, _sess: &Session, _dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel::<
            Result<(mpsc::Receiver<UpMsg>, mpsc::Sender<DownMsg>)>,
        >();
        self.core
            .cmd_tx
            .send(Cmd::ConnectUdp { reply: reply_tx })
            .await
            .map_err(|_| Error::ProtoMsg("wireguard 隧道任务已退出".into()))?;
        let (up_rx, down_tx) = reply_rx
            .await
            .map_err(|_| Error::ProtoMsg("wireguard 隧道任务已退出".into()))??;
        Ok(Box::new(WgUdpConn {
            up_rx,
            down_tx,
            local: SocketAddr::new(std::net::IpAddr::V4(self.core.local_v4), 0),
        }))
    }

    fn support_udp(&self) -> bool {
        self.udp
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        Some((self.core.server.clone(), self.core.port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boringtun::noise::Tunn as ServerTunn;

    struct NetDebug;
    static INIT: std::sync::Once = std::sync::Once::new();
    impl log::Log for NetDebug {
        fn enabled(&self, meta: &log::Metadata) -> bool {
            meta.level() <= log::Level::Trace
        }
        fn log(&self, record: &log::Record) {
            if record.target().contains("smoltcp") {}
        }
        fn flush(&self) {}
    }
    fn init_log() {
        INIT.call_once(|| {
            let _ = log::set_boxed_logger(Box::new(NetDebug));
            log::set_max_level(log::LevelFilter::Trace);
        });
    }
    use boringtun::noise::TunnResult;
    use boringtun::x25519::{PublicKey, StaticSecret};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UdpSocket;

    const SERVER_TUN_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const CLIENT_TUN_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const ECHO_PORT: u16 = 9091;

    /// WG 服务端任务：UDP ↔ Tunn(服务端角色) ↔ smoltcp 栈 TCP echo。
    async fn wg_server_task(udp: UdpSocket, mut tunn: ServerTunn, _client_pub: PublicKey) {
        let q = Arc::new(SharedQueues {
            rx: std::sync::Mutex::new(std::collections::VecDeque::new()),
            tx: std::sync::Mutex::new(std::collections::VecDeque::new()),
        });
        let mut device = QueueDevice { q: q.clone() };
        let mut config = IfaceConfig::new(smoltcp::wire::HardwareAddress::Ip);
        config.random_seed = 42;
        let mut iface = Interface::new(config, &mut device, SmolInstant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::Ipv4(smoltcp::wire::Ipv4Cidr::new(
                SERVER_TUN_IP.into(),
                24,
            )));
        });
        let mut sockets = SocketSet::new(vec![]);
        let mut udp_echo = smoltcp::socket::udp::Socket::new(
            smoltcp::socket::udp::PacketBuffer::new(
                vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 64],
                vec![0u8; SOCK_BUF],
            ),
            smoltcp::socket::udp::PacketBuffer::new(
                vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 64],
                vec![0u8; SOCK_BUF],
            ),
        );
        udp_echo.bind(5353).expect("udp bind");
        let udp_handle = sockets.add(udp_echo);

        let mut echo = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]),
            tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]),
        );
        echo.set_nagle_enabled(false);
        echo.listen(ECHO_PORT).map_err(|_| ()).expect("listen");
        let echo_handle = sockets.add(echo);

        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut ts_ms: i64 = 0;
        let mut udp_buf = vec![0u8; 65535];
        let mut dec_buf = vec![0u8; 65535];
        let mut peer: Option<std::net::SocketAddr> = None;
        loop {
            tokio::select! {
                r = udp.recv_from(&mut udp_buf) => {
                    let Ok((n, from)) = r else { continue };
                    peer = Some(from);
                    let r = tunn.decapsulate(None, &udp_buf[..n], &mut dec_buf);
                    match r {
                        TunnResult::WriteToTunnelV4(pkt, _) => {
                            q.rx.lock().unwrap().push_back(pkt.to_vec());
                        }
                        TunnResult::WriteToNetwork(p) => {
                            let _ = udp.send_to(p, from).await;
                        }
                        TunnResult::WriteToTunnelV6(pkt, _) => q.rx.lock().unwrap().push_back(pkt.to_vec()),
                        TunnResult::Done => {}
                        TunnResult::Err(e) => {
                            warn!("wg server decapsulate: {e:?}");
                        }
                    }
                }
                _ = tick.tick() => {
                    ts_ms += 1;
                    let ts = SmolInstant::from_millis(ts_ms);
                    let _ = iface.poll(ts, &mut device, &mut sockets);
                    let to_send = {
                        let mut txq = q.tx.lock().unwrap();
                        std::mem::take(&mut *txq)
                    };
                    for pkt in to_send {
                        let mut enc = vec![0u8; 65535];
                        if let (TunnResult::WriteToNetwork(p), Some(peer)) =
                            (tunn.encapsulate(&pkt, &mut enc), peer)
                        {
                            let _ = udp.send_to(p, peer).await;
                        }
                    }
                    let sock = sockets.get_mut::<tcp::Socket>(echo_handle);
                    if sock.may_recv() {
                        let mut buf = [0u8; 16 * 1024];
                        if let Ok(n) = sock.recv_slice(&mut buf) {
                            if n > 0 {
                                let _ = sock.send_slice(&buf[..n]);
                            }
                        }
                    }
                    // UDP echo
                    let uecho = sockets.get_mut::<smoltcp::socket::udp::Socket>(udp_handle);
                    let mut ubuf = [0u8; 2048];
                    while let Ok((n, meta)) = uecho.recv_slice(&mut ubuf) {
                        if n == 0 {
                            break;
                        }
                        let _ = uecho.send_slice(&ubuf[..n], meta.endpoint);
                    }
                }
            }
        }
    }

    fn gen_keypair() -> ([u8; 32], [u8; 32], String, String) {
        let mut priv_bytes = [0u8; 32];
        vp_common::rand_bytes(&mut priv_bytes);
        let secret = StaticSecret::from(priv_bytes);
        let public = PublicKey::from(&secret);
        let b64 = |v: &[u8]| base64::engine::general_purpose::STANDARD.encode(v);
        (
            priv_bytes,
            *public.as_bytes(),
            b64(&priv_bytes),
            b64(public.as_bytes()),
        )
    }

    #[tokio::test]
    async fn wg_e2e_loopback() {
        init_log();
        // 密钥对
        let (server_priv, _server_pub, _server_priv_b64, server_pub_b64) = gen_keypair();
        let (client_priv, client_pub, client_priv_b64, client_pub_b64) = gen_keypair();
        let _ = (server_priv, client_priv);

        // 服务端 UDP + Tunn
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_port = udp.local_addr().unwrap().port();
        let index = WG_INDEX_SEQ.fetch_add(1, Ordering::Relaxed);
        let server_pub = PublicKey::from(&StaticSecret::from(server_priv));
        let rate_limiter = Arc::new(boringtun::noise::rate_limiter::RateLimiter::new(
            &server_pub,
            1024,
        ));
        let server_tunn = ServerTunn::new(
            StaticSecret::from(server_priv),
            PublicKey::from(client_pub),
            None,
            None,
            index,
            Some(rate_limiter),
        )
        .unwrap();
        tokio::spawn(wg_server_task(
            udp,
            server_tunn,
            PublicKey::from(client_pub),
        ));

        // 客户端出站
        let cfg = WgCfg {
            server: "127.0.0.1".into(),
            port: server_port,
            private_key: client_priv_b64,
            public_key: server_pub_b64,
            pre_shared_key: None,
            persistent_keepalive: None,
            ip: CLIENT_TUN_IP.to_string(),
            ipv6: None,
            udp: true,
            mtu: None,
        };
        let out = WgOutbound::new_named("wg-test", &cfg, Arc::new(Resolver::system())).unwrap();
        let dst = DstAddr::ip(SERVER_TUN_IP.into(), ECHO_PORT);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            out.connect_stream(&sess, &dst),
        )
        .await
        .unwrap()
        .expect("wg 连接应成功");

        // 数据往返（先等稳定：排除 SYN-SENT 排队段）
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        s.write_all(b"wg-e2e-ping-16b!").await.unwrap();
        let mut buf = [0u8; 16];
        tokio::time::timeout(std::time::Duration::from_secs(5), s.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"wg-e2e-ping-16b!");

        // 大数据往返（256KB，分块写）
        let big: Vec<u8> = (0..262_144u32).map(|i| (i % 253) as u8).collect();
        let half = big.len() / 2;
        s.write_all(&big[..half]).await.unwrap();
        let mut echo = vec![0u8; big.len()];
        let mut got = 0;
        // 边写边读：先读一半再写另一半，避免缓冲死锁
        s.write_all(&big[half..]).await.unwrap();
        while got < big.len() {
            let n =
                tokio::time::timeout(std::time::Duration::from_secs(5), s.read(&mut echo[got..]))
                    .await
                    .unwrap()
                    .unwrap();
            assert!(n > 0, "echo 中断于 {got}");
            got += n;
        }
        assert_eq!(echo, big, "大数据回显应逐字节一致");

        // UDP 往返
        assert!(out.support_udp());
        let mut conn = out
            .connect_packet(&sess, &dst)
            .await
            .expect("wg UDP 应可用");
        conn.send(&vp_core::stream::UdpPacket {
            src: "0.0.0.0:0".parse().unwrap(),
            dst: SocketAddr::new(SERVER_TUN_IP.into(), 5353),
            data: b"wg-udp-ping".to_vec().into(),
        })
        .await
        .unwrap();
        let pong = tokio::time::timeout(std::time::Duration::from_secs(5), conn.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pong.data.as_ref(), b"wg-udp-ping");
        assert_eq!(pong.src.port(), 5353, "回包源端口应为 5353");
        let _ = client_pub_b64;
    }
}

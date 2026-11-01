//! Hysteria2 协议（QUIC + HTTP/3 认证 + QUIC varint 帧）。
//!
//! - 认证：HTTP/3 `POST /auth`，`Hysteria-Auth` 头携带密码，响应状态码 233
//! - TCP：每连接一条 QUIC 双向流，首包 `[varint 0x401][varint |addr|]["host:port"][varint |pad|]`
//!   服务端 TCPResponse `[u8 status][varint |msg|][msg]`
//! - UDP：QUIC unreliable datagram，UDPMessage
//!   `[u32 BE session][u16 BE pkt][u8 frag][u8 frag_total][varint |addr|][addr][payload]`
//!   超过 datagram 上限的包按 apernet/hysteria `frag.go` 分片（每片都带地址），收端按会话重组

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};

use async_trait::async_trait;
use blake2::digest::{Digest, consts::U32};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, RwLock, mpsc};

use vp_common::{DstAddr, Error, Result};
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;
use vp_core::tunnel::{RelayHook, relay};
use vp_core::{Inbound, Outbound, PacketConn, ProxyStream, UdpPacket};

type Blake2b256 = blake2::Blake2b<U32>;

const TCP_REQUEST_ID: u64 = 0x401;

// ---------------------------------------------------------------------------
// QUIC varint
// ---------------------------------------------------------------------------

pub fn write_varint(out: &mut Vec<u8>, v: u64) {
    if v < 0x40 {
        out.push(v as u8);
    } else if v < 0x4000 {
        let n: u16 = 0x4000 | v as u16;
        out.extend_from_slice(&n.to_be_bytes());
    } else if v < 0x4000_0000 {
        let n: u32 = 0x8000_0000 | v as u32;
        out.extend_from_slice(&n.to_be_bytes());
    } else {
        let n: u64 = 0xC000_0000_0000_0000 | v;
        out.extend_from_slice(&n.to_be_bytes());
    }
}

pub fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let b0 = *buf.first()?;
    match b0 >> 6 {
        0 => Some((b0 as u64, 1)),
        1 => {
            if buf.len() < 2 {
                return None;
            }
            Some((((b0 as u64) & 0x3f) << 8 | buf[1] as u64, 2))
        }
        2 => {
            if buf.len() < 4 {
                return None;
            }
            let mut b = [0u8; 4];
            b[0] = b0 & 0x3f;
            b[1..].copy_from_slice(&buf[1..4]);
            Some((u32::from_be_bytes(b) as u64, 4))
        }
        _ => {
            if buf.len() < 8 {
                return None;
            }
            let mut b = [0u8; 8];
            b[0] = b0 & 0x3f;
            b[1..].copy_from_slice(&buf[1..8]);
            Some((u64::from_be_bytes(b), 8))
        }
    }
}

/// 流式读取 QUIC varint（TCPResponse 字段边界可能落在任意字节处）。
async fn read_varint_async(recv: &mut quinn::RecvStream) -> Result<(u64, usize)> {
    let mut one = [0u8; 1];
    recv.read_exact(&mut one)
        .await
        .map_err(|e| Error::Io(std::io::Error::other(format!("hy2 varint: {e}"))))?;
    let b0 = one[0];
    let len = match b0 >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    if len == 1 {
        return Ok((b0 as u64, 1));
    }
    let mut b = [0u8; 8];
    b[0] = b0 & 0x3f;
    recv.read_exact(&mut b[1..len])
        .await
        .map_err(|e| Error::Io(std::io::Error::other(format!("hy2 varint: {e}"))))?;
    let v = match len {
        2 => u16::from_be_bytes([b[0], b[1]]) as u64,
        4 => u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64,
        _ => u64::from_be_bytes(b),
    };
    Ok((v, len))
}

fn addr_text(dst: &DstAddr) -> String {
    dst.to_string()
}

// ---------------------------------------------------------------------------
// UDP 分片 / 重组 / 服务端会话（TUIC 复用 split_frags、Defragger、udp_session）
// ---------------------------------------------------------------------------

/// 切分载荷：返回 `(frag_id, frag_total, 片段)`。`head` 为每片头部开销，`max` 为单片上限。
/// 整包放得下时只有一片；头部都放不下或超过 255 片时返回空，即丢包而不是 panic
/// （GHSA-qh5x-rfwf-rvfv）
pub(crate) fn split_frags(data: &[u8], head: usize, max: usize) -> Vec<(u8, u8, &[u8])> {
    let chunk = if head + data.len() <= max {
        data.len().max(1)
    } else {
        match max.checked_sub(head) {
            Some(c) if c > 0 => c,
            _ => return Vec::new(),
        }
    };
    let n = data.len().div_ceil(chunk).max(1);
    let Ok(total) = u8::try_from(n) else {
        return Vec::new();
    };
    (0..n)
        .map(|i| {
            let part = &data[i * chunk..((i + 1) * chunk).min(data.len())];
            (i as u8, total, part)
        })
        .collect()
}

/// 编码 UDPMessage，超过 `max` 时分片（每片都带地址）
fn frag_udp_message(session: u32, pkt_id: u16, addr: &str, data: &[u8], max: usize) -> Vec<Bytes> {
    let mut head = Vec::with_capacity(16 + addr.len());
    head.extend_from_slice(&session.to_be_bytes());
    head.extend_from_slice(&pkt_id.to_be_bytes());
    head.extend_from_slice(&[0, 1]);
    write_varint(&mut head, addr.len() as u64);
    head.extend_from_slice(addr.as_bytes());
    split_frags(data, head.len(), max)
        .into_iter()
        .map(|(id, total, part)| {
            let mut m = Vec::with_capacity(head.len() + part.len());
            m.extend_from_slice(&head);
            m[6] = id;
            m[7] = total;
            m.extend_from_slice(part);
            Bytes::from(m)
        })
        .collect()
}

/// 分片重组（同 hysteria `Defragger` / mihomo tuic `deFragger`）：只跟踪当前一个 pkt id，
/// 新 pkt id 到来即丢弃未凑齐的旧包。地址取自带地址的分片（TUIC 只有首片带）
pub(crate) struct Defragger<A> {
    pkt_id: u16,
    frags: Vec<Option<Bytes>>,
    count: usize,
    addr: Option<A>,
}

impl<A> Default for Defragger<A> {
    fn default() -> Self {
        Self {
            pkt_id: 0,
            frags: Vec::new(),
            count: 0,
            addr: None,
        }
    }
}

impl<A: Clone> Defragger<A> {
    /// 喂入一片；凑齐整包时返回 `(地址, 载荷)`
    pub(crate) fn feed(
        &mut self,
        pkt_id: u16,
        frag_id: u8,
        frag_total: u8,
        addr: Option<A>,
        data: Bytes,
    ) -> Option<(A, Bytes)> {
        if frag_total <= 1 {
            return Some((addr?, data));
        }
        if frag_id >= frag_total {
            return None;
        }
        let (id, total) = (frag_id as usize, frag_total as usize);
        if pkt_id != self.pkt_id || total != self.frags.len() {
            self.pkt_id = pkt_id;
            self.frags = vec![None; total];
            self.count = 0;
            self.addr = None;
        }
        if self.frags[id].is_some() {
            return None; // 重复分片
        }
        self.frags[id] = Some(data);
        self.count += 1;
        if addr.is_some() {
            self.addr = addr;
        }
        if self.count < total {
            return None;
        }
        // 分片留到下个包再清：迟到的重复分片落进已占用的槽位，被忽略
        let len = self.frags.iter().flatten().map(Bytes::len).sum();
        let mut out = BytesMut::with_capacity(len);
        for f in self.frags.iter().flatten() {
            out.extend_from_slice(f);
        }
        Some((self.addr.clone()?, out.freeze()))
    }
}

/// 服务端 UDP 会话空闲回收时间（同 hysteria 默认 udpIdleTimeout）
const UDP_SESSION_IDLE: std::time::Duration = std::time::Duration::from_secs(60);

/// 服务端 UDP 会话表：会话 id → (发往会话任务的通道, 该会话的重组器)
pub(crate) type UdpSessions<K, A> = HashMap<K, (mpsc::Sender<(DstAddr, Bytes)>, Defragger<A>)>;

/// 取会话；不存在或已空闲回收时新建（顺带清掉其它已结束的会话）。`reply` 构造新会话的回包函数
pub(crate) fn udp_session<K, A, F>(
    sessions: &mut UdpSessions<K, A>,
    key: K,
    reply: impl FnOnce() -> F,
) -> &mut (mpsc::Sender<(DstAddr, Bytes)>, Defragger<A>)
where
    K: Eq + Hash,
    F: FnMut(SocketAddr, &[u8]) -> bool + Send + 'static,
{
    if sessions.get(&key).is_none_or(|(tx, _)| tx.is_closed()) {
        sessions.retain(|_, (tx, _)| !tx.is_closed());
    }
    sessions.entry(key).or_insert_with(|| {
        let (tx, rx) = mpsc::channel(256);
        tokio::spawn(serve_udp_session(rx, reply()));
        (tx, Defragger::default())
    })
}

/// 一个会话一个未 connect 的套接字：每包按各自目标 send_to（域名在此解析），
/// 回包连同来源地址交给 `reply`（返回 false 结束会话）；双向都空闲超时后退出
async fn serve_udp_session(
    mut rx: mpsc::Receiver<(DstAddr, Bytes)>,
    mut reply: impl FnMut(SocketAddr, &[u8]) -> bool,
) {
    // ponytail: 只绑 IPv4，IPv6 目标 send_to 失败即丢包；要支持再按地址族补一个套接字
    let Ok(sock) = vp_transport::create_udp_socket(SocketAddr::from(([0, 0, 0, 0], 0))) else {
        return;
    };
    let mut buf = vec![0u8; 65535];
    // 同一会话通常只发往一个目标：缓存最近一次解析结果
    let mut last: Option<(DstAddr, SocketAddr)> = None;
    loop {
        tokio::select! {
            m = rx.recv() => {
                let Some((dst, data)) = m else { break };
                let target = match &last {
                    Some((d, a)) if *d == dst => *a,
                    _ => {
                        let Some(a) = resolve_udp_target(&dst).await else { continue };
                        last = Some((dst, a));
                        a
                    }
                };
                let _ = sock.send_to(&data, target).await;
            }
            r = sock.recv_from(&mut buf) => match r {
                Ok((n, from)) => {
                    if !reply(from, &buf[..n]) {
                        break;
                    }
                }
                // Windows：先前目标端口不可达（ICMP）会让下一次 recv_from 报 WSAECONNRESET，会话仍可用
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
                Err(_) => break,
            },
            _ = tokio::time::sleep(UDP_SESSION_IDLE) => break,
        }
    }
}

async fn resolve_udp_target(dst: &DstAddr) -> Option<SocketAddr> {
    match &dst.host {
        vp_common::Host::Ip(ip) => Some(SocketAddr::new(*ip, dst.port)),
        vp_common::Host::Domain(d) => tokio::net::lookup_host((d.as_str(), dst.port))
            .await
            .ok()?
            .find(SocketAddr::is_ipv4),
    }
}

// ---------------------------------------------------------------------------
// 出站
// ---------------------------------------------------------------------------

/// Hysteria 2 官方 Salamander 协议混淆实现
/// 数据报格式：[8 字节随机 Salt][XOR 混淆载荷]
/// 密钥派生：Blake2b-256(concat(salt, psk))
#[derive(Debug, Clone)]
pub struct SalamanderObfs {
    key: [u8; 32],
}

impl SalamanderObfs {
    pub fn new(password: &str) -> Self {
        let mut hasher = Blake2b256::new();
        hasher.update(password.as_bytes());
        let res = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&res);
        Self { key }
    }

    pub fn obfuscate(&self, input: &[u8]) -> Vec<u8> {
        let salt = rand::random::<[u8; 8]>();
        let mut hasher = Blake2b256::new();
        hasher.update(salt);
        hasher.update(self.key);
        let derived = hasher.finalize();

        let mut out = Vec::with_capacity(input.len() + 8);
        out.extend_from_slice(&salt);
        for (i, &b) in input.iter().enumerate() {
            out.push(b ^ derived[i % 32]);
        }
        out
    }

    pub fn deobfuscate(&self, input: &[u8]) -> Option<Vec<u8>> {
        if input.len() < 8 {
            return None;
        }
        let (salt, encrypted) = input.split_at(8);
        let mut hasher = Blake2b256::new();
        hasher.update(salt);
        hasher.update(self.key);
        let derived = hasher.finalize();

        let mut out = Vec::with_capacity(encrypted.len());
        for (i, &b) in encrypted.iter().enumerate() {
            out.push(b ^ derived[i % 32]);
        }
        Some(out)
    }
}

pub struct Hysteria2Session {
    pub conn: quinn::Connection,
    pub endpoint: quinn::Endpoint,
    pub _critical_streams: crate::h3_min::H3CriticalStreams,
    pub udp_demux: Arc<Hysteria2UdpDemuxer>,
    pub created_at: std::time::Instant,
}

impl Hysteria2Session {
    pub fn is_alive(&self) -> bool {
        self.conn.close_reason().is_none()
    }
}

pub struct Hysteria2UdpDemuxer {
    listeners: Arc<RwLock<HashMap<u32, mpsc::Sender<UdpPacket>>>>,
    _task: tokio::task::JoinHandle<()>,
}

impl Hysteria2UdpDemuxer {
    pub fn new(conn: quinn::Connection) -> Self {
        let listeners: Arc<RwLock<HashMap<u32, mpsc::Sender<UdpPacket>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let listeners_cloned = listeners.clone();
        let task = tokio::spawn(async move {
            let mut defrag: HashMap<u32, Defragger<SocketAddr>> = HashMap::new();
            while let Ok(dgram) = conn.read_datagram().await {
                let Some(m) = parse_udp_message(dgram) else {
                    continue;
                };
                // 服务端回包地址恒为 "ip:port"
                let Ok(src) = m.addr.parse::<SocketAddr>() else {
                    continue;
                };
                let guard = listeners_cloned.read().await;
                let Some(sender) = guard.get(&m.session) else {
                    continue;
                };
                // 已注销会话的重组状态批量清掉（会话 id 只增不复用）
                if defrag.len() > guard.len() + 64 {
                    defrag.retain(|k, _| guard.contains_key(k));
                }
                let whole = defrag.entry(m.session).or_default().feed(
                    m.pkt_id,
                    m.frag_id,
                    m.frag_total,
                    Some(src),
                    m.payload,
                );
                if let Some((src, data)) = whole {
                    let _ = sender.try_send(UdpPacket {
                        src,
                        dst: src,
                        data,
                    });
                }
            }
        });
        Self {
            listeners,
            _task: task,
        }
    }

    pub async fn register(&self, session_id: u32, sender: mpsc::Sender<UdpPacket>) {
        self.listeners.write().await.insert(session_id, sender);
    }

    pub async fn unregister(&self, session_id: u32) {
        self.listeners.write().await.remove(&session_id);
    }
}

impl Drop for Hysteria2UdpDemuxer {
    /// 接收任务持有连接副本：不停掉它，被替换的旧会话（端口跳跃等）会靠 keepalive 一直活着
    fn drop(&mut self) {
        self._task.abort();
    }
}

pub fn parse_port_ranges(spec: &str) -> Vec<(u16, u16)> {
    let mut out = Vec::new();
    for seg in spec.split(',') {
        let seg = seg.trim();
        if seg.is_empty() {
            continue;
        }
        if let Some((a, b)) = seg.split_once('-') {
            if let (Ok(start), Ok(end)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                if start > 0 && end >= start {
                    out.push((start, end));
                }
            }
        } else if let Ok(p) = seg.parse::<u16>() {
            if p > 0 {
                out.push((p, p));
            }
        }
    }
    out
}

pub struct Hysteria2Outbound {
    name: Arc<str>,
    server: String,
    port: u16,
    port_ranges: Vec<(u16, u16)>,
    hop_interval_secs: u64,
    password: String,
    sni: Option<String>,
    skip_verify: bool,
    _up_mbps: u32,
    down_mbps: u32,
    obfs: Option<SalamanderObfs>,
    udp_session: AtomicU32,
    session: Mutex<Option<Arc<Hysteria2Session>>>,
}

impl Hysteria2Outbound {
    pub fn new(cfg: &vp_config::Hysteria2Cfg) -> Result<Self> {
        let obfs = if let Some(ref o) = cfg.obfs {
            if o.eq_ignore_ascii_case("salamander") {
                let psw = cfg
                    .obfs_password
                    .as_deref()
                    .unwrap_or(cfg.password.as_str());
                Some(SalamanderObfs::new(psw))
            } else {
                None
            }
        } else {
            cfg.obfs_password.as_deref().map(SalamanderObfs::new)
        };

        let port_ranges = cfg
            .ports
            .as_deref()
            .map(parse_port_ranges)
            .unwrap_or_default();
        let hop_interval_secs = cfg.hop_interval.unwrap_or(30).max(5);

        Ok(Hysteria2Outbound {
            name: "hysteria2".into(),
            server: cfg.server.clone(),
            port: cfg.port,
            port_ranges,
            hop_interval_secs,
            password: cfg.password.clone(),
            sni: cfg
                .sni
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .or_else(|| Some(cfg.server.clone())),
            skip_verify: cfg.skip_cert_verify,
            _up_mbps: cfg.up.unwrap_or(0),
            down_mbps: cfg.down.unwrap_or(0),
            obfs,
            udp_session: AtomicU32::new(1),
            session: Mutex::new(None),
        })
    }

    fn pick_port(&self) -> u16 {
        if self.port_ranges.is_empty() {
            return self.port;
        }
        let total: u32 = self
            .port_ranges
            .iter()
            .map(|(s, e)| (*e as u32) - (*s as u32) + 1)
            .sum();
        if total == 0 {
            return self.port;
        }
        let mut rnd = [0u8; 4];
        vp_common::rand_bytes(&mut rnd);
        let mut offset = u32::from_le_bytes(rnd) % total;
        for &(s, e) in &self.port_ranges {
            let span = (e as u32) - (s as u32) + 1;
            if offset < span {
                return s + (offset as u16);
            }
            offset -= span;
        }
        self.port
    }

    async fn connect_quic(&self) -> Result<(quinn::Connection, quinn::Endpoint)> {
        let target_port = self.pick_port();
        let addrs = vp_transport::resolve_node_addrs(&self.server, target_port).await?;
        vp_transport::race_addrs(&addrs, vp_transport::HAPPY_EYEBALLS_DELAY, |addr| {
            self.connect_quic_addr(addr)
        })
        .await
    }

    async fn connect_quic_addr(
        &self,
        addr: SocketAddr,
    ) -> Result<(quinn::Connection, quinn::Endpoint)> {
        if let Some(ref obfs) = self.obfs {
            let local_proxy_sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
            let local_proxy_addr = local_proxy_sock.local_addr()?;

            // 走 create_udp_socket：按地址族绑定，并带上出站网卡绑定（同非混淆路径）
            let remote_bind = if addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let remote_sock = Arc::new(vp_transport::create_udp_socket(
                remote_bind.parse().unwrap(),
            )?);
            remote_sock.connect(addr).await?;

            let quinn_tokio_sock = vp_transport::create_udp_socket("127.0.0.1:0".parse().unwrap())?;
            let std_sock = quinn_tokio_sock.into_std().map_err(Error::Io)?;
            let mut ep = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                None,
                std_sock,
                Arc::new(quinn::TokioRuntime),
            )
            .map_err(|e| Error::Io(std::io::Error::other(format!("hy2 endpoint: {e}"))))?;
            ep.set_default_client_config(hysteria_client_config(
                self.skip_verify,
                self.sni.as_deref(),
            ));

            let l_recv = local_proxy_sock.clone();
            let r_send = remote_sock.clone();
            let obfs_c = obfs.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 65535];
                loop {
                    let Ok((n, _)) = l_recv.recv_from(&mut buf).await else {
                        break;
                    };
                    let out = obfs_c.obfuscate(&buf[..n]);
                    if r_send.send(&out).await.is_err() {
                        break;
                    }
                }
            });

            let r_recv = remote_sock.clone();
            let l_send = local_proxy_sock.clone();
            let obfs_c2 = obfs.clone();
            let quinn_local = ep.local_addr()?;
            tokio::spawn(async move {
                let mut buf = [0u8; 65535];
                loop {
                    let Ok(n) = r_recv.recv(&mut buf).await else {
                        break;
                    };
                    if let Some(plain) = obfs_c2.deobfuscate(&buf[..n]) {
                        let _ = l_send.send_to(&plain, quinn_local).await;
                    }
                }
            });

            let conn = ep
                .connect(
                    local_proxy_addr,
                    self.sni.as_deref().unwrap_or(&self.server),
                )
                .map_err(|e| Error::Addr(format!("hy2 连接参数: {e}")))?
                .await
                .map_err(|e| Error::Io(std::io::Error::other(format!("hy2 QUIC 握手: {e}"))))?;
            Ok((conn, ep))
        } else {
            let bind: &'static str = if addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let tokio_sock = vp_transport::create_udp_socket(bind.parse().unwrap())?;
            let std_sock = tokio_sock.into_std().map_err(Error::Io)?;
            let mut ep = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                None,
                std_sock,
                Arc::new(quinn::TokioRuntime),
            )
            .map_err(|e| Error::Io(std::io::Error::other(format!("hy2 endpoint: {e}"))))?;
            ep.set_default_client_config(hysteria_client_config(
                self.skip_verify,
                self.sni.as_deref(),
            ));
            let conn = ep
                .connect(addr, self.sni.as_deref().unwrap_or(&self.server))
                .map_err(|e| Error::Addr(format!("hy2 连接参数: {e}")))?
                .await
                .map_err(|e| Error::Io(std::io::Error::other(format!("hy2 QUIC 握手: {e}"))))?;
            Ok((conn, ep))
        }
    }

    /// HTTP/3 认证（返回关键控制流集合，必须由会话长久持有避免 260 错误）
    async fn auth(&self, conn: &quinn::Connection) -> Result<crate::h3_min::H3CriticalStreams> {
        let cc_rx = if self.down_mbps > 0 {
            ((self.down_mbps as u64) * 125_000).to_string()
        } else {
            "0".to_string()
        };
        let headers: Vec<(&str, &str)> = vec![
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", "hysteria"),
            (":path", "/auth"),
            ("hysteria-auth", &self.password),
            ("hysteria-cc-rx", &cc_rx),
            ("hysteria-padding", "0000000000000000"),
        ];
        let (resp, critical) = crate::h3_min::auth_roundtrip(conn, &headers).await?;
        let status = resp
            .iter()
            .find(|(k, _)| k == ":status")
            .map(|(_, v)| v.clone())
            .ok_or(Error::Proto("hy2: 响应缺 :status"))?;
        if status != "233" {
            return Err(Error::ProtoMsg(format!("hy2 认证失败（状态 {status}）")));
        }
        Ok(critical)
    }

    async fn get_or_connect_session(&self) -> Result<Arc<Hysteria2Session>> {
        let mut guard = self.session.lock().await;
        if let Some(ref s) = *guard {
            let need_hop = !self.port_ranges.is_empty()
                && s.created_at.elapsed() >= std::time::Duration::from_secs(self.hop_interval_secs);
            if s.is_alive() && !need_hop {
                return Ok(s.clone());
            }
        }
        let (conn, ep) = self.connect_quic().await?;
        let critical = self.auth(&conn).await?;
        let udp_demux = Arc::new(Hysteria2UdpDemuxer::new(conn.clone()));
        let s = Arc::new(Hysteria2Session {
            conn,
            endpoint: ep,
            _critical_streams: critical,
            udp_demux,
            created_at: std::time::Instant::now(),
        });
        *guard = Some(s.clone());
        Ok(s)
    }
}

#[async_trait]
impl Outbound for Hysteria2Outbound {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect_stream(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        for attempt in 0..2 {
            let sess = self.get_or_connect_session().await?;
            let open_res = sess.conn.open_bi().await;
            let (mut send, mut recv) = match open_res {
                Ok(pair) => pair,
                Err(e) => {
                    let mut guard = self.session.lock().await;
                    *guard = None;
                    if attempt == 0 {
                        continue;
                    }
                    return Err(Error::Io(std::io::Error::other(format!(
                        "hy2 open_bi: {e}"
                    ))));
                }
            };

            let addr = addr_text(dst);
            let mut req = Vec::with_capacity(addr.len() + 12);
            write_varint(&mut req, TCP_REQUEST_ID);
            write_varint(&mut req, addr.len() as u64);
            req.extend_from_slice(addr.as_bytes());
            write_varint(&mut req, 0); // padding
            if let Err(e) = send.write_all(&req).await {
                let mut guard = self.session.lock().await;
                *guard = None;
                if attempt == 0 {
                    continue;
                }
                return Err(Error::Io(std::io::Error::other(format!("hy2 写请求: {e}"))));
            }

            // TCPResponse: [u8 status][varint |msg|][msg][varint |pad|][pad]
            let mut status = [0u8; 1];
            if let Err(e) = recv.read_exact(&mut status).await {
                let mut guard = self.session.lock().await;
                *guard = None;
                if attempt == 0 {
                    continue;
                }
                return Err(Error::Io(std::io::Error::other(format!("hy2 读响应: {e}"))));
            }
            if status[0] != 0x00 {
                return Err(Error::ProtoMsg("hy2 TCPResponse 错误".into()));
            }
            let (msg_len, _) = read_varint_async(&mut recv).await?;
            if msg_len > 0 {
                let mut msg = vec![0u8; msg_len as usize];
                recv.read_exact(&mut msg)
                    .await
                    .map_err(|e| Error::Io(std::io::Error::other(format!("hy2 读消息: {e}"))))?;
            }
            let (pad_len, _) = read_varint_async(&mut recv).await?;
            if pad_len > 0 {
                let mut pad = vec![0u8; pad_len as usize];
                recv.read_exact(&mut pad).await.map_err(|e| {
                    Error::Io(std::io::Error::other(format!("hy2 跳过 padding: {e}")))
                })?;
            }
            return Ok(Box::new(QuicBiStream { send, recv }));
        }
        Err(Error::ProtoMsg("hy2 连接重试失败".into()))
    }

    fn support_udp(&self) -> bool {
        true
    }

    async fn connect_packet(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        let sess = self.get_or_connect_session().await?;
        let session_id = self.udp_session.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(256);
        sess.udp_demux.register(session_id, tx).await;
        Ok(Box::new(Hy2UdpConn {
            conn: sess.conn.clone(),
            demux: sess.udp_demux.clone(),
            rx,
            session: session_id,
            pkt_id: AtomicU16::new(1),
            target: dst.clone(),
        }))
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
}

/// QUIC 双向流包装（tuic 复用）
pub struct QuicBiStream {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}

impl vp_core::ProxyStream for QuicBiStream {}

impl AsyncRead for QuicBiStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        AsyncRead::poll_read(std::pin::Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for QuicBiStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(std::pin::Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.send), cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.send), cx)
    }
}

/// UDP over QUIC datagram
struct Hy2UdpConn {
    conn: quinn::Connection,
    demux: Arc<Hysteria2UdpDemuxer>,
    rx: mpsc::Receiver<UdpPacket>,
    session: u32,
    pkt_id: AtomicU16,
    target: DstAddr,
}

impl Drop for Hy2UdpConn {
    fn drop(&mut self) {
        let demux = self.demux.clone();
        let session = self.session;
        tokio::spawn(async move {
            demux.unregister(session).await;
        });
    }
}

#[async_trait]
impl PacketConn for Hy2UdpConn {
    async fn send(&self, pkt: &UdpPacket) -> Result<()> {
        let pkt_id = self.pkt_id.fetch_add(1, Ordering::Relaxed);
        let addr = if pkt.dst.ip().is_loopback()
            || matches!(self.target.host, vp_common::Host::Domain(_))
        {
            self.target.to_string()
        } else {
            pkt.dst.to_string() // IPv6 带方括号，对端按 host:port 拆分
        };
        let max = self
            .conn
            .max_datagram_size()
            .ok_or(Error::Proto("hy2: 对端未启用 QUIC datagram"))?;
        for m in frag_udp_message(self.session, pkt_id, &addr, &pkt.data, max) {
            self.conn
                .send_datagram(m)
                .map_err(|e| Error::Io(std::io::Error::other(format!("hy2 datagram: {e}"))))?;
        }
        Ok(())
    }

    async fn recv(&mut self) -> Result<UdpPacket> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| Error::Io(std::io::Error::other("hy2 udp 接收通道已关闭")))
    }
}

fn hysteria_client_config(skip_verify: bool, _sni: Option<&str>) -> quinn::ClientConfig {
    static VERIFY: std::sync::OnceLock<quinn::ClientConfig> = std::sync::OnceLock::new();
    static NO_VERIFY: std::sync::OnceLock<quinn::ClientConfig> = std::sync::OnceLock::new();
    if skip_verify {
        NO_VERIFY
            .get_or_init(|| build_hy2_client_config(true))
            .clone()
    } else {
        VERIFY
            .get_or_init(|| build_hy2_client_config(false))
            .clone()
    }
}

fn build_hy2_client_config(skip_verify: bool) -> quinn::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if skip_verify {
        crypto
            .dangerous()
            .set_certificate_verifier(Arc::new(Hy2NoVerify));
    }
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let mut cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("hy2 client cfg"),
    ));
    let mut t = quinn::TransportConfig::default();
    t.datagram_receive_buffer_size(Some(1 << 20));
    t.max_idle_timeout(Some(
        std::time::Duration::from_secs(30)
            .try_into()
            .expect("idle timeout"),
    ));
    t.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    cfg.transport_config(Arc::new(t));
    cfg
}

#[derive(Debug)]
struct Hy2NoVerify;

impl rustls::client::danger::ServerCertVerifier for Hy2NoVerify {
    fn verify_server_cert(
        &self,
        _e: &rustls::pki_types::CertificateDer<'_>,
        _i: &[rustls::pki_types::CertificateDer<'_>],
        _n: &rustls::pki_types::ServerName<'_>,
        _o: &[u8],
        _t: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

// ---------------------------------------------------------------------------
// 入站（服务端）
// ---------------------------------------------------------------------------

pub struct Hysteria2Inbound {
    bind: String,
    port: u16,
    tag: Arc<str>,
    passwords: Arc<HashSet<String>>,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    user_manager: Option<Arc<vp_core::UserManager>>,
    salamander: Option<Arc<SalamanderObfs>>,
    ports: Option<Vec<u16>>,
    gate: Option<Arc<vp_core::InboundGate>>,
}

impl Hysteria2Inbound {
    pub fn new(
        bind: &str,
        port: u16,
        tag: &str,
        passwords: &[String],
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
    ) -> Self {
        Self::with_options(
            bind, port, tag, passwords, cert_pem, key_pem, None, None, None,
        )
    }

    pub fn new_single(
        bind: &str,
        port: u16,
        tag: &str,
        password: &str,
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
    ) -> Self {
        Self::new(bind, port, tag, &[password.to_string()], cert_pem, key_pem)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_options(
        bind: &str,
        port: u16,
        tag: &str,
        passwords: &[String],
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
        user_manager: Option<Arc<vp_core::UserManager>>,
        salamander_pw: Option<&str>,
        ports: Option<Vec<u16>>,
    ) -> Self {
        Self::with_gate(
            bind,
            port,
            tag,
            passwords,
            cert_pem,
            key_pem,
            user_manager,
            salamander_pw,
            ports,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_gate(
        bind: &str,
        port: u16,
        tag: &str,
        passwords: &[String],
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
        user_manager: Option<Arc<vp_core::UserManager>>,
        salamander_pw: Option<&str>,
        ports: Option<Vec<u16>>,
        gate: Option<Arc<vp_core::InboundGate>>,
    ) -> Self {
        Hysteria2Inbound {
            bind: bind.into(),
            port,
            tag: tag.into(),
            passwords: Arc::new(passwords.iter().map(|s| s.trim().to_string()).collect()),
            cert_pem,
            key_pem,
            user_manager,
            salamander: salamander_pw
                .filter(|s| !s.is_empty())
                .map(SalamanderObfs::new)
                .map(Arc::new),
            ports,
            gate,
        }
    }
}

#[async_trait]
impl Inbound for Hysteria2Inbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, ctx: InboundCtx) -> Result<u16> {
        let certs: Vec<_> = rustls_pemfile::certs(&mut &self.cert_pem[..])
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| Error::Config(format!("hy2 证书: {e}")))?;
        let key = rustls_pemfile::private_key(&mut &self.key_pem[..])
            .map_err(|e| Error::Config(format!("hy2 私钥: {e}")))?
            .ok_or(Error::Config("hy2 缺私钥".into()))?;
        let mut crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| Error::Config(format!("hy2 tls: {e}")))?;
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        let mut scfg = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
                .map_err(|e| Error::Config(format!("hy2 server cfg: {e}")))?,
        ));
        let mut t = quinn::TransportConfig::default();
        t.datagram_receive_buffer_size(Some(1 << 20));
        scfg.transport_config(Arc::new(t));

        let has_obfs = self.salamander.is_some();
        let has_mport = self.ports.as_ref().map(|p| !p.is_empty()).unwrap_or(false);

        let bound = if has_obfs || has_mport {
            // 前置 Salamander 混淆与多端口汇聚中继模式
            let endpoint = quinn::Endpoint::server(scfg, "127.0.0.1:0".parse().unwrap())?;
            let quinn_local_addr = endpoint.local_addr()?;

            let bind_addr: SocketAddr = format!("{}:{}", self.bind, self.port)
                .parse()
                .unwrap_or_else(|_| {
                    SocketAddr::new(std::net::IpAddr::V4([0, 0, 0, 0].into()), self.port)
                });
            let main_sock = Arc::new(tokio::net::UdpSocket::bind(bind_addr).await?);
            let actual_port = main_sock.local_addr()?.port();

            let mut all_socks = vec![main_sock.clone()];
            if let Some(ref extra_ports) = self.ports {
                for &ep in extra_ports {
                    if ep != actual_port {
                        let eaddr: SocketAddr =
                            format!("{}:{}", self.bind, ep).parse().unwrap_or_else(|_| {
                                SocketAddr::new(std::net::IpAddr::V4([0, 0, 0, 0].into()), ep)
                            });
                        if let Ok(esock) = tokio::net::UdpSocket::bind(eaddr).await {
                            all_socks.push(Arc::new(esock));
                        }
                    }
                }
            }

            type SessionMap = Arc<
                tokio::sync::Mutex<
                    HashMap<
                        SocketAddr,
                        (
                            Arc<tokio::net::UdpSocket>,
                            Arc<std::sync::atomic::AtomicU64>,
                        ),
                    >,
                >,
            >;
            let sessions: SessionMap = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

            for sock in all_socks {
                let sessions = sessions.clone();
                let salamander = self.salamander.clone();
                let main_reply_sock = sock.clone();
                let self_gate = self.gate.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 65535];
                    loop {
                        let Ok((n, client_addr)) = sock.recv_from(&mut buf).await else {
                            break;
                        };
                        // 门禁前置检查：未通过 GeoIP / ASN / 端口敲门过滤的直接丢弃
                        if let Some(ref g) = self_gate {
                            if !g.check_accept(client_addr.ip()) {
                                continue;
                            }
                        }
                        let payload = if let Some(ref obfs) = salamander {
                            match obfs.deobfuscate(&buf[..n]) {
                                Some(plain) => plain,
                                None => continue, // 混淆校验失败（探针/扫描），直接丢弃
                            }
                        } else {
                            buf[..n].to_vec()
                        };

                        let now_ts = vp_common::now_millis();
                        let mut map = sessions.lock().await;
                        let (pair_sock, _last_ts) = match map.get(&client_addr) {
                            Some((s, ts)) => {
                                ts.store(now_ts, Ordering::Relaxed);
                                (s.clone(), ts.clone())
                            }
                            None => {
                                let Ok(pair) = tokio::net::UdpSocket::bind("127.0.0.1:0").await
                                else {
                                    continue;
                                };
                                let pair = Arc::new(pair);
                                let ts = Arc::new(std::sync::atomic::AtomicU64::new(now_ts));
                                map.insert(client_addr, (pair.clone(), ts.clone()));

                                // 启动反向接收：内部 Quinn -> 外部客户端
                                let pair_recv = pair.clone();
                                let reply_sock = main_reply_sock.clone();
                                let obfs_sender = salamander.clone();
                                let self_gate_reply = self_gate.clone();
                                tokio::spawn(async move {
                                    let mut resp_buf = [0u8; 65535];
                                    loop {
                                        let Ok((rn, _)) = pair_recv.recv_from(&mut resp_buf).await
                                        else {
                                            break;
                                        };
                                        // RRL 防放大检查：若未认证客户端超速则丢弃
                                        if let Some(ref g) = self_gate_reply {
                                            match g.check_rrl(client_addr.ip()) {
                                                vp_core::RrlDecision::Drop => continue,
                                                vp_core::RrlDecision::Allow
                                                | vp_core::RrlDecision::Slip => {}
                                            }
                                        }
                                        let out_data = if let Some(ref obfs) = obfs_sender {
                                            obfs.obfuscate(&resp_buf[..rn])
                                        } else {
                                            resp_buf[..rn].to_vec()
                                        };
                                        if reply_sock.send_to(&out_data, client_addr).await.is_err()
                                        {
                                            break;
                                        }
                                    }
                                });

                                (pair, ts)
                            }
                        };
                        drop(map);
                        let _ = pair_sock.send_to(&payload, quinn_local_addr).await;
                    }
                });
            }

            // 定期清理超时的 client_sessions (180s)
            let sess_clean = sessions.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
                loop {
                    ticker.tick().await;
                    let now = vp_common::now_millis();
                    sess_clean.lock().await.retain(|_, (_, ts)| {
                        now.saturating_sub(ts.load(Ordering::Relaxed)) < 180_000
                    });
                }
            });

            // 监听 Quinn 接收连接
            let this = self.clone();
            let ctx = ctx.clone();
            tokio::spawn(async move {
                while let Some(incoming) = endpoint.accept().await {
                    let Ok(conn) = incoming.await else { continue };
                    let this = this.clone();
                    let ctx = ctx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = this.serve_conn(conn, &ctx).await {
                            tracing::debug!("hy2 连接结束: {e}");
                        }
                    });
                }
            });

            actual_port
        } else {
            // 原生直连监听模式
            let bind_addr: SocketAddr = format!("{}:{}", self.bind, self.port)
                .parse()
                .unwrap_or_else(|_| {
                    SocketAddr::new(std::net::IpAddr::V4([0, 0, 0, 0].into()), self.port)
                });
            let endpoint = quinn::Endpoint::server(scfg, bind_addr)?;
            let bound = endpoint.local_addr()?.port();
            let this = self.clone();
            tokio::spawn(async move {
                while let Some(incoming) = endpoint.accept().await {
                    let remote_addr = incoming.remote_address();
                    if let Some(ref g) = this.gate {
                        if !g.check_accept(remote_addr.ip()) {
                            continue;
                        }
                    }
                    let Ok(conn) = incoming.await else { continue };
                    let this = this.clone();
                    let ctx = ctx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = this.serve_conn(conn, &ctx).await {
                            tracing::debug!("hy2 连接结束: {e}");
                        }
                    });
                }
            });
            bound
        };

        Ok(bound)
    }
}

impl Hysteria2Inbound {
    async fn serve_conn(self: Arc<Self>, conn: quinn::Connection, ctx: &InboundCtx) -> Result<()> {
        let authenticated_user: Arc<tokio::sync::RwLock<Option<Arc<vp_core::UserAccount>>>> =
            Arc::new(tokio::sync::RwLock::new(None));
        let mut udp_sessions: UdpSessions<u32, DstAddr> = HashMap::new();
        loop {
            tokio::select! {
                uni = conn.accept_uni() => {
                    let Ok(mut s) = uni else { break };
                    let mut tb = [0u8; 1];
                    if s.read_exact(&mut tb).await.is_err() {
                        continue;
                    }
                    let st = read_varint(&tb).map(|(v, _)| v).unwrap_or(u64::MAX);
                    if st == crate::h3_min::STREAM_CONTROL {
                        // 客户端开了控制流：服务端也开一条并回应空 SETTINGS
                        if let Ok(out) = conn.open_uni().await {
                            let _ = crate::h3_min::server_init_stream(out, crate::h3_min::STREAM_CONTROL).await;
                        }
                    }
                }
                bi = conn.accept_bi() => {
                    let Ok((mut send, mut recv)) = bi else { break };
                    // 嗅探首字节：TCP 请求(0x44 0x01) 或 HEADERS 帧(0x01)
                    let mut first: Vec<u8> = Vec::with_capacity(16);
                    let handled = loop {
                        let mut b = [0u8; 1];
                        if recv.read_exact(&mut b).await.is_err() {
                            break false;
                        }
                        first.push(b[0]);
                        if first.len() == 2 && first == [0x44, 0x01] {
                            let this = self.clone();
                            let ctx = ctx.clone();
                            let conn = conn.clone();
                            let authed_user = authenticated_user.clone();
                            tokio::spawn(async move {
                                this.serve_tcp(recv, send, &conn, &ctx, authed_user).await;
                            });
                            break true;
                        }
                        if first[0] == 0x01 {
                            let mut full = first.clone();
                            match read_h3_headers(&mut recv, &mut full).await {
                                Ok(headers) => {
                                    let this = self.clone();
                                    let conn = conn.clone();
                                    let ctx = ctx.clone();
                                    let authed_user = authenticated_user.clone();
                                    tokio::spawn(async move {
                                        this.serve_auth(headers, send, &conn, &ctx, authed_user).await;
                                    });
                                    break true;
                                }
                                Err(e) => {
                                    tracing::debug!("hy2 请求解析失败: {e}");
                                    let _ = send.reset(quinn::VarInt::from_u32(0x8));
                                    break true;
                                }
                            }
                        }
                        if first.len() > 8 {
                            break false;
                        }
                    };
                    let _ = handled;
                }
                dg = conn.read_datagram() => {
                    let Ok(dg) = dg else { break };
                    let Some(m) = parse_udp_message(dg) else { continue };
                    let Ok(dst) = DstAddr::parse(&m.addr) else { continue };
                    // 用户配额：超限断开连接；上行按载荷计量
                    let cur_user = authenticated_user.read().await.clone();
                    if let Some(ref u) = cur_user {
                        if u.is_quota_exceeded() {
                            break;
                        }
                        u.add_up(m.payload.len() as u64);
                    }
                    let session = m.session;
                    let (tx, defrag) = udp_session(&mut udp_sessions, session, || {
                        let conn = conn.clone();
                        let user = cur_user.clone();
                        let mut pkt_id = 0u16;
                        move |from: SocketAddr, data: &[u8]| {
                            if let Some(ref u) = user {
                                u.add_down(data.len() as u64);
                            }
                            pkt_id = pkt_id.wrapping_add(1);
                            let max = conn.max_datagram_size().unwrap_or(0);
                            for f in frag_udp_message(session, pkt_id, &from.to_string(), data, max) {
                                let _ = conn.send_datagram(f);
                            }
                            conn.close_reason().is_none()
                        }
                    });
                    if let Some(whole) =
                        defrag.feed(m.pkt_id, m.frag_id, m.frag_total, Some(dst), m.payload)
                    {
                        let _ = tx.try_send(whole);
                    }
                }
            }
        }
        Ok(())
    }

    /// /auth → 233；其它/密码错 → 伪装 404
    async fn serve_auth(
        &self,
        headers: Vec<(String, String)>,
        mut send: quinn::SendStream,
        conn: &quinn::Connection,
        _ctx: &InboundCtx,
        authed_user: Arc<tokio::sync::RwLock<Option<Arc<vp_core::UserAccount>>>>,
    ) {
        let path = headers
            .iter()
            .find(|(k, _)| k == ":path")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let got = headers
            .iter()
            .find(|(k, _)| k == "hysteria-auth")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();

        let mut matched_account: Option<Arc<vp_core::UserAccount>> = None;
        if let Some(ref um) = self.user_manager {
            if let Some(acc) = um.get_user(&got).or_else(|| um.get_user_by_target(&got)) {
                if acc.is_quota_exceeded() {
                    tracing::warn!("hy2 用户 {} 流量超额被阻断", acc.username);
                    let _ = crate::h3_min::write_response_headers(&mut send, &[(":status", "403")])
                        .await;
                    let _ = send.finish();
                    conn.close(quinn::VarInt::from_u32(8), b"quota exceeded");
                    return;
                }
                matched_account = Some(acc);
            }
        }

        if path != "/auth" || (matched_account.is_none() && !self.passwords.contains(&got)) {
            let _ = crate::h3_min::write_response_headers(&mut send, &[(":status", "404")]).await;
            let _ = send.finish();
            if path == "/auth" {
                conn.close(quinn::VarInt::from_u32(8), b"auth failed");
            }
            return;
        }

        // 计算 Brutal / QoS 客户端下行通告速率 (bps)
        let cc_rx = if let Some(ref acc) = matched_account {
            if let Some(ref bp) = acc.brutal_pacer {
                (bp.rate_bytes_per_sec() * 8.0) as u64
            } else if let Some(ref lim) = acc.limiter {
                lim.down_rate_bytes_per_sec()
                    .map(|r| (r * 8.0) as u64)
                    .unwrap_or(0)
            } else {
                0
            }
        } else {
            0
        };
        let cc_rx_str = cc_rx.to_string();

        if let Some(acc) = matched_account {
            *authed_user.write().await = Some(acc);
        }
        if let Some(ref g) = self.gate {
            g.mark_authenticated(conn.remote_address().ip());
        }

        let _ = crate::h3_min::write_response_headers(
            &mut send,
            &[
                (":status", "233"),
                ("hysteria-udp", "true"),
                ("hysteria-cc-rx", &cc_rx_str),
            ],
        )
        .await;
        let _ = send.finish();
    }

    /// TCP 请求流（0x44 0x01 已消费）
    async fn serve_tcp(
        &self,
        mut recv: quinn::RecvStream,
        mut send: quinn::SendStream,
        conn: &quinn::Connection,
        ctx: &InboundCtx,
        authed_user: Arc<tokio::sync::RwLock<Option<Arc<vp_core::UserAccount>>>>,
    ) {
        let mut addr_buf: Vec<u8> = Vec::with_capacity(300);
        let dst = loop {
            match read_varint(&addr_buf) {
                Some((alen, used)) if addr_buf.len() >= used + alen as usize => {
                    let s = std::str::from_utf8(&addr_buf[used..used + alen as usize])
                        .unwrap_or("127.0.0.1:0");
                    break DstAddr::parse(s)
                        .unwrap_or_else(|_| DstAddr::ip([127, 0, 0, 1].into(), 0));
                }
                _ => {
                    let mut b = [0u8; 1];
                    if recv.read_exact(&mut b).await.is_err() {
                        break DstAddr::ip([127, 0, 0, 1].into(), 0);
                    }
                    addr_buf.push(b[0]);
                    if addr_buf.len() > 300 {
                        break DstAddr::ip([127, 0, 0, 1].into(), 0);
                    }
                }
            }
        };
        if dst.port == 0 {
            let _ = send.reset(quinn::VarInt::from_u32(0x8));
            return;
        }
        // 消费 padding：[varint |pad|][pad bytes]（本实现恒空，读 varint 即可）
        let mut padb: Vec<u8> = Vec::with_capacity(8);
        let pad_len = loop {
            match read_varint(&padb) {
                Some((v, _)) => break v as usize,
                None => {
                    let mut b = [0u8; 1];
                    if recv.read_exact(&mut b).await.is_err() {
                        break 0;
                    }
                    padb.push(b[0]);
                    if padb.len() > 8 {
                        break 0;
                    }
                }
            }
        };
        if pad_len > 0 {
            let mut skip = vec![0u8; pad_len];
            let _ = recv.read_exact(&mut skip).await;
        }

        let user = authed_user.read().await.clone();
        let src = conn.remote_address();
        let mut sess = Session::new_tcp(self.tag.clone(), Some(src), dst.clone());
        if let Some(ref u) = user {
            sess.inbound_user = Some(u.username.clone());
        }

        let res = ctx.router.pick(&sess).await;
        let rule_tag = res.rule.as_ref().map(|r| r.rule.clone());
        let chain_tag = if res.outbound.name() != res.via.as_ref() {
            format!("{}[{}]", res.via, res.outbound.name())
        } else {
            res.outbound.name().to_string()
        };

        match res.outbound.connect_stream(&sess, &dst).await {
            Ok(remote) => {
                // TCPResponse: [0x00][varint 0][varint 0]
                let _ = send.write_all(&[0x00, 0x00, 0x00]).await;
                let client: Box<dyn ProxyStream> = Box::new(QuicBiStream { send, recv });
                let meta = vp_core::ConnMeta {
                    id: sess.id,
                    inbound: sess.inbound.clone(),
                    network: "tcp",
                    host: dst.host.to_string(),
                    dst_port: dst.port,
                    src: Some(src.to_string()),
                    process: None,
                    user: user.as_ref().map(|u| u.username.clone()),
                    rule: rule_tag,
                    chain: Some(chain_tag.into()),
                    start: vp_common::now_millis(),
                };
                let hook = RelayHook {
                    table: Some(ctx.conns.clone()),
                    meta: Some(meta),
                    stats: Some(ctx.stats.clone()),
                    user: user.clone(),
                    limiter: user.as_ref().and_then(|u| u.limiter.clone()),
                    brutal: user.as_ref().and_then(|u| u.brutal_pacer.clone()),
                };
                let _ = relay(client, remote, hook).await;
            }
            Err(e) => {
                tracing::debug!("hy2 目标连接失败: {e}");
                let _ = send.reset(quinn::VarInt::from_u32(0x8));
            }
        }
    }
}

struct Hy2Packet {
    session: u32,
    pkt_id: u16,
    frag_id: u8,
    frag_total: u8,
    addr: String,
    payload: Bytes,
}

fn parse_udp_message(dg: Bytes) -> Option<Hy2Packet> {
    if dg.len() < 9 {
        return None;
    }
    let (alen, used) = read_varint(&dg[8..])?;
    let start = 8 + used;
    let end = start.checked_add(usize::try_from(alen).ok()?)?;
    if dg.len() < end {
        return None;
    }
    Some(Hy2Packet {
        session: u32::from_be_bytes([dg[0], dg[1], dg[2], dg[3]]),
        pkt_id: u16::from_be_bytes([dg[4], dg[5]]),
        frag_id: dg[6],
        frag_total: dg[7],
        addr: std::str::from_utf8(&dg[start..end]).ok()?.to_string(),
        payload: dg.slice(end..),
    })
}

/// 从流读出完整 HEADERS 帧（buf 含已读前缀）
async fn read_h3_headers(
    recv: &mut quinn::RecvStream,
    buf: &mut Vec<u8>,
) -> Result<Vec<(String, String)>> {
    loop {
        if let Some((ty, payload, _)) = crate::h3_min::parse_frame(buf) {
            if ty != crate::h3_min::FRAME_HEADERS {
                return Err(Error::ProtoMsg(format!("h3min: 期望 HEADERS（{ty}）")));
            }
            return crate::h3_min::decode_header_block(&payload);
        }
        let mut chunk = [0u8; 1024];
        let n = recv
            .read(&mut chunk)
            .await
            .map_err(|e| Error::Io(std::io::Error::other(format!("{e:?}"))))?
            .unwrap_or(0);
        if n == 0 {
            return Err(Error::Proto("h3min: 流中断"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 16 * 1024 {
            return Err(Error::Proto("h3min: 头过大"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for v in [
            0u64,
            1,
            63,
            64,
            0x3fff,
            0x4000,
            0x401,
            u32::MAX as u64,
            0x3fff_ffff_ffff,
        ] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            let (got, used) = read_varint(&buf).unwrap();
            assert_eq!(got, v);
            assert_eq!(used, buf.len());
        }
    }

    #[test]
    fn tcp_request_frame_layout() {
        // [varint 0x401][varint |addr|][addr][varint 0]
        let addr = "example.com:443";
        let mut req = Vec::new();
        write_varint(&mut req, TCP_REQUEST_ID);
        write_varint(&mut req, addr.len() as u64);
        req.extend_from_slice(addr.as_bytes());
        write_varint(&mut req, 0);
        // 0x401 → 2 字节 varint：01 前缀 + 14bit → 0x4401
        assert_eq!(&req[..2], &[0x44, 0x01]);
        // 回读
        let (id, used) = read_varint(&req).unwrap();
        assert_eq!(id, TCP_REQUEST_ID);
        let (alen, used2) = read_varint(&req[used..]).unwrap();
        assert_eq!(alen as usize, addr.len());
        assert_eq!(
            std::str::from_utf8(&req[used + used2..used + used2 + alen as usize]).unwrap(),
            addr
        );
    }

    #[test]
    fn salamander_obfs_roundtrip() {
        let obfs = SalamanderObfs::new("my-obfs-secret-password");
        let payload = b"Hello Hysteria2 QUIC Packet with Salamander Obfs!";
        let obfs_data = obfs.obfuscate(payload);
        assert_eq!(obfs_data.len(), payload.len() + 8);
        assert_ne!(&obfs_data[8..], payload);

        let recovered = obfs.deobfuscate(&obfs_data).expect("deobfuscate failed");
        assert_eq!(&recovered, payload);

        // 验证错误盐/截断包处理
        assert!(obfs.deobfuscate(&[0u8; 4]).is_none());
    }

    /// hysteria2 出入站自环：认证 → TCP → UDP（全链路走 h3_min 认证层）
    #[tokio::test]
    async fn hysteria2_loopback() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // echo 源站（TCP + UDP）
        let tcp_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tcp_l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = tcp_l.accept().await {
                tokio::spawn(async move {
                    let mut b = [0u8; 1024];
                    while let Ok(n) = s.read(&mut b).await {
                        if n == 0 || s.write_all(&b[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        let udp = std::sync::Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let udp_addr = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            while let Ok((n, from)) = udp.recv_from(&mut b).await {
                let mut r = b"echo:".to_vec();
                r.extend_from_slice(&b[..n]);
                let _ = udp.send_to(&r, from).await;
            }
        });

        // hy2 服务端（自签）
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let ctx = InboundCtx {
            router: Arc::new(crate::test_support::NoopRouter()),
            stats: Arc::new(vp_common::Stats::default()),
            conns: Arc::new(vp_core::ConnTable::new()),
        };
        let server = Hysteria2Inbound::new(
            "127.0.0.1",
            0,
            "hy2-srv",
            &["s3cret".to_string()],
            cert.cert.pem().into_bytes(),
            cert.key_pair.serialize_pem().into_bytes(),
        );
        let port = Arc::new(server).start(ctx).await.unwrap();

        let out = Hysteria2Outbound::new(&vp_config::Hysteria2Cfg {
            server: "127.0.0.1".into(),
            port,
            password: "s3cret".into(),
            sni: None,
            skip_cert_verify: true,
            up: None,
            down: None,
            obfs: None,
            obfs_password: None,
            ports: None,
            hop_interval: None,
        })
        .unwrap();

        // TCP
        let dst = DstAddr::ip("127.0.0.1".parse().unwrap(), tcp_port);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = out.connect_stream(&sess, &dst).await.unwrap();
        s.write_all(b"ping-hy2").await.unwrap();
        let mut buf = [0u8; 8];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-hy2");

        // 验证多路复用：同一个 Hysteria2Outbound 并发发起第 2 条 TCP 流
        let mut s2 = out.connect_stream(&sess, &dst).await.unwrap();
        s2.write_all(b"ping-hy2").await.unwrap();
        let mut buf2 = [0u8; 8];
        s2.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"ping-hy2");

        // 验证高并发多路复用：单条 QUIC 会话并发开启 20 个子流并发收发
        let mut handles = Vec::new();
        let out_arc = Arc::new(out);
        for idx in 0..20 {
            let out_c = out_arc.clone();
            let dst_c = dst.clone();
            handles.push(tokio::spawn(async move {
                let sess_c = Session::new_tcp("t".into(), None, dst_c.clone());
                let mut stream = out_c.connect_stream(&sess_c, &dst_c).await.unwrap();
                let msg = format!("ping-{idx:02}");
                stream.write_all(msg.as_bytes()).await.unwrap();
                let mut resp_buf = vec![0u8; msg.len()];
                stream.read_exact(&mut resp_buf).await.unwrap();
                assert_eq!(resp_buf, msg.as_bytes());
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let out = Arc::try_unwrap(out_arc).ok().unwrap();

        // UDP
        let dst = DstAddr::ip(udp_addr.ip(), udp_addr.port());
        let sess = Session::new_udp("t".into(), None, dst.clone());
        let mut conn = out.connect_packet(&sess, &dst).await.unwrap();
        conn.send(&UdpPacket {
            src: "127.0.0.1:0".parse().unwrap(),
            dst: udp_addr,
            data: b"hy2-udp".to_vec().into(),
        })
        .await
        .unwrap();
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), conn.recv())
            .await
            .expect("udp 超时")
            .unwrap();
        assert_eq!(&resp.data[..], b"echo:hy2-udp");

        // 错误密码 → 认证失败
        let bad = Hysteria2Outbound::new(&vp_config::Hysteria2Cfg {
            server: "127.0.0.1".into(),
            port,
            password: "wrong".into(),
            sni: None,
            skip_cert_verify: true,
            up: None,
            down: None,
            obfs: None,
            obfs_password: None,
            ports: None,
            hop_interval: None,
        })
        .unwrap();
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        assert!(bad.connect_stream(&sess, &dst).await.is_err());
    }

    #[tokio::test]
    async fn test_hy2_server_user_quota_and_brutal_cc() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let tcp_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tcp_l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = tcp_l.accept().await {
                tokio::spawn(async move {
                    let mut b = [0u8; 1024];
                    while let Ok(n) = s.read(&mut b).await {
                        if n == 0 || s.write_all(&b[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        let user_mgr = Arc::new(vp_core::UserManager::new());
        let user_acc = Arc::new(
            vp_core::UserAccount::new("hy2-vip", "vip-secret-123", Some(1024 * 1024), None)
                .with_brutal(Some(Arc::new(vp_core::BrutalPacer::from_mbps(50)))),
        );
        user_mgr.add_user(user_acc.clone());

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let ctx = InboundCtx {
            router: Arc::new(crate::test_support::NoopRouter()),
            stats: Arc::new(vp_common::Stats::default()),
            conns: Arc::new(vp_core::ConnTable::new()),
        };
        let server = Hysteria2Inbound::with_options(
            "127.0.0.1",
            0,
            "hy2-user-srv",
            &[],
            cert.cert.pem().into_bytes(),
            cert.key_pair.serialize_pem().into_bytes(),
            Some(user_mgr),
            None,
            None,
        );
        let port = Arc::new(server).start(ctx).await.unwrap();

        let out = Hysteria2Outbound::new(&vp_config::Hysteria2Cfg {
            server: "127.0.0.1".into(),
            port,
            password: "vip-secret-123".into(),
            sni: None,
            skip_cert_verify: true,
            up: None,
            down: None,
            obfs: None,
            obfs_password: None,
            ports: None,
            hop_interval: None,
        })
        .unwrap();

        let dst = DstAddr::ip("127.0.0.1".parse().unwrap(), tcp_port);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = out.connect_stream(&sess, &dst).await.unwrap();
        s.write_all(b"test-traffic-accounting").await.unwrap();
        let mut buf = [0u8; 23];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"test-traffic-accounting");

        // 验证用户流量完成记账
        assert!(user_acc.upload.load(std::sync::atomic::Ordering::Relaxed) > 0);
    }

    #[tokio::test]
    async fn test_hy2_server_salamander_obfs() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let tcp_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tcp_l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = tcp_l.accept().await {
                tokio::spawn(async move {
                    let mut b = [0u8; 1024];
                    while let Ok(n) = s.read(&mut b).await {
                        if n == 0 || s.write_all(&b[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let ctx = InboundCtx {
            router: Arc::new(crate::test_support::NoopRouter()),
            stats: Arc::new(vp_common::Stats::default()),
            conns: Arc::new(vp_core::ConnTable::new()),
        };
        let server = Hysteria2Inbound::with_options(
            "127.0.0.1",
            0,
            "hy2-obfs-srv",
            &["obfs-pass".to_string()],
            cert.cert.pem().into_bytes(),
            cert.key_pair.serialize_pem().into_bytes(),
            None,
            Some("salamander-pwd-999"),
            None,
        );
        let port = Arc::new(server).start(ctx).await.unwrap();

        // 开启了 Salamander 混淆的客户端
        let out = Hysteria2Outbound::new(&vp_config::Hysteria2Cfg {
            server: "127.0.0.1".into(),
            port,
            password: "obfs-pass".into(),
            sni: None,
            skip_cert_verify: true,
            up: None,
            down: None,
            obfs: Some("salamander".into()),
            obfs_password: Some("salamander-pwd-999".into()),
            ports: None,
            hop_interval: None,
        })
        .unwrap();

        let dst = DstAddr::ip("127.0.0.1".parse().unwrap(), tcp_port);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = out.connect_stream(&sess, &dst).await.unwrap();
        s.write_all(b"obfs-handshake-ok").await.unwrap();
        let mut buf = [0u8; 17];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"obfs-handshake-ok");

        // 未开启混淆的客户端连接应当因解混淆校验失败而无法建立连接
        let plain_out = Hysteria2Outbound::new(&vp_config::Hysteria2Cfg {
            server: "127.0.0.1".into(),
            port,
            password: "obfs-pass".into(),
            sni: None,
            skip_cert_verify: true,
            up: None,
            down: None,
            obfs: None,
            obfs_password: None,
            ports: None,
            hop_interval: None,
        })
        .unwrap();
        let plain_sess = Session::new_tcp("t".into(), None, dst.clone());
        let res = tokio::time::timeout(
            std::time::Duration::from_millis(1500),
            plain_out.connect_stream(&plain_sess, &dst),
        )
        .await;
        assert!(res.is_err() || res.unwrap().is_err());
    }

    #[test]
    fn udp_frag_defrag() {
        let big: Vec<u8> = (0..8000u32).map(|i| i as u8).collect();
        let feed = |d: &mut Defragger<String>, f: &Bytes| {
            let m = parse_udp_message(f.clone()).unwrap();
            assert_eq!((m.session, m.addr.as_str()), (7, "1.2.3.4:53"));
            d.feed(m.pkt_id, m.frag_id, m.frag_total, Some(m.addr), m.payload)
        };

        // 分片都不超上限、每片带地址；乱序到达照样重组
        let frags = frag_udp_message(7, 3, "1.2.3.4:53", &big, 1200);
        assert!(frags.len() > 1 && frags.iter().all(|f| f.len() <= 1200));
        let mut d = Defragger::default();
        let mut out = None;
        for f in frags.iter().rev() {
            out = feed(&mut d, f);
        }
        assert_eq!(out, Some(("1.2.3.4:53".into(), Bytes::from(big.clone()))));

        // 丢了一片的旧包被新包顶掉：新包完整拼出，旧包迟到的那片不会拼出残缺包
        let old = frag_udp_message(7, 4, "1.2.3.4:53", &big, 1200);
        let new = frag_udp_message(7, 5, "1.2.3.4:53", &big[..3000], 1200);
        let mut d = Defragger::default();
        for f in &old[1..] {
            assert!(feed(&mut d, f).is_none());
        }
        let got = new
            .iter()
            .filter_map(|f| feed(&mut d, f))
            .collect::<Vec<_>>();
        assert_eq!(
            got,
            [("1.2.3.4:53".into(), Bytes::copy_from_slice(&big[..3000]))]
        );
        // 重复分片不重复交付
        assert!(feed(&mut d, &new[0]).is_none());
        assert!(feed(&mut d, &old[0]).is_none());

        // 放得下就不分片；头部超过上限 / 超过 255 片时丢包而不是 panic
        assert_eq!(frag_udp_message(1, 1, "1.2.3.4:53", b"", 1200).len(), 1);
        assert_eq!(frag_udp_message(1, 1, "1.2.3.4:53", b"hi", 1200).len(), 1);
        assert!(frag_udp_message(1, 1, &"a".repeat(2000), b"hi", 1200).is_empty());
        assert!(frag_udp_message(1, 1, "1.2.3.4:53", &[0; 400_000], 1200).is_empty());
    }

    /// 超过 datagram 上限的 UDP 包：客户端分片 → 服务端重组转发 → 回包分片 → 客户端重组
    #[tokio::test]
    async fn hysteria2_udp_large_packets() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let ctx = InboundCtx {
            router: Arc::new(crate::test_support::NoopRouter()),
            stats: Arc::new(vp_common::Stats::default()),
            conns: Arc::new(vp_core::ConnTable::new()),
        };
        let server = Hysteria2Inbound::new(
            "127.0.0.1",
            0,
            "hy2-srv",
            &["s3cret".to_string()],
            cert.cert.pem().into_bytes(),
            cert.key_pair.serialize_pem().into_bytes(),
        );
        let port = Arc::new(server).start(ctx).await.unwrap();
        let out = Hysteria2Outbound::new(&vp_config::Hysteria2Cfg {
            server: "127.0.0.1".into(),
            port,
            password: "s3cret".into(),
            sni: None,
            skip_cert_verify: true,
            up: None,
            down: None,
            obfs: None,
            obfs_password: None,
            ports: None,
            hop_interval: None,
        })
        .unwrap();
        let echo = crate::test_support::udp_echo().await;
        let dst = DstAddr::ip(echo.ip(), echo.port());
        let sess = Session::new_udp("t".into(), None, dst.clone());
        let mut conn = out.connect_packet(&sess, &dst).await.unwrap();
        crate::test_support::assert_udp_roundtrip(&mut conn, echo).await;
    }

    #[test]
    fn udp_message_layout() {
        // [u32 session][u16 pkt][u8 frag][u8 total][varint |addr|][addr][payload]
        let addr = "8.8.8.8:53";
        let mut msg = Vec::new();
        msg.extend_from_slice(&0xdead_beefu32.to_be_bytes());
        msg.extend_from_slice(&7u16.to_be_bytes());
        msg.push(0);
        msg.push(1);
        write_varint(&mut msg, addr.len() as u64);
        msg.extend_from_slice(addr.as_bytes());
        assert_eq!(
            u32::from_be_bytes([msg[0], msg[1], msg[2], msg[3]]),
            0xdead_beef
        );
        let (alen, used) = read_varint(&msg[8..]).unwrap();
        assert_eq!(alen, 10);
        assert_eq!(used, 1);
        assert_eq!(
            std::str::from_utf8(&msg[8 + used..8 + used + alen as usize]).unwrap(),
            addr
        );
        assert_eq!(&msg[8 + used + alen as usize..], b"");
    }
}

#[cfg(test)]
mod real_node_probe {
    use super::*;

    /// 真实节点 hy2 QUIC 握手探针（#[ignore]，需要外网与可达 UDP）。
    #[tokio::test]
    #[ignore = "真实节点调试：需要外网"]
    async fn hy2_real_quic_probe() {
        let server = std::env::var("HY2_TEST_SERVER").unwrap_or_else(|_| "localhost".into());
        let port = std::env::var("HY2_TEST_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(443);
        let password = std::env::var("HY2_TEST_PASSWORD").unwrap_or_default();
        let sni = std::env::var("HY2_TEST_SNI").ok();
        let skip_verify = std::env::var("HY2_SKIP_VERIFY")
            .map(|v| v != "false" && v != "0")
            .unwrap_or(true);
        let cfg = vp_config::Hysteria2Cfg {
            server,
            port,
            password,
            sni,
            skip_cert_verify: skip_verify,
            up: None,
            down: None,
            obfs: None,
            obfs_password: None,
            ports: None,
            hop_interval: None,
        };
        let out = Hysteria2Outbound::new(&cfg).expect("build");
        let t0 = std::time::Instant::now();
        let r = tokio::time::timeout(std::time::Duration::from_secs(10), out.connect_quic()).await;
        let (conn, _ep) = match r {
            Err(_) => {
                println!(
                    "[{:.2}s] QUIC 握手 10s 超时 —— UDP 无响应",
                    t0.elapsed().as_secs_f32()
                );
                return;
            }
            Ok(Err(e)) => {
                println!("[{:.2}s] QUIC 握手 error: {e}", t0.elapsed().as_secs_f32());
                return;
            }
            Ok(Ok(v)) => {
                println!("[{:.2}s] QUIC 握手 OK", t0.elapsed().as_secs_f32());
                v
            }
        };
        let r = tokio::time::timeout(std::time::Duration::from_secs(8), out.auth(&conn)).await;
        match r {
            Err(_) => println!("[{:.2}s] auth 8s 超时", t0.elapsed().as_secs_f32()),
            Ok(Err(e)) => println!("[{:.2}s] auth error: {e}", t0.elapsed().as_secs_f32()),
            Ok(Ok(_)) => println!(
                "[{:.2}s] auth OK —— hy2 全链路握手通过",
                t0.elapsed().as_secs_f32()
            ),
        }
    }

    /// hy2 数据面探针：connect_stream 后直接发 HTTP GET 并转储响应字节。
    #[tokio::test]
    #[ignore = "真实节点调试：需要外网"]
    async fn hy2_real_data_probe() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let server = std::env::var("HY2_TEST_SERVER").unwrap_or_else(|_| "localhost".into());
        let port = std::env::var("HY2_TEST_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(443);
        let password = std::env::var("HY2_TEST_PASSWORD").unwrap_or_default();
        let sni = std::env::var("HY2_TEST_SNI").ok();
        let skip_verify = std::env::var("HY2_SKIP_VERIFY")
            .map(|v| v != "false" && v != "0")
            .unwrap_or(true);
        let cfg = vp_config::Hysteria2Cfg {
            server,
            port,
            password,
            sni,
            skip_cert_verify: skip_verify,
            up: None,
            down: None,
            obfs: None,
            obfs_password: None,
            ports: None,
            hop_interval: None,
        };
        let out = Hysteria2Outbound::new(&cfg).expect("build");
        let dst = vp_common::DstAddr::new("www.gstatic.com", 80);
        let sess = Session::new_tcp("probe".into(), None, dst.clone());
        let mut s = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            out.connect_stream(&sess, &dst),
        )
        .await
        {
            Err(_) => {
                println!("connect 10s 超时");
                return;
            }
            Ok(Err(e)) => {
                println!("connect error: {e}");
                return;
            }
            Ok(Ok(s)) => s,
        };
        s.write_all(
            b"GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("write");
        let mut buf = vec![0u8; 300];
        let n = tokio::time::timeout(std::time::Duration::from_secs(8), s.read(&mut buf)).await;
        match n {
            Err(_) => println!("读 8s 超时"),
            Ok(Ok(0)) => println!("EOF"),
            Ok(Ok(n)) => println!(
                "{} 字节: {:02x?} ({})",
                n,
                &buf[..n],
                String::from_utf8_lossy(&buf[..n])
            ),
            Ok(Err(e)) => println!("read error: {e}"),
        }
    }

    #[tokio::test]
    #[ignore = "真实节点调试：需要外网"]
    async fn hy2_real_udp_probe() {
        let server = std::env::var("HY2_TEST_SERVER").unwrap_or_else(|_| "localhost".into());
        let port = std::env::var("HY2_TEST_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(443);
        let password = std::env::var("HY2_TEST_PASSWORD").unwrap_or_default();
        let sni = std::env::var("HY2_TEST_SNI").ok();
        let cfg = vp_config::Hysteria2Cfg {
            server,
            port,
            password,
            sni,
            skip_cert_verify: true,
            up: None,
            down: None,
            obfs: None,
            obfs_password: None,
            ports: None,
            hop_interval: None,
        };
        let out = Hysteria2Outbound::new(&cfg).expect("build");
        let dst = vp_common::DstAddr::new("1.1.1.1", 53);
        let sess = Session::new_udp("probe".into(), None, dst.clone());
        let mut conn = out
            .connect_packet(&sess, &dst)
            .await
            .expect("connect_packet");
        let query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let pkt = UdpPacket {
            src: "127.0.0.1:12345".parse().unwrap(),
            dst: "1.1.1.1:53".parse().unwrap(),
            data: query.to_vec().into(),
        };
        conn.send(&pkt).await.expect("send");
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), conn.recv()).await;
        match resp {
            Ok(Ok(p)) => println!("UDP OK, 收到回包 {} 字节", p.data.len()),
            Ok(Err(e)) => println!("UDP recv error: {e}"),
            Err(_) => println!("UDP 5s 超时未收到回包！服务端不支持 UDP 或丢包！"),
        }
    }
}

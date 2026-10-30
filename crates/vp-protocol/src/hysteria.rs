//! Hysteria v1 协议（QUIC + struc 大端二进制帧 + XPlus 混淆）。
//!
//! 线上格式对齐 apernet/hysteria `hy1` 分支 `core/cs/protocol.go`
//! （lunixbochs/struc 默认大端序）：
//! - 控制流：`[u8 版本=3]` + clientHello `{u64 SendBPS, u64 RecvBPS, u16 AuthLen, Auth}`
//!   ← serverHello `{u8 OK, u64 SendBPS, u64 RecvBPS, u16 MsgLen, Msg}`
//! - TCP：每连接一条双向流，clientRequest `{u8 UDP=0, u16 HostLen, Host, u16 Port}`
//!   ← serverResponse `{u8 OK, u32 UDPSessionID, u16 MsgLen, Msg}`，随后为原始字节流
//! - UDP：clientRequest `{UDP=1, 空 Host, Port=0}` ← serverResponse `{OK, UDPSessionID}`，
//!   数据报走 QUIC datagram：udpMessage `{u32 Session, u16 HostLen, Host, u16 Port,
//!   u16 MsgID, u8 FragID, u8 FragCount, u16 DataLen, Data}`
//! - XPlus 混淆（obfs，值为密码本身）：报文 = `[16B 随机盐][SHA256(key‖salt) 循环 XOR 载荷]`
//!
//! 传输伪装仅支持 `protocol: udp`（默认）；wechat-video / faketcp 需要特定
//! 包伪装层，配置中出现时报错提示。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::task::{Poll, ready};

use async_trait::async_trait;
use sha2::{Digest as ShaDigest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, mpsc};

use vp_common::{DstAddr, Error, Result};
use vp_core::session::Session;
use vp_core::{Outbound, PacketConn, ProxyStream, UdpPacket};

const PROTOCOL_VERSION: u8 = 3;

// ---------------------------------------------------------------------------
// XPlus 混淆（hysteria v1 obfs；报文格式：[16B salt][XOR 载荷]）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct XPlusObfs {
    key: Vec<u8>,
}

impl XPlusObfs {
    pub fn new(password: &[u8]) -> Self {
        XPlusObfs {
            key: password.to_vec(),
        }
    }

    fn keystream(&self, salt: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.key);
        hasher.update(salt);
        let mut ks = [0u8; 32];
        ks.copy_from_slice(&hasher.finalize());
        ks
    }

    pub fn obfuscate(&self, plain: &[u8], salt: &[u8; 16]) -> Vec<u8> {
        let ks = self.keystream(salt);
        let mut out = Vec::with_capacity(16 + plain.len());
        out.extend_from_slice(salt);
        for (i, c) in plain.iter().enumerate() {
            out.push(c ^ ks[i % 32]);
        }
        out
    }
}

// ---------------------------------------------------------------------------
// 出站
// ---------------------------------------------------------------------------

/// quinn WriteError → vp Error
fn we(e: quinn::WriteError) -> Error {
    Error::Io(std::io::Error::other(format!("hy1 写流: {e}")))
}

/// quinn ReadExactError → vp Error
fn re(e: quinn::ReadExactError) -> Error {
    Error::Io(std::io::Error::other(format!("hy1 读流: {e}")))
}

pub struct Hysteria1Outbound {
    name: String,
    server: String,
    port: u16,
    auth: Vec<u8>,
    sni: String,
    alpn: Vec<String>,
    skip_verify: bool,
    send_bps: u64,
    recv_bps: u64,
    obfs: Option<Arc<XPlusObfs>>,
    session: Mutex<Option<Arc<Hy1Session>>>,
}

pub struct Hy1Session {
    pub conn: quinn::Connection,
    pub endpoint: quinn::Endpoint,
    pub udp_demux: Arc<Hy1UdpDemuxer>,
    /// 控制流句柄：与连接同生命周期持有，避免 Drop 触发 RESET/STOP 影响会话
    pub _ctl_streams: (quinn::SendStream, quinn::RecvStream),
}

impl Hy1Session {
    fn is_alive(&self) -> bool {
        self.conn.close_reason().is_none()
    }
}

impl Hysteria1Outbound {
    pub fn new(cfg: &vp_config::Hysteria1Cfg) -> Result<Self> {
        let proto = cfg.protocol.as_deref().unwrap_or("udp");
        if !proto.eq_ignore_ascii_case("udp") {
            return Err(Error::Unsupported(format!(
                "hysteria v1 protocol {proto:?} 暂不支持（仅支持 udp）"
            )));
        }
        // v1 的 obfs 字段即为混淆密码（mihomo 语义）；兼容 obfs-password
        let obfs_pass = cfg
            .obfs_password
            .as_deref()
            .map(str::to_owned)
            .or_else(|| cfg.obfs.clone().filter(|s| !s.is_empty()));
        let obfs = obfs_pass.map(|p| Arc::new(XPlusObfs::new(p.as_bytes())));
        // auth 语义（对齐 Clash Premium / mihomo 两种写法）：
        // - mihomo：auth = 密码；auth-str = 编码方法（str/base64）
        // - Clash Premium：auth-str 就是密码本身
        let method = cfg.auth_str.as_deref().unwrap_or("").trim();
        let auth: Vec<u8> = match cfg.auth.as_deref().filter(|s| !s.is_empty()) {
            Some(a) if method.eq_ignore_ascii_case("base64") => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(a.trim())
                    .map_err(|e| Error::Config(format!("hysteria v1 auth base64 解码失败: {e}")))?
            }
            Some(a) => a.as_bytes().to_vec(),
            None if !method.is_empty()
                && !method.eq_ignore_ascii_case("str")
                && !method.eq_ignore_ascii_case("base64") =>
            {
                // Clash Premium 兼容：auth-str 即密码
                method.as_bytes().to_vec()
            }
            None => return Err(Error::Config("hysteria v1 缺少 auth / auth-str".into())),
        };
        Ok(Hysteria1Outbound {
            name: "hysteria".into(),
            server: cfg.server.clone(),
            port: cfg.port,
            auth,
            sni: cfg.sni.clone().unwrap_or_else(|| cfg.server.clone()),
            alpn: {
                let mut list = cfg.alpn.clone();
                // 兜底追加 hysteria（服务器只认 hysteria 而配置写了 h3 的场景）
                if !list.iter().any(|a| a.eq_ignore_ascii_case("hysteria")) {
                    list.push("hysteria".into());
                }
                list
            },
            skip_verify: cfg.skip_cert_verify,
            send_bps: (cfg.up.unwrap_or(0) as u64) * 125_000,
            recv_bps: (cfg.down.unwrap_or(0) as u64) * 125_000,
            obfs,
            session: Mutex::new(None),
        })
    }

    fn client_config(&self) -> quinn::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        if self.skip_verify {
            crypto
                .dangerous()
                .set_certificate_verifier(Arc::new(Hy1NoVerify));
        }
        crypto.alpn_protocols = self
            .alpn
            .iter()
            .map(|a| a.as_bytes().to_vec())
            .collect::<Vec<_>>();
        let mut cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("hy1 client cfg"),
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

    async fn connect_quic(&self) -> Result<(quinn::Connection, quinn::Endpoint)> {
        let addr: SocketAddr = tokio::net::lookup_host((self.server.as_str(), self.port))
            .await
            .map_err(|e| Error::Addr(format!("解析 {}: {e}", self.server)))?
            .next()
            .ok_or(Error::Addr("无地址".into()))?;
        tracing::debug!(target: "hy1", %addr, sni = %self.sni, alpn = ?self.alpn, "hy1: 开始 QUIC 握手");
        let mut ep = match &self.obfs {
            Some(ob) => {
                let bind: &'static str = if addr.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let sock = vp_transport::create_udp_socket(bind.parse().unwrap())?;
                let wrapped = Arc::new(ObfsUdpSocket::new(sock, ob.clone()));
                quinn::Endpoint::new_with_abstract_socket(
                    quinn::EndpointConfig::default(),
                    None,
                    wrapped,
                    Arc::new(quinn::TokioRuntime),
                )
                .map_err(|e| Error::Io(std::io::Error::other(format!("hy1 endpoint: {e}"))))?
            }
            None => quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?,
        };
        ep.set_default_client_config(self.client_config());
        let conn = ep
            .connect(addr, self.sni.as_str())
            .map_err(|e| Error::Addr(format!("hy1 连接参数: {e}")))?
            .await
            .map_err(|e| Error::Io(std::io::Error::other(format!("hy1 QUIC 握手: {e}"))))?;
        tracing::debug!(target: "hy1", "hy1: QUIC 握手完成");
        Ok((conn, ep))
    }

    /// 控制流认证（版本字节 + clientHello ← serverHello），返回控制流句柄
    async fn auth(
        &self,
        conn: &quinn::Connection,
    ) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        let fut = self.auth_inner(conn);
        tokio::time::timeout(std::time::Duration::from_secs(10), fut)
            .await
            .map_err(|_| {
                Error::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "hy1 auth 超时",
                ))
            })?
    }

    async fn auth_inner(
        &self,
        conn: &quinn::Connection,
    ) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| Error::Io(std::io::Error::other(format!("hy1 控制流: {e}"))))?;
        tracing::debug!(target: "hy1", auth_len = self.auth.len(), send_bps = self.send_bps, recv_bps = self.recv_bps, "hy1: 发送认证");
        send.write_all(&[PROTOCOL_VERSION]).await.map_err(we)?;
        let mut hello = Vec::with_capacity(20 + self.auth.len());
        hello.extend_from_slice(&self.send_bps.to_be_bytes());
        hello.extend_from_slice(&self.recv_bps.to_be_bytes());
        hello.extend_from_slice(&(self.auth.len() as u16).to_be_bytes());
        hello.extend_from_slice(&self.auth);
        send.write_all(&hello).await.map_err(we)?;
        send.flush().await?;

        async fn rd(r: &mut quinn::RecvStream, b: &mut [u8]) -> Result<()> {
            r.read_exact(b)
                .await
                .map_err(|e| Error::Io(std::io::Error::other(format!("hy1 读响应: {e}"))))
        }
        let mut ok = [0u8; 1];
        rd(&mut recv, &mut ok).await?;
        let mut rate = [0u8; 16];
        rd(&mut recv, &mut rate).await?;
        let mut msg_len = [0u8; 2];
        rd(&mut recv, &mut msg_len).await?;
        let msg_len = u16::from_be_bytes(msg_len) as usize;
        let mut msg = vec![0u8; msg_len];
        rd(&mut recv, &mut msg).await?;
        tracing::debug!(target: "hy1", ok = ok[0], "hy1: 收到 serverHello");
        if ok[0] == 0 {
            return Err(Error::ProtoMsg(format!(
                "hy1 认证失败: {}",
                String::from_utf8_lossy(&msg)
            )));
        }
        Ok((send, recv))
    }

    async fn get_or_connect_session(&self) -> Result<Arc<Hy1Session>> {
        let mut guard = self.session.lock().await;
        if let Some(ref s) = *guard {
            if s.is_alive() {
                return Ok(s.clone());
            }
        }
        let (conn, ep) = self.connect_quic().await?;
        let ctl_streams = self.auth(&conn).await?;
        let udp_demux = Arc::new(Hy1UdpDemuxer::new(conn.remote_address()));
        {
            let demux = udp_demux.clone();
            let c = conn.clone();
            tokio::spawn(async move { demux_task(c, demux).await });
        }
        let s = Arc::new(Hy1Session {
            conn,
            endpoint: ep,
            udp_demux,
            _ctl_streams: ctl_streams,
        });
        *guard = Some(s.clone());
        Ok(s)
    }
}

impl Hysteria1Outbound {
    /// 探针用：暴露 QUIC 连接阶段
    pub async fn connect_quic_for_probe(&self) -> Result<(quinn::Connection, quinn::Endpoint)> {
        self.connect_quic().await
    }

    /// 探针用：暴露认证阶段
    pub async fn auth_for_probe(&self, conn: &quinn::Connection) -> Result<()> {
        self.auth(conn).await.map(|_| ())
    }
}

#[async_trait]
impl Outbound for Hysteria1Outbound {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect_stream(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        for attempt in 0..2 {
            let sess = self.get_or_connect_session().await?;
            let (mut send, mut recv) = match sess.conn.open_bi().await {
                Ok(pair) => pair,
                Err(e) => {
                    *self.session.lock().await = None;
                    if attempt == 0 {
                        continue;
                    }
                    return Err(Error::Io(std::io::Error::other(format!(
                        "hy1 open_bi: {e}"
                    ))));
                }
            };
            // clientRequest{UDP=false, Host, Port}
            let host = dst.host.to_string();
            let mut req = Vec::with_capacity(host.len() + 8);
            req.push(0); // UDP = false
            req.extend_from_slice(&(host.len() as u16).to_be_bytes());
            req.extend_from_slice(host.as_bytes());
            req.extend_from_slice(&dst.port.to_be_bytes());
            if let Err(e) = send.write_all(&req).await {
                *self.session.lock().await = None;
                if attempt == 0 {
                    continue;
                }
                return Err(Error::Io(std::io::Error::other(format!("hy1 写请求: {e}"))));
            }
            // serverResponse{OK, UDPSessionID, MsgLen, Msg}
            let mut head = [0u8; 7];
            if let Err(e) = recv.read_exact(&mut head).await {
                *self.session.lock().await = None;
                if attempt == 0 {
                    continue;
                }
                return Err(Error::Io(std::io::Error::other(format!("hy1 读响应: {e}"))));
            }
            let msg_len = u16::from_be_bytes([head[5], head[6]]) as usize;
            let mut msg = vec![0u8; msg_len];
            if msg_len > 0 {
                recv.read_exact(&mut msg).await.map_err(re)?;
            }
            if head[0] == 0 {
                return Err(Error::ProtoMsg(format!(
                    "hy1 连接被拒绝: {}",
                    String::from_utf8_lossy(&msg)
                )));
            }
            return Ok(Box::new(crate::hysteria2::QuicBiStream { send, recv }));
        }
        Err(Error::ProtoMsg("hy1 连接重试失败".into()))
    }

    fn support_udp(&self) -> bool {
        true
    }

    async fn connect_packet(&self, _sess: &Session, _dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        let sess = self.get_or_connect_session().await?;
        let (mut send, mut recv) = sess
            .conn
            .open_bi()
            .await
            .map_err(|e| Error::Io(std::io::Error::other(format!("hy1 udp 流: {e}"))))?;
        // clientRequest{UDP=true, 空 Host, Port=0}
        let req = [1u8, 0, 0, 0, 0];
        send.write_all(&req).await.map_err(we)?;
        send.flush().await?;
        let mut head = [0u8; 7];
        recv.read_exact(&mut head).await.map_err(re)?;
        let msg_len = u16::from_be_bytes([head[5], head[6]]) as usize;
        let mut msg = vec![0u8; msg_len];
        if msg_len > 0 {
            recv.read_exact(&mut msg).await.map_err(re)?;
        }
        if head[0] == 0 {
            return Err(Error::ProtoMsg(format!(
                "hy1 UDP 会话被拒绝: {}",
                String::from_utf8_lossy(&msg)
            )));
        }
        let session_id = u32::from_be_bytes([head[1], head[2], head[3], head[4]]);
        let (tx, rx) = mpsc::channel(256);
        sess.udp_demux.register(session_id, tx).await;
        Ok(Box::new(Hy1UdpConn {
            conn: sess.conn.clone(),
            demux: sess.udp_demux.clone(),
            rx,
            session_id,
            msg_id: AtomicU16::new(1),
        }))
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
}

// ---------------------------------------------------------------------------
// UDP：数据报收发 + 分片重组（对齐官方 defragger 语义）
// ---------------------------------------------------------------------------

struct Hy1UdpConn {
    conn: quinn::Connection,
    demux: Arc<Hy1UdpDemuxer>,
    rx: mpsc::Receiver<UdpPacket>,
    session_id: u32,
    msg_id: AtomicU16,
}

impl Drop for Hy1UdpConn {
    fn drop(&mut self) {
        let demux = self.demux.clone();
        let session = self.session_id;
        tokio::spawn(async move {
            demux.unregister(session).await;
        });
    }
}

#[async_trait]
impl PacketConn for Hy1UdpConn {
    async fn send(&self, pkt: &UdpPacket) -> Result<()> {
        let msg_id = self.msg_id.fetch_add(1, Ordering::Relaxed).max(1);
        let host = pkt.dst.ip().to_string();
        let mut msg = Vec::with_capacity(pkt.data.len() + host.len() + 16);
        msg.extend_from_slice(&self.session_id.to_be_bytes());
        msg.extend_from_slice(&(host.len() as u16).to_be_bytes());
        msg.extend_from_slice(host.as_bytes());
        msg.extend_from_slice(&pkt.dst.port().to_be_bytes());
        msg.extend_from_slice(&msg_id.to_be_bytes());
        msg.push(0); // FragID
        msg.push(1); // FragCount
        msg.extend_from_slice(&(pkt.data.len() as u16).to_be_bytes());
        msg.extend_from_slice(&pkt.data);
        self.conn
            .send_datagram(bytes::Bytes::from(msg))
            .map_err(|e| Error::Io(std::io::Error::other(format!("hy1 datagram: {e}"))))?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<UdpPacket> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| Error::Io(std::io::Error::other("hy1 udp 接收通道已关闭")))
    }
}

type DemuxMap = Mutex<HashMap<u32, mpsc::Sender<UdpPacket>>>;

pub struct Hy1UdpDemuxer {
    map: DemuxMap,
    /// QUIC 连接对端（作为 UdpPacket.src）
    remote: SocketAddr,
    /// 分片重组：(session, msg_id) → 聚合状态
    frags: Mutex<HashMap<(u32, u16), FragState>>,
}

struct FragState {
    count: u8,
    parts: Vec<Option<Vec<u8>>>,
    host: String,
    port: u16,
}

impl Hy1UdpDemuxer {
    pub fn new(remote: SocketAddr) -> Self {
        Hy1UdpDemuxer {
            map: Mutex::new(HashMap::new()),
            remote,
            frags: Mutex::new(HashMap::new()),
        }
    }

    pub async fn register(&self, session: u32, tx: mpsc::Sender<UdpPacket>) {
        self.map.lock().await.insert(session, tx);
    }

    pub async fn unregister(&self, session: u32) {
        self.map.lock().await.remove(&session);
        self.frags.lock().await.retain(|k, _| k.0 != session);
    }

    async fn dispatch(&self, session: u32, host: String, port: u16, data: Vec<u8>) {
        let addr = match format!("{host}:{port}").parse::<SocketAddr>() {
            Ok(a) => a,
            Err(_) => return,
        };
        let tx = self.map.lock().await.get(&session).cloned();
        if let Some(tx) = tx {
            let _ = tx
                .send(UdpPacket {
                    src: self.remote,
                    dst: addr,
                    data: bytes::Bytes::from(data),
                })
                .await;
        }
    }
}

async fn demux_task(conn: quinn::Connection, demux: Arc<Hy1UdpDemuxer>) {
    // read_datagram 出错即连接已关，循环自然结束
    while let Ok(buf) = conn.read_datagram().await {
        let Some((session, host, port, msg_id, frag_id, frag_count, data)) =
            parse_udp_message(&buf)
        else {
            continue;
        };
        if frag_count <= 1 {
            demux.dispatch(session, host, port, data).await;
            continue;
        }
        // 分片重组
        let key = (session, msg_id);
        let mut frags = demux.frags.lock().await;
        let complete = {
            let entry = frags.entry(key).or_insert_with(|| FragState {
                count: frag_count,
                parts: (0..frag_count).map(|_| None).collect(),
                host: host.clone(),
                port,
            });
            if entry.count != frag_count || entry.parts[frag_id as usize].is_some() {
                // 冲突/重复：丢弃本轮分片
                frags.remove(&key);
                None
            } else {
                entry.parts[frag_id as usize] = Some(data);
                if entry.parts.iter().all(|p| p.is_some()) {
                    let st = frags.remove(&key).unwrap();
                    let mut data = Vec::new();
                    for p in st.parts.into_iter().flatten() {
                        data.extend_from_slice(&p);
                    }
                    Some((st.host, st.port, data))
                } else {
                    None
                }
            }
        };
        if let Some((host, port, data)) = complete {
            demux.dispatch(session, host, port, data).await;
        }
    }
}

/// 解析 udpMessage：返回 (session, host, port, msg_id, frag_id, frag_count, data)
type UdpMsgParts = (u32, String, u16, u16, u8, u8, Vec<u8>);

fn parse_udp_message(buf: &[u8]) -> Option<UdpMsgParts> {
    if buf.len() < 4 + 2 {
        return None;
    }
    let session = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let mut pos = 4;
    let host_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    if buf.len() < pos + host_len + 2 + 2 + 1 + 1 + 2 {
        return None;
    }
    let host = String::from_utf8_lossy(&buf[pos..pos + host_len]).into_owned();
    pos += host_len;
    let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;
    let msg_id = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;
    let frag_id = buf[pos];
    pos += 1;
    let frag_count = buf[pos];
    pos += 1;
    let data_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    if buf.len() < pos + data_len {
        return None;
    }
    Some((
        session,
        host,
        port,
        msg_id,
        frag_id,
        frag_count,
        buf[pos..pos + data_len].to_vec(),
    ))
}

// ---------------------------------------------------------------------------
// XPlus 混淆 UDP socket（quinn AsyncUdpSocket 包装）
// ---------------------------------------------------------------------------

struct ObfsUdpSocket {
    sock: Arc<tokio::net::UdpSocket>,
    obfs: Arc<XPlusObfs>,
}

impl std::fmt::Debug for ObfsUdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObfsUdpSocket").finish()
    }
}

impl ObfsUdpSocket {
    fn new(sock: tokio::net::UdpSocket, obfs: Arc<XPlusObfs>) -> Self {
        ObfsUdpSocket {
            sock: Arc::new(sock),
            obfs,
        }
    }
}

impl quinn::AsyncUdpSocket for ObfsUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        #[derive(Debug)]
        struct Poller {
            sock: Arc<tokio::net::UdpSocket>,
        }
        impl quinn::UdpPoller for Poller {
            fn poll_writable(
                self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                self.sock.poll_send_ready(cx)
            }
        }
        Box::pin(Poller {
            sock: self.sock.clone(),
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        let mut salt = [0u8; 16];
        vp_common::rand_bytes(&mut salt);
        let payload = self.obfs.obfuscate(transmit.contents.as_ref(), &salt);
        self.sock.try_send_to(&payload, transmit.destination)?;
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        ready!(self.sock.poll_recv_ready(cx))?;
        let mut tmp = vec![0u8; 65_535];
        match self.sock.try_recv_from(&mut tmp) {
            Ok((n, from)) => {
                if n <= 16 || bufs.is_empty() {
                    // 无有效载荷：本次返回 0 让 quinn 重试
                    return Poll::Ready(Ok(0));
                }
                let ks = self.obfs.keystream(&tmp[..16]);
                let body = &tmp[16..n];
                let out = &mut bufs[0];
                let cap = out.len().min(body.len());
                for (i, b) in body.iter().take(cap).enumerate() {
                    out[i] = b ^ ks[i % 32];
                }
                meta[0] = quinn::udp::RecvMeta {
                    addr: from,
                    len: cap,
                    stride: cap,
                    dst_ip: None,
                    ecn: None,
                };
                Poll::Ready(Ok(1))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.sock.local_addr()
    }
}

// ---------------------------------------------------------------------------
// 客户端 TLS/QUIC 配置
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Hy1NoVerify;

impl rustls::client::danger::ServerCertVerifier for Hy1NoVerify {
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
// 测试：最小 v1 服务端 + 回环
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use vp_core::Session;

    /// 测试用最小 Hysteria v1 服务端（与官方线上格式逐字对齐）
    async fn spawn_test_server() -> (u16, std::net::SocketAddr) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // echo 源站（TCP）
        let tcp_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_tcp_port = tcp_l.local_addr().unwrap().port();
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

        // echo 源站（UDP）
        let udp = std::sync::Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let udp_addr = udp.local_addr().unwrap();
        tokio::spawn({
            let udp = udp.clone();
            async move {
                let mut b = [0u8; 2048];
                while let Ok((n, from)) = udp.recv_from(&mut b).await {
                    let mut r = b"echo:".to_vec();
                    r.extend_from_slice(&b[..n]);
                    let _ = udp.send_to(&r, from).await;
                }
            }
        });

        // quinn 服务端（自签，ALPN hysteria）
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert.cert.pem().as_bytes())
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut cert.key_pair.serialize_pem().as_bytes())
            .unwrap()
            .unwrap();
        let mut crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        crypto.alpn_protocols = vec![b"hysteria".to_vec()];
        let mut scfg = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto).unwrap(),
        ));
        let mut t = quinn::TransportConfig::default();
        t.datagram_receive_buffer_size(Some(1 << 20));
        scfg.transport_config(Arc::new(t));
        let endpoint = quinn::Endpoint::server(scfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let port = endpoint.local_addr().unwrap().port();

        tokio::spawn(async move {
            let udp_sessions = std::sync::Arc::new(std::sync::Mutex::new(0u32));
            while let Some(incoming) = endpoint.accept().await {
                let Ok(conn) = incoming.await else { continue };
                let udp_sessions = udp_sessions.clone();
                tokio::spawn(async move {
                    // 控制流：版本 + clientHello <- serverHello
                    let Ok(mut ctl) = conn.accept_bi().await else {
                        return;
                    };
                    let mut ver = [0u8; 1];
                    if ctl.1.read_exact(&mut ver).await.is_err() {
                        return;
                    }
                    assert_eq!(ver[0], PROTOCOL_VERSION);
                    let mut hello = [0u8; 18];
                    if ctl.1.read_exact(&mut hello).await.is_err() {
                        return;
                    }
                    let auth_len = u16::from_be_bytes([hello[16], hello[17]]) as usize;
                    let mut auth = vec![0u8; auth_len];
                    if auth_len > 0 && ctl.1.read_exact(&mut auth).await.is_err() {
                        return;
                    }
                    // serverHello{OK=1, rate 0/0, msg ""}
                    let _ = ctl.0.write_all(&[1u8]).await;
                    let _ = ctl.0.write_all(&[0u8; 18]).await;
                    let _ = ctl.0.write_all(&[0u8; 2]).await;
                    let _ = ctl.0.flush().await;

                    // 数据流
                    loop {
                        let Ok((mut send, mut recv)) = conn.accept_bi().await else {
                            break;
                        };
                        let mut head = [0u8; 3];
                        if recv.read_exact(&mut head).await.is_err() {
                            break;
                        }
                        let is_udp = head[0] == 1;
                        let host_len = u16::from_be_bytes([head[1], head[2]]) as usize;
                        let mut rest = vec![0u8; host_len + 2];
                        if recv.read_exact(&mut rest).await.is_err() {
                            break;
                        }
                        if !is_udp {
                            // TCP：重定向到 echo 源站
                            let port = u16::from_be_bytes([rest[host_len], rest[host_len + 1]]);
                            // serverResponse{OK=1, session 0, msg ""}
                            let _ = send.write_all(&[1u8]).await;
                            let _ = send.write_all(&[0u8; 6]).await;
                            let _ = send.flush().await;
                            let up_port = if port == 1 { echo_tcp_port } else { port };
                            let Ok(origin) =
                                tokio::net::TcpStream::connect(("127.0.0.1", up_port)).await
                            else {
                                continue;
                            };
                            let (mut or, mut ow) = origin.into_split();
                            // 双向搬运各起独立任务，accept 循环立即返回受理下一条流
                            tokio::spawn(async move {
                                let mut b = [0u8; 4096];
                                loop {
                                    match or.read(&mut b).await {
                                        Ok(0) | Err(_) => break,
                                        Ok(n) => {
                                            if send.write_all(&b[..n]).await.is_err() {
                                                break;
                                            }
                                        }
                                    }
                                }
                            });
                            tokio::spawn(async move {
                                let mut b = [0u8; 4096];
                                loop {
                                    match recv.read(&mut b).await {
                                        Ok(Some(0)) | Ok(None) | Err(_) => break,
                                        Ok(Some(n)) => {
                                            if ow.write_all(&b[..n]).await.is_err() {
                                                break;
                                            }
                                        }
                                    }
                                }
                            });
                        } else {
                            // UDP 会话：分配 session id
                            let sid = {
                                let mut m = udp_sessions.lock().unwrap();
                                *m += 1;
                                *m
                            };
                            // serverResponse{OK=1, UDPSessionID, msg ""}
                            let mut resp = vec![1u8];
                            resp.extend_from_slice(&sid.to_be_bytes());
                            resp.extend_from_slice(&[0u8; 2]);
                            let _ = send.write_all(&resp).await;
                            let _ = send.flush().await;
                            // 会话维持：读数据报并回显
                            let c = conn.clone();
                            tokio::spawn(async move {
                                while let Ok(buf) = c.read_datagram().await {
                                    let Some((_s, host, port, _mid, _fid, _fc, data)) =
                                        parse_udp_message(&buf)
                                    else {
                                        continue;
                                    };
                                    let mut r = b"echo:".to_vec();
                                    r.extend_from_slice(&data);
                                    let mut m = Vec::new();
                                    m.extend_from_slice(&sid.to_be_bytes());
                                    m.extend_from_slice(&(host.len() as u16).to_be_bytes());
                                    m.extend_from_slice(host.as_bytes());
                                    m.extend_from_slice(&port.to_be_bytes());
                                    m.extend_from_slice(&1u16.to_be_bytes());
                                    m.push(0);
                                    m.push(1);
                                    m.extend_from_slice(&(r.len() as u16).to_be_bytes());
                                    m.extend_from_slice(&r);
                                    let _ = c.send_datagram(bytes::Bytes::from(m));
                                }
                            });
                        }
                    }
                });
            }
        });

        (port, udp_addr)
    }

    async fn hy1_udp_roundtrip(out: &Hysteria1Outbound, udp_port: u16) {
        let sess = Session::new_tcp(
            "t".into(),
            None,
            DstAddr::ip("127.0.0.1".parse().unwrap(), udp_port),
        );
        let dst = DstAddr::ip("127.0.0.1".parse().unwrap(), udp_port);
        let mut pc = out.connect_packet(&sess, &dst).await.unwrap();
        let pkt = UdpPacket {
            src: "127.0.0.1:1".parse().unwrap(),
            dst: "127.0.0.1:5353".parse().unwrap(),
            data: bytes::Bytes::from_static(b"hy1-udp"),
        };
        pc.send(&pkt).await.unwrap();
        let got = pc.recv().await.unwrap();
        assert_eq!(&got.data[..], &b"echo:hy1-udp"[..]);
    }

    #[tokio::test]
    async fn hysteria1_loopback() {
        use tokio::io::AsyncWriteExt;
        let (port, udp_addr) = spawn_test_server().await;
        let udp_port = udp_addr.port();

        // Clash Premium 风格：auth-str 即密码；alpn 列表（含非 hysteria 项）
        let out = Hysteria1Outbound::new(&vp_config::Hysteria1Cfg {
            server: "127.0.0.1".into(),
            port,
            auth_str: Some("s3cret".into()),
            auth: None,
            up: Some(10),
            down: Some(50),
            protocol: None,
            obfs: None,
            obfs_password: None,
            sni: None,
            alpn: vec!["h3".into()],
            skip_cert_verify: true,
        })
        .unwrap();

        // TCP（dst 端口 1 → 测试服务端重定向到 echo 源站）
        let dst = DstAddr::ip("127.0.0.1".parse().unwrap(), 1);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = out.connect_stream(&sess, &dst).await.unwrap();
        s.write_all(b"ping-hy1").await.unwrap();
        let mut buf = [0u8; 8];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-hy1");

        // UDP
        hy1_udp_roundtrip(&out, udp_port).await;
    }

    #[tokio::test]
    async fn hysteria1_obfs_mismatch_fails() {
        // 客户端带混淆、服务端无混淆 → QUIC 握手必须失败（防假通过）
        let (port, _udp_addr) = spawn_test_server().await;
        let out = Hysteria1Outbound::new(&vp_config::Hysteria1Cfg {
            server: "127.0.0.1".into(),
            port,
            auth_str: Some("s3cret".into()),
            auth: None,
            up: None,
            down: None,
            protocol: None,
            obfs: Some("obfspass".into()),
            obfs_password: None,
            sni: None,
            alpn: Vec::new(),
            skip_cert_verify: true,
        })
        .unwrap();
        let dst = DstAddr::ip("127.0.0.1".parse().unwrap(), 1);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_secs(20),
                out.connect_stream(&sess, &dst)
            )
            .await
            .is_err()
        );
    }
}

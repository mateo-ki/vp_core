//! brook（txthinking/brook 原生协议，当前 master 线格式）。
//!
//! TCP 会话：
//! - 客户端先发 12 字节随机 `ClientNonce`，服务端以 `HKDF-SHA256(password,
//!   salt=ClientNonce, info="brook")` 派生 32 字节 AES-256-GCM 密钥；反向
//!   密钥由服务端随机 `ServerNonce` 派生并在首条记录前明文发送。
//! - 随后双向均为记录流：`AES_GCM(len u16be) + AES_GCM(fragment)`，
//!   AAD 为空；每条记录耗两个 nonce（长度、载荷各一），nonce 递增方式为
//!   前 8 字节按 LE u64 加一。
//! - 首个 fragment = `u32be Unix 时间戳 + SOCKS 风格目标地址`；时间戳
//!   偶数表示 TCP 流、奇数表示 UDP-over-TCP 数据报流，服务端据此分发，
//!   并要求 `now - ts <= 60s` 防重放。
//! - TCP 记录（长度密文+载荷密文+标签）总长 ≤ 2048；UoT 模式 ≤ 65507，
//!   且首条 ≤ 2048。
//!
//! 原生 UDP 数据报（packetclient，单向一条一个 nonce，不在本期范围；
//! 本期 UoT 走 TCP 流封装，与服务端 `network == "udp"` 分支互通）。
//!
//! 参考：txthinking/brook `protocol/brook-server-protocol.md`、
//! `streamclient.go` / `streamserver.go`。

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use async_trait::async_trait;
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

use vp_common::addr::{decode_socks_addr, encode_socks_addr};
use vp_common::{DstAddr, Error, Result};
use vp_config::BrookCfg;
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;
use vp_core::stream::{PacketConn, ProxyStream, UdpPacket};
use vp_core::{Inbound, Outbound};
use vp_crypto::AnyAead;
use vp_transport as transport;

use crate::direct::DirectOutbound;
use vp_dns::Resolver;

const HKDF_INFO: &[u8] = b"brook";
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const TAG: usize = 16;
/// 记录头：密文长度（2B）+ 标签
const HDR_LEN: usize = 2 + TAG;
/// TCP 记录总长上限（含头部与载荷标签）
const MAX_TCP_RECORD: usize = 2048;
/// UoT 记录总长上限（首条仍受 MAX_TCP_RECORD 约束）
const MAX_DGRAM_RECORD: usize = 65507;
/// 重放窗口（秒）
const REPLAY_WINDOW: i64 = 60;

fn max_frag(record_max: usize) -> usize {
    record_max - HDR_LEN - TAG
}

/// nonce 前 8 字节按 LE u64 加一（与参考实现 NextNonce 一致）
fn inc_nonce(n: &mut [u8; NONCE_LEN]) {
    let v = u64::from_le_bytes(n[..8].try_into().unwrap()).wrapping_add(1);
    n[..8].copy_from_slice(&v.to_le_bytes());
}

/// HKDF-SHA256(ikm=password, salt=nonce, info="brook") → 32B AES 密钥
fn derive_key(password: &[u8], nonce: &[u8; NONCE_LEN]) -> Result<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(Some(nonce), password);
    let mut out = [0u8; KEY_LEN];
    hk.expand(HKDF_INFO, &mut out)
        .map_err(|_| Error::Proto("brook: 密钥派生失败"))?;
    Ok(out)
}

/// 单向会话密码：滚动 nonce 的 AES-256-GCM，每条记录耗两个 nonce
struct BrookCipher {
    aead: AnyAead,
    nonce: [u8; NONCE_LEN],
}

impl BrookCipher {
    fn new(nonce: [u8; NONCE_LEN], key: [u8; KEY_LEN]) -> Result<Self> {
        Ok(BrookCipher {
            aead: AnyAead::new(vp_crypto::AeadKind::Aes256Gcm, &key)?,
            nonce,
        })
    }

    /// 加密一条记录：GCM(len u16be) ‖ GCM(frag)，双 nonce 各进一
    fn seal(&mut self, frag: &[u8]) -> Vec<u8> {
        let mut out = self
            .aead
            .seal_nonce(&self.nonce, &(frag.len() as u16).to_be_bytes(), b"");
        inc_nonce(&mut self.nonce);
        out.extend_from_slice(&self.aead.seal_nonce(&self.nonce, frag, b""));
        inc_nonce(&mut self.nonce);
        out
    }

    /// 解记录头（密文 18B）→ 片长；不推进 nonce（载荷解密后一并推进）
    fn open_len(&mut self, hdr: &[u8; HDR_LEN]) -> Result<usize> {
        let pt = self.aead.open_nonce(&self.nonce, hdr, b"")?;
        let l = u16::from_be_bytes(pt.as_slice().try_into().unwrap()) as usize;
        inc_nonce(&mut self.nonce);
        Ok(l)
    }

    /// 解记录载荷（密文 l+16B）；随头、载荷两个 nonce 各进一
    fn open_body(&mut self, body_ct: &[u8]) -> Result<Vec<u8>> {
        let pt = self.aead.open_nonce(&self.nonce, body_ct, b"")?;
        inc_nonce(&mut self.nonce);
        Ok(pt)
    }
}

/// 会话模式：时间戳奇偶（偶 = TCP 流 / 奇 = UDP over TCP）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Tcp,
    Uot,
}

impl Mode {
    fn align_ts(&self, ts: i64) -> i64 {
        match self {
            Mode::Tcp if ts % 2 != 0 => ts + 1,
            Mode::Uot if ts % 2 != 1 => ts + 1,
            _ => ts,
        }
    }
}

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 首个 fragment：时间戳 + SOCKS 地址
fn first_fragment(dst: &DstAddr, mode: Mode) -> Result<Vec<u8>> {
    let mut f = Vec::with_capacity(4 + 262);
    f.extend_from_slice(&(mode.align_ts(now_ts()) as u32).to_be_bytes());
    encode_socks_addr(dst, &mut f);
    if f.len() > max_frag(MAX_TCP_RECORD) {
        return Err(Error::Proto("brook: 目标地址过长"));
    }
    Ok(f)
}

/// 客户端握手：发 ClientNonce + 首条记录，读 ServerNonce
async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    password: &[u8],
    dst: &DstAddr,
    mode: Mode,
) -> Result<(BrookCipher, BrookCipher)> {
    let mut cn = [0u8; NONCE_LEN];
    vp_common::rand_bytes(&mut cn);
    io.write_all(&cn).await?;
    let mut tx = BrookCipher::new(cn, derive_key(password, &cn)?)?;
    let frag = first_fragment(dst, mode)?;
    io.write_all(&tx.seal(&frag)).await?;
    io.flush().await?;

    let mut sn = [0u8; NONCE_LEN];
    io.read_exact(&mut sn).await?;
    let rx = BrookCipher::new(sn, derive_key(password, &sn)?)?;
    Ok((tx, rx))
}

/// 读一条记录；记录边界上对端正常关闭返回 None
async fn try_read_record<S: AsyncRead + Unpin>(
    io: &mut S,
    c: &mut BrookCipher,
) -> Result<Option<Vec<u8>>> {
    let mut hdr = [0u8; HDR_LEN];
    match io.read(&mut hdr).await? {
        0 => return Ok(None),
        n if n < HDR_LEN => {
            io.read_exact(&mut hdr[n..]).await?;
        }
        _ => {}
    }
    let l = c.open_len(&hdr)?;
    let mut body_ct = vec![0u8; l + TAG];
    io.read_exact(&mut body_ct).await?;
    Ok(Some(c.open_body(&body_ct)?))
}

/// 写一条记录（ frag 不得超出记录上限）
async fn write_record<S: AsyncWrite + Unpin>(
    io: &mut S,
    c: &mut BrookCipher,
    frag: &[u8],
) -> Result<()> {
    io.write_all(&c.seal(frag)).await?;
    io.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 出站
// ---------------------------------------------------------------------------

pub struct BrookOutbound {
    name: Arc<str>,
    server: String,
    port: u16,
    password: Vec<u8>,
    udp: bool,
}

impl BrookOutbound {
    pub fn new(cfg: &BrookCfg) -> Result<Self> {
        Self::new_named("brook", cfg)
    }

    pub fn new_named(name: &str, cfg: &BrookCfg) -> Result<Self> {
        if cfg.password.is_empty() {
            return Err(Error::Config("brook 密码不能为空".into()));
        }
        Ok(BrookOutbound {
            name: name.into(),
            server: cfg.server.clone(),
            port: cfg.port,
            password: cfg.password.clone().into_bytes(),
            udp: cfg.udp,
        })
    }
}

#[async_trait]
impl Outbound for BrookOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect_stream(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        let mut io = transport::dial(
            &self.server,
            self.port,
            &transport::TransportConfig::default(),
        )
        .await?;
        let (tx, rx) = client_handshake(&mut io, &self.password, dst, Mode::Tcp).await?;
        Ok(Box::new(BrookStream::new(io, tx, rx, false)))
    }

    async fn connect_packet(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        if !self.udp {
            return Err(Error::Proto("brook: 该节点未启用 udp"));
        }
        let mut io = transport::dial(
            &self.server,
            self.port,
            &transport::TransportConfig::default(),
        )
        .await?;
        let (tx, rx) = client_handshake(&mut io, &self.password, dst, Mode::Uot).await?;
        // 域名目标：回包源地址未知，用 0.0.0.0:port 占位
        let addr = dst_to_socket(dst);
        Ok(Box::new(BrookPacketConn {
            io: Mutex::new(io),
            tx: Mutex::new(tx),
            rx,
            default_src: addr,
            default_dst: addr,
        }))
    }

    fn support_udp(&self) -> bool {
        self.udp
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
}

// ---------------------------------------------------------------------------
// 客户端流：记录读状态机 + 记录化写出
// ---------------------------------------------------------------------------

enum ReadState {
    Header { hdr: [u8; HDR_LEN], fill: usize },
    Body { buf: Vec<u8>, fill: usize },
}

pub struct BrookStream<S> {
    io: S,
    tx: BrookCipher,
    rx: BrookCipher,
    datagram: bool,
    // 读状态
    rst: ReadState,
    rbuf: Vec<u8>,
    dgrams: VecDeque<Vec<u8>>,
    eof: bool,
    fatal: Option<String>,
    // 写状态：已加密待发
    outq: Vec<u8>,
    opos: usize,
    shutdown: bool,
}

impl<S: ProxyStream> vp_core::ProxyStream for BrookStream<S> {}

impl<S> BrookStream<S> {
    fn new(io: S, tx: BrookCipher, rx: BrookCipher, datagram: bool) -> Self {
        BrookStream {
            io,
            tx,
            rx,
            datagram,
            rst: ReadState::Header {
                hdr: [0u8; HDR_LEN],
                fill: 0,
            },
            rbuf: Vec::new(),
            dgrams: VecDeque::new(),
            eof: false,
            fatal: None,
            outq: Vec::new(),
            opos: 0,
            shutdown: false,
        }
    }

    fn reset_read(&mut self) {
        self.rst = ReadState::Header {
            hdr: [0u8; HDR_LEN],
            fill: 0,
        };
    }
}

impl<S: ProxyStream> BrookStream<S> {
    /// 推进读状态机直到 Pending / EOF / 有可读数据 / 错误
    fn pump_read(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncRead + Unpin,
    {
        loop {
            match &mut self.rst {
                ReadState::Header { hdr, fill } => {
                    while *fill < HDR_LEN {
                        let mut rb = tokio::io::ReadBuf::new(&mut hdr[*fill..]);
                        match Pin::new(&mut self.io).poll_read(cx, &mut rb) {
                            Poll::Ready(Ok(())) if rb.filled().is_empty() => {
                                return Poll::Ready(Ok(())); // EOF（记录边界）
                            }
                            Poll::Ready(Ok(())) => *fill += rb.filled().len(),
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    let hdr = std::mem::take(hdr);
                    let fill = *fill;
                    self.rst = ReadState::Header {
                        hdr: [0u8; HDR_LEN],
                        fill: 0,
                    };
                    let l = match self.rx.open_len(&hdr) {
                        Ok(l) => l,
                        Err(e) => {
                            self.fatal = Some(e.to_string());
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                e.to_string(),
                            )));
                        }
                    };
                    let _ = fill;
                    self.rst = ReadState::Body {
                        buf: vec![0u8; l + TAG],
                        fill: 0,
                    };
                }
                ReadState::Body { buf, fill } => {
                    while *fill < buf.len() {
                        let mut rb = tokio::io::ReadBuf::new(&mut buf[*fill..]);
                        match Pin::new(&mut self.io).poll_read(cx, &mut rb) {
                            Poll::Ready(Ok(())) if rb.filled().is_empty() => {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "brook: 记录中断",
                                )));
                            }
                            Poll::Ready(Ok(())) => *fill += rb.filled().len(),
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    let buf = std::mem::take(buf);
                    match self.rx.open_body(&buf) {
                        Ok(pt) => {
                            if self.datagram {
                                self.dgrams.push_back(pt);
                            } else {
                                self.rbuf.extend_from_slice(&pt);
                            }
                        }
                        Err(e) => {
                            self.fatal = Some(e.to_string());
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                e.to_string(),
                            )));
                        }
                    }
                    self.reset_read();
                }
            }
            // 有产出即返回（datagram 模式每条记录一个数据报）
            if !self.rbuf.is_empty() || !self.dgrams.is_empty() || self.eof {
                return Poll::Ready(Ok(()));
            }
        }
    }

    /// 将 outq 尽量写出
    fn drive_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncWrite + Unpin,
    {
        while self.opos < self.outq.len() {
            let n = ready!(Pin::new(&mut self.io).poll_write(cx, &self.outq[self.opos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "brook: 写入 0 字节",
                )));
            }
            self.opos += n;
        }
        self.outq.clear();
        self.opos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: ProxyStream> AsyncRead for BrookStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        rb: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.rbuf.is_empty() || !self.dgrams.is_empty() || (!self.eof && self.fatal.is_none()) {
            ready!(self.pump_read(cx))?;
        }
        if let Some(e) = &self.fatal {
            let e = io::Error::new(io::ErrorKind::InvalidData, e.clone());
            self.fatal = None;
            return Poll::Ready(Err(e));
        }
        if !self.rbuf.is_empty() {
            let n = self.rbuf.len().min(rb.remaining());
            let data: Vec<u8> = self.rbuf.drain(..n).collect();
            rb.put_slice(&data);
            return Poll::Ready(Ok(()));
        }
        if !self.dgrams.is_empty() {
            let d = self.dgrams.pop_front().unwrap();
            rb.put_slice(&d);
            return Poll::Ready(Ok(()));
        }
        debug_assert!(self.eof);
        Poll::Ready(Ok(()))
    }
}

impl<S: ProxyStream> AsyncWrite for BrookStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "brook: 已关闭",
            )));
        }
        let max = if self.datagram {
            max_frag(MAX_DGRAM_RECORD)
        } else {
            max_frag(MAX_TCP_RECORD)
        };
        let mut rest = data;
        while !rest.is_empty() {
            let n = rest.len().min(max);
            let rec = self.tx.seal(&rest[..n]);
            self.outq.extend_from_slice(&rec);
            rest = &rest[n..];
        }
        ready!(self.drive_out(cx))?;
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.drive_out(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shutdown {
            ready!(self.drive_out(cx))?;
            ready!(Pin::new(&mut self.io).poll_flush(cx))?;
            self.shutdown = true;
        }
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// 客户端数据报通道（UDP over TCP，对应服务端 network == "udp" 分支）
// ---------------------------------------------------------------------------

pub struct BrookPacketConn<S> {
    io: Mutex<S>,
    tx: Mutex<BrookCipher>,
    rx: BrookCipher,
    default_src: SocketAddr,
    default_dst: SocketAddr,
}

/// 域名目标回包地址未知：用 0.0.0.0:port 占位
fn dst_to_socket(dst: &DstAddr) -> SocketAddr {
    match &dst.host {
        vp_common::Host::Ip(ip) => SocketAddr::new(*ip, dst.port),
        vp_common::Host::Domain(_) => SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            dst.port,
        ),
    }
}

#[async_trait]
impl<S: ProxyStream> PacketConn for BrookPacketConn<S> {
    async fn send(&self, pkt: &UdpPacket) -> Result<()> {
        let data = &pkt.data[..];
        if data.len() > max_frag(MAX_DGRAM_RECORD) {
            return Err(Error::Proto("brook: 数据报过长"));
        }
        let mut io = self.io.lock().await;
        let mut tx = self.tx.lock().await;
        write_record(&mut *io, &mut tx, data).await
    }

    async fn recv(&mut self) -> Result<UdpPacket> {
        let mut io = self.io.lock().await;
        let data = try_read_record(&mut *io, &mut self.rx)
            .await?
            .ok_or(Error::Proto("brook: UoT 对端关闭"))?;
        Ok(UdpPacket {
            src: self.default_src,
            dst: self.default_dst,
            data: bytes::Bytes::from(data),
        })
    }
}

// ---------------------------------------------------------------------------
// 入站（TCP 中继 + UDP over TCP 中继）
// ---------------------------------------------------------------------------

pub struct BrookInbound {
    bind: String,
    port: u16,
    tag: Arc<str>,
    passwords: Vec<Vec<u8>>,
    direct: Arc<DirectOutbound>,
}

impl BrookInbound {
    pub fn new(bind: &str, port: u16, tag: &str, passwords: &[String]) -> Result<Self> {
        if passwords.is_empty() {
            return Err(Error::Config("brook 入站需要至少一个密码".into()));
        }
        Ok(BrookInbound {
            bind: bind.to_string(),
            port,
            tag: tag.into(),
            passwords: passwords.iter().map(|p| p.as_bytes().to_vec()).collect(),
            direct: Arc::new(DirectOutbound::new(Arc::new(Resolver::system()), false)),
        })
    }

    /// 认证 + 首记录解析：多密码逐一试解记录头；成功即回发 ServerNonce
    async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: &mut S,
    ) -> Result<(BrookCipher, BrookCipher, DstAddr, Mode)> {
        let mut cn = [0u8; NONCE_LEN];
        io.read_exact(&mut cn).await?;
        let mut hdr = [0u8; HDR_LEN];
        io.read_exact(&mut hdr).await?;

        let mut matched: Option<(BrookCipher, usize, usize)> = None;
        for (idx, pw) in self.passwords.iter().enumerate() {
            let mut c = BrookCipher::new(cn, derive_key(pw, &cn)?)?;
            match c.open_len(&hdr) {
                Ok(l) => {
                    matched = Some((c, l, idx));
                    break;
                }
                Err(_) => continue,
            }
        }
        let Some((mut c, l, pw_idx)) = matched else {
            return Err(Error::Proto("brook: 认证失败"));
        };
        let mut body_ct = vec![0u8; l + TAG];
        io.read_exact(&mut body_ct).await?;
        let frag = c.open_body(&body_ct)?;
        if frag.len() < 4 + 1 + 2 {
            return Err(Error::Proto("brook: 首记录过短"));
        }
        let ts = i64::from(u32::from_be_bytes(frag[..4].try_into().unwrap()));
        if now_ts() - ts > REPLAY_WINDOW {
            return Err(Error::Proto("brook: 过期请求"));
        }
        let mode = if ts % 2 == 0 { Mode::Tcp } else { Mode::Uot };
        let (dst, _used) = decode_socks_addr(&frag[4..])?;
        // 生成并明文发送 ServerNonce；反向密钥由认证通过的密码派生
        let mut sn = [0u8; NONCE_LEN];
        vp_common::rand_bytes(&mut sn);
        io.write_all(&sn).await?;
        io.flush().await?;
        let rx = BrookCipher::new(sn, derive_key(&self.passwords[pw_idx], &sn)?)?;
        Ok((c, rx, dst, mode))
    }

    async fn serve(
        &self,
        mut io: tokio::net::TcpStream,
        src: SocketAddr,
        ctx: &InboundCtx,
    ) -> Result<()> {
        // tx：解客户端方向记录；rx：加密服务端方向记录
        let (mut tx, rx, dst, mode) = self.accept(&mut io).await?;
        let _ = ctx;
        // 读写半分离：客户端记录读取与目标回写分属两侧，避免 select
        // 丢弃半读记录（try_read_record 非取消安全）
        let (mut rh, mut wh) = io.into_split();
        match mode {
            Mode::Tcp => {
                use tokio::sync::mpsc;
                let sess = Session::new_tcp(self.tag.clone(), Some(src), dst.clone());
                let mut remote = self.direct.connect_stream(&sess, &dst).await?;
                // 读任务：客户端记录 → 通道；写任务：通道明文 → 加密记录
                let (rec_tx, mut rec_rx) = mpsc::channel::<Vec<u8>>(64);
                let reader = tokio::spawn(async move {
                    while let Ok(Some(data)) = try_read_record(&mut rh, &mut tx).await {
                        if rec_tx.send(data).await.is_err() {
                            break;
                        }
                    }
                });
                let (chunk_tx, mut chunk_rx) = mpsc::channel::<Vec<u8>>(64);
                let writer = tokio::spawn(async move {
                    let mut rx = rx;
                    while let Some(c) = chunk_rx.recv().await {
                        let mut rest: &[u8] = &c;
                        while !rest.is_empty() {
                            let k = rest.len().min(max_frag(MAX_TCP_RECORD));
                            if write_record(&mut wh, &mut rx, &rest[..k]).await.is_err() {
                                return;
                            }
                            rest = &rest[k..];
                        }
                    }
                });
                let mut b = vec![0u8; 16384];
                loop {
                    tokio::select! {
                        r = rec_rx.recv() => match r {
                            Some(data) => {
                                if !data.is_empty() && remote.write_all(&data).await.is_err() {
                                    break;
                                }
                            }
                            None => break,
                        },
                        n = remote.read(&mut b) => match n {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if chunk_tx.send(b[..n].to_vec()).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
                reader.abort();
                writer.abort();
                Ok(())
            }
            Mode::Uot => self.serve_uot(rh, wh, tx, rx, src, dst).await,
        }
    }

    /// UDP over TCP：客户端记录 ⇄ 目标 UDP 数据报
    async fn serve_uot(
        &self,
        mut rh: tokio::net::tcp::OwnedReadHalf,
        mut wh: tokio::net::tcp::OwnedWriteHalf,
        mut tx: BrookCipher,
        mut rx: BrookCipher,
        _src: SocketAddr,
        dst: DstAddr,
    ) -> Result<()> {
        let target = match &dst.host {
            vp_common::Host::Ip(ip) => SocketAddr::new(*ip, dst.port),
            vp_common::Host::Domain(d) => {
                let ips = Resolver::system().resolve_domain(d, false).await?;
                SocketAddr::new(ips[0], dst.port)
            }
        };
        let sock = tokio::net::UdpSocket::bind(if target.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        })
        .await?;
        sock.connect(target).await?;
        let sock = std::sync::Arc::new(sock);
        let writer = {
            let sock = sock.clone();
            tokio::spawn(async move {
                let mut b = vec![0u8; 65535];
                loop {
                    match sock.recv(&mut b).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if write_record(&mut wh, &mut rx, &b[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            })
        };
        while let Some(data) = try_read_record(&mut rh, &mut tx).await? {
            if !data.is_empty() && sock.send(&data).await.is_err() {
                break;
            }
        }
        writer.abort();
        Ok(())
    }
}

#[async_trait]
impl Inbound for BrookInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, ctx: InboundCtx) -> Result<u16> {
        let listener = tokio::net::TcpListener::bind((self.bind.as_str(), self.port)).await?;
        let bound = listener.local_addr()?.port();
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, src)) => {
                        transport::tune(&stream);
                        let this = this.clone();
                        let ctx = ctx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = this.serve(stream, src, &ctx).await {
                                tracing::warn!("brook 入站会话结束: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("brook 入站 accept 失败: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        });
        Ok(bound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, timeout};

    fn outbound_plain(server: &str, port: u16, password: &str) -> BrookOutbound {
        BrookOutbound::new(&BrookCfg {
            server: server.into(),
            port,
            password: password.into(),
            udp: true,
        })
        .unwrap()
    }

    async fn echo_server() -> std::sync::Arc<tokio::net::TcpListener> {
        let l = std::sync::Arc::new(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap());
        let l2 = l.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l2.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut b = vec![0u8; 65536];
                    loop {
                        match s.read(&mut b).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&b[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        l
    }

    fn test_ctx() -> InboundCtx {
        InboundCtx {
            router: Arc::new(crate::test_support::NoopRouter()),
            stats: Arc::new(vp_common::Stats::default()),
            conns: Arc::new(vp_core::ConnTable::new()),
        }
    }

    #[test]
    fn nonce_increment_le() {
        let mut n = [0u8; 12];
        inc_nonce(&mut n);
        assert_eq!(n, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        n[..8].copy_from_slice(&0xffff_ffff_ffff_ffffu64.to_le_bytes());
        inc_nonce(&mut n);
        assert_eq!(&n[..8], &0u64.to_le_bytes());
    }

    /// RFC 5869 Test Case 1（SHA-256）：验证 hkdf 用法（salt/ikm/info 顺序）
    #[test]
    fn hkdf_rfc5869_vector() {
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let ikm = [0x0bu8; 22];
        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = [0u8; 42];
        hk.expand(b"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9", &mut okm)
            .unwrap();
        assert_eq!(
            okm[..32],
            [
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf,
            ]
        );
    }

    #[test]
    fn record_roundtrip_and_nonce_roll() {
        let mut a = BrookCipher::new([0u8; 12], [7u8; 32]).unwrap();
        let mut b = BrookCipher::new([0u8; 12], [7u8; 32]).unwrap();
        let rec = a.seal(b"hello brook");
        assert_eq!(rec.len(), 2 + TAG + 11 + TAG);
        // 双段解密：头（nonce0）→ 载荷（nonce1），共进两个 nonce
        let l = b.open_len(rec[..HDR_LEN].try_into().unwrap()).unwrap();
        assert_eq!(l, 11);
        assert_eq!(b.open_body(&rec[HDR_LEN..]).unwrap(), b"hello brook");
        // 第二条记录必须用滚动后的 nonce
        let rec2 = a.seal(b"second");
        let l2 = b.open_len(rec2[..HDR_LEN].try_into().unwrap()).unwrap();
        assert_eq!(l2, 6);
        assert_eq!(b.open_body(&rec2[HDR_LEN..]).unwrap(), b"second");
        // 篡改载荷 → 解密失败
        let mut rec3 = a.seal(b"tamper");
        let _l3 = b.open_len(rec3[..HDR_LEN].try_into().unwrap()).unwrap();
        let n = rec3.len();
        rec3[n - 1] ^= 1;
        assert!(b.open_body(&rec3[HDR_LEN..]).is_err());
    }

    #[tokio::test]
    async fn brook_loopback() {
        let echo = echo_server().await;
        let echo_port = echo.local_addr().unwrap().port();
        let server =
            Arc::new(BrookInbound::new("127.0.0.1", 0, "bk-srv", &["pw123".to_string()]).unwrap());
        let port = server.clone().start(test_ctx()).await.unwrap();

        let out = outbound_plain("127.0.0.1", port, "pw123");
        let dst = DstAddr::new("127.0.0.1", echo_port);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = timeout(Duration::from_secs(5), out.connect_stream(&sess, &dst))
            .await
            .unwrap()
            .unwrap();

        // 小回显
        s.write_all(b"ping-brook").await.unwrap();
        let mut buf = [0u8; 10];
        timeout(Duration::from_secs(5), s.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"ping-brook");

        // 大回显（跨记录分帧，逐字节一致）
        let big: Vec<u8> = (0..300_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 3) as u8)
            .collect();
        let mut rb = vec![0u8; big.len()];
        let (mut rr, mut rw) = tokio::io::split(s);
        let big2 = big.clone();
        let wtask = tokio::spawn(async move {
            rw.write_all(&big2).await.unwrap();
            rw.flush().await.unwrap();
        });
        timeout(Duration::from_secs(20), rr.read_exact(&mut rb))
            .await
            .unwrap()
            .unwrap();
        wtask.await.unwrap();
        assert_eq!(rb, big, "大回显逐字节不一致");
    }

    #[tokio::test]
    async fn brook_wrong_password() {
        let echo = echo_server().await;
        let echo_port = echo.local_addr().unwrap().port();
        let server = Arc::new(
            BrookInbound::new("127.0.0.1", 0, "bk-srv", &["right-pw".to_string()]).unwrap(),
        );
        let port = server.clone().start(test_ctx()).await.unwrap();

        let out = outbound_plain("127.0.0.1", port, "wrong-pw");
        let dst = DstAddr::new("127.0.0.1", echo_port);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        match out.connect_stream(&sess, &dst).await {
            Err(_) => {} // 服务端认证失败关闭：握手读失败
            Ok(mut s) => {
                let mut b = [0u8; 16];
                let r = timeout(Duration::from_secs(5), s.read(&mut b))
                    .await
                    .unwrap();
                assert!(matches!(r, Ok(0) | Err(_)), "错误密码不应收到数据: {r:?}");
            }
        }
    }

    #[tokio::test]
    async fn brook_expired_request() {
        // 构造时间戳超窗的客户端首记录 → 服务端拒绝
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        let pw = b"pw123";
        tokio::spawn(async move {
            let (mut s, _) = server.accept().await.unwrap();
            let mut cn = [0u8; 12];
            s.read_exact(&mut cn).await.unwrap();
            let mut c = BrookCipher::new(cn, derive_key(pw, &cn).unwrap()).unwrap();
            let mut hdr = [0u8; HDR_LEN];
            s.read_exact(&mut hdr).await.unwrap();
            let l = c.open_len(&hdr).unwrap();
            let mut body = vec![0u8; l + TAG];
            s.read_exact(&mut body).await.unwrap();
            let frag = c.open_body(&body).unwrap();
            let ts = i64::from(u32::from_be_bytes(frag[..4].try_into().unwrap()));
            assert!(now_ts() - ts > REPLAY_WINDOW, "测试时间戳应已过期");
        });

        let mut io = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let mut cn = [0u8; 12];
        vp_common::rand_bytes(&mut cn);
        io.write_all(&cn).await.unwrap();
        let mut tx = BrookCipher::new(cn, derive_key(b"pw123", &cn).unwrap()).unwrap();
        // 手工构造 10 分钟前的过期时间戳（偶数，TCP 模式）
        let old = now_ts() - REPLAY_WINDOW - 600;
        let old = old - old % 2;
        let mut frag = Vec::new();
        frag.extend_from_slice(&(old as u32).to_be_bytes());
        encode_socks_addr(&DstAddr::new("127.0.0.1", 80), &mut frag);
        io.write_all(&tx.seal(&frag)).await.unwrap();
        timeout(Duration::from_secs(5), io.read_to_end(&mut Vec::new()))
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn brook_uot_loopback() {
        // 经 BrookInbound 的 UoT 中继发收 UDP 数据报
        let server =
            Arc::new(BrookInbound::new("127.0.0.1", 0, "bk-srv", &["pw123".to_string()]).unwrap());
        let port = server.clone().start(test_ctx()).await.unwrap();

        // 真实 UDP 回显服务
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_port = udp.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut b = vec![0u8; 65536];
            while let Ok((n, from)) = udp.recv_from(&mut b).await {
                if udp.send_to(&b[..n], from).await.is_err() {
                    break;
                }
            }
        });

        let out = outbound_plain("127.0.0.1", port, "pw123");
        let dst = DstAddr::new("127.0.0.1", udp_port);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut conn = timeout(Duration::from_secs(5), out.connect_packet(&sess, &dst))
            .await
            .unwrap()
            .unwrap();

        for i in 0..8u16 {
            let payload: Vec<u8> = (0..1000u32)
                .map(|j| ((u32::from(i) * 131 + j) % 251) as u8)
                .collect();
            conn.send(&UdpPacket {
                src: SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    40000 + i,
                ),
                dst: SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    udp_port,
                ),
                data: bytes::Bytes::from(payload.clone()),
            })
            .await
            .unwrap();
            let pkt = timeout(Duration::from_secs(5), conn.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(pkt.data.as_ref(), payload.as_slice());
        }
    }
}

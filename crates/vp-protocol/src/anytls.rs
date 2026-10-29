//! anytls（sing-anytls v2）：TLS 之上的多路复用流协议。
//!
//! 线格式（参照 anytls-go / sing-anytls 参考实现）：
//! - 会话复用一条 TLS 流；客户端先发 32 字节 sha256(password) + 2 字节
//!   握手 padding 长度 + 对应零字节，随后（随首个流一并）发 settings 帧。
//! - 帧：`[cmd u8][sid u32be][len u16be][data]`，cmd：
//!   0 waste / 1 SYN / 2 PSH / 3 FIN / 4 settings / 5 alert /
//!   6 update-padding-scheme / 7 SYNACK / 8+9 心跳 / 10 server-settings。
//! - 目标地址：SYN 后首个 PSH，载荷为 SOCKS 风格地址（ATYP+addr+port）。
//! - padding scheme（`stop=N` + 每包号 `min-max,c,...`）把前 N 个写包
//!   切分成定长记录并用 waste 帧填充，抵御 TLS-in-TLS 流量分析；
//!   双端 scheme md5 不一致时服务端下发新 scheme。
//! - UDP 无原生支持，走 UoT（udp-over-tcp）封装（见 build_outbound）。

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use async_trait::async_trait;
use md5::{Digest, Md5};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};

use vp_common::addr::{decode_socks_addr, encode_socks_addr};
use vp_common::{DstAddr, Error, Result};
use vp_config::AnytlsCfg;
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;
use vp_core::stream::ProxyStream;
use vp_core::{Inbound, Outbound};

use crate::direct::DirectOutbound;
use vp_dns::Resolver;
use vp_transport as transport;

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQ: u8 = 8;
const CMD_HEART_RESP: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

const PROTOCOL_VERSION: u32 = 2;
const FRAME_OVERHEAD: usize = 7;
const MAX_FRAME: usize = 0xFFFF;
const PASSWORD_LEN: usize = 32;
const MAX_PADDING_SIZE: i64 = 1 << 20;
const CHECK_MARK: i64 = -1;
/// 地址累积上限（ATYP + 255 域名 + 端口）
const MAX_ADDR_LEN: usize = 262;

pub(crate) const DEFAULT_PADDING_SCHEME: &[u8] = b"stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn frame(cmd: u8, sid: u32, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(FRAME_OVERHEAD + data.len());
    v.push(cmd);
    v.extend_from_slice(&sid.to_be_bytes());
    v.extend_from_slice(&(data.len() as u16).to_be_bytes());
    v.extend_from_slice(data);
    v
}

fn push_waste(out: &mut Vec<u8>, len: usize) {
    out.push(CMD_WASTE);
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.resize(out.len() + len, 0);
}

fn parse_settings(data: &[u8]) -> Vec<(String, String)> {
    String::from_utf8_lossy(data)
        .lines()
        .filter_map(|l| {
            l.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

fn random_below(n: i64) -> i64 {
    if n <= 1 {
        return 0;
    }
    let mut b = [0u8; 8];
    vp_common::rand_bytes(&mut b);
    (u64::from_be_bytes(b) % n as u64) as i64
}

// ---------------------------------------------------------------------------
// padding scheme
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct PaddingRange {
    min: i64,
    max: i64,
}

#[derive(Debug, Clone)]
struct PaddingFactory {
    raw: Vec<u8>,
    md5: String,
    stop: u32,
    records: HashMap<u32, Vec<PaddingRange>>,
}

impl PaddingFactory {
    fn new(raw: &[u8]) -> Result<Self> {
        let scheme = parse_settings(raw);
        if scheme.is_empty() {
            return Err(Error::Proto("anytls: 空 padding scheme"));
        }
        let stop = scheme
            .iter()
            .find(|(k, _)| k == "stop")
            .and_then(|(_, v)| v.trim().parse::<i64>().ok())
            .ok_or(Error::Proto("anytls: padding scheme 缺少 stop"))?;
        if stop < 0 {
            return Err(Error::Proto("anytls: padding scheme stop 非法"));
        }
        let mut records = HashMap::new();
        for (k, v) in scheme {
            let Ok(pkt) = k.parse::<u32>() else { continue };
            let mut ranges = Vec::new();
            for item in v.split(',') {
                if item.trim() == "c" {
                    ranges.push(PaddingRange {
                        min: CHECK_MARK,
                        max: CHECK_MARK,
                    });
                    continue;
                }
                let Some((a, b)) = item.split_once('-') else {
                    continue;
                };
                let (Ok(mut mn), Ok(mut mx)) = (a.trim().parse::<i64>(), b.trim().parse::<i64>())
                else {
                    continue;
                };
                if mn > mx {
                    std::mem::swap(&mut mn, &mut mx);
                }
                if mn <= 0 || mx > MAX_PADDING_SIZE {
                    continue;
                }
                ranges.push(PaddingRange { min: mn, max: mx });
            }
            if !ranges.is_empty() {
                records.insert(pkt, ranges);
            }
        }
        Ok(PaddingFactory {
            raw: raw.to_vec(),
            md5: hex(&Md5::digest(raw)),
            stop: stop as u32,
            records,
        })
    }

    fn generate_sizes(&self, pkt: u32) -> Vec<i64> {
        let Some(ranges) = self.records.get(&pkt) else {
            return Vec::new();
        };
        ranges
            .iter()
            .map(|r| {
                if r.min == CHECK_MARK {
                    CHECK_MARK
                } else if r.max > r.min {
                    r.min + random_below(r.max - r.min)
                } else {
                    r.min
                }
            })
            .collect()
    }

    /// 握手 padding 长度 = scheme 第 0 包的首个尺寸
    fn handshake_padding_size(&self) -> usize {
        match self.generate_sizes(0).first() {
            Some(&s) if s > 0 => s as usize,
            _ => 0,
        }
    }
}

/// 写侧 padding 状态机：按包号把字节流切分成记录块（数据 + waste 填充）。
/// 双端对称；读侧无需感知（waste 帧在读循环中直接丢弃）。
#[derive(Debug, Clone)]
struct Padder {
    factory: PaddingFactory,
    send_padding: bool,
    packet_count: u32,
}

impl Padder {
    fn new(factory: PaddingFactory) -> Self {
        Padder {
            factory,
            send_padding: true,
            packet_count: 0,
        }
    }

    fn segment(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        if !self.send_padding {
            return vec![data.to_vec()];
        }
        self.packet_count += 1;
        if self.packet_count >= self.factory.stop {
            self.send_padding = false;
            return vec![data.to_vec()];
        }
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        let mut rest: &[u8] = data;
        for size in self.factory.generate_sizes(self.packet_count) {
            if size == CHECK_MARK {
                if rest.is_empty() {
                    break;
                }
                continue;
            }
            let size = size as usize;
            if rest.len() > size {
                chunks.push(rest[..size].to_vec());
                rest = &rest[size..];
                continue;
            }
            // 剩余数据（若有）+ waste 帧填满一条 size 记录
            let mut rec = Vec::with_capacity(size);
            if !rest.is_empty() {
                rec.extend_from_slice(rest);
                rest = &[];
                let mut remaining = size - rec.len();
                while remaining > FRAME_OVERHEAD {
                    let wl = (remaining - FRAME_OVERHEAD).min(MAX_FRAME);
                    push_waste(&mut rec, wl);
                    remaining -= FRAME_OVERHEAD + wl;
                }
            } else {
                let mut remaining = size;
                while remaining > 0 {
                    let wl = remaining.min(MAX_FRAME);
                    push_waste(&mut rec, wl);
                    remaining -= wl;
                }
            }
            chunks.push(rec);
        }
        if !rest.is_empty() {
            chunks.push(rest.to_vec());
        }
        chunks
    }
}

// ---------------------------------------------------------------------------
// 出站
// ---------------------------------------------------------------------------

pub struct AnytlsOutbound {
    name: Arc<str>,
    server: String,
    port: u16,
    hash: [u8; PASSWORD_LEN],
    transport: transport::TransportConfig,
}

impl AnytlsOutbound {
    pub fn new(cfg: &AnytlsCfg) -> Result<Self> {
        Self::internal_new(None, cfg)
    }

    pub fn new_named(name: &str, cfg: &AnytlsCfg) -> Result<Self> {
        Self::internal_new(Some(name), cfg)
    }

    fn internal_new(name: Option<&str>, cfg: &AnytlsCfg) -> Result<Self> {
        let reality = match &cfg.reality_opts {
            Some(r) => Some(vp_transport::parse_reality_config(
                &r.public_key,
                r.short_id.as_deref(),
                r.spider_x.clone(),
            )?),
            None => None,
        };
        Ok(AnytlsOutbound {
            name: name.unwrap_or("anytls").into(),
            server: cfg.server.clone(),
            port: cfg.port,
            hash: Sha256::digest(cfg.password.as_bytes()).into(),
            transport: transport::TransportConfig {
                // 协议本身即 TLS 传输，无需显式 tls 字段
                tls: true,
                server_name: cfg.server_name.clone(),
                skip_cert_verify: cfg.skip_cert_verify,
                fingerprint: cfg.client_fingerprint.clone(),
                alpn: Vec::new(),
                ws: None,
                http: None,
                grpc: None,
                reality,
                ech: None,
            },
        })
    }

    async fn handshake(
        &self,
        mut io: Box<dyn ProxyStream>,
        dst: &DstAddr,
    ) -> Result<AnytlsStream<Box<dyn ProxyStream>>> {
        let factory = PaddingFactory::new(DEFAULT_PADDING_SCHEME)?;
        let hs_pad = factory.handshake_padding_size();
        let mut req = Vec::with_capacity(PASSWORD_LEN + 2 + hs_pad);
        req.extend_from_slice(&self.hash);
        req.extend_from_slice(&(hs_pad as u16).to_be_bytes());
        req.resize(req.len() + hs_pad, 0);
        io.write_all(&req).await?;

        let mut st = AnytlsStream::new(io, 1, Padder::new(factory));
        // settings + SYN + 首个 PSH（目标地址）合并为一个写包（packet 1）
        let settings = format!(
            "client=\npadding-md5={}\nv={PROTOCOL_VERSION}",
            st.padder.factory.md5
        );
        let mut pkt = frame(CMD_SETTINGS, 0, settings.as_bytes());
        pkt.extend_from_slice(&frame(CMD_SYN, st.sid, &[]));
        let mut addr = Vec::with_capacity(280);
        encode_socks_addr(dst, &mut addr);
        pkt.extend_from_slice(&frame(CMD_PSH, st.sid, &addr));
        for c in st.padder.segment(&pkt) {
            st.io.write_all(&c).await?;
        }
        st.io.flush().await?;
        Ok(st)
    }
}

#[async_trait]
impl Outbound for AnytlsOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect_stream(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        let io = transport::dial(&self.server, self.port, &self.transport).await?;
        let st = self.handshake(io, dst).await?;
        Ok(Box::new(st))
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
}

// ---------------------------------------------------------------------------
// 客户端流：帧读状态机 + padding 写队列（单流会话，sid 固定）
// ---------------------------------------------------------------------------

struct AnytlsStream<S> {
    io: S,
    sid: u32,
    padder: Padder,
    // 读状态
    hdr: [u8; FRAME_OVERHEAD],
    hfill: usize,
    in_body: bool,
    rcmd: u8,
    rsid: u32,
    body: Vec<u8>,
    bfill: usize,
    rbuf: Vec<u8>,
    rpos: usize,
    eof: bool,
    fatal: Option<String>,
    // 写状态
    outq: VecDeque<Vec<u8>>,
    opos: usize,
    fin_sent: bool,
}

impl<S: ProxyStream> vp_core::ProxyStream for AnytlsStream<S> {}

impl<S> AnytlsStream<S> {
    // （pump_read / drive_out 要求 S: Unpin，见下方 poll impl 约束）
    fn new(io: S, sid: u32, padder: Padder) -> Self {
        AnytlsStream {
            io,
            sid,
            padder,
            hdr: [0; FRAME_OVERHEAD],
            hfill: 0,
            in_body: false,
            rcmd: 0,
            rsid: 0,
            body: Vec::new(),
            bfill: 0,
            rbuf: Vec::new(),
            rpos: 0,
            eof: false,
            fatal: None,
            outq: VecDeque::new(),
            opos: 0,
            fin_sent: false,
        }
    }

    fn psh_payload(&self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + FRAME_OVERHEAD);
        let mut rest = data;
        while !rest.is_empty() {
            let n = rest.len().min(MAX_FRAME);
            out.extend_from_slice(&frame(CMD_PSH, self.sid, &rest[..n]));
            rest = &rest[n..];
        }
        out
    }

    fn enqueue_psh(&mut self, data: &[u8]) {
        let payload = self.psh_payload(data);
        self.outq.extend(self.padder.segment(&payload));
    }

    /// 处理完整帧；返回是否产生了可读数据
    fn handle_frame(&mut self, cmd: u8, sid: u32, data: &[u8]) -> bool {
        match cmd {
            CMD_PSH if sid == self.sid => {
                self.rbuf.extend_from_slice(data);
                !data.is_empty()
            }
            CMD_WASTE | CMD_PSH | CMD_SETTINGS | CMD_HEART_RESP | CMD_SERVER_SETTINGS => false,
            CMD_FIN => {
                self.eof = true;
                false
            }
            CMD_SYNACK if !data.is_empty() => {
                self.fatal = Some(format!(
                    "anytls: 远端握手失败: {}",
                    String::from_utf8_lossy(data)
                ));
                false
            }
            CMD_SYNACK => false,
            CMD_ALERT => {
                self.fatal = Some(format!(
                    "anytls: 服务端 alert: {}",
                    String::from_utf8_lossy(data)
                ));
                false
            }
            CMD_UPDATE_PADDING => match PaddingFactory::new(data) {
                Ok(f) => {
                    self.padder.factory = f;
                    false
                }
                Err(e) => {
                    tracing::warn!("anytls: padding scheme 更新失败: {e}");
                    false
                }
            },
            CMD_HEART_REQ => {
                self.outq.push_back(frame(CMD_HEART_RESP, sid, &[]));
                false
            }
            _ => false,
        }
    }

    /// 推进读状态机直到 Pending / EOF / 产生数据 / 错误
    fn pump_read(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncRead + Unpin,
    {
        if !self.in_body {
            while self.hfill < FRAME_OVERHEAD {
                let mut rb = tokio::io::ReadBuf::new(&mut self.hdr[self.hfill..]);
                match Pin::new(&mut self.io).poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) if rb.filled().is_empty() => {
                        // 对端关闭：视为 EOF
                        self.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Ok(())) => self.hfill += rb.filled().len(),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            self.rcmd = self.hdr[0];
            self.rsid = u32::from_be_bytes([self.hdr[1], self.hdr[2], self.hdr[3], self.hdr[4]]);
            let len = u16::from_be_bytes([self.hdr[5], self.hdr[6]]) as usize;
            self.body = vec![0u8; len];
            self.bfill = 0;
            self.in_body = true;
        }
        while self.bfill < self.body.len() {
            let mut rb = tokio::io::ReadBuf::new(&mut self.body[self.bfill..]);
            match Pin::new(&mut self.io).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) if rb.filled().is_empty() => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "anytls: 帧体截断",
                    )));
                }
                Poll::Ready(Ok(())) => self.bfill += rb.filled().len(),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.in_body = false;
        self.hfill = 0;
        let (cmd, sid, body) = (self.rcmd, self.rsid, std::mem::take(&mut self.body));
        self.handle_frame(cmd, sid, &body);
        Poll::Ready(Ok(()))
    }

    fn drive_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncWrite + Unpin,
    {
        while let Some(cur) = self.outq.front() {
            match Pin::new(&mut self.io).poll_write(cx, &cur[self.opos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "anytls: 写端关闭",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    self.opos += n;
                    if self.opos >= cur.len() {
                        self.outq.pop_front();
                        self.opos = 0;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: ProxyStream + Unpin> AsyncRead for AnytlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.rpos < this.rbuf.len() {
                let n = buf.remaining().min(this.rbuf.len() - this.rpos);
                buf.put_slice(&this.rbuf[this.rpos..this.rpos + n]);
                this.rpos += n;
                if this.rpos == this.rbuf.len() {
                    this.rbuf.clear();
                    this.rpos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if let Some(msg) = this.fatal.take() {
                return Poll::Ready(Err(io::Error::other(msg)));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            ready!(this.pump_read(cx))?;
        }
    }
}

impl<S: ProxyStream + Unpin> AsyncWrite for AnytlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.fin_sent {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "anytls: 流已关闭",
            )));
        }
        if !this.outq.is_empty() {
            ready!(this.drive_out(cx))?;
            if !this.outq.is_empty() {
                return Poll::Pending;
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.enqueue_psh(buf);
        ready!(this.drive_out(cx))?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().drive_out(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.fin_sent {
            this.fin_sent = true;
            let fin = frame(CMD_FIN, this.sid, &[]);
            this.outq.extend(this.padder.segment(&fin));
        }
        ready!(this.drive_out(cx))?;
        ready!(Pin::new(&mut this.io).poll_flush(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// 入站（服务端会话：多流 + 直连转发）
// ---------------------------------------------------------------------------

pub struct AnytlsInbound {
    bind: String,
    port: u16,
    tag: Arc<str>,
    passwords: Vec<[u8; PASSWORD_LEN]>,
    padding: PaddingFactory,
    direct: Arc<DirectOutbound>,
}

impl AnytlsInbound {
    pub fn new(bind: &str, port: u16, tag: &str, passwords: &[String]) -> Result<Self> {
        Self::with_scheme(bind, port, tag, passwords, None)
    }

    /// scheme：自定义 padding scheme（sing-box `padding_scheme` 语法，
    /// `\n` 行分隔）；None 用参考实现默认值
    pub fn with_scheme(
        bind: &str,
        port: u16,
        tag: &str,
        passwords: &[String],
        scheme: Option<&[u8]>,
    ) -> Result<Self> {
        if passwords.is_empty() {
            return Err(Error::Config("anytls 入站需要至少一个密码".into()));
        }
        let padding = PaddingFactory::new(scheme.unwrap_or(DEFAULT_PADDING_SCHEME))?;
        Ok(AnytlsInbound {
            bind: bind.to_string(),
            port,
            tag: tag.into(),
            passwords: passwords
                .iter()
                .map(|p| -> [u8; PASSWORD_LEN] { Sha256::digest(p.as_bytes()).into() })
                .collect(),
            padding,
            direct: Arc::new(DirectOutbound::new(Arc::new(Resolver::system()), false)),
        })
    }

    async fn serve(
        self: &Arc<Self>,
        stream: tokio::net::TcpStream,
        src: SocketAddr,
        _ctx: &InboundCtx,
    ) -> Result<()> {
        let mut io = stream;
        // 认证：32 字节 sha256(password) + 握手 padding
        let mut pw = [0u8; PASSWORD_LEN];
        io.read_exact(&mut pw).await?;
        if !self.passwords.contains(&pw) {
            return Err(Error::Proto("anytls: 密码错误"));
        }
        let mut plen = [0u8; 2];
        io.read_exact(&mut plen).await?;
        let pad = u16::from_be_bytes(plen) as usize;
        if pad > 0 {
            let mut sink = vec![0u8; pad];
            io.read_exact(&mut sink).await?;
        }

        let (r, w) = io.into_split();
        let writer = Arc::new(Mutex::new(ServerWriter {
            io: w,
            padder: Padder::new(self.padding.clone()),
        }));
        let mut session = SessionReader::new(r);
        let mut settings_received = false;
        let mut peer_version = 0u32;
        let mut streams: HashMap<u32, StreamState> = HashMap::new();

        loop {
            let (cmd, sid, body) = session.next_frame().await?;
            match cmd {
                CMD_SETTINGS => {
                    settings_received = true;
                    let peer = parse_settings(&body);
                    let peer_md5 = peer
                        .iter()
                        .find(|(k, _)| k == "padding-md5")
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default();
                    if peer_md5 != self.padding.md5 && self.padding.raw.len() <= MAX_FRAME {
                        let raw = self.padding.raw.clone();
                        writer
                            .lock()
                            .await
                            .write_packet(&frame(CMD_UPDATE_PADDING, 0, &raw))
                            .await?;
                    }
                    if let Some(v) = peer.iter().find(|(k, _)| k == "v").map(|(_, v)| v.clone()) {
                        if let Ok(v) = v.trim().parse::<u32>() {
                            if v >= PROTOCOL_VERSION {
                                peer_version = v;
                                writer
                                    .lock()
                                    .await
                                    .write_packet(&frame(
                                        CMD_SERVER_SETTINGS,
                                        0,
                                        format!("v={PROTOCOL_VERSION}").as_bytes(),
                                    ))
                                    .await?;
                            }
                        }
                    }
                }
                CMD_SYN => {
                    if !settings_received {
                        let msg = b"client did not send its settings";
                        let _ = writer
                            .lock()
                            .await
                            .write_packet(&frame(CMD_ALERT, 0, msg))
                            .await;
                        return Err(Error::Proto("anytls: 客户端未发 settings"));
                    }
                    streams
                        .entry(sid)
                        .or_insert(StreamState::Pending(Vec::new()));
                }
                CMD_PSH => {
                    let Some(state) = streams.get_mut(&sid) else {
                        continue;
                    };
                    match state {
                        StreamState::Open(tx) => {
                            if tx.send(body).await.is_err() {
                                streams.remove(&sid);
                            }
                        }
                        StreamState::Pending(buf) => {
                            buf.extend_from_slice(&body);
                            if buf.len() > MAX_ADDR_LEN {
                                streams.remove(&sid);
                                continue;
                            }
                            let (dst, used) = match decode_socks_addr(buf) {
                                Ok(x) => x,
                                Err(Error::Proto("address truncated"))
                                | Err(Error::Proto("empty domain")) => continue,
                                Err(e) => {
                                    streams.remove(&sid);
                                    return Err(e);
                                }
                            };
                            let rest = buf[used..].to_vec();
                            let (tx, rx) = mpsc::channel(64);
                            *state = StreamState::Open(tx);
                            tokio::spawn(pump_stream(
                                self.direct.clone(),
                                self.tag.clone(),
                                src,
                                dst,
                                sid,
                                peer_version,
                                rx,
                                rest,
                                writer.clone(),
                            ));
                        }
                    }
                }
                CMD_FIN => {
                    streams.remove(&sid);
                }
                CMD_HEART_REQ => {
                    writer
                        .lock()
                        .await
                        .write_packet(&frame(CMD_HEART_RESP, sid, &[]))
                        .await?;
                }
                _ => {}
            }
        }
    }
}

enum StreamState {
    /// 地址未收全：累积 PSH 载荷
    Pending(Vec<u8>),
    /// 中继中：数据通道
    Open(mpsc::Sender<Vec<u8>>),
}

/// 服务端写侧：padded 帧写出
struct ServerWriter<W: AsyncWrite + Unpin> {
    io: W,
    padder: Padder,
}

impl<W: AsyncWrite + Unpin> ServerWriter<W> {
    async fn write_packet(&mut self, data: &[u8]) -> Result<()> {
        for c in self.padder.segment(data) {
            self.io.write_all(&c).await?;
        }
        self.io.flush().await?;
        Ok(())
    }
}

/// 单条流的转发：anytls PSH/FIN ⇄ 目标 TCP
#[allow(clippy::too_many_arguments)]
async fn pump_stream(
    direct: Arc<DirectOutbound>,
    tag: Arc<str>,
    src: SocketAddr,
    dst: DstAddr,
    sid: u32,
    peer_version: u32,
    mut rx: mpsc::Receiver<Vec<u8>>,
    initial: Vec<u8>,
    writer: Arc<Mutex<ServerWriter<tokio::net::tcp::OwnedWriteHalf>>>,
) {
    let sess = Session::new_tcp(tag, Some(src), dst.clone());
    let mut remote = match direct.connect_stream(&sess, &dst).await {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            let _ = writer
                .lock()
                .await
                .write_packet(&frame(CMD_SYNACK, sid, msg.as_bytes()))
                .await;
            return;
        }
    };
    if peer_version >= PROTOCOL_VERSION {
        let _ = writer
            .lock()
            .await
            .write_packet(&frame(CMD_SYNACK, sid, &[]))
            .await;
    }
    if !initial.is_empty() && remote.write_all(&initial).await.is_err() {
        return;
    }
    let mut b = vec![0u8; 16384];
    let mut client_eof = false;
    loop {
        tokio::select! {
            n = remote.read(&mut b) => match n {
                Ok(0) | Err(_) => {
                    let _ = writer.lock().await.write_packet(&frame(CMD_FIN, sid, &[])).await;
                    break;
                }
                Ok(n) => {
                    let mut payload = Vec::with_capacity(n + FRAME_OVERHEAD);
                    let mut rest: &[u8] = &b[..n];
                    while !rest.is_empty() {
                        let k = rest.len().min(MAX_FRAME);
                        payload.extend_from_slice(&frame(CMD_PSH, sid, &rest[..k]));
                        rest = &rest[k..];
                    }
                    if writer.lock().await.write_packet(&payload).await.is_err() {
                        break;
                    }
                }
            },
            rxv = rx.recv(), if !client_eof => match rxv {
                Some(data) => {
                    if remote.write_all(&data).await.is_err() {
                        break;
                    }
                }
                None => {
                    client_eof = true;
                    let _ = remote.shutdown().await;
                }
            },
        }
    }
}

/// 会话读侧：完整帧读取（async fn 风格，服务端专用）
struct SessionReader<R: AsyncRead + Unpin> {
    io: R,
}

impl<R: AsyncRead + Unpin> SessionReader<R> {
    fn new(io: R) -> Self {
        SessionReader { io }
    }

    async fn next_frame(&mut self) -> Result<(u8, u32, Vec<u8>)> {
        let mut hdr = [0u8; FRAME_OVERHEAD];
        self.io.read_exact(&mut hdr).await?;
        let cmd = hdr[0];
        let sid = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
        let len = u16::from_be_bytes([hdr[5], hdr[6]]) as usize;
        let mut body = vec![0u8; len];
        if len > 0 {
            self.io.read_exact(&mut body).await?;
        }
        Ok((cmd, sid, body))
    }
}

#[async_trait]
impl Inbound for AnytlsInbound {
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
                                tracing::warn!("anytls 入站会话结束: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("anytls 入站 accept 失败: {e}");
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{Duration, timeout};

    fn outbound_plain(server: &str, port: u16, password: &str) -> AnytlsOutbound {
        let cfg = AnytlsCfg {
            server: server.into(),
            port,
            password: password.into(),
            server_name: None,
            skip_cert_verify: false,
            client_fingerprint: None,
            reality_opts: None,
            udp: false,
        };
        let mut o = AnytlsOutbound::new(&cfg).unwrap();
        o.transport.tls = false; // 自环走明文（TLS 拨号已由 utls e2e 覆盖）
        o
    }

    #[test]
    fn anytls_outbound_with_reality_config() {
        let cfg = AnytlsCfg {
            server: "1.2.3.4".into(),
            port: 443,
            password: "password123".into(),
            server_name: Some("www.apple.com".into()),
            skip_cert_verify: false,
            client_fingerprint: Some("chrome".into()),
            reality_opts: Some(vp_config::RealityOpts {
                public_key: "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio".into(),
                short_id: Some("1234".into()),
                spider_x: Some("/".into()),
            }),
            udp: true,
        };
        let o = AnytlsOutbound::new(&cfg).expect("AnytlsOutbound with REALITY should build");
        assert!(o.transport.tls);
        assert!(o.transport.reality.is_some());
        let r = o.transport.reality.unwrap();
        assert_eq!(r.short_id[..2], [0x12, 0x34]);
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
    fn padding_factory_parse() {
        let f = PaddingFactory::new(DEFAULT_PADDING_SCHEME).unwrap();
        assert_eq!(f.stop, 8);
        assert_eq!(f.handshake_padding_size(), 30);
        assert_eq!(f.md5.len(), 32);
        // 带 c 标记的包号
        let sizes = f.generate_sizes(2);
        assert_eq!(sizes.len(), 9);
        assert_eq!(sizes.iter().filter(|&&s| s == CHECK_MARK).count(), 4);
        for &s in sizes.iter().filter(|&&s| s != CHECK_MARK) {
            assert!((400..=1000).contains(&s), "size {s} 超出范围");
        }
        assert!(PaddingFactory::new(b"").is_err());
        assert!(PaddingFactory::new(b"nostop=1").is_err());
    }

    #[test]
    fn padder_segment_deterministic() {
        let mut p = Padder::new(PaddingFactory::new(b"stop=3\n1=50-50\n2=40-40").unwrap());
        // packet 1：10B 数据 → 单条 50B 记录（数据 + waste 填充）
        let c = p.segment(&[7u8; 10]);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].len(), 50);
        assert_eq!(&c[0][..10], &[7u8; 10]);
        // 记录里填充部分是 waste 帧：7B 头 + 33B 零载荷
        assert_eq!(c[0][10], CMD_WASTE);
        assert_eq!(&c[0][11..15], &0u32.to_be_bytes());
        assert_eq!(&c[0][15..17], &33u16.to_be_bytes());
        // packet 2：空数据 → 纯 waste 记录（40B 零载荷 + 7B 帧头）
        let c = p.segment(&[]);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].len(), 47);
        assert_eq!(c[0][0], CMD_WASTE);
        assert_eq!(&c[0][5..7], &40u16.to_be_bytes());
        // packet 3（>= stop）→ 不再填充，原样透传
        let c = p.segment(&[1u8; 5]);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].len(), 5);
    }

    #[tokio::test]
    async fn anytls_loopback() {
        let echo = echo_server().await;
        let echo_port = echo.local_addr().unwrap().port();
        let server =
            Arc::new(AnytlsInbound::new("127.0.0.1", 0, "at-srv", &["pw123".to_string()]).unwrap());
        let port = server.clone().start(test_ctx()).await.unwrap();

        let out = outbound_plain("127.0.0.1", port, "pw123");
        let dst = DstAddr::new("127.0.0.1", echo_port);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = timeout(Duration::from_secs(5), out.connect_stream(&sess, &dst))
            .await
            .unwrap()
            .unwrap();

        // 小回显
        s.write_all(b"ping-anytls").await.unwrap();
        let mut buf = [0u8; 11];
        timeout(Duration::from_secs(5), s.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"ping-anytls");

        // 大回显（跨 PSH 分帧 + waste 混入，逐字节一致）
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
    async fn anytls_wrong_password() {
        let echo = echo_server().await;
        let echo_port = echo.local_addr().unwrap().port();
        let server = Arc::new(
            AnytlsInbound::new("127.0.0.1", 0, "at-srv", &["right-pw".to_string()]).unwrap(),
        );
        let port = server.clone().start(test_ctx()).await.unwrap();

        let out = outbound_plain("127.0.0.1", port, "wrong-pw");
        let dst = DstAddr::new("127.0.0.1", echo_port);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        match out.connect_stream(&sess, &dst).await {
            Err(_) => {} // 服务端已关闭：写握手即失败
            Ok(mut s) => {
                // 连接成功但首读必然 EOF/错误（服务端认证失败即断开）
                let mut b = [0u8; 16];
                let r = timeout(Duration::from_secs(5), s.read(&mut b))
                    .await
                    .unwrap();
                assert!(matches!(r, Ok(0) | Err(_)), "错误密码不应收到数据: {r:?}");
            }
        }
    }

    #[tokio::test]
    async fn anytls_custom_padding_scheme() {
        let echo = echo_server().await;
        let echo_port = echo.local_addr().unwrap().port();
        // 自定义 scheme：与客户端默认不同 → 服务端下发 update-padding-scheme
        let scheme = b"stop=4\n1=77-77\n2=111-111\n3=93-93";
        let server = Arc::new(
            AnytlsInbound::with_scheme(
                "127.0.0.1",
                0,
                "at-srv",
                &["pw123".to_string()],
                Some(scheme),
            )
            .unwrap(),
        );
        let port = server.clone().start(test_ctx()).await.unwrap();

        let out = outbound_plain("127.0.0.1", port, "pw123");
        let dst = DstAddr::new("127.0.0.1", echo_port);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = timeout(Duration::from_secs(5), out.connect_stream(&sess, &dst))
            .await
            .unwrap()
            .unwrap();
        s.write_all(b"scheme-echo").await.unwrap();
        let mut buf = [0u8; 11];
        timeout(Duration::from_secs(5), s.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"scheme-echo");
    }

    #[tokio::test]
    async fn anytls_missing_settings_alert() {
        let server =
            Arc::new(AnytlsInbound::new("127.0.0.1", 0, "at-srv", &["pw123".to_string()]).unwrap());
        let port = server.clone().start(test_ctx()).await.unwrap();

        // 裸协议：密码正确但直接发 SYN（无 settings 帧）→ 服务端回 Alert 并断开
        let mut t = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let hash: [u8; PASSWORD_LEN] = Sha256::digest(b"pw123").into();
        let mut prologue = hash.to_vec();
        prologue.extend_from_slice(&0u16.to_be_bytes());
        t.write_all(&prologue).await.unwrap();
        t.write_all(&frame(CMD_SYN, 1, &[])).await.unwrap();
        let mut r = SessionReader::new(t);
        let (cmd, sid, body) = timeout(Duration::from_secs(5), r.next_frame())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cmd, CMD_ALERT);
        assert_eq!(sid, 0);
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            "client did not send its settings"
        );
    }
}

//! mieru（enfein/mieru v3，TCP 传输最小实现）。
//!
//! 会话层线格式（参考 pkg/cipher / pkg/protocol 参考实现）：
//! - 密钥：hashedPassword = SHA256(password ‖ 0x00 ‖ username)；
//!   timeSalt = SHA256(u64be(unix 秒按 2 分钟取整))；
//!   key = PBKDF2-HMAC-SHA256(hashedPassword, timeSalt, 64 轮, 32B)。
//!   客户端用当前取整时刻；服务端最多试 3 个 salt（取整时刻 ±2 分钟），
//!   容忍 4 分钟时差。双方向同 key，nonce 流各自独立。
//! - 加密：XChaCha20-Poly1305（24B nonce）。TCP 为隐式 nonce 模式：每方向
//!   首段在线上带 24B nonce（末 4 字节 = SHA256(username ‖ nonce[0..16])[..4]
//!   用户提示），此后每个加密操作 nonce 递增 1（自末字节进位）。
//!   元数据加密消耗一个 nonce，载荷加密消耗下一个。
//! - 段布局：[nonce(仅首段)] + [enc metadata 32+16] + [padding1] +
//!   [enc payload n+16] + [padding2]；padding 长度记在 metadata 里（本实现恒 0）。
//! - metadata 32B：sessionStruct（open/close session）与 dataAckStruct（data/ack），
//!   时间戳为自纪元起的分钟数，双端允许 ±1。
//! - 会话语义：客户端 openSessionRequest（首写数据 ≤1024B 可搭载）→ 服务端
//!   openSessionResponse；数据段 seq 每段 +1，fragment=0 为单段；TCP 流模式
//!   服务端按到达顺序直递，无需 ACK。关闭互发 closeSession。
//! - 会话载荷是 SOCKS5 流量：greeting + CONNECT 请求，服务端内嵌 SOCKS5 处理器。
//!
//! 本实现范围：每条 underlay TCP 连接承载单个会话（无多路复用）、无低熵
//! 编码、无压缩、padding 恒为 0；UDP（packet 传输）不支持。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use async_trait::async_trait;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use vp_common::addr::{decode_socks_addr, encode_socks_addr};
use vp_common::{DstAddr, Error, Result};
use vp_config::MieruCfg;
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;
use vp_core::stream::ProxyStream;
use vp_core::{Inbound, Outbound};
use vp_transport as transport;

use crate::direct::DirectOutbound;
use vp_dns::Resolver;

const METADATA_LEN: usize = 32;
const TAG: usize = 16;
const NONCE_LEN: usize = 24;
const ENC_META_LEN: usize = METADATA_LEN + TAG;
const FIRST_SEG_HDR: usize = NONCE_LEN + ENC_META_LEN;
const MAX_PDU: usize = 32 * 1024;
const MAX_SESSION_OPEN_PAYLOAD: usize = 1024;
const KEY_ITER: u32 = 64;
const MAX_USERNAME_LEN: usize = 64;
/// 我方接收窗口（段数）；TCP 流模式下对端不校验
const RECV_WINDOW: u16 = 256;

const OPEN_SESSION_REQUEST: u8 = 2;
const OPEN_SESSION_RESPONSE: u8 = 3;
const CLOSE_SESSION_REQUEST: u8 = 4;
const CLOSE_SESSION_RESPONSE: u8 = 5;
const DATA_C2S: u8 = 6;
const DATA_S2C: u8 = 7;
const ACK_C2S: u8 = 8;
const ACK_S2C: u8 = 9;

fn is_session_protocol(p: u8) -> bool {
    (2..=5).contains(&p)
}

fn is_data_ack_protocol(p: u8) -> bool {
    (6..=9).contains(&p)
}

// ---------------------------------------------------------------------------
// 密钥派生
// ---------------------------------------------------------------------------

/// SHA256(password ‖ 0x00 ‖ username)
fn hashed_password(password: &[u8], username: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(password);
    h.update([0u8]);
    h.update(username);
    h.finalize().into()
}

/// SHA256(u64be(unix 秒按 2 分钟取整))；与 Go t.Round(2min) 半值向上一致
fn time_salt(unix: u64) -> [u8; 32] {
    let rounded = ((unix + 60) / 120) * 120;
    let mut h = Sha256::new();
    h.update(rounded.to_be_bytes());
    h.finalize().into()
}

/// PBKDF2-HMAC-SHA256，单块输出（32B）
fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iters: u32) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(password).unwrap();
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u = mac.finalize().into_bytes();
    let mut out: [u8; 32] = u.into();
    for _ in 1..iters {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(password).unwrap();
        mac.update(&u);
        u = mac.finalize().into_bytes();
        for i in 0..32 {
            out[i] ^= u[i];
        }
    }
    out
}

/// 服务端发现用：3 个 salt（取整时刻 ±2 分钟）
fn candidate_keys(password: &[u8], username: &[u8], unix: u64) -> Vec<[u8; 32]> {
    let hp = hashed_password(password, username);
    let rounded = ((unix + 60) / 120) * 120;
    [-120i64, 0, 120]
        .iter()
        .map(|d| {
            let t = (rounded as i64 + d).max(0) as u64;
            pbkdf2_hmac_sha256(&hp, &time_salt(t), KEY_ITER)
        })
        .collect()
}

fn derive_key(password: &[u8], username: &[u8], unix: u64) -> [u8; 32] {
    candidate_keys(password, username, unix)[1]
}

// ---------------------------------------------------------------------------
// 会话密码：XChaCha20-Poly1305 隐式 nonce 模式
// ---------------------------------------------------------------------------

/// 24 字节 nonce 自末字节进位递增
fn inc_nonce(n: &mut [u8; NONCE_LEN]) {
    for b in n.iter_mut().rev() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            break;
        }
    }
}

struct MieruCipher {
    aead: XChaCha20Poly1305,
    nonce: [u8; NONCE_LEN],
    started: bool,
    /// 用户提示：首个 nonce 末 4 字节 = SHA256(username ‖ nonce[0..16])[..4]
    username: Vec<u8>,
}

impl MieruCipher {
    fn new(key: [u8; 32], username: &[u8]) -> Self {
        MieruCipher {
            aead: XChaCha20Poly1305::new((&key).into()),
            nonce: [0u8; NONCE_LEN],
            started: false,
            username: username.to_vec(),
        }
    }

    /// 生成首个 nonce 并写入用户提示
    fn init_nonce(&mut self) {
        vp_common::rand_bytes(&mut self.nonce);
        if !self.username.is_empty() && self.username.len() <= MAX_USERNAME_LEN {
            let mut input = Vec::with_capacity(self.username.len() + 16);
            input.extend_from_slice(&self.username);
            input.extend_from_slice(&self.nonce[..16]);
            let out = Sha256::digest(&input);
            self.nonce[20..].copy_from_slice(&out[..4]);
        }
        self.started = true;
    }

    /// 加密一段：首个调用把 nonce 前置写入 out，此后仅密文
    fn seal_into(&mut self, pt: &[u8], out: &mut Vec<u8>) -> Result<()> {
        if !self.started {
            self.init_nonce();
            out.extend_from_slice(&self.nonce);
        } else {
            inc_nonce(&mut self.nonce);
        }
        let ct = self
            .aead
            .encrypt((&self.nonce).into(), pt)
            .map_err(|_| Error::Proto("mieru: 加密失败"))?;
        out.extend_from_slice(&ct);
        Ok(())
    }

    /// 解密一段：首个调用从 buf 取前 24B nonce 并返回其长度，随后仅密文
    fn open(&mut self, buf: &[u8]) -> Result<(Vec<u8>, usize)> {
        let rest = if !self.started {
            if buf.len() < NONCE_LEN {
                return Err(Error::Proto("mieru: 首段过短"));
            }
            self.nonce.copy_from_slice(&buf[..NONCE_LEN]);
            self.started = true;
            NONCE_LEN
        } else {
            inc_nonce(&mut self.nonce);
            0
        };
        let pt = self
            .aead
            .decrypt((&self.nonce).into(), &buf[rest..])
            .map_err(|_| Error::Proto("mieru: 解密失败"))?;
        Ok((pt, rest))
    }
}

// ---------------------------------------------------------------------------
// metadata 编解码
// ---------------------------------------------------------------------------

fn now_minutes() -> u32 {
    (now_unix() / 60) as u32
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    vp_common::rand_bytes(&mut b);
    u32::from_be_bytes(b)
}

/// sessionStruct：open/close session
#[derive(Debug, Clone)]
struct SessionMeta {
    protocol: u8,
    session_id: u32,
    seq: u32,
    status: u8,
    payload_len: u16,
    suffix_len: u8,
}

impl SessionMeta {
    fn marshal(&self) -> [u8; METADATA_LEN] {
        let mut b = [0u8; METADATA_LEN];
        b[0] = self.protocol;
        b[2..6].copy_from_slice(&now_minutes().to_be_bytes());
        b[6..10].copy_from_slice(&self.session_id.to_be_bytes());
        b[10..14].copy_from_slice(&self.seq.to_be_bytes());
        b[14] = self.status;
        b[15..17].copy_from_slice(&self.payload_len.to_be_bytes());
        b[17] = self.suffix_len;
        b
    }

    /// 校验协议类型与时间戳（±1 分钟）
    fn unmarshal(b: &[u8; METADATA_LEN]) -> Result<Self> {
        let protocol = b[0];
        if !is_session_protocol(protocol) {
            return Err(Error::ProtoMsg(format!("mieru: 非法会话协议 {protocol}")));
        }
        let timestamp = u32::from_be_bytes(b[2..6].try_into().unwrap());
        if now_minutes().abs_diff(timestamp) > 1 {
            return Err(Error::ProtoMsg(format!("mieru: 过期时间戳 {timestamp}")));
        }
        let payload_len = u16::from_be_bytes(b[15..17].try_into().unwrap());
        if payload_len as usize > MAX_SESSION_OPEN_PAYLOAD {
            return Err(Error::ProtoMsg(format!(
                "mieru: 会话载荷超长 {payload_len}"
            )));
        }
        Ok(SessionMeta {
            protocol,
            session_id: u32::from_be_bytes(b[6..10].try_into().unwrap()),
            seq: u32::from_be_bytes(b[10..14].try_into().unwrap()),
            status: b[14],
            payload_len,
            suffix_len: b[17],
        })
    }
}

/// dataAckStruct：data / ack
#[derive(Debug, Clone)]
struct DataMeta {
    protocol: u8,
    session_id: u32,
    seq: u32,
    un_ack_seq: u32,
    window_size: u16,
    fragment: u8,
    prefix_len: u8,
    payload_len: u16,
    suffix_len: u8,
}

impl DataMeta {
    fn marshal(&self) -> [u8; METADATA_LEN] {
        let mut b = [0u8; METADATA_LEN];
        b[0] = self.protocol;
        b[2..6].copy_from_slice(&now_minutes().to_be_bytes());
        b[6..10].copy_from_slice(&self.session_id.to_be_bytes());
        b[10..14].copy_from_slice(&self.seq.to_be_bytes());
        b[14..18].copy_from_slice(&self.un_ack_seq.to_be_bytes());
        b[18..20].copy_from_slice(&self.window_size.to_be_bytes());
        b[20] = self.fragment;
        b[21] = self.prefix_len;
        b[22..24].copy_from_slice(&self.payload_len.to_be_bytes());
        b[24] = self.suffix_len;
        b
    }

    fn unmarshal(b: &[u8; METADATA_LEN]) -> Result<Self> {
        let protocol = b[0];
        if !is_data_ack_protocol(protocol) {
            return Err(Error::ProtoMsg(format!("mieru: 非法数据协议 {protocol}")));
        }
        let timestamp = u32::from_be_bytes(b[2..6].try_into().unwrap());
        if now_minutes().abs_diff(timestamp) > 1 {
            return Err(Error::ProtoMsg(format!("mieru: 过期时间戳 {timestamp}")));
        }
        Ok(DataMeta {
            protocol,
            session_id: u32::from_be_bytes(b[6..10].try_into().unwrap()),
            seq: u32::from_be_bytes(b[10..14].try_into().unwrap()),
            un_ack_seq: u32::from_be_bytes(b[14..18].try_into().unwrap()),
            window_size: u16::from_be_bytes(b[18..20].try_into().unwrap()),
            fragment: b[20],
            prefix_len: b[21],
            payload_len: u16::from_be_bytes(b[22..24].try_into().unwrap()),
            suffix_len: b[24],
        })
    }
}

// ---------------------------------------------------------------------------
// 段读写（async，握手期与服务端共用）
// ---------------------------------------------------------------------------

/// 段长（prefix/payload/suffix）
fn segment_layout(meta: &[u8; METADATA_LEN]) -> Result<(usize, usize, usize)> {
    Ok(if is_session_protocol(meta[0]) {
        let m = SessionMeta::unmarshal(meta)?;
        (0, m.payload_len as usize, m.suffix_len as usize)
    } else {
        let m = DataMeta::unmarshal(meta)?;
        (
            m.prefix_len as usize,
            m.payload_len as usize,
            m.suffix_len as usize,
        )
    })
}

/// 读一个完整段：返回 (metadata 明文, 载荷明文)。cipher 状态跨段保持。
async fn read_segment<S: AsyncRead + Unpin>(
    io: &mut S,
    rx: &mut MieruCipher,
    first: bool,
) -> Result<([u8; METADATA_LEN], Vec<u8>)> {
    let hdr_len = if first { FIRST_SEG_HDR } else { ENC_META_LEN };
    let mut hdr = vec![0u8; hdr_len];
    io.read_exact(&mut hdr).await?;
    let (meta, _) = rx.open(&hdr)?;
    let meta: [u8; METADATA_LEN] = meta
        .as_slice()
        .try_into()
        .map_err(|_| Error::Proto("mieru: 元数据长度错误"))?;
    let (prefix_len, payload_len, suffix_len) = segment_layout(&meta)?;
    if prefix_len > 0 {
        let mut pad = vec![0u8; prefix_len];
        io.read_exact(&mut pad).await?;
    }
    let payload = if payload_len > 0 {
        let mut ct = vec![0u8; payload_len + TAG];
        io.read_exact(&mut ct).await?;
        rx.open(&ct)?.0
    } else {
        Vec::new()
    };
    if suffix_len > 0 {
        let mut pad = vec![0u8; suffix_len];
        io.read_exact(&mut pad).await?;
    }
    Ok((meta, payload))
}

/// 写一个会话控制段（可搭载载荷）
async fn write_session_segment<S: AsyncWrite + Unpin>(
    io: &mut S,
    tx: &mut MieruCipher,
    protocol: u8,
    session_id: u32,
    seq: u32,
    status: u8,
    payload: &[u8],
) -> Result<()> {
    if payload.len() > MAX_SESSION_OPEN_PAYLOAD {
        return Err(Error::Proto("mieru: 会话载荷超长"));
    }
    let meta = SessionMeta {
        protocol,
        session_id,
        seq,
        status,
        payload_len: payload.len() as u16,
        suffix_len: 0,
    }
    .marshal();
    let mut out = Vec::with_capacity(FIRST_SEG_HDR + payload.len() + TAG);
    tx.seal_into(&meta, &mut out)?;
    if !payload.is_empty() {
        tx.seal_into(payload, &mut out)?;
    }
    io.write_all(&out).await?;
    io.flush().await?;
    Ok(())
}

/// 写一个数据段（单段 ≤ MAX_PDU，fragment=0）
async fn write_data_segment<S: AsyncWrite + Unpin>(
    io: &mut S,
    tx: &mut MieruCipher,
    protocol: u8,
    session_id: u32,
    seq: u32,
    un_ack_seq: u32,
    payload: &[u8],
) -> Result<()> {
    let meta = DataMeta {
        protocol,
        session_id,
        seq,
        un_ack_seq,
        window_size: RECV_WINDOW,
        fragment: 0,
        prefix_len: 0,
        payload_len: payload.len() as u16,
        suffix_len: 0,
    }
    .marshal();
    let mut out = Vec::with_capacity(FIRST_SEG_HDR + payload.len() + TAG);
    tx.seal_into(&meta, &mut out)?;
    if !payload.is_empty() {
        tx.seal_into(payload, &mut out)?;
    }
    io.write_all(&out).await?;
    io.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// SOCKS5 会话载荷
// ---------------------------------------------------------------------------

fn socks5_greeting() -> Vec<u8> {
    vec![0x05, 0x01, 0x00]
}

fn socks5_request(dst: &DstAddr) -> Result<Vec<u8>> {
    let mut req = vec![0x05, 0x01, 0x00];
    encode_socks_addr(dst, &mut req);
    Ok(req)
}

fn socks5_success_reply() -> Vec<u8> {
    // BIND 0.0.0.0:0
    vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

/// SOCKS5 应答解析（greeting 应答 + CONNECT 应答，容忍合并/分片到达）
#[derive(Default)]
struct Socks5ReplyParser {
    got_greeting: bool,
}

impl Socks5ReplyParser {
    /// 喂入累积数据；Ok(true) 表示握手完成（已消费应答，剩余为数据）
    fn feed(&mut self, buf: &mut Vec<u8>) -> Result<bool> {
        if !self.got_greeting {
            if buf.len() < 2 {
                return Ok(false);
            }
            if buf[0] != 0x05 {
                return Err(Error::Proto("mieru: SOCKS5 应答版本错误"));
            }
            if buf[1] != 0x00 {
                return Err(Error::Proto("mieru: SOCKS5 认证协商失败"));
            }
            buf.drain(..2);
            self.got_greeting = true;
        }
        if buf.len() < 4 {
            return Ok(false);
        }
        if buf[0] != 0x05 {
            return Err(Error::Proto("mieru: SOCKS5 应答版本错误"));
        }
        if buf[1] != 0x00 {
            return Err(Error::ProtoMsg(format!(
                "mieru: SOCKS5 连接失败 rep={}",
                buf[1]
            )));
        }
        let atyp = buf[3];
        let hdr_extra = if atyp == 0x03 { 1 } else { 0 };
        if buf.len() < 4 + hdr_extra {
            return Ok(false);
        }
        let addr_len = match atyp {
            0x01 => 4,
            0x03 => buf[4] as usize,
            0x04 => 16,
            a => return Err(Error::ProtoMsg(format!("mieru: SOCKS5 非法 ATYP {a:#04x}"))),
        };
        let total = 4 + hdr_extra + addr_len + 2;
        if buf.len() < total {
            return Ok(false);
        }
        buf.drain(..total);
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// 出站
// ---------------------------------------------------------------------------

pub struct MieruOutbound {
    name: Arc<str>,
    server: String,
    port: u16,
    username: String,
    password: String,
}

impl MieruOutbound {
    pub fn new(cfg: &MieruCfg) -> Result<Self> {
        Self::new_named("mieru", cfg)
    }

    pub fn new_named(name: &str, cfg: &MieruCfg) -> Result<Self> {
        if cfg.username.is_empty() {
            return Err(Error::Config("mieru 用户名不能为空".into()));
        }
        if cfg.username.len() > MAX_USERNAME_LEN {
            return Err(Error::Config("mieru 用户名超长（≤64 字节）".into()));
        }
        if cfg.password.is_empty() {
            return Err(Error::Config("mieru 密码不能为空".into()));
        }
        Ok(MieruOutbound {
            name: name.into(),
            server: cfg.server.clone(),
            port: cfg.port,
            username: cfg.username.clone(),
            password: cfg.password.clone(),
        })
    }

    async fn handshake(
        &self,
        mut io: Box<dyn ProxyStream>,
        dst: &DstAddr,
    ) -> Result<MieruStream<Box<dyn ProxyStream>>> {
        let key = derive_key(
            self.password.as_bytes(),
            self.username.as_bytes(),
            now_unix(),
        );
        let mut tx = MieruCipher::new(key, self.username.as_bytes());
        let session_id = random_u32();

        // openSessionRequest：搭载 SOCKS5 greeting + CONNECT 请求
        let mut req = socks5_greeting();
        req.extend_from_slice(&socks5_request(dst)?);
        write_session_segment(
            &mut io,
            &mut tx,
            OPEN_SESSION_REQUEST,
            session_id,
            0,
            0,
            &req,
        )
        .await?;

        // 服务端方向：同 key，独立 nonce 流
        let mut rx = MieruCipher::new(key, &[]);
        let mut rbuf: Vec<u8> = Vec::new();
        let mut parser = Socks5ReplyParser::default();
        let mut first = true;
        loop {
            let (meta, payload) = read_segment(&mut io, &mut rx, first).await?;
            first = false;
            match meta[0] {
                OPEN_SESSION_RESPONSE => {
                    let m = SessionMeta::unmarshal(&meta)?;
                    if m.status != 0 {
                        return Err(Error::ProtoMsg(format!(
                            "mieru: open session 失败 status={}",
                            m.status
                        )));
                    }
                }
                DATA_S2C => rbuf.extend_from_slice(&payload),
                CLOSE_SESSION_REQUEST | CLOSE_SESSION_RESPONSE => {
                    return Err(Error::Proto("mieru: 服务端已关闭会话"));
                }
                _ => {} // ACK 等控制段已按元数据消费
            }
            if parser.feed(&mut rbuf)? {
                return Ok(MieruStream::new(io, tx, rx, session_id, 1, rbuf));
            }
        }
    }
}

#[async_trait]
impl Outbound for MieruOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect_stream(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        let io = transport::dial(
            &self.server,
            self.port,
            &transport::TransportConfig::default(),
        )
        .await?;
        let st = self.handshake(io, dst).await?;
        Ok(Box::new(st))
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
}

// ---------------------------------------------------------------------------
// 客户端流：段读状态机 + 段化写出
// ---------------------------------------------------------------------------

enum RState {
    /// 读加密元数据（首个方向段含 nonce，buf 长度不同）
    Meta { buf: Vec<u8>, fill: usize },
    /// padding1
    Prefix { size: usize, fill: usize },
    /// 载荷密文（含 tag）
    Payload { buf: Vec<u8>, fill: usize },
    /// padding2
    Suffix { size: usize, fill: usize },
}

pub struct MieruStream<S> {
    io: S,
    tx: MieruCipher,
    rx: MieruCipher,
    session_id: u32,
    seq: u32,
    next_recv: u32,
    // 读状态
    rst: RState,
    pending_meta: Option<[u8; METADATA_LEN]>,
    pending_pt: Vec<u8>,
    rbuf: Vec<u8>,
    eof: bool,
    // 写状态：已加密待发
    outq: Vec<u8>,
    opos: usize,
    closed: bool,
}

impl<S> MieruStream<S> {
    fn new(
        io: S,
        tx: MieruCipher,
        rx: MieruCipher,
        session_id: u32,
        next_seq: u32,
        initial: Vec<u8>,
    ) -> Self {
        MieruStream {
            io,
            tx,
            rx,
            session_id,
            seq: next_seq,
            next_recv: 0,
            rst: RState::Meta {
                buf: vec![0u8; ENC_META_LEN],
                fill: 0,
            },
            pending_meta: None,
            pending_pt: Vec::new(),
            rbuf: initial,
            eof: false,
            outq: Vec::new(),
            opos: 0,
            closed: false,
        }
    }
}

impl<S: ProxyStream> MieruStream<S> {
    /// 处理完整段；返回是否产生可读数据
    fn handle_segment(&mut self, meta: [u8; METADATA_LEN], payload: Vec<u8>) -> bool {
        self.next_recv = self.next_recv.wrapping_add(1);
        match meta[0] {
            DATA_S2C => {
                self.rbuf.extend_from_slice(&payload);
                !payload.is_empty()
            }
            OPEN_SESSION_RESPONSE | ACK_S2C | ACK_C2S | DATA_C2S => false,
            CLOSE_SESSION_REQUEST | CLOSE_SESSION_RESPONSE => {
                self.eof = true;
                false
            }
            _ => false,
        }
    }

    /// 元数据已解出：按段布局推进状态
    fn enter_segment(&mut self, meta: [u8; METADATA_LEN]) -> io::Result<()> {
        let (prefix, payload_len, suffix) = segment_layout(&meta)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        self.pending_meta = Some(meta);
        self.pending_pt = Vec::new();
        if prefix > 0 {
            self.rst = RState::Prefix {
                size: prefix,
                fill: 0,
            };
        } else if payload_len > 0 {
            self.rst = RState::Payload {
                buf: vec![0u8; payload_len + TAG],
                fill: 0,
            };
        } else if suffix > 0 {
            self.rst = RState::Suffix {
                size: suffix,
                fill: 0,
            };
        } else {
            let meta = self.pending_meta.take().unwrap_or([0u8; METADATA_LEN]);
            self.handle_segment(meta, Vec::new());
            self.reset_meta();
        }
        Ok(())
    }

    fn reset_meta(&mut self) {
        self.rst = RState::Meta {
            buf: vec![0u8; ENC_META_LEN],
            fill: 0,
        };
    }

    fn decrypt_payload(&mut self, buf: Vec<u8>) -> io::Result<()> {
        let (pt, _) = self
            .rx
            .open(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        self.pending_pt = pt;
        Ok(())
    }

    /// 段收尾：处理待决载荷并复位
    fn finish_segment(&mut self) {
        if let Some(meta) = self.pending_meta.take() {
            let pt = std::mem::take(&mut self.pending_pt);
            self.handle_segment(meta, pt);
        }
        self.reset_meta();
    }

    /// 推进读状态机直到 Pending / EOF / 有可读数据 / 错误
    fn pump_read(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncRead + Unpin,
    {
        loop {
            match &mut self.rst {
                RState::Meta { buf, fill } => {
                    let done = poll_fill(&mut self.io, cx, buf, fill)?;
                    if !done {
                        return Poll::Pending;
                    }
                    let buf = std::mem::take(buf);
                    let (meta, _) = self
                        .rx
                        .open(&buf)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    let meta: [u8; METADATA_LEN] = meta.as_slice().try_into().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "mieru: 元数据长度错误")
                    })?;
                    self.enter_segment(meta)?;
                }
                RState::Prefix { size, fill } => {
                    // padding 明文直接丢弃
                    let mut sink = vec![0u8; *size - *fill];
                    let mut read_bytes = 0;
                    let done = poll_fill(&mut self.io, cx, &mut sink, &mut read_bytes)?;
                    *fill += read_bytes;
                    if !done {
                        return Poll::Pending;
                    }
                    // 进入载荷或 suffix
                    let meta = self.pending_meta.unwrap_or([0u8; METADATA_LEN]);
                    let (_, payload_len, suffix) = segment_layout(&meta)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    if payload_len > 0 {
                        self.rst = RState::Payload {
                            buf: vec![0u8; payload_len + TAG],
                            fill: 0,
                        };
                    } else if suffix > 0 {
                        self.rst = RState::Suffix {
                            size: suffix,
                            fill: 0,
                        };
                    } else {
                        self.finish_segment();
                    }
                }
                RState::Payload { buf, fill } => {
                    let done = poll_fill(&mut self.io, cx, buf, fill)?;
                    if !done {
                        return Poll::Pending;
                    }
                    let buf = std::mem::take(buf);
                    self.decrypt_payload(buf)?;
                    let meta = self.pending_meta.unwrap_or([0u8; METADATA_LEN]);
                    let (_, _, suffix) = segment_layout(&meta)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    if suffix > 0 {
                        self.rst = RState::Suffix {
                            size: suffix,
                            fill: 0,
                        };
                    } else {
                        self.finish_segment();
                    }
                }
                RState::Suffix { size, fill } => {
                    let mut sink = vec![0u8; *size - *fill];
                    let done = poll_fill(&mut self.io, cx, &mut sink, &mut 0)?;
                    if !done {
                        return Poll::Pending;
                    }
                    self.finish_segment();
                }
            }
            if !self.rbuf.is_empty() || self.eof {
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
                    "mieru: 写入 0 字节",
                )));
            }
            self.opos += n;
        }
        self.outq.clear();
        self.opos = 0;
        Poll::Ready(Ok(()))
    }

    fn enqueue_data(&mut self, chunk: &[u8]) -> io::Result<()> {
        let meta = DataMeta {
            protocol: DATA_C2S,
            session_id: self.session_id,
            seq: self.seq,
            un_ack_seq: self.next_recv,
            window_size: RECV_WINDOW,
            fragment: 0,
            prefix_len: 0,
            payload_len: chunk.len() as u16,
            suffix_len: 0,
        }
        .marshal();
        self.seq = self.seq.wrapping_add(1);
        self.tx
            .seal_into(&meta, &mut self.outq)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let mut rec = Vec::with_capacity(chunk.len() + TAG);
        self.tx
            .seal_into(chunk, &mut rec)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        self.outq.extend_from_slice(&rec);
        Ok(())
    }
}

/// 填满 buf；对端关闭返回 true（EOF 标志由调用方处理）。
/// 返回值：true = 缓冲已填满或读到了 EOF（buf 未满时已记录 eof）。
fn poll_fill<S: AsyncRead + Unpin>(
    io: &mut S,
    cx: &mut Context<'_>,
    buf: &mut [u8],
    fill: &mut usize,
) -> io::Result<bool> {
    // 这里无法访问 self.eof，用哨兵：读满返回 Ok(true)，EOF 返回 Err(UnexpectedEof)
    while *fill < buf.len() {
        let mut rb = tokio::io::ReadBuf::new(&mut buf[*fill..]);
        match Pin::new(&mut *io).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) if rb.filled().is_empty() => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "mieru: 对端关闭",
                ));
            }
            Poll::Ready(Ok(())) => *fill += rb.filled().len(),
            Poll::Ready(Err(e)) => return Err(e),
            Poll::Pending => return Ok(false),
        }
    }
    Ok(true)
}

impl<S: ProxyStream> AsyncRead for MieruStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        rb: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.rbuf.is_empty() {
            let n = self.rbuf.len().min(rb.remaining());
            let data: Vec<u8> = self.rbuf.drain(..n).collect();
            rb.put_slice(&data);
            return Poll::Ready(Ok(()));
        }
        ready!(self.pump_read(cx))?;
        if !self.rbuf.is_empty() {
            let n = self.rbuf.len().min(rb.remaining());
            let data: Vec<u8> = self.rbuf.drain(..n).collect();
            rb.put_slice(&data);
            return Poll::Ready(Ok(()));
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: ProxyStream> AsyncWrite for MieruStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "mieru: 已关闭",
            )));
        }
        let mut rest = data;
        while !rest.is_empty() {
            let n = rest.len().min(MAX_PDU);
            self.enqueue_data(&rest[..n])?;
            rest = &rest[n..];
        }
        ready!(self.drive_out(cx))?;
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.drive_out(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closed {
            ready!(self.drive_out(cx))?;
            let meta = SessionMeta {
                protocol: CLOSE_SESSION_REQUEST,
                session_id: self.session_id,
                seq: self.seq,
                status: 0,
                payload_len: 0,
                suffix_len: 0,
            }
            .marshal();
            self.seq = self.seq.wrapping_add(1);
            let mut close_rec = Vec::new();
            if self.tx.seal_into(&meta, &mut close_rec).is_ok() {
                self.outq.extend_from_slice(&close_rec);
                let _ = ready!(self.drive_out(cx));
                let _ = Pin::new(&mut self.io).poll_flush(cx);
            }
            self.closed = true;
        }
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// 入站（单会话 SOCKS5 中继）
// ---------------------------------------------------------------------------

pub struct MieruInbound {
    bind: String,
    port: u16,
    tag: Arc<str>,
    /// (username, password) 列表
    users: Vec<(String, String)>,
    direct: Arc<DirectOutbound>,
}

impl MieruInbound {
    pub fn new(bind: &str, port: u16, tag: &str, users: &[String]) -> Result<Self> {
        if users.is_empty() {
            return Err(Error::Config("mieru 入站需要至少一个用户".into()));
        }
        let mut parsed = Vec::with_capacity(users.len());
        for u in users {
            let (name, pw) = u
                .split_once(':')
                .ok_or_else(|| Error::Config("mieru 入站用户格式应为 username:password".into()))?;
            if name.is_empty() || name.len() > MAX_USERNAME_LEN {
                return Err(Error::Config("mieru 用户名长度非法（1..=64 字节）".into()));
            }
            if pw.is_empty() {
                return Err(Error::Config("mieru 密码不能为空".into()));
            }
            parsed.push((name.to_string(), pw.to_string()));
        }
        Ok(MieruInbound {
            bind: bind.to_string(),
            port,
            tag: tag.into(),
            users: parsed,
            direct: Arc::new(DirectOutbound::new(Arc::new(Resolver::system()), false)),
        })
    }

    /// 用户发现 + openSessionRequest 载荷读取
    /// 返回 (发送方向 cipher, 接收方向 cipher, session_id, SOCKS5 请求缓冲)
    async fn accept(
        &self,
        io: &mut tokio::net::TcpStream,
    ) -> Result<(MieruCipher, MieruCipher, u32, Vec<u8>)> {
        let mut hdr = vec![0u8; FIRST_SEG_HDR];
        io.read_exact(&mut hdr).await?;
        let now = now_unix();
        let mut matched: Option<(MieruCipher, MieruCipher, [u8; METADATA_LEN])> = None;
        'outer: for (name, pw) in &self.users {
            for key in candidate_keys(pw.as_bytes(), name.as_bytes(), now) {
                let mut c = MieruCipher::new(key, &[]);
                if let Ok((meta, _)) = c.open(&hdr) {
                    let Ok(meta) = <[u8; METADATA_LEN]>::try_from(meta.as_slice()) else {
                        return Err(Error::Proto("mieru: 元数据长度错误"));
                    };
                    if meta[0] != OPEN_SESSION_REQUEST {
                        return Err(Error::Proto("mieru: 首段不是 openSessionRequest"));
                    }
                    let m = SessionMeta::unmarshal(&meta)?;
                    let tx = MieruCipher::new(key, name.as_bytes());
                    matched = Some((tx, c, meta));
                    let _ = m;
                    break 'outer;
                }
            }
        }
        let Some((tx, mut rx, meta)) = matched else {
            return Err(Error::Proto("mieru: 用户发现失败"));
        };
        let m = SessionMeta::unmarshal(&meta)?;
        let mut socks_buf: Vec<u8> = Vec::new();
        if m.payload_len > 0 {
            let mut ct = vec![0u8; m.payload_len as usize + TAG];
            io.read_exact(&mut ct).await?;
            socks_buf.extend_from_slice(&rx.open(&ct)?.0);
        }
        if m.suffix_len > 0 {
            let mut pad = vec![0u8; m.suffix_len as usize];
            io.read_exact(&mut pad).await?;
        }
        Ok((tx, rx, m.session_id, socks_buf))
    }

    async fn serve(
        &self,
        mut io: tokio::net::TcpStream,
        src: SocketAddr,
        _ctx: &InboundCtx,
    ) -> Result<()> {
        let (mut tx, mut rx, session_id, mut socks_buf) = self.accept(&mut io).await?;
        let mut seq: u32 = 0;
        let mut next_recv: u32 = 1; // openSessionRequest 已消费 seq 0

        // 1. SOCKS5 greeting（可能搭载在首段，也可能在后续数据段）
        loop {
            if socks_buf.len() >= 2 && socks_buf[0] == 0x05 {
                let n = socks_buf[1] as usize;
                if socks_buf.len() >= 2 + n {
                    socks_buf.drain(..2 + n);
                    write_data_segment(
                        &mut io,
                        &mut tx,
                        DATA_S2C,
                        session_id,
                        seq,
                        next_recv,
                        &[0x05, 0x00],
                    )
                    .await?;
                    seq += 1;
                    break;
                }
            }
            let (meta, payload) = read_segment(&mut io, &mut rx, false).await?;
            match meta[0] {
                DATA_C2S => {
                    next_recv += 1;
                    socks_buf.extend_from_slice(&payload);
                }
                CLOSE_SESSION_REQUEST | CLOSE_SESSION_RESPONSE => {
                    return Err(Error::Proto("mieru: 客户端关闭会话"));
                }
                _ => {}
            }
        }

        // 2. SOCKS5 CONNECT 请求
        let dst = loop {
            if socks_buf.len() >= 4 && socks_buf[0] == 0x05 {
                match decode_socks_addr(&socks_buf[3..]) {
                    Ok((dst, used)) => {
                        socks_buf.drain(..3 + used);
                        break dst;
                    }
                    Err(Error::Proto("address truncated")) | Err(Error::Proto("empty domain")) => {}
                    Err(e) => return Err(e),
                }
            } else if socks_buf.len() >= 4 && socks_buf[0] != 0x05 {
                return Err(Error::Proto("mieru: SOCKS5 请求版本错误"));
            }
            let (meta, payload) = read_segment(&mut io, &mut rx, false).await?;
            match meta[0] {
                DATA_C2S => {
                    next_recv += 1;
                    socks_buf.extend_from_slice(&payload);
                }
                CLOSE_SESSION_REQUEST | CLOSE_SESSION_RESPONSE => {
                    return Err(Error::Proto("mieru: 客户端关闭会话"));
                }
                _ => {}
            }
        };

        // 3. 连接目标并回 SOCKS5 成功应答
        let sess = Session::new_tcp(self.tag.clone(), Some(src), dst.clone());
        let mut remote = match self.direct.connect_stream(&sess, &dst).await {
            Ok(r) => r,
            Err(e) => {
                // SOCKS5 general failure
                let rep = [0x05u8, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
                let _ = write_data_segment(
                    &mut io, &mut tx, DATA_S2C, session_id, seq, next_recv, &rep,
                )
                .await;
                return Err(e);
            }
        };
        write_data_segment(
            &mut io,
            &mut tx,
            DATA_S2C,
            session_id,
            seq,
            next_recv,
            &socks5_success_reply(),
        )
        .await?;
        seq += 1;

        // 4. 中继：读写半分离（read_segment 非取消安全，独占接收任务）
        let (mut rh, mut wh) = io.into_split();
        let (rec_tx, mut rec_rx) = mpsc::channel::<Vec<u8>>(64);
        let reader = tokio::spawn(async move {
            let mut first = false; // accept/handshake 已消费 rx 首段 nonce
            while let Ok((meta, payload)) = read_segment(&mut rh, &mut rx, first).await {
                first = false;
                match meta[0] {
                    DATA_C2S => {
                        if rec_tx.send(payload).await.is_err() {
                            break;
                        }
                    }
                    CLOSE_SESSION_REQUEST | CLOSE_SESSION_RESPONSE => break,
                    _ => {}
                }
            }
        });
        let (chunk_tx, mut chunk_rx) = mpsc::channel::<Vec<u8>>(64);
        let writer = tokio::spawn(async move {
            let mut s = seq;
            while let Some(c) = chunk_rx.recv().await {
                let mut rest: &[u8] = &c;
                while !rest.is_empty() {
                    let k = rest.len().min(MAX_PDU);
                    if write_data_segment(
                        &mut wh,
                        &mut tx,
                        DATA_S2C,
                        session_id,
                        s,
                        next_recv,
                        &rest[..k],
                    )
                    .await
                    .is_err()
                    {
                        return;
                    }
                    s += 1;
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
}

#[async_trait]
impl Inbound for MieruInbound {
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
                                tracing::warn!("mieru 入站会话结束: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("mieru 入站 accept 失败: {e}");
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

    fn outbound_plain(server: &str, port: u16, username: &str, password: &str) -> MieruOutbound {
        MieruOutbound::new(&MieruCfg {
            server: server.into(),
            port,
            username: username.into(),
            password: password.into(),
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
    fn pbkdf2_rfc7914_vectors() {
        // PBKDF2-HMAC-SHA256 已知向量（draft-josefsson-scrypt-pdf / RFC 7914 附录）
        let v1 = pbkdf2_hmac_sha256(b"passwd", b"salt", 1);
        let v2 = pbkdf2_hmac_sha256(b"Password", b"NaCl", 80000);
        // c=1：dk = 55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc
        assert_eq!(
            hex_str(&v1),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
        // c=80000（取前 32B）：
        // 4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56
        assert_eq!(
            hex_str(&v2),
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
        );
    }

    fn hex_str(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn nonce_increment_carry() {
        let mut n = [0u8; 24];
        inc_nonce(&mut n);
        assert_eq!(n[23], 1);
        n[23] = 0xff;
        inc_nonce(&mut n);
        assert_eq!(n[23], 0);
        assert_eq!(n[22], 1);
    }

    #[test]
    fn user_hint_in_nonce() {
        let mut c = MieruCipher::new([7u8; 32], b"alice");
        let mut out = Vec::new();
        c.seal_into(b"hello", &mut out).unwrap();
        assert_eq!(out.len(), NONCE_LEN + 5 + TAG);
        // 末 4 字节 = SHA256("alice" ‖ nonce[0..16])[..4]
        let mut input = Vec::new();
        input.extend_from_slice(b"alice");
        input.extend_from_slice(&out[..16]);
        let h = Sha256::digest(&input);
        assert_eq!(&out[20..24], &h[..4]);
        // 接收端（无用户名）可以解密
        let mut r = MieruCipher::new([7u8; 32], b"");
        let (pt, rest) = r.open(&out).unwrap();
        assert_eq!(rest, NONCE_LEN);
        assert_eq!(pt, b"hello");
        // 第二段隐式 nonce
        let mut out2 = Vec::new();
        c.seal_into(b"world", &mut out2).unwrap();
        assert_eq!(out2.len(), 5 + TAG);
        let (pt2, _) = r.open(&out2).unwrap();
        assert_eq!(pt2, b"world");
    }

    #[tokio::test]
    async fn mieru_loopback() {
        let echo = echo_server().await;
        let echo_port = echo.local_addr().unwrap().port();
        let server = Arc::new(
            MieruInbound::new("127.0.0.1", 0, "mu-srv", &["alice:pw123".to_string()]).unwrap(),
        );
        let port = server.clone().start(test_ctx()).await.unwrap();

        let out = outbound_plain("127.0.0.1", port, "alice", "pw123");
        let dst = DstAddr::new("127.0.0.1", echo_port);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = timeout(Duration::from_secs(5), out.connect_stream(&sess, &dst))
            .await
            .unwrap()
            .unwrap();

        // 小回显
        s.write_all(b"ping-mieru").await.unwrap();
        let mut buf = [0u8; 10];
        timeout(Duration::from_secs(5), s.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"ping-mieru");

        // 大回显（跨段分帧，逐字节一致）
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
    async fn mieru_wrong_password() {
        let echo = echo_server().await;
        let echo_port = echo.local_addr().unwrap().port();
        let server = Arc::new(
            MieruInbound::new("127.0.0.1", 0, "mu-srv", &["alice:right-pw".to_string()]).unwrap(),
        );
        let port = server.clone().start(test_ctx()).await.unwrap();

        let out = outbound_plain("127.0.0.1", port, "alice", "wrong-pw");
        let dst = DstAddr::new("127.0.0.1", echo_port);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        match timeout(Duration::from_secs(5), out.connect_stream(&sess, &dst)).await {
            Err(_) => panic!("握手应快速失败而非超时"),
            Ok(Err(_)) => {} // 服务端发现失败关闭
            Ok(Ok(mut s)) => {
                let mut b = [0u8; 16];
                let r = timeout(Duration::from_secs(5), s.read(&mut b))
                    .await
                    .unwrap();
                assert!(matches!(r, Ok(0) | Err(_)), "错误密码不应收到数据: {r:?}");
            }
        }
    }

    #[tokio::test]
    async fn mieru_multi_user() {
        let echo = echo_server().await;
        let echo_port = echo.local_addr().unwrap().port();
        let server = Arc::new(
            MieruInbound::new(
                "127.0.0.1",
                0,
                "mu-srv",
                &[
                    "bob:pw-bob".to_string(),
                    "alice:pw-alice".to_string(),
                    "carol:pw-carol".to_string(),
                ],
            )
            .unwrap(),
        );
        let port = server.clone().start(test_ctx()).await.unwrap();

        // 第二个用户（非列表首位）也能发现成功
        let out = outbound_plain("127.0.0.1", port, "alice", "pw-alice");
        let dst = DstAddr::new("127.0.0.1", echo_port);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = timeout(Duration::from_secs(5), out.connect_stream(&sess, &dst))
            .await
            .unwrap()
            .unwrap();
        s.write_all(b"hi").await.unwrap();
        let mut buf = [0u8; 2];
        timeout(Duration::from_secs(5), s.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"hi");
    }
}

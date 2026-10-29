//! shadow-tls v3 出入站。
//!
//! 协议（对照 ihciah/shadow-tls docs/protocol-v3 与 mihomo transport/shadowtls）：
//! - 认证：ClientHello 的 session_id[28..32] = HMAC-SHA1(password, CH 尾 4 字节置零)[0..4]。
//! - ServerRandom：伪装站 ServerHello 的 32 字节 random，是所有密钥材料的种子。
//! - XOR 掩码（仅服务端包装伪装站 appdata 时使用）：SHA256(password || ServerRandom) 循环。
//! - HMAC 链：HMAC-SHA1(password) 预吸收 ServerRandom（握手相位）或 ServerRandom+"C"/"S"
//!   （数据相位双向各一条）；每帧先吸收 payload 再取 4 字节 tag，写侧随后吸收 tag，
//!   读侧校验通过后吸收 tag。
//! - 数据帧：`17 03 03 (4+n) || tag4 || payload`；认证失败回复 26 字节 padding 的 alert。
//!
//! 客户端不与伪装站完成 TLS 握手：ClientHello 手写（Chrome 风格，可完全控制
//! session_id），读到首个通过 HMAC 认证的伪装记录即证明中间是真实 v3 服务端，
//! 直接进入数据相位——劫持由首个 C 链数据帧触发，与握手是否完成无关（mihomo
//! 客户端的 TLS Finished 同样是原样转发，首个数据帧才带认证）。HRR 不支持。

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, BytesMut};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Digest as _;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

const TLS_HEADER: usize = 5;
const TLS_RANDOM: usize = 32;
const TLS_SESSION_ID: usize = 32;
/// 认证 tag 长度（v3 = 4）
const HMAC_SIZE: usize = 4;
/// `17 03 03 len` + tag
const FRAME_HDR_HMAC: usize = TLS_HEADER + HMAC_SIZE;
const MAX_PLAIN: usize = 16384;
/// 帧上限（payload + tag + 少量余量）
const MAX_FRAME: usize = MAX_PLAIN + HMAC_SIZE + 256;
const REC_CCS: u8 = 20;
const REC_ALERT: u8 = 21;
const REC_HANDSHAKE: u8 = 22;
const REC_APP: u8 = 23;
/// HelloRetryRequest 的固定 ServerRandom
const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// shadow-tls 拨号/入站参数（由 SsCfg.plugin_opts / ListenerCfg.shadow_tls 归一化）。
#[derive(Debug, Clone)]
pub struct ShadowTlsDial {
    /// 伪装站域名
    pub host: String,
    /// 伪装站端口（默认 443）
    pub port: u16,
    pub password: String,
}

// ---------------------------------------------------------------------------
// HMAC 链
// ---------------------------------------------------------------------------

/// 增量 HMAC-SHA1 链（前 4 字节作为 tag）。
#[derive(Clone)]
struct HmacChain(Hmac<Sha1>);

impl HmacChain {
    fn new(password: &[u8]) -> Self {
        HmacChain(Hmac::new_from_slice(password).expect("hmac 接受任意长度密钥"))
    }

    fn absorb(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn current_tag(&self) -> [u8; HMAC_SIZE] {
        let out = self.0.clone().finalize().into_bytes();
        [out[0], out[1], out[2], out[3]]
    }

    /// 试探：吸收 data 后的 tag，不改动链状态。
    fn try_tag(&self, data: &[u8]) -> [u8; HMAC_SIZE] {
        let mut c = self.0.clone();
        c.update(data);
        let out = c.finalize().into_bytes();
        [out[0], out[1], out[2], out[3]]
    }

    /// 写侧：吸收 data，产出 tag 并吸收之。
    fn seal(&mut self, data: &[u8]) -> [u8; HMAC_SIZE] {
        self.0.update(data);
        let t = self.current_tag();
        self.0.update(&t);
        t
    }

    /// 读侧：吸收 data 并校验 tag；无论成败都吸收 tag（失败即断连，链状态无后续意义）。
    fn open(&mut self, data: &[u8], tag: &[u8]) -> bool {
        let t = self.seal(data);
        t == tag
    }

    /// 服务端包装链：吸收伪装帧 payload，产出 tag 但不吸收（与客户端握手链一致）。
    fn wrap_tag(&mut self, data: &[u8]) -> [u8; HMAC_SIZE] {
        self.0.update(data);
        self.current_tag()
    }
}

/// XOR 掩码 = SHA256(password || serverRandom)。
fn xor_key(password: &[u8], server_random: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(password);
    h.update(server_random);
    h.finalize().into()
}

fn xor_in_place(key: &[u8; 32], data: &mut [u8]) {
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key[i & 31];
    }
}

/// 认证失败时回复的伪 alert 记录（与 mihomo 等长：5 + 26）。
fn alert_bytes() -> Vec<u8> {
    let mut v = Vec::with_capacity(31);
    v.extend_from_slice(&[REC_ALERT, 0x03, 0x03, 0x00, 0x1A]);
    let mut pad = [0u8; 26];
    vp_common::rand_bytes(&mut pad);
    v.extend_from_slice(&pad);
    v
}

// ---------------------------------------------------------------------------
// TLS 记录帧读取
// ---------------------------------------------------------------------------

async fn read_frame<S: AsyncRead + Unpin>(s: &mut S) -> std::io::Result<BytesMut> {
    let mut hdr = [0u8; TLS_HEADER];
    s.read_exact(&mut hdr).await?;
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "shadowtls: 帧超长",
        ));
    }
    let mut frame = BytesMut::with_capacity(TLS_HEADER + len);
    frame.put_slice(&hdr);
    frame.resize(TLS_HEADER + len, 0);
    s.read_exact(&mut frame[TLS_HEADER..]).await?;
    Ok(frame)
}

// ---------------------------------------------------------------------------
// ClientHello 构造 / 校验（session_id 藏认证）
// ---------------------------------------------------------------------------

/// 构造 Chrome 风格 TLS 1.3 ClientHello，session_id 尾 4 字节嵌入 HMAC-SHA1 认证。
/// 返回完整 TLS 记录（`16 03 01 ...`）。
pub fn build_client_hello(password: &[u8], sni: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(517);
    body.push(0x01); // ClientHello
    // 长度占位（3 字节）
    body.extend_from_slice(&[0, 0, 0]);
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    let mut rnd = [0u8; TLS_RANDOM];
    vp_common::rand_bytes(&mut rnd);
    body.extend_from_slice(&rnd);
    // session_id：28 随机 + 4 认证（先置零，构造完再回填）
    let sid_start = body.len();
    let mut sid = [0u8; TLS_SESSION_ID];
    vp_common::rand_bytes(&mut sid[..TLS_SESSION_ID - HMAC_SIZE]);
    body.push(TLS_SESSION_ID as u8);
    body.extend_from_slice(&sid);
    // cipher_suites（Chrome 常用集合，14 个）
    let suites: [u8; 28] = [
        0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xc0,
        0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a,
    ];
    body.extend_from_slice(&((suites.len() / 2) as u16).to_be_bytes());
    body.extend_from_slice(&suites);
    body.push(0x01); // compression methods: null
    body.push(0x00); // （列表长度 1）

    let mut exts: Vec<u8> = Vec::with_capacity(256);
    // server_name
    if !sni.is_empty() && !sni.parse::<std::net::IpAddr>().is_ok() {
        let name = sni.as_bytes();
        let mut e = Vec::with_capacity(name.len() + 9);
        e.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes()); // server_name_list
        e.push(0x00); // host_name
        e.extend_from_slice(&(name.len() as u16).to_be_bytes());
        e.extend_from_slice(name);
        exts.extend_from_slice(&0u16.to_be_bytes());
        exts.extend_from_slice(&(e.len() as u16).to_be_bytes());
        exts.extend_from_slice(&e);
    }
    // supported_groups: x25519 / secp256r1 / secp384r1
    let groups = [0x00u8, 0x1d, 0x00, 0x17, 0x00, 0x18];
    exts.extend_from_slice(&10u16.to_be_bytes());
    exts.extend_from_slice(&((groups.len()) as u16).to_be_bytes());
    exts.extend_from_slice(&groups);
    // ec_point_formats: uncompressed
    exts.extend_from_slice(&11u16.to_be_bytes());
    exts.extend_from_slice(&2u16.to_be_bytes());
    exts.extend_from_slice(&[0x01, 0x00]);
    // signature_algorithms
    let sigs = [
        0x04u8, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06,
        0x01, 0x02, 0x01,
    ];
    exts.extend_from_slice(&13u16.to_be_bytes());
    exts.extend_from_slice(&((sigs.len() + 2) as u16).to_be_bytes());
    exts.extend_from_slice(&(sigs.len() as u16 / 2).to_be_bytes());
    exts.extend_from_slice(&sigs);
    // supported_versions: TLS 1.3
    exts.extend_from_slice(&43u16.to_be_bytes());
    exts.extend_from_slice(&3u16.to_be_bytes());
    exts.extend_from_slice(&[0x02, 0x03, 0x04]);
    // psk_key_exchange_modes: psk_dhe_ke
    exts.extend_from_slice(&45u16.to_be_bytes());
    exts.extend_from_slice(&2u16.to_be_bytes());
    exts.extend_from_slice(&[0x01, 0x01]);
    // key_share: x25519（32 字节随机公钥占位——任意 32 字节均为合法 X25519 公钥）
    let mut kspub = [0u8; 32];
    vp_common::rand_bytes(&mut kspub);
    exts.extend_from_slice(&51u16.to_be_bytes());
    exts.extend_from_slice(&((32 + 4 + 2) as u16).to_be_bytes());
    exts.extend_from_slice(&((32 + 2) as u16).to_be_bytes()); // client_shares 长度
    exts.extend_from_slice(&[0x00, 0x1d]); // x25519
    exts.extend_from_slice(&32u16.to_be_bytes());
    exts.extend_from_slice(&kspub);

    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    // 回填 handshake 长度（body[0]=type 已写，长度 = body 总长 - 4）
    let total = body.len() - 4;
    body[1] = (total >> 16) as u8;
    body[2] = (total >> 8) as u8;
    body[3] = total as u8;

    // 认证 tag：HMAC-SHA1(password, CH body with sid 尾 4 字节置零)[0..4]
    let sid_abs = sid_start + 1; // 长度字节之后
    let hmac_idx = sid_abs + TLS_SESSION_ID - HMAC_SIZE;
    let mut mac = HmacSha1::new_from_slice(password).expect("hmac key");
    mac.update(&body[..hmac_idx]);
    mac.update(&[0u8; HMAC_SIZE]);
    mac.update(&body[hmac_idx + HMAC_SIZE..]);
    let tag = mac.finalize().into_bytes();
    body[hmac_idx..hmac_idx + HMAC_SIZE].copy_from_slice(&tag[..HMAC_SIZE]);

    let mut rec = Vec::with_capacity(body.len() + TLS_HEADER);
    rec.extend_from_slice(&[REC_HANDSHAKE, 0x03, 0x01]);
    rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
    rec.extend_from_slice(&body);
    rec
}

type HmacSha1 = Hmac<Sha1>;

/// 校验 ClientHello 的 session_id 认证（frame 含记录头）。
pub fn verify_client_hello(frame: &[u8], password: &[u8]) -> bool {
    // record 层：handshake 记录 + body[0]==ClientHello
    if frame.len() < 5 + 44 || frame[0] != REC_HANDSHAKE || frame[5] != 0x01 {
        return false;
    }
    // session_id 长度字节在 record 偏移 43
    if frame[43] != TLS_SESSION_ID as u8 {
        return false;
    }
    let hmac_idx = 5 + 4 + 2 + TLS_RANDOM + 1 + TLS_SESSION_ID - HMAC_SIZE;
    let Some(mut mac) = HmacSha1::new_from_slice(password).ok() else {
        return false;
    };
    mac.update(&frame[TLS_HEADER..hmac_idx]);
    mac.update(&[0u8; HMAC_SIZE]);
    mac.update(&frame[hmac_idx + HMAC_SIZE..]);
    let tag = mac.finalize().into_bytes();
    tag[..HMAC_SIZE] == frame[hmac_idx..hmac_idx + HMAC_SIZE]
}

/// 从 ServerHello 记录提取 (server_random, 是否 TLS1.3, 是否 HRR)。
fn extract_server_hello(frame: &[u8]) -> Option<([u8; 32], bool, bool)> {
    if frame.len() < 5 + 44 || frame[0] != REC_HANDSHAKE || frame[5] != 0x02 {
        return None;
    }
    let random: [u8; 32] = frame[11..43].try_into().ok()?;
    let hrr = random == HRR_RANDOM;
    // TLS1.3：supported_versions 扩展 == 0304（HRR 除外）
    let sid_len = frame[43] as usize;
    let mut off = 44 + sid_len;
    if frame.len() < off + 4 {
        return None;
    }
    off += 2; // cipher suite
    off += 1 + frame[off] as usize; // compression
    if frame.len() < off + 2 {
        return None;
    }
    let ext_len = u16::from_be_bytes([frame[off], frame[off + 1]]) as usize;
    off += 2;
    let ext_end = (off + ext_len).min(frame.len());
    let mut tls13 = false;
    while off + 4 <= ext_end {
        let et = u16::from_be_bytes([frame[off], frame[off + 1]]);
        let el = u16::from_be_bytes([frame[off + 2], frame[off + 3]]) as usize;
        let vstart = off + 4;
        if et == 43 && el >= 2 && ext_end >= vstart + 2 {
            tls13 = frame[vstart] == 0x03 && frame[vstart + 1] == 0x04;
        }
        off = vstart + el;
    }
    Some((random, tls13, hrr))
}

// ---------------------------------------------------------------------------
// 认证流（数据相位）
// ---------------------------------------------------------------------------

/// shadow-tls v3 认证流：读侧校验 S 链并过滤伪装残留帧，写侧封 C 链。
pub struct ShadowTlsStream<S> {
    inner: S,
    write_chain: HmacChain,
    read_chain: HmacChain,
    /// 握手相位残留的伪装帧过滤链（None = 已关闭分支）
    ignore_chain: Option<HmacChain>,
    pending: BytesMut,
    raw: BytesMut,
    out: BytesMut,
    closed: bool,
    err: Option<std::io::Error>,
}

impl<S> vp_core::ProxyStream for ShadowTlsStream<S> where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
}

impl<S> ShadowTlsStream<S> {
    #[cfg(test)]
    fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    fn data_chains(password: &[u8], server_random: &[u8]) -> (HmacChain, HmacChain) {
        let mut w = HmacChain::new(password);
        w.absorb(server_random);
        w.absorb(b"C");
        let mut r = HmacChain::new(password);
        r.absorb(server_random);
        r.absorb(b"S");
        (w, r)
    }

    /// 握手相位链（seed = serverRandom，吸收 payload 不吸收 tag）。
    fn handshake_chain(password: &[u8], server_random: &[u8]) -> HmacChain {
        let mut c = HmacChain::new(password);
        c.absorb(server_random);
        c
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> ShadowTlsStream<S> {
    /// 从 raw 提取完整帧，校验/过滤后汇入 pending。
    fn process_frames(&mut self) {
        loop {
            if self.raw.len() < TLS_HEADER {
                return;
            }
            let len = u16::from_be_bytes([self.raw[3], self.raw[4]]) as usize;
            if len > MAX_FRAME {
                self.fail("shadowtls: 帧超长");
                return;
            }
            if self.raw.len() < TLS_HEADER + len {
                return;
            }
            let mut f = self.raw.split_to(TLS_HEADER + len);
            match f[0] {
                REC_APP => {
                    if f.len() <= FRAME_HDR_HMAC {
                        self.fail("shadowtls: 认证帧过短");
                        return;
                    }
                    let tag: [u8; HMAC_SIZE] = f[5..9].try_into().unwrap();
                    let content = f.split_off(FRAME_HDR_HMAC);
                    // 伪装站残留帧：握手链校验通过则整帧跳过（不吸收 tag）
                    if let Some(ig) = self.ignore_chain.as_mut() {
                        if ig.try_tag(&content) == tag {
                            ig.absorb(&content);
                            continue;
                        }
                        self.ignore_chain = None;
                    }
                    if !self.read_chain.open(&content, &tag) {
                        self.fail("shadowtls: HMAC 校验失败");
                        return;
                    }
                    self.pending.extend_from_slice(&content);
                }
                REC_ALERT => {
                    self.fail("shadowtls: 对端 alert");
                    return;
                }
                // 数据相位不应出现 CCS/handshake；丢弃（对端实现在极端场景的尾帧）
                _ => continue,
            }
        }
    }

    fn fail(&mut self, msg: &str) {
        self.out.extend_from_slice(&alert_bytes());
        self.err = Some(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            msg.to_string(),
        ));
        self.closed = true;
    }

    fn flush_out(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while !self.out.is_empty() {
            let mut inner = Pin::new(&mut self.inner);
            match inner.as_mut().poll_write(cx, &self.out) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "shadowtls: 写入 0 字节",
                    )));
                }
                Poll::Ready(Ok(n)) => self.out.advance(n),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ShadowTlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        loop {
            if !this.pending.is_empty() {
                let n = this.pending.len().min(buf.remaining());
                buf.put_slice(&this.pending[..n]);
                this.pending.advance(n);
                return Poll::Ready(Ok(()));
            }
            if let Some(e) = this.err.take() {
                return Poll::Ready(Err(e));
            }
            if this.closed {
                return Poll::Ready(Ok(()));
            }
            this.process_frames();
            if !this.pending.is_empty() || this.closed {
                continue;
            }
            this.raw.reserve(18 * 1024);
            let spare = this.raw.spare_capacity_mut();
            let mut rb = ReadBuf::uninit(spare);
            std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
            let filled = rb.filled().len();
            if filled == 0 {
                this.closed = true;
                continue;
            }
            unsafe { this.raw.advance_mut(filled) };
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ShadowTlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if this.err.is_some() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "shadowtls: 已失效",
            )));
        }
        std::task::ready!(this.flush_out(cx))?;
        let n = buf.len().min(MAX_PLAIN);
        let tag = this.write_chain.seal(&buf[..n]);
        this.out.reserve(FRAME_HDR_HMAC + n);
        this.out.put_u8(REC_APP);
        this.out.put_u8(0x03);
        this.out.put_u8(0x03);
        this.out.put_u16((n + HMAC_SIZE) as u16);
        this.out.put_slice(&tag);
        this.out.put_slice(&buf[..n]);
        std::task::ready!(this.flush_out(cx))?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        std::task::ready!(this.flush_out(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        let _ = this.flush_out(cx);
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// 客户端握手
// ---------------------------------------------------------------------------

/// v3 客户端握手：`io` 必须是已连到 shadow-tls 服务端的裸 TCP。
/// `sni` 为伪装站域名（写入 ClientHello SNI，与对端 camouflage 配置一致）。
pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    mut io: S,
    password: &str,
    sni: &str,
) -> std::io::Result<ShadowTlsStream<S>> {
    let fut = async {
        let ch = build_client_hello(password.as_bytes(), sni);
        io.write_all(&ch).await?;
        io.flush().await?;

        let sh = read_frame(&mut io).await?;
        let (server_random, tls13, hrr) = extract_server_hello(&sh).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "shadowtls: 伪装站回包不是 ServerHello",
            )
        })?;
        if hrr {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "shadowtls: 伪装站要求 HelloRetryRequest，暂不支持",
            ));
        }
        if !tls13 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "shadowtls: 伪装站非 TLS 1.3（strict 模式要求）",
            ));
        }

        // 等待首个通过 HMAC 认证的伪装帧（授权证明）
        let mut ignore = ShadowTlsStream::<S>::handshake_chain(password.as_bytes(), &server_random);
        loop {
            let f = read_frame(&mut io).await?;
            match f[0] {
                REC_HANDSHAKE | REC_CCS => continue,
                REC_ALERT => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "shadowtls: 握手期收到 alert（traffic hijacked）",
                    ));
                }
                REC_APP => {
                    if f.len() <= FRAME_HDR_HMAC {
                        continue; // 空载帧（非伪装包装帧），跳过
                    }
                    let tag: [u8; HMAC_SIZE] = f[5..9].try_into().unwrap();
                    let content = &f[FRAME_HDR_HMAC..];
                    if ignore.try_tag(content) == tag {
                        ignore.absorb(content);
                        break; // authorized
                    }
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "shadowtls: 伪装帧 HMAC 校验失败（对端非 shadow-tls v3 服务端）",
                    ));
                }
                _ => continue,
            }
        }

        let (write_chain, read_chain) =
            ShadowTlsStream::<S>::data_chains(password.as_bytes(), &server_random);
        Ok(ShadowTlsStream {
            inner: io,
            write_chain,
            read_chain,
            ignore_chain: Some(ignore),
            pending: BytesMut::new(),
            raw: BytesMut::new(),
            out: BytesMut::new(),
            closed: false,
            err: None,
        })
    };
    tokio::time::timeout(HANDSHAKE_TIMEOUT, fut)
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "shadowtls: 客户端握手超时")
        })?
}

// ---------------------------------------------------------------------------
// 服务端握手
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ServerHandshakeError {
    /// 未认证/异常连接：已作为普通 TLS 流量转发伪装站并排水完毕。
    Fallback,
    Io(std::io::Error),
}

impl std::fmt::Display for ServerHandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerHandshakeError::Fallback => write!(f, "shadowtls: 未认证连接已回退伪装站"),
            ServerHandshakeError::Io(e) => write!(f, "shadowtls 服务端握手失败: {e}"),
        }
    }
}

/// 未认证流量回退：把 `prefix` 发往伪装站后双向排水（反主动探测）。
async fn fallback_relay(client: TcpStream, cam: TcpStream, prefix: Vec<u8>) {
    let (mut cr, mut cw) = cam.into_split();
    if !prefix.is_empty() {
        let _ = cw.write_all(&prefix).await;
    }
    let (mut xr, mut xw) = client.into_split();
    let a = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut xr, &mut cw).await;
    });
    let _ = tokio::io::copy(&mut cr, &mut xw).await;
    let _ = a.await;
}

/// v3 服务端握手。返回认证后的数据流（首帧 payload 已在 pending 中）。
pub async fn server_handshake(
    client: TcpStream,
    password: &str,
    cam_host: &str,
    cam_port: u16,
) -> Result<ShadowTlsStream<TcpStream>, ServerHandshakeError> {
    let pw = password.as_bytes();
    let inner = async {
        let mut client = client;
        let ch = read_frame(&mut client)
            .await
            .map_err(ServerHandshakeError::Io)?;
        let authed = verify_client_hello(&ch, pw);
        let mut cam = TcpStream::connect((cam_host, cam_port))
            .await
            .map_err(ServerHandshakeError::Io)?;
        vp_transport::tune(&cam);
        if !authed {
            tokio::spawn(fallback_relay(client, cam, ch.to_vec()));
            return Err(ServerHandshakeError::Fallback);
        }
        cam.write_all(&ch).await.map_err(ServerHandshakeError::Io)?;

        // 读伪装站 ServerHello 并原样转发客户端
        let sh = match read_frame(&mut cam).await {
            Ok(sh) => sh,
            Err(e) => {
                tokio::spawn(fallback_relay(client, cam, Vec::new()));
                return Err(ServerHandshakeError::Io(e));
            }
        };
        client
            .write_all(&sh)
            .await
            .map_err(ServerHandshakeError::Io)?;
        let (server_random, tls13, hrr) = match extract_server_hello(&sh) {
            Some(v) => v,
            None => {
                tokio::spawn(fallback_relay(client, cam, Vec::new()));
                return Err(ServerHandshakeError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "伪装站回包不是 ServerHello",
                )));
            }
        };
        if hrr || !tls13 {
            tokio::spawn(fallback_relay(client, cam, Vec::new()));
            return Err(ServerHandshakeError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "伪装站非 TLS 1.3",
            )));
        }

        // 伪装站 → 客户端：appdata 加 XOR 掩码与 HMAC 前缀（任务 A）
        let (cam_r, cam_w) = cam.into_split();
        let (client_r, mut client_w) = client.into_split();
        let mut wrap = ShadowTlsStream::<TcpStream>::handshake_chain(pw, &server_random);
        let xk = xor_key(pw, &server_random);
        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        let task_a = tokio::spawn(async move {
            let mut cam_r = cam_r;
            loop {
                let f = tokio::select! {
                    f = read_frame(&mut cam_r) => match f {
                        Ok(f) => f,
                        Err(_) => break,
                    },
                    _ = stop_rx.changed() => break,
                };
                let mut f = f;
                if f[0] == REC_APP {
                    let payload = &mut f[TLS_HEADER..];
                    xor_in_place(&xk, payload);
                    let tag = wrap.wrap_tag(payload);
                    let n = payload.len();
                    let mut frame = Vec::with_capacity(FRAME_HDR_HMAC + n);
                    frame.extend_from_slice(&[REC_APP, 0x03, 0x03]);
                    frame.extend_from_slice(&((n + HMAC_SIZE) as u16).to_be_bytes());
                    frame.extend_from_slice(&tag);
                    frame.extend_from_slice(&f[TLS_HEADER..]);
                    if client_w.write_all(&frame).await.is_err() {
                        break;
                    }
                } else if client_w.write_all(&f).await.is_err() {
                    break;
                }
            }
            client_w
        });

        // 客户端 → 伪装站：原样转发，直至首个 C 链认证帧（劫持）
        let mut c_chain = ShadowTlsStream::<TcpStream>::handshake_chain(pw, &server_random);
        c_chain.absorb(b"C");
        let mut cam_w = cam_w;
        let mut client_r = client_r;
        let mut leftover = BytesMut::new();
        let hijacked = loop {
            let f = match read_frame(&mut client_r).await {
                Ok(f) => f,
                Err(e) => {
                    let _ = stop_tx.send(true);
                    let _ = task_a.await;
                    return Err(ServerHandshakeError::Io(e));
                }
            };
            if f[0] == REC_APP && f.len() > FRAME_HDR_HMAC {
                let tag: [u8; HMAC_SIZE] = f[5..9].try_into().unwrap();
                let content = &f[FRAME_HDR_HMAC..];
                if c_chain.try_tag(content) == tag {
                    c_chain.absorb(content);
                    c_chain.absorb(&tag);
                    leftover.extend_from_slice(content);
                    break true;
                }
            }
            if cam_w.write_all(&f).await.is_err() {
                break false;
            }
        };
        let _ = stop_tx.send(true);
        let client_w = task_a
            .await
            .map_err(|e| ServerHandshakeError::Io(std::io::Error::other(format!("{e}"))))?;
        drop(cam_w);
        if !hijacked {
            return Err(ServerHandshakeError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "伪装站连接中断",
            )));
        }

        let client = client_r
            .reunite(client_w)
            .map_err(|_| ServerHandshakeError::Io(std::io::Error::other("reunite 失败")))?;
        let mut s_chain = ShadowTlsStream::<TcpStream>::handshake_chain(pw, &server_random);
        s_chain.absorb(b"S");
        Ok(ShadowTlsStream {
            inner: client,
            write_chain: s_chain,
            read_chain: c_chain,
            ignore_chain: None,
            pending: leftover,
            raw: BytesMut::new(),
            out: BytesMut::new(),
            closed: false,
            err: None,
        })
    };
    tokio::time::timeout(HANDSHAKE_TIMEOUT, inner)
        .await
        .map_err(|_| {
            ServerHandshakeError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "shadowtls: 服务端握手超时",
            ))
        })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const PW: &str = "stls-pass";

    /// 构造 canned TLS1.3 ServerHello 记录（supported_versions = 0304）。
    fn fake_server_hello() -> Vec<u8> {
        let mut rnd = [0u8; 32];
        vp_common::rand_bytes(&mut rnd);
        let mut body = Vec::with_capacity(90);
        body.extend_from_slice(&[0x02]); // ServerHello
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&rnd);
        body.push(32);
        body.extend_from_slice(&[0x42u8; 32]); // session id echo
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0x01);
        body.push(0x00); // compression: null
        // ext: supported_versions
        let mut exts = Vec::new();
        exts.extend_from_slice(&43u16.to_be_bytes());
        exts.extend_from_slice(&2u16.to_be_bytes());
        exts.extend_from_slice(&[0x03, 0x04]);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut msg = vec![0x02];
        let l = body.len() - 1;
        msg.extend_from_slice(&((l as u32) << 8).to_be_bytes()[1..]);
        msg.extend_from_slice(&body[1..]);
        let mut rec = vec![0x16, 0x03, 0x03];
        rec.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        rec.extend_from_slice(&msg);
        rec
    }

    fn fake_appdata(payload: &[u8]) -> Vec<u8> {
        let mut rec = vec![0x17, 0x03, 0x03];
        rec.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        rec.extend_from_slice(payload);
        rec
    }

    /// 伪装站 stub：读 ClientHello，回 ServerHello + N 帧伪 appdata，随后挂起。
    async fn spawn_camouflage(n_appdata: usize) -> (String, u16) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut hdr = [0u8; 5];
            s.read_exact(&mut hdr).await.unwrap();
            let mut ch = vec![0u8; u16::from_be_bytes([hdr[3], hdr[4]]) as usize];
            s.read_exact(&mut ch).await.unwrap();
            s.write_all(&fake_server_hello()).await.unwrap();
            for i in 0..n_appdata {
                let payload = format!("camouflage-flight-{i}");
                s.write_all(&fake_appdata(payload.as_bytes()))
                    .await
                    .unwrap();
            }
            // 保持连接（不关闭），等待对端关闭
            let mut b = [0u8; 64];
            let _ = s.read(&mut b).await;
        });
        ("127.0.0.1".into(), addr.port())
    }

    #[test]
    fn client_hello_auth_roundtrip() {
        let ch = build_client_hello(PW.as_bytes(), "www.apple.com");
        assert!(verify_client_hello(&ch, PW.as_bytes()));
        assert!(!verify_client_hello(&ch, b"wrong-pass"));
        // ClientHello 应携带 SNI
        let sni = b"www.apple.com";
        assert!(
            ch.windows(sni.len()).any(|w| w == sni),
            "ClientHello 缺少 SNI"
        );
    }

    #[tokio::test]
    async fn e2e_data_phase() {
        let (cam_host, cam_port) = spawn_camouflage(2).await; // 2 帧：1 授权 + 1 残留（ignore 链过滤）
        // shadow-tls 服务端
        let srv = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = srv.local_addr().unwrap();
        tokio::spawn(async move {
            let (s, _) = srv.accept().await.unwrap();
            let st = server_handshake(s, PW, &cam_host, cam_port).await.unwrap();
            // echo
            let mut st = st;
            let mut b = [0u8; 8192];
            loop {
                let n = st.read(&mut b).await.unwrap();
                if n == 0 {
                    break;
                }
                st.write_all(&b[..n]).await.unwrap();
            }
        });

        let c = TcpStream::connect(srv_addr).await.unwrap();
        let mut cl = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client_handshake(c, PW, "cam.example"),
        )
        .await
        .unwrap()
        .unwrap();

        // 小数据往返
        cl.write_all(b"hello-shadowtls").await.unwrap();
        let mut buf = [0u8; 15];
        cl.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello-shadowtls");

        // 大数据往返（跨 16384 分块），同时验证残留伪装帧不混入
        let big: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        let big_len = big.len();
        let mut echo = Vec::with_capacity(big_len);
        let writer_big = big.clone();
        let (mut r, mut w) = tokio::io::split(cl);
        let writer = tokio::spawn(async move {
            w.write_all(&writer_big).await.unwrap();
            w.flush().await.unwrap();
        });
        let mut got = 0;
        while got < big_len {
            let n = r.read(&mut buf).await.unwrap();
            assert!(n > 0, "echo 中断于 {got}");
            echo.extend_from_slice(&buf[..n]);
            got += n;
        }
        writer.await.unwrap();
        assert_eq!(echo, big, "大数据回显应逐字节一致");
    }

    #[tokio::test]
    async fn unauthenticated_falls_back_to_camouflage() {
        let (cam_host, cam_port) = spawn_camouflage(1).await;
        let srv = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = srv.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (s, _) = srv.accept().await.unwrap();
            server_handshake(s, PW, &cam_host, cam_port).await
        });

        // 客户端用错误密码构造 ClientHello → 服务端应回退伪装站
        let mut c = TcpStream::connect(srv_addr).await.unwrap();
        let ch = build_client_hello(b"wrong-pass", "cam.example");
        c.write_all(&ch).await.unwrap();

        let res = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(res, Err(ServerHandshakeError::Fallback)));
    }

    #[tokio::test]
    async fn hmac_tamper_detected() {
        let (cam_host, cam_port) = spawn_camouflage(1).await;
        let srv = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = srv.local_addr().unwrap();
        tokio::spawn(async move {
            let (s, _) = srv.accept().await.unwrap();
            if let Ok(mut st) = server_handshake(s, PW, &cam_host, cam_port).await {
                // 读客户端数据后篡改内容再回写（破坏 S 链）
                let mut b = [0u8; 128];
                let _ = st.read(&mut b).await;
                let mut tampered = b"tampered!!".to_vec();
                tampered[0] ^= 0xFF; // 直接写裸字节绕过 seal（模拟链失效）
                use tokio::io::AsyncWriteExt;
                let _ = st.inner_mut().write_all(&fake_appdata(&tampered)).await;
            }
        });
        let c = TcpStream::connect(srv_addr).await.unwrap();
        let mut cl = client_handshake(c, PW, "cam.example").await.unwrap();
        cl.write_all(b"ping").await.unwrap();
        let mut b = [0u8; 64];
        let r = cl.read(&mut b).await;
        assert!(
            r.is_err() || matches!(r, Ok(0)),
            "篡改帧应触发校验失败/关闭"
        );
    }
}

//! VMess（AEAD 认证头 + AEAD/明文分块 body）出入站。
//! 字节格式对齐 v2fly/Xray：port-then-address、atyp 1/2/3、fnv1a 尾校验。

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tracing::warn;

use vp_common::{DstAddr, Error, Host, Result};
use vp_config::VmessCfg;
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;
use vp_core::tunnel::{RelayHook, relay};
use vp_core::{Inbound, Outbound, ProxyStream};
use vp_crypto::vmess_kdf as kdf;
use vp_crypto::{AeadKind, AnyAead};

use crate::direct::DirectOutbound;
use vp_dns::Resolver;
use vp_transport as transport;

pub const OPT_CHUNK_STREAM: u8 = 0x01;
/// 主流客户端（v2ray/sing-vmess/mihomo）对分块流一律启用长度掩码；
/// 服务端按掩码长度分帧，客户端发裸长度会被误分帧导致上游收到畸形数据。
pub const OPT_CHUNK_MASKING: u8 = 0x04;
pub const SEC_AES128_GCM: u8 = 0x03;
pub const SEC_CHACHA20: u8 = 0x04;
pub const SEC_NONE: u8 = 0x05;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    Aes128Gcm,
    ChaCha20,
    None,
}

impl Security {
    fn from_cipher(s: &str) -> Result<Security> {
        match s {
            "auto" | "aes-128-gcm" | "aes-128-gcm-cfb" => Ok(Security::Aes128Gcm),
            "chacha20-poly1305" => Ok(Security::ChaCha20),
            "none" | "zero" => Ok(Security::None),
            other => Err(Error::Config(format!("vmess 加密 {other:?} 不支持"))),
        }
    }

    fn byte(self) -> u8 {
        match self {
            Security::Aes128Gcm => SEC_AES128_GCM,
            Security::ChaCha20 => SEC_CHACHA20,
            Security::None => SEC_NONE,
        }
    }
}

fn body_aead(security: Security, body_key: &[u8; 16]) -> Result<AnyAead> {
    match security {
        Security::Aes128Gcm => AnyAead::new(AeadKind::Aes128Gcm, body_key),
        Security::ChaCha20 => {
            let k = kdf::generate_chacha20_key(body_key);
            AnyAead::new(AeadKind::ChaCha20Poly1305, &k)
        }
        Security::None => Err(Error::Unsupported("none 无 AEAD".into())),
    }
}

// ---------------------------------------------------------------------------
// 地址编解码（port 2B → atyp → addr；atyp 1/2/3）
// ---------------------------------------------------------------------------

fn encode_v2ray_addr(dst: &DstAddr, out: &mut Vec<u8>) {
    out.extend_from_slice(&dst.port.to_be_bytes());
    match &dst.host {
        Host::Ip(std::net::IpAddr::V4(v4)) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        Host::Ip(std::net::IpAddr::V6(v6)) => {
            out.push(0x03);
            out.extend_from_slice(&v6.octets());
        }
        Host::Domain(d) => {
            out.push(0x02);
            out.push(d.len() as u8);
            out.extend_from_slice(d.as_bytes());
        }
    }
}

fn decode_v2ray_addr(buf: &[u8]) -> Result<(DstAddr, usize)> {
    if buf.len() < 3 {
        return Err(Error::Proto("vmess 地址截断"));
    }
    let port = u16::from_be_bytes([buf[0], buf[1]]);
    let atyp = buf[2];
    let (host, used) = match atyp {
        0x01 => {
            if buf.len() < 7 {
                return Err(Error::Proto("vmess 地址截断"));
            }
            (
                Host::Ip(std::net::IpAddr::V4(
                    [buf[3], buf[4], buf[5], buf[6]].into(),
                )),
                7,
            )
        }
        0x02 => {
            if buf.len() < 4 {
                return Err(Error::Proto("vmess 地址截断"));
            }
            let n = buf[3] as usize;
            if buf.len() < 4 + n {
                return Err(Error::Proto("vmess 地址截断"));
            }
            let d = std::str::from_utf8(&buf[4..4 + n])
                .map_err(|_| Error::Proto("域名非 utf-8"))?
                .to_ascii_lowercase();
            (Host::Domain(d), 4 + n)
        }
        0x03 => {
            if buf.len() < 19 {
                return Err(Error::Proto("vmess 地址截断"));
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[3..19]);
            (Host::Ip(std::net::IpAddr::V6(o.into())), 19)
        }
        _ => return Err(Error::Proto("vmess atyp 非法")),
    };
    Ok((DstAddr { host, port }, used))
}

// ---------------------------------------------------------------------------
// 请求头构造/解析
// ---------------------------------------------------------------------------

pub struct VmessRequest {
    pub body_key: [u8; 16],
    pub body_iv: [u8; 16],
    pub resp_auth: u8,
    pub security: Security,
    pub cmd: u8,
    pub dst: DstAddr,
    /// 客户端请求头里的 Option 位（是否启用 chunk 长度掩码等）
    pub option: u8,
}

fn build_request_plaintext(r: &VmessRequest) -> Vec<u8> {
    let mut p = Vec::with_capacity(64);
    p.push(0x01); // version
    p.extend_from_slice(&r.body_iv);
    p.extend_from_slice(&r.body_key);
    p.push(r.resp_auth);
    p.push(OPT_CHUNK_STREAM | OPT_CHUNK_MASKING);
    p.push(r.security.byte()); // (0 << 4) | security
    p.push(0); // reserved
    p.push(r.cmd);
    encode_v2ray_addr(&r.dst, &mut p);
    let fnv = kdf::fnv1a32(&p).to_be_bytes();
    p.extend_from_slice(&fnv);
    p
}

fn parse_request_plaintext(p: &[u8]) -> Result<VmessRequest> {
    if p.len() < 41 {
        return Err(Error::Proto("vmess 请求头过短"));
    }
    // 尾部 fnv 校验
    let (body, fnv_bytes) = p.split_at(p.len() - 4);
    let expect = kdf::fnv1a32(body).to_be_bytes();
    if fnv_bytes != expect {
        return Err(Error::Proto("vmess 请求头 fnv 校验失败"));
    }
    let mut i = 0usize;
    if body[i] != 0x01 {
        return Err(Error::Proto("vmess 版本不支持"));
    }
    i += 1;
    let mut body_iv = [0u8; 16];
    body_iv.copy_from_slice(&body[i..i + 16]);
    i += 16;
    let mut body_key = [0u8; 16];
    body_key.copy_from_slice(&body[i..i + 16]);
    i += 16;
    let resp_auth = body[i];
    i += 1;
    let option = body[i];
    i += 1;
    let security = match body[i] & 0x0f {
        SEC_AES128_GCM => Security::Aes128Gcm,
        SEC_CHACHA20 => Security::ChaCha20,
        SEC_NONE => Security::None,
        _ => return Err(Error::Proto("vmess security 不支持")),
    };
    i += 1;
    i += 1; // reserved
    let cmd = body[i];
    i += 1;
    let (dst, used) = decode_v2ray_addr(&body[i..])?;
    i += used;
    if i != body.len() {
        return Err(Error::Proto("vmess 请求头长度异常"));
    }
    Ok(VmessRequest {
        body_key,
        body_iv,
        resp_auth,
        security,
        cmd,
        dst,
        option,
    })
}

/// 密封 AEAD 认证头：authID(16) + lenCT(18) + nonce(8) + payloadCT
fn seal_header(cmd_key: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let auth_id = kdf::create_auth_id(cmd_key, now);
    let mut nonce8 = [0u8; 8];
    vp_common::rand_bytes(&mut nonce8);
    let len_key = kdf::kdf16(
        cmd_key,
        &[kdf::SALT_HEADER_LEN_KEY.as_bytes(), &auth_id, &nonce8],
    );
    let len_nonce = kdf::kdf_x(
        cmd_key,
        &[kdf::SALT_HEADER_LEN_IV.as_bytes(), &auth_id, &nonce8],
        12,
    );
    let mut len_nonce12 = [0u8; 12];
    len_nonce12.copy_from_slice(&len_nonce);
    let len_aead = AnyAead::new(AeadKind::Aes128Gcm, &len_key)?;
    let len_ct = len_aead.seal_nonce(
        &len_nonce12,
        &(plaintext.len() as u16).to_be_bytes(),
        &auth_id,
    );

    let pay_key = kdf::kdf16(
        cmd_key,
        &[kdf::SALT_HEADER_KEY.as_bytes(), &auth_id, &nonce8],
    );
    let pay_nonce = kdf::kdf_x(
        cmd_key,
        &[kdf::SALT_HEADER_IV.as_bytes(), &auth_id, &nonce8],
        12,
    );
    let mut pay_nonce12 = [0u8; 12];
    pay_nonce12.copy_from_slice(&pay_nonce);
    let pay_aead = AnyAead::new(AeadKind::Aes128Gcm, &pay_key)?;
    let pay_ct = pay_aead.seal_nonce(&pay_nonce12, plaintext, &auth_id);

    let mut out = Vec::with_capacity(16 + 18 + 8 + pay_ct.len());
    out.extend_from_slice(&auth_id);
    out.extend_from_slice(&len_ct);
    out.extend_from_slice(&nonce8);
    out.extend_from_slice(&pay_ct);
    Ok(out)
}

/// legacy（alterId>0）认证头：HMAC-MD5(alterKey, ts) ‖ AES-128-CFB(Key(uuid), MD5(ts×4)) 指令块
fn seal_header_legacy(uuid: &[u8; 16], ts: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
    use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
    let alter_key = kdf::uuid_alter_key(uuid);
    let auth = kdf::legacy_auth_id(&alter_key, ts);
    let key = kdf::legacy_req_key(uuid);
    let iv = kdf::legacy_req_iv(ts);
    let cfb = cfb_mode::Encryptor::<aes::Aes128>::new(&key.into(), &iv.into());
    let mut ct = plaintext.to_vec();
    cfb.encrypt(&mut ct);
    let mut out = Vec::with_capacity(16 + ct.len());
    out.extend_from_slice(&auth);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// 开启 AEAD 认证头（服务端）：输入为去掉 authID 后的剩余字节流读取函数
async fn open_header<S: AsyncRead + Unpin>(
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    io: &mut S,
) -> Result<Vec<u8>> {
    let mut len_ct = [0u8; 18];
    io.read_exact(&mut len_ct).await?;
    let mut nonce8 = [0u8; 8];
    io.read_exact(&mut nonce8).await?;
    let len_key = kdf::kdf16(
        cmd_key,
        &[kdf::SALT_HEADER_LEN_KEY.as_bytes(), auth_id, &nonce8],
    );
    let len_nonce = kdf::kdf_x(
        cmd_key,
        &[kdf::SALT_HEADER_LEN_IV.as_bytes(), auth_id, &nonce8],
        12,
    );
    let mut n12 = [0u8; 12];
    n12.copy_from_slice(&len_nonce);
    let len_aead = AnyAead::new(AeadKind::Aes128Gcm, &len_key)?;
    let len_pt = len_aead
        .open_nonce(&n12, &len_ct, auth_id)
        .map_err(|_| Error::Proto("vmess 头长度块解密失败"))?;
    if len_pt.len() != 2 {
        return Err(Error::Proto("vmess 头长度非法"));
    }
    let plen = u16::from_be_bytes([len_pt[0], len_pt[1]]) as usize;
    let mut pay_ct = vec![0u8; plen + 16];
    io.read_exact(&mut pay_ct).await?;
    let pay_key = kdf::kdf16(
        cmd_key,
        &[kdf::SALT_HEADER_KEY.as_bytes(), auth_id, &nonce8],
    );
    let pay_nonce = kdf::kdf_x(
        cmd_key,
        &[kdf::SALT_HEADER_IV.as_bytes(), auth_id, &nonce8],
        12,
    );
    let mut pn12 = [0u8; 12];
    pn12.copy_from_slice(&pay_nonce);
    let pay_aead = AnyAead::new(AeadKind::Aes128Gcm, &pay_key)?;
    pay_aead
        .open_nonce(&pn12, &pay_ct, auth_id)
        .map_err(|_| Error::Proto("vmess 头解密失败"))
}

// ---------------------------------------------------------------------------
// 响应头（服务端发送 / 客户端读取）
// ---------------------------------------------------------------------------

/// 响应方向派生（对齐 xray/sing-vmess）：各自独立 sha256(requestBodyKey/IV)[:16]
fn resp_keys(body_key: &[u8; 16], body_iv: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    (kdf::sha256_16(body_key), kdf::sha256_16(body_iv))
}

fn build_response_header(
    resp_auth: u8,
    resp_key: &[u8; 16],
    resp_iv: &[u8; 16],
    option: u8,
) -> Result<Vec<u8>> {
    let payload = [resp_auth, option];
    let len_key = kdf::kdf16(resp_key, &[kdf::SALT_RESP_LEN_KEY.as_bytes()]);
    let len_nonce = kdf::kdf_x(resp_iv, &[kdf::SALT_RESP_LEN_IV.as_bytes()], 12);
    let mut n12 = [0u8; 12];
    n12.copy_from_slice(&len_nonce);
    let aead = AnyAead::new(AeadKind::Aes128Gcm, &len_key)?;
    let len_ct = aead.seal_nonce(&n12, &2u16.to_be_bytes(), b"");
    let pay_key = kdf::kdf16(resp_key, &[kdf::SALT_RESP_KEY.as_bytes()]);
    let pay_nonce = kdf::kdf_x(resp_iv, &[kdf::SALT_RESP_IV.as_bytes()], 12);
    let mut pn12 = [0u8; 12];
    pn12.copy_from_slice(&pay_nonce);
    let pay_aead = AnyAead::new(AeadKind::Aes128Gcm, &pay_key)?;
    let pay_ct = pay_aead.seal_nonce(&pn12, &payload, b"");
    let mut out = Vec::with_capacity(18 + 18);
    out.extend_from_slice(&len_ct);
    out.extend_from_slice(&pay_ct);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Body 流（AEAD 分块或明文+fnv 分块）
// ---------------------------------------------------------------------------

/// v2ray/sing-vmess 对齐的 chunk 长度掩码：SHAKE128(seed) 顺序每次取 2 字节 BE。
/// 请求方向 seed = body_iv，响应方向 seed = 派生的 resp_iv。
struct SizeMask {
    xof: sha3::Shake128Reader,
}

impl SizeMask {
    fn new(seed: &[u8]) -> Self {
        use sha3::digest::{ExtendableOutput, Update};
        let mut h = sha3::Shake128::default();
        h.update(seed);
        Self {
            xof: h.finalize_xof(),
        }
    }

    fn next_u16(&mut self) -> u16 {
        let mut b = [0u8; 2];
        use sha3::digest::XofReader;
        self.xof.read(&mut b);
        u16::from_be_bytes(b)
    }
}

/// xray/sing-vmess 对齐的 body 分块编解码：
/// chunk = [2B BE 掩码后的 ct 长度][AEAD(payload) ct+tag]
/// GCM nonce = [u16 chunk 序号 BE][IV[2..12]]（GenerateChunkNonce）
struct VmessBodyCodec {
    aead: AnyAead,
    base: [u8; 10],
    idx: u16,
    mask: Option<SizeMask>,
    expected_ct_len: Option<usize>,
}

impl VmessBodyCodec {
    fn new(security: Security, key16: &[u8; 16], iv16: &[u8; 16], masked: bool) -> Result<Self> {
        let mut base = [0u8; 10];
        base.copy_from_slice(&iv16[2..12]);
        Ok(VmessBodyCodec {
            aead: body_aead(security, key16)?,
            base,
            idx: 0,
            mask: masked.then(|| SizeMask::new(iv16)),
            expected_ct_len: None,
        })
    }

    fn nonce(&self, idx: u16) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..2].copy_from_slice(&idx.to_be_bytes());
        n[2..].copy_from_slice(&self.base);
        n
    }

    fn seal_chunk(&mut self, payload: &[u8]) -> Vec<u8> {
        let idx = self.idx;
        self.idx = self.idx.wrapping_add(1);
        let ct = self.aead.seal_nonce(&self.nonce(idx), payload, b"");
        // 线上 chunk = [2B 长度^掩码][ct]，长度值 = ct 长度（payload+tag）
        let mut len_field = ct.len() as u16;
        if let Some(m) = self.mask.as_mut() {
            len_field ^= m.next_u16();
        }
        let mut out = Vec::with_capacity(ct.len() + 2);
        out.extend_from_slice(&len_field.to_be_bytes());
        out.extend_from_slice(&ct);
        out
    }

    /// 尝试从 buf 解出一条 payload；数据不足返回 None。
    /// 必须缓存已解出的分块长度，不能在分片到达时反复消费 SizeMask XOF 流，
    /// 否则会导致掩码失步与后续所有分块解密失败。
    fn try_open_chunk(&mut self, buf: &[u8]) -> Option<Result<(Vec<u8>, usize)>> {
        let ct_len = match self.expected_ct_len {
            Some(len) => len,
            None => {
                if buf.len() < 2 {
                    return None;
                }
                let mut ct_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                if let Some(m) = self.mask.as_mut() {
                    ct_len ^= m.next_u16() as usize;
                }
                self.expected_ct_len = Some(ct_len);
                ct_len
            }
        };
        let total = 2 + ct_len;
        if buf.len() < total {
            return None;
        }
        self.expected_ct_len = None;
        if ct_len < 16 {
            return Some(Err(Error::Proto("vmess 分块长度小于 AEAD 标签")));
        }
        let idx = self.idx;
        let data = match self.aead.open_nonce(&self.nonce(idx), &buf[2..total], b"") {
            Ok(p) => p,
            Err(e) => return Some(Err(e)),
        };
        self.idx = self.idx.wrapping_add(1);
        Some(Ok((data, total)))
    }
}

enum BodyCodec {
    Aead(VmessBodyCodec),
    Plain(PlainCodec),
}

impl BodyCodec {
    fn new(security: Security, key16: &[u8; 16], iv16: &[u8; 16], masked: bool) -> Result<Self> {
        Ok(match security {
            Security::Aes128Gcm | Security::ChaCha20 => {
                BodyCodec::Aead(VmessBodyCodec::new(security, key16, iv16, masked)?)
            }
            Security::None => BodyCodec::Plain(PlainCodec::new(iv16, masked)),
        })
    }

    fn seal_chunk(&mut self, payload: &[u8]) -> Vec<u8> {
        match self {
            BodyCodec::Aead(c) => c.seal_chunk(payload),
            BodyCodec::Plain(c) => c.seal_chunk(payload),
        }
    }

    fn try_open_chunk(&mut self, buf: &[u8]) -> Option<Result<(Vec<u8>, usize)>> {
        match self {
            BodyCodec::Aead(c) => c.try_open_chunk(buf),
            BodyCodec::Plain(c) => c.try_open_chunk(buf),
        }
    }
}

/// Security::None 的明文分块：chunk = [2B 掩码后长度][fnv32][payload]
struct PlainCodec {
    mask: Option<SizeMask>,
    expected_plen: Option<usize>,
}

impl PlainCodec {
    fn new(iv16: &[u8; 16], masked: bool) -> Self {
        PlainCodec {
            mask: masked.then(|| SizeMask::new(iv16)),
            expected_plen: None,
        }
    }

    fn seal_chunk(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut len_field = payload.len() as u16;
        if let Some(m) = self.mask.as_mut() {
            len_field ^= m.next_u16();
        }
        let mut out = Vec::with_capacity(6 + payload.len());
        out.extend_from_slice(&len_field.to_be_bytes());
        out.extend_from_slice(&kdf::fnv1a32(payload).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn try_open_chunk(&mut self, buf: &[u8]) -> Option<Result<(Vec<u8>, usize)>> {
        let plen = match self.expected_plen {
            Some(len) => len,
            None => {
                if buf.len() < 2 {
                    return None;
                }
                let mut plen = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                if let Some(m) = self.mask.as_mut() {
                    plen ^= m.next_u16() as usize;
                }
                self.expected_plen = Some(plen);
                plen
            }
        };
        let total = 2 + 4 + plen;
        if buf.len() < total {
            return None;
        }
        self.expected_plen = None;
        let fnv = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
        let payload = &buf[6..total];
        if kdf::fnv1a32(payload) != fnv {
            return Some(Err(Error::Proto("vmess 明文块 fnv 校验失败")));
        }
        Some(Ok((payload.to_vec(), total)))
    }
}

pub struct VmessStream<S> {
    inner: S,
    enc: BodyCodec,
    dec: BodyCodec,
    raw: BytesMut,
    pending: BytesMut,
    out: BytesMut,
    closed: bool,
    /// 懒读响应头：xray 服务端把响应头缓冲到首个 body 块才 flush，
    /// 客户端必须先发数据再解析响应（对齐 sing-vmess clientConn.Read）
    resp_header: Option<RespHeader>,
}

impl<S> vp_core::ProxyStream for VmessStream<S> where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static
{
}

enum RespState {
    AeadReadLen(BytesMut),
    AeadReadPayload { plen: usize, buf: BytesMut },
    LegacyReadHead(BytesMut),
    LegacySkipCmd { n: usize },
    Done,
}

struct RespHeader {
    auth_expect: u8,
    key: [u8; 16],
    iv: Vec<u8>,
    state: RespState,
}

impl RespHeader {
    fn new(auth_expect: u8, key: [u8; 16], iv: Vec<u8>, legacy: bool) -> Self {
        let state = if legacy {
            RespState::LegacyReadHead(BytesMut::with_capacity(4))
        } else {
            RespState::AeadReadLen(BytesMut::with_capacity(18))
        };
        RespHeader {
            auth_expect,
            key,
            iv,
            state,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> VmessStream<S> {
    fn flush_out(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while !self.out.is_empty() {
            let mut inner = Pin::new(&mut self.inner);
            match inner.as_mut().poll_write(cx, &self.out) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "vmess: 写入 0 字节",
                    )));
                }
                Poll::Ready(Ok(n)) => self.out.advance(n),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn try_progress(&mut self) {
        while let Some(r) = self.dec.try_open_chunk(&self.raw) {
            match r {
                Ok((payload, used)) => {
                    self.raw.advance(used);
                    self.pending.extend_from_slice(&payload);
                }
                Err(_) => {
                    self.closed = true;
                    break;
                }
            }
        }
    }

    /// 首次 poll_read 时解析响应头（懒，显式状态机）
    fn poll_resp_header<S2: AsyncRead + Unpin>(
        slot: &mut Option<RespHeader>,
        io: &mut S2,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let Some(h) = slot.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        loop {
            match &mut h.state {
                RespState::AeadReadLen(buf) => {
                    while buf.len() < 18 {
                        let mut tmp = [0u8; 18];
                        let mut read = ReadBuf::new(&mut tmp);
                        match Pin::new(&mut *io).poll_read(cx, &mut read) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Ready(Ok(())) if read.filled().is_empty() => {
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "vmess: 响应头 EOF",
                                )));
                            }
                            Poll::Ready(Ok(())) => buf.extend_from_slice(read.filled()),
                        }
                    }
                    let len_key = kdf::kdf16(&h.key, &[kdf::SALT_RESP_LEN_KEY.as_bytes()]);
                    let len_nonce = kdf::kdf_x(&h.iv, &[kdf::SALT_RESP_LEN_IV.as_bytes()], 12);
                    let mut n12 = [0u8; 12];
                    n12.copy_from_slice(&len_nonce);
                    let aead = match AnyAead::new(AeadKind::Aes128Gcm, &len_key) {
                        Ok(a) => a,
                        Err(e) => return Poll::Ready(Err(std::io::Error::other(e))),
                    };
                    let pt = match aead.open_nonce(&n12, buf, b"") {
                        Ok(p) => p,
                        Err(_e) => {
                            return Poll::Ready(Err(std::io::Error::other(
                                Error::Proto("vmess 响应头长度块解密失败").to_string(),
                            )));
                        }
                    };
                    let plen = u16::from_be_bytes([pt[0], pt[1]]) as usize;
                    h.state = RespState::AeadReadPayload {
                        plen,
                        buf: BytesMut::with_capacity(plen + 16),
                    };
                }
                RespState::AeadReadPayload { plen, buf } => {
                    let need = *plen + 16;
                    while buf.len() < need {
                        let mut tmp = vec![0u8; need - buf.len()];
                        let mut read = ReadBuf::new(&mut tmp);
                        match Pin::new(&mut *io).poll_read(cx, &mut read) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Ready(Ok(())) if read.filled().is_empty() => {
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "vmess: 响应头 EOF",
                                )));
                            }
                            Poll::Ready(Ok(())) => buf.extend_from_slice(read.filled()),
                        }
                    }
                    let pay_key = kdf::kdf16(&h.key, &[kdf::SALT_RESP_KEY.as_bytes()]);
                    let pay_nonce = kdf::kdf_x(&h.iv, &[kdf::SALT_RESP_IV.as_bytes()], 12);
                    let mut pn12 = [0u8; 12];
                    pn12.copy_from_slice(&pay_nonce);
                    let paead = match AnyAead::new(AeadKind::Aes128Gcm, &pay_key) {
                        Ok(a) => a,
                        Err(e) => return Poll::Ready(Err(std::io::Error::other(e))),
                    };
                    let payload = match paead.open_nonce(&pn12, buf, b"") {
                        Ok(p) => p,
                        Err(_e) => {
                            return Poll::Ready(Err(std::io::Error::other(
                                Error::Proto("vmess 响应头解密失败").to_string(),
                            )));
                        }
                    };
                    if payload.len() < 2 || payload[0] != h.auth_expect {
                        return Poll::Ready(Err(std::io::Error::other(
                            Error::Proto("vmess 响应认证不匹配").to_string(),
                        )));
                    }
                    h.state = RespState::Done;
                }
                RespState::LegacyReadHead(buf) => {
                    while buf.len() < 4 {
                        let mut tmp = [0u8; 4];
                        let mut read = ReadBuf::new(&mut tmp);
                        match Pin::new(&mut *io).poll_read(cx, &mut read) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Ready(Ok(())) if read.filled().is_empty() => {
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "vmess: 响应头 EOF",
                                )));
                            }
                            Poll::Ready(Ok(())) => buf.extend_from_slice(read.filled()),
                        }
                    }
                    // CFB 解密（一次性，读 4B [V][opt][?][cmdLen]）
                    use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
                    let iv16: [u8; 16] =
                        h.iv.as_slice()
                            .try_into()
                            .map_err(|_| std::io::Error::other("vmess legacy iv"))?;
                    let cfb =
                        cfb_mode::Decryptor::<aes::Aes128>::new((&h.key).into(), (&iv16).into());
                    cfb.decrypt(buf);
                    if buf[0] != h.auth_expect {
                        return Poll::Ready(Err(std::io::Error::other(
                            Error::Proto("vmess 响应认证不匹配").to_string(),
                        )));
                    }
                    let cmd_len = buf[3] as usize;
                    h.state = if cmd_len > 0 {
                        RespState::LegacySkipCmd { n: cmd_len }
                    } else {
                        RespState::Done
                    };
                }
                RespState::LegacySkipCmd { n } => {
                    let need = *n;
                    let mut tmp = vec![0u8; need];
                    let mut read = ReadBuf::new(&mut tmp);
                    match Pin::new(&mut *io).poll_read(cx, &mut read) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) if read.filled().is_empty() => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "vmess: 响应头 cmd EOF",
                            )));
                        }
                        Poll::Ready(Ok(())) => {
                            h.state = RespState::Done;
                        }
                    }
                }
                RespState::Done => {
                    *slot = None;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VmessStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        // 懒解析响应头（首次 read 触发）
        std::task::ready!(Self::poll_resp_header(
            &mut this.resp_header,
            &mut this.inner,
            cx
        ))?;
        loop {
            if !this.pending.is_empty() {
                let n = this.pending.len().min(buf.remaining());
                buf.put_slice(&this.pending[..n]);
                this.pending.advance(n);
                return Poll::Ready(Ok(()));
            }
            if this.closed {
                return Poll::Ready(Ok(()));
            }
            this.try_progress();
            if !this.pending.is_empty() {
                continue;
            }
            this.raw.reserve(16 * 1024);
            let spare = this.raw.spare_capacity_mut();
            let mut rb = ReadBuf::uninit(spare);
            std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
            let filled = rb.filled().len();
            if filled == 0 {
                this.closed = true;
                return Poll::Ready(Ok(()));
            }
            unsafe { this.raw.advance_mut(filled) };
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VmessStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if this.closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "vmess: 已关闭",
            )));
        }
        std::task::ready!(this.flush_out(cx))?;
        let chunk = this.enc.seal_chunk(buf);
        this.out.extend_from_slice(&chunk);
        std::task::ready!(this.flush_out(cx))?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        std::task::ready!(this.flush_out(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        if !this.closed {
            let chunk = this.enc.seal_chunk(&[]);
            this.out.extend_from_slice(&chunk);
            this.closed = true;
        }
        let _ = this.flush_out(cx);
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// 出站
// ---------------------------------------------------------------------------

pub struct VmessOutbound {
    name: Arc<str>,
    server: String,
    port: u16,
    uuid: [u8; 16],
    cmd_key: [u8; 16],
    /// alterId>0 的旧版节点只认 legacy（MD5/HMAC-MD5 + AES-CFB）认证头
    legacy: bool,
    security: Security,
    transport: transport::TransportConfig,
}

impl VmessOutbound {
    pub fn new(cfg: &VmessCfg) -> Result<Self> {
        Self::internal_new(None, cfg)
    }

    pub fn new_named(name: &str, cfg: &VmessCfg) -> Result<Self> {
        Self::internal_new(Some(name), cfg)
    }

    fn internal_new(name: Option<&str>, cfg: &VmessCfg) -> Result<Self> {
        let uuid = kdf::parse_uuid(&cfg.uuid)?;
        let cmd_key = kdf::uuid_to_cmd_key(&uuid);
        let security = Security::from_cipher(&cfg.cipher)?;
        let mut t = crate::transport_of_full(
            cfg.tls,
            &cfg.server_name,
            cfg.skip_cert_verify,
            &cfg.network,
            &cfg.ws_opts,
            &None,
            &cfg.client_fingerprint,
            &None,
            &cfg.http_opts,
            &cfg.ech_opts,
        )?;
        t.alpn = cfg.alpn.clone().unwrap_or_default();
        Ok(VmessOutbound {
            name: name.unwrap_or("vmess").into(),
            server: cfg.server.clone(),
            port: cfg.port,
            uuid,
            cmd_key,
            legacy: cfg.alter_id > 0,
            security,
            transport: t,
        })
    }

    async fn handshake<S>(&self, mut io: S, dst: &DstAddr) -> Result<Box<dyn ProxyStream>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut body_key = [0u8; 16];
        let mut body_iv = [0u8; 16];
        vp_common::rand_bytes(&mut body_key);
        vp_common::rand_bytes(&mut body_iv);
        let mut resp_auth = [0u8; 1];
        vp_common::rand_bytes(&mut resp_auth);
        let req = VmessRequest {
            body_key,
            body_iv,
            resp_auth: resp_auth[0],
            security: self.security,
            cmd: 0x01,
            dst: dst.clone(),
            option: OPT_CHUNK_STREAM | OPT_CHUNK_MASKING,
        };
        let pt = build_request_plaintext(&req);
        use tokio::io::AsyncWriteExt;
        // body 编解码 key/iv：写方向 requestKey/Nonce，读方向按认证头类型派生
        let (dec_key, dec_iv, legacy) = if self.legacy {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let header = seal_header_legacy(&self.uuid, ts, &pt)?;
            io.write_all(&header).await?;
            let (rk, riv) = kdf::legacy_resp_keys(&body_key, &body_iv);
            (rk, riv, true)
        } else {
            let header = seal_header(&self.cmd_key, &pt)?;
            io.write_all(&header).await?;
            let (rk, riv) = resp_keys(&body_key, &body_iv);
            (rk, riv, false)
        };
        let stream = VmessStream {
            inner: io,
            // 主流服务端按请求头 Option 的 ChunkMasking 位分帧：
            // 请求方向掩码 seed=body_iv，响应方向服务端镜像同一位、seed=resp_iv
            enc: BodyCodec::new(self.security, &body_key, &body_iv, true)?,
            dec: BodyCodec::new(self.security, &dec_key, &dec_iv, true)?,
            raw: BytesMut::new(),
            pending: BytesMut::new(),
            out: BytesMut::new(),
            closed: false,
            resp_header: Some(RespHeader::new(
                resp_auth[0],
                dec_key,
                dec_iv.to_vec(),
                legacy,
            )),
        };
        Ok(Box::new(stream))
    }
}

#[async_trait]
impl Outbound for VmessOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect_stream(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        let io = transport::dial(&self.server, self.port, &self.transport).await?;
        self.handshake(io, dst).await
    }

    async fn connect_over(
        &self,
        _sess: &Session,
        dst: &DstAddr,
        underlying: Box<dyn ProxyStream>,
    ) -> Result<Box<dyn ProxyStream>> {
        let io = transport::wrap_transport(underlying, &self.server, &self.transport).await?;
        self.handshake(io, dst).await
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
}

// ---------------------------------------------------------------------------
// 入站
// ---------------------------------------------------------------------------

pub struct VmessUser {
    pub uuid: String,
}

pub struct VmessInbound {
    bind: String,
    port: u16,
    tag: Arc<str>,
    users: Vec<([u8; 16], [u8; 16])>, // (uuid, cmd_key)
    direct: Arc<DirectOutbound>,
}

impl VmessInbound {
    pub fn new(bind: &str, port: u16, tag: &str, uuids: &[String]) -> Result<Self> {
        let mut users = Vec::new();
        for u in uuids {
            let id = kdf::parse_uuid(u)?;
            users.push((id, kdf::uuid_to_cmd_key(&id)));
        }
        if users.is_empty() {
            return Err(Error::Config("vmess 入站需要至少一个用户".into()));
        }
        Ok(VmessInbound {
            bind: bind.to_string(),
            port,
            tag: tag.into(),
            users,
            direct: Arc::new(DirectOutbound::new(Arc::new(Resolver::system()), false)),
        })
    }

    async fn serve(
        self: &Arc<Self>,
        mut stream: tokio::net::TcpStream,
        src: std::net::SocketAddr,
        ctx: &InboundCtx,
    ) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        // authID → 用户匹配
        let mut auth_id = [0u8; 16];
        stream.read_exact(&mut auth_id).await?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let mut matched: Option<[u8; 16]> = None;
        for (_, cmd_key) in &self.users {
            if let Some((ts, _)) = kdf::decode_auth_id(cmd_key, &auth_id) {
                if (ts - now).abs() <= kdf::AUTH_WINDOW_SECS {
                    matched = Some(*cmd_key);
                    break;
                }
            }
        }
        let cmd_key = matched.ok_or(Error::Proto("vmess: 用户认证失败"))?;
        let plaintext = open_header(&cmd_key, &auth_id, &mut stream).await?;
        let req = parse_request_plaintext(&plaintext)?;
        if req.cmd != 0x01 {
            return Err(Error::Unsupported("vmess 入站仅支持 TCP".into()));
        }
        // 直连目标
        let sess = Session::new_tcp(self.tag.clone(), Some(src), req.dst.clone());
        let remote = self.direct.connect_stream(&sess, &req.dst).await?;
        // 客户端 Option 的 ChunkMasking 位决定双向分块长度是否掩码
        let masked = req.option & OPT_CHUNK_MASKING != 0;
        // 响应头
        let (resp_key, resp_iv) = resp_keys(&req.body_key, &req.body_iv);
        let resp = build_response_header(
            req.resp_auth,
            &resp_key,
            &resp_iv,
            OPT_CHUNK_STREAM | if masked { OPT_CHUNK_MASKING } else { 0 },
        )?;
        stream.write_all(&resp).await?;
        let client = VmessStream {
            inner: stream,
            enc: BodyCodec::new(req.security, &resp_key, &resp_iv, masked)?,
            dec: BodyCodec::new(req.security, &req.body_key, &req.body_iv, masked)?,
            raw: BytesMut::new(),
            pending: BytesMut::new(),
            out: BytesMut::new(),
            closed: false,
            resp_header: None,
        };
        let meta = vp_core::conn_table::ConnMeta {
            id: sess.id,
            inbound: self.tag.clone(),
            network: "tcp",
            host: req.dst.host.to_string(),
            dst_port: req.dst.port,
            src: Some(src.to_string()),
            process: None,
            rule: None,
            chain: Some("vmess-server".into()),
            start: vp_common::now_millis(),
        };
        let hook = RelayHook {
            table: Some(ctx.conns.clone()),
            meta: Some(meta),
            stats: Some(ctx.stats.clone()),
        };
        tokio::spawn(async move {
            let _ = relay(Box::new(client), remote, hook).await;
        });
        Ok(())
    }
}

#[async_trait]
impl Inbound for VmessInbound {
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
                        vp_transport::tune(&stream);
                        let this = this.clone();
                        let ctx = ctx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = this.serve(stream, src, &ctx).await {
                                warn!("vmess 入站会话结束: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        warn!("vmess 入站 accept 失败: {e}");
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

    async fn roundtrip(security: &str) {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut b = [0u8; 1024];
            loop {
                let n = s.read(&mut b).await.unwrap();
                if n == 0 {
                    break;
                }
                s.write_all(&b[..n]).await.unwrap();
            }
        });
        let ctx = InboundCtx {
            router: Arc::new(crate::test_support::NoopRouter()),
            stats: Arc::new(vp_common::Stats::default()),
            conns: Arc::new(vp_core::ConnTable::new()),
        };
        let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811".to_string();
        let server =
            VmessInbound::new("127.0.0.1", 0, "vm-srv", std::slice::from_ref(&uuid)).unwrap();
        let port = Arc::new(server).start(ctx).await.unwrap();

        let out = VmessOutbound::new(&VmessCfg {
            server: "127.0.0.1".into(),
            port,
            uuid,
            alter_id: 0,
            cipher: security.into(),
            tls: false,
            server_name: None,
            skip_cert_verify: false,
            client_fingerprint: None,
            alpn: None,
            network: None,
            ws_opts: None,
            grpc_opts: None,
            http_opts: None,
            udp: false,
            ech_opts: None,
        })
        .unwrap();
        let dst = DstAddr::ip("127.0.0.1".parse().unwrap(), echo_addr.port());
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = out.connect_stream(&sess, &dst).await.unwrap();
        s.write_all(b"ping-vmess").await.unwrap();
        let mut buf = [0u8; 10];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-vmess");
    }

    #[tokio::test]
    async fn vmess_loopback() {
        roundtrip("auto").await;
        roundtrip("chacha20-poly1305").await;
        roundtrip("none").await;
    }

    #[tokio::test]
    async fn wrong_user_rejected() {
        let ctx = InboundCtx {
            router: Arc::new(crate::test_support::NoopRouter()),
            stats: Arc::new(vp_common::Stats::default()),
            conns: Arc::new(vp_core::ConnTable::new()),
        };
        let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811".to_string();
        let server =
            VmessInbound::new("127.0.0.1", 0, "vm-srv", std::slice::from_ref(&uuid)).unwrap();
        let port = Arc::new(server).start(ctx).await.unwrap();
        let out = VmessOutbound::new(&VmessCfg {
            server: "127.0.0.1".into(),
            port,
            uuid: "11111111-2222-3333-4444-555555555555".into(),
            alter_id: 0,
            cipher: "auto".into(),
            tls: false,
            server_name: None,
            skip_cert_verify: false,
            client_fingerprint: None,
            alpn: None,
            network: None,
            ws_opts: None,
            grpc_opts: None,
            http_opts: None,
            udp: false,
            ech_opts: None,
        })
        .unwrap();
        let dst = DstAddr::ip("127.0.0.1".parse().unwrap(), 80);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        // 响应头懒读：认证失败在首次 read 时才暴露
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = out
            .connect_stream(&sess, &dst)
            .await
            .expect("connect_stream 本身应成功");
        let _ = s
            .write_all(
                b"GET / HTTP/1.1

",
            )
            .await;
        let mut b = [0u8; 16];
        assert!(s.read(&mut b).await.is_err(), "错误用户的首次 read 应报错");
    }

    #[test]
    fn test_vmess_codec_fragmented_stream() {
        let key = [0x42u8; 16];
        let iv = [0x24u8; 16];
        let mut enc = BodyCodec::new(Security::Aes128Gcm, &key, &iv, true).unwrap();
        let mut dec = BodyCodec::new(Security::Aes128Gcm, &key, &iv, true).unwrap();

        let chunk1 = enc.seal_chunk(b"hello vmess chunk 1");
        let chunk2 = enc.seal_chunk(b"second chunk with more data here");

        let mut stream_bytes = Vec::new();
        stream_bytes.extend_from_slice(&chunk1);
        stream_bytes.extend_from_slice(&chunk2);

        // 模拟网络逐字节到达：之前由于未缓存分块长度，每次字节不足都会重复调用 next_u16() 导致失步
        let mut raw = bytes::BytesMut::new();
        let mut decoded = Vec::new();
        for b in stream_bytes {
            raw.extend_from_slice(&[b]);
            while let Some(res) = dec.try_open_chunk(&raw) {
                let (payload, used) = res.expect("chunk should decode cleanly");
                bytes::Buf::advance(&mut raw, used);
                decoded.push(payload);
            }
        }
        assert_eq!(decoded.len(), 2);
        assert_eq!(&decoded[0], b"hello vmess chunk 1");
        assert_eq!(&decoded[1], b"second chunk with more data here");
    }
}

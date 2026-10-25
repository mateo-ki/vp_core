//! uTLS 指纹：手写 TLS 1.3 客户端（Chrome 指纹）。
//!
//! 服务器侧指纹（JA3/JA4 等）只看 ClientHello：本模块自绘 Chrome 风格 CH
//! （套件/扩展/顺序对齐 Chrome），随后以标准 TLS 1.3 握手完成后续（RFC 8446）。
//! 密码原语全部复用 ring（rustls 已链接，零新增依赖、零体积增量）：
//! x25519（agreement）/ HKDF-SHA256 / SHA256 / HMAC / AES-GCM / CHACHA20-POLY1305。
//!
//! 证书校验复用 rustls 的 WebPkiServerVerifier（链 + SNI + 有效期），
//! CertificateVerify 签名用 ring 直接验证（RSA-PSS / ECDSA / Ed25519）。
//!
//! 边界（明确报错）：仅 TLS 1.3（服务器选 1.2 / HRR / 请求客户端证书时不支持）；
//! 密钥交换仅 x25519；不支持 compress_certificate / ECH / PSK 恢复。

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, BytesMut};
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::client::danger::ServerCertVerifier;
use tokio_rustls::rustls::RootCertStore;

use vp_common::{Error, Result};

const REC_APPDATA: u8 = 23;
const REC_ALERT: u8 = 21;
const REC_HANDSHAKE: u8 = 22;
/// TLS 1.3 记录密文上限（2^14 + 255 tag/padding）
const MAX_CIPHERTEXT: usize = 16_384 + 256;

// 握手消息类型
const HS_EE: u8 = 8;
const HS_CERT: u8 = 11;
const HS_CERT_STATUS: u8 = 22;
const HS_CERT_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;
const HS_CERT_REQUEST: u8 = 13;
const HS_KEY_UPDATE: u8 = 24;

// HRR 随机值（RFC 8446 §4.1.3）
const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8,
    0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8,
    0x33, 0x9C,
];

/// 支持的指纹（v1：chrome）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fingerprint {
    Chrome,
}

impl Fingerprint {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "chrome" => Ok(Fingerprint::Chrome),
            other => Err(Error::Unsupported(format!(
                "TLS 指纹 {other:?} 暂不支持（当前支持 chrome）"
            ))),
        }
    }
}

pub struct UtlsConfig {
    pub fingerprint: Fingerprint,
    pub server_name: Option<String>,
    pub alpn: Vec<String>,
    pub skip_cert_verify: bool,
}

// ---------------------------------------------------------------------------
// Chrome 风格 ClientHello（真实 x25519 密钥对）
// ---------------------------------------------------------------------------

/// Chrome 常用套件（与 shadow-tls CH 同表：1301/1302/1303 + 11 个 TLS1.2 套件）
const CH_SUITES: [u8; 28] = [
    0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xc0,
    0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a,
];
/// Chrome 签名算法（ecdsa_sha256, rsa_pss_*, rsa_pkcs1_*, …）
const CH_SIG_ALGS: [u8; 18] = [
    0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06,
    0x01, 0x02, 0x01,
];

struct ClientHello {
    record: Vec<u8>,
    /// CH 私钥（ring 内部不透明）
    priv_key: ring::agreement::EphemeralPrivateKey,
}

fn ext(out: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    out.extend_from_slice(&ty.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
}

/// Chrome 风格 CH（扩展顺序对齐 Chrome：0,23,65281,10,11,35,16,5,13,18,51,45,43）
fn build_ch(sni: &str, alpn: &[String]) -> Result<ClientHello> {
    let rng = ring::rand::SystemRandom::new();
    let priv_key = ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::X25519, &rng)
        .map_err(|_| Error::Proto("utls: x25519 密钥生成失败"))?;
    let pk = priv_key
        .compute_public_key()
        .map_err(|_| Error::Proto("utls: x25519 公钥计算失败"))?;
    let share: &[u8] = pk.as_ref();

    let mut body = Vec::with_capacity(517);
    body.push(0x01); // ClientHello
    body.extend_from_slice(&[0, 0, 0]); // 长度占位
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    let mut rnd = [0u8; 32];
    vp_common::rand_bytes(&mut rnd);
    body.extend_from_slice(&rnd);
    let mut sid = [0u8; 32];
    vp_common::rand_bytes(&mut sid);
    body.push(32);
    body.extend_from_slice(&sid);
    body.extend_from_slice(&(CH_SUITES.len() as u16).to_be_bytes());
    body.extend_from_slice(&CH_SUITES);
    body.extend_from_slice(&[0x01, 0x00]); // compression: null

    let mut exts: Vec<u8> = Vec::with_capacity(256);
    // server_name（IP 不带 SNI）
    let is_ip = sni.parse::<std::net::IpAddr>().is_ok();
    if !sni.is_empty() && !is_ip {
        let name = sni.as_bytes();
        let mut e = Vec::with_capacity(name.len() + 9);
        e.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        e.push(0x00);
        e.extend_from_slice(&(name.len() as u16).to_be_bytes());
        e.extend_from_slice(name);
        ext(&mut exts, 0, &e);
    }
    ext(&mut exts, 23, &[]); // extended_master_secret
    ext(&mut exts, 65281, &[0x00]); // renegotiation_info（初次握手：空向量）
    // supported_groups: 前缀 = 群列表字节长度（NamedGroup list<2..2^16-1>）
    ext(&mut exts, 10, &[0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18]);
    ext(&mut exts, 11, &[0x01, 0x00]); // ec_point_formats
    ext(&mut exts, 35, &[]); // session_ticket
    if !alpn.is_empty() {
        let mut list = Vec::new();
        for p in alpn {
            list.push(p.len() as u8);
            list.extend_from_slice(p.as_bytes());
        }
        let mut payload = (list.len() as u16).to_be_bytes().to_vec();
        payload.extend_from_slice(&list);
        ext(&mut exts, 16, &payload);
    }
    ext(&mut exts, 5, &[0x01, 0x00, 0x00, 0x00, 0x00]); // status_request (OCSP)
    // signature_algorithms: 前缀 = 方案列表字节长度（不是条目数！）
    let mut sig_payload = (CH_SIG_ALGS.len() as u16).to_be_bytes().to_vec();
    sig_payload.extend_from_slice(&CH_SIG_ALGS);
    ext(&mut exts, 13, &sig_payload);
    ext(&mut exts, 18, &[]); // signed_certificate_timestamp
    // key_share: x25519
    {
        let mut payload = (32u16 + 4).to_be_bytes().to_vec(); // client_shares 长度
        payload.extend_from_slice(&[0x00, 0x1d]);
        payload.extend_from_slice(&32u16.to_be_bytes());
        payload.extend_from_slice(share);
        ext(&mut exts, 51, &payload);
    }
    ext(&mut exts, 45, &[0x01, 0x01]); // psk_key_exchange_modes: psk_dhe_ke
    ext(&mut exts, 43, &[0x04, 0x03, 0x04, 0x03, 0x03]); // supported_versions: [1.3, 1.2]

    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    let total = body.len() - 4;
    body[1] = (total >> 16) as u8;
    body[2] = (total >> 8) as u8;
    body[3] = total as u8;

    let mut record = Vec::with_capacity(body.len() + 5);
    record.extend_from_slice(&[REC_HANDSHAKE, 0x03, 0x01]);
    record.extend_from_slice(&(body.len() as u16).to_be_bytes());
    record.extend_from_slice(&body);

    Ok(ClientHello { record, priv_key })
}

// ---------------------------------------------------------------------------
// 密钥调度（RFC 8446 §7.1，SHA256）
// ---------------------------------------------------------------------------

/// Prk::expand 的输出长度包装（ring 0.17 未内置 Len）
struct OkmLen(usize);
impl ring::hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn hkdf_expand_label(prk: &ring::hkdf::Prk, label: &str, context: &[u8], len: usize) -> Result<Vec<u8>> {
    let full_label = format!("tls13 {label}");
    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    let mut out = vec![0u8; len];
    let info_ref: [&[u8]; 1] = [&info];
    // 注意：Prk::expand 的第二参数是输出长度（Len），不是算法
    let okm = prk
        .expand(&info_ref, OkmLen(len))
        .map_err(|_| Error::ProtoMsg(format!("utls: hkdf expand 失败 label={label} len={len}")))?;
    okm.fill(&mut out)
        .map_err(|_| Error::ProtoMsg(format!("utls: hkdf fill 失败 label={label} len={len}")))?;
    Ok(out)
}

/// Extract(salt, ikm)
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Result<ring::hkdf::Prk> {
    Ok(ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, salt).extract(ikm))
}

/// Derive-Secret(secret, label, messages)
fn derive_secret(prk: &ring::hkdf::Prk, label: &str, transcript_hash: &[u8]) -> Result<Vec<u8>> {
    hkdf_expand_label(prk, label, transcript_hash, 32)
}

fn sha256(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, data).as_ref().to_vec()
}

const SUITE_AES128: u16 = 0x1301;
const SUITE_AES256: u16 = 0x1302;
const SUITE_CHACHA: u16 = 0x1303;

fn suite_alg(suite: u16) -> Option<(&'static ring::aead::Algorithm, usize)> {
    match suite {
        SUITE_AES128 => Some((&ring::aead::AES_128_GCM, 16)),
        SUITE_AES256 => Some((&ring::aead::AES_256_GCM, 32)),
        SUITE_CHACHA => Some((&ring::aead::CHACHA20_POLY1305, 32)),
        _ => None,
    }
}

/// 单方向记录层密钥
struct Direction {
    alg: &'static ring::aead::Algorithm,
    key: Vec<u8>,
    iv: [u8; 12],
    seq: u64,
}

impl Direction {
    fn new(alg: &'static ring::aead::Algorithm, secret: &[u8]) -> Result<Self> {
        let prk = ring::hkdf::Prk::new_less_safe(ring::hkdf::HKDF_SHA256, secret);
        let key = hkdf_expand_label(&prk, "key", &[], alg.key_len())?;
        let iv = hkdf_expand_label(&prk, "iv", &[], 12)?;
        Ok(Direction {
            alg,
            key,
            iv: iv.try_into().unwrap(),
            seq: 0,
        })
    }

    fn nonce(&self) -> [u8; 12] {
        let seq = self.seq.to_be_bytes();
        let mut n = self.iv;
        for i in 0..8 {
            n[4 + i] ^= seq[i];
        }
        n
    }

    fn key(&self) -> Result<ring::aead::LessSafeKey> {
        let uk = ring::aead::UnboundKey::new(self.alg, &self.key)
            .map_err(|_| Error::Proto("utls: aead key 失败"))?;
        Ok(ring::aead::LessSafeKey::new(uk))
    }

    fn seal(&mut self, aad: &[u8], content: &mut BytesMut) -> Result<()> {
        let n = ring::aead::Nonce::assume_unique_for_key(self.nonce());
        self.key()?
            .seal_in_place_append_tag(n, ring::aead::Aad::from(aad), content)
            .map_err(|_| Error::Proto("utls: 加密失败"))?;
        self.seq += 1;
        Ok(())
    }

    /// 解密密文（含 tag），返回内层内容（去 padding / inner type 前的数据）
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<(u8, Vec<u8>)> {
        let n = ring::aead::Nonce::assume_unique_for_key(self.nonce());
        let mut buf = ciphertext.to_vec();
        let plain = self
            .key()?
            .open_in_place(n, ring::aead::Aad::from(aad), &mut buf)
            .map_err(|_| Error::ProtoMsg(format!("utls: 解密失败 seq={} ctlen={}", self.seq, ciphertext.len())))?;
        self.seq += 1;
        if plain.is_empty() {
            return Err(Error::Proto("utls: 空记录"));
        }
        // 末字节为 inner content type，其前全零为 padding
        let inner = plain[plain.len() - 1];
        let mut end = plain.len() - 1;
        while end > 0 && plain[end - 1] == 0 {
            end -= 1;
        }
        Ok((inner, plain[..end].to_vec()))
    }

    /// 密钥更新（KeyUpdate）：traffic upd
    fn update(&mut self) -> Result<()> {
        let prk = ring::hkdf::Prk::new_less_safe(ring::hkdf::HKDF_SHA256, &self.key.clone());
        let secret = hkdf_expand_label(&prk, "traffic upd", &[], 32)?;
        *self = Direction::new(self.alg, &secret)?;
        Ok(())
    }
}

/// 由流量密钥（transcript 密钥）派生 Direction
fn traffic_direction(alg: &'static ring::aead::Algorithm, secret: &[u8]) -> Result<Direction> {
    Direction::new(alg, secret)
}

// ---------------------------------------------------------------------------
// 记录读写
// ---------------------------------------------------------------------------

async fn read_record_raw<S: tokio::io::AsyncRead + Unpin>(
    s: &mut S,
) -> Result<(u8, [u8; 3], Vec<u8>)> {
    use tokio::io::AsyncReadExt;
    let mut hdr = [0u8; 5];
    s.read_exact(&mut hdr).await.map_err(Error::Io)?;
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if len > MAX_CIPHERTEXT {
        return Err(Error::Proto("utls: 记录超长"));
    }
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).await.map_err(Error::Io)?;
    Ok((hdr[0], [hdr[1], hdr[2], 0], body))
}

/// 一条记录（已解密）；Closed = 对端 close_notify（干净关闭）
enum Frame {
    Data { inner: u8, data: Vec<u8> },
    Closed,
}

async fn read_record<S: tokio::io::AsyncRead + Unpin>(
    s: &mut S,
    rx: Option<&mut Direction>,
) -> Result<Frame> {
    let (outer, _ver, body) = read_record_raw(s).await?;
    match outer {
        REC_APPDATA => match rx {
            Some(dir) => {
                // AAD 为记录头（长度即密文长度）
                let h = [
                    REC_APPDATA,
                    0x03,
                    0x03,
                    (body.len() >> 8) as u8,
                    body.len() as u8,
                ];
                let (inner, data) = dir.open(&h, &body)?;
                Ok(Frame::Data { inner, data })
            }
            None => Err(Error::Proto("utls: 提前收到加密记录")),
        },
        REC_HANDSHAKE => Ok(Frame::Data {
            inner: REC_HANDSHAKE,
            data: body,
        }),
        REC_ALERT => {
            if body.len() >= 2 && body[1] == 0 {
                Ok(Frame::Closed)
            } else {
                Err(Error::ProtoMsg(format!(
                    "utls: 收到告警 {}",
                    body.get(1).copied().unwrap_or(0)
                )))
            }
        }
        // dummy ChangeCipherSpec（中间盒兼容模式）：透传，由调用方跳过
        20 => Ok(Frame::Data { inner: 20, data: body }),
        t => Err(Error::ProtoMsg(format!("utls: 非法记录类型 {t}"))),
    }
}

// ---------------------------------------------------------------------------
// 握手消息解析辅助
// ---------------------------------------------------------------------------

struct MsgIter {
    buf: Vec<u8>,
    pos: usize,
}

impl MsgIter {
    fn new() -> Self {
        MsgIter {
            buf: Vec::new(),
            pos: 0,
        }
    }

    fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// 取一条完整消息：(type, 内容)。缓冲不足返回 None
    fn next_msg(&mut self) -> Option<(u8, Vec<u8>)> {
        if self.buf.len() < self.pos + 4 {
            return None;
        }
        let ty = self.buf[self.pos];
        let len = ((self.buf[self.pos + 1] as usize) << 16)
            | ((self.buf[self.pos + 2] as usize) << 8)
            | self.buf[self.pos + 3] as usize;
        if len > 128 * 1024 {
            return None; // 消息异常（调用方按错误终止）
        }
        let end = self.pos + 4 + len;
        if self.buf.len() < end {
            return None;
        }
        let msg = self.buf[self.pos + 4..end].to_vec();
        self.pos = end;
        Some((ty, msg))
    }

    fn compact(&mut self) {
        self.buf.drain(..self.pos);
        self.pos = 0;
    }
}

struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Cursor { b, pos: 0 }
    }
    fn u8(&mut self) -> Result<u8> {
        let v = *self.b.get(self.pos).ok_or(Error::Proto("utls: 解析越界"))?;
        self.pos += 1;
        Ok(v)
    }
    fn u16(&mut self) -> Result<u16> {
        let v = self
            .b
            .get(self.pos..self.pos + 2)
            .ok_or(Error::Proto("utls: 解析越界"))?;
        self.pos += 2;
        Ok(u16::from_be_bytes([v[0], v[1]]))
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let v = self
            .b
            .get(self.pos..self.pos + n)
            .ok_or(Error::Proto("utls: 解析越界"))?;
        self.pos += n;
        Ok(v)
    }
    fn done(&self) -> bool {
        self.pos >= self.b.len()
    }
}

/// ServerHello 解析结果
struct ServerHello {
    suite: u16,
    peer_share: Vec<u8>,
    selected_psk: bool,
}

fn parse_server_hello(msg: &[u8]) -> Result<ServerHello> {
    let mut c = Cursor::new(msg);
    if c.take(2)? != [0x03, 0x03] {
        return Err(Error::Proto("utls: SH legacy_version 异常"));
    }
    let random = c.take(32)?;
    if random == HRR_RANDOM {
        return Err(Error::Unsupported("utls: 不支持 HelloRetryRequest".into()));
    }
    let sid_len = c.u8()? as usize;
    c.take(sid_len)?;
    let suite = c.u16()?;
    if c.u8()? != 0 {
        return Err(Error::Proto("utls: SH compression 非法"));
    }
    let ext_len = c.u16()? as usize;
    let exts = c.take(ext_len)?;
    let mut peer_share = None;
    let mut selected_psk = false;
    let mut e = Cursor::new(exts);
    while !e.done() {
        let ty = e.u16()?;
        let len = e.u16()? as usize;
        let body = e.take(len)?;
        match ty {
            51 => {
                // ServerHello 的 ext 51 是单个 KeyShareEntry（group + key），
                // 没有客户端列表的总长前缀
                let mut k = Cursor::new(body);
                let group = k.u16()?;
                let plen = k.u16()? as usize;
                let point = k.take(plen)?;
                if group == 0x001d {
                    peer_share = Some(point.to_vec());
                }
            }
            43 => {
                // supported_versions：ServerHello 是裸的 selected_version（2 字节，无前缀）
                if body.len() != 2 {
                    return Err(Error::Proto("utls: supported_versions 非法"));
                }
                let sel = u16::from_be_bytes([body[0], body[1]]);
                if sel != 0x0304 {
                    return Err(Error::Unsupported(
                        "utls: 服务器选择了 TLS 1.2，本指纹客户端仅支持 TLS 1.3".into(),
                    ));
                }
            }
            41 => selected_psk = true,
            _ => {}
        }
    }
    let peer_share = peer_share.ok_or(Error::Proto("utls: SH 缺 x25519 key_share"))?;
    Ok(ServerHello {
        suite,
        peer_share,
        selected_psk,
    })
}

/// Certificate 消息解析：返回 (叶子, 中间链)
fn parse_certificate(msg: &[u8]) -> Result<(CertificateDer<'static>, Vec<CertificateDer<'static>>)> {
    let mut c = Cursor::new(msg);
    let ctx_len = c.u8()? as usize;
    if !c.take(ctx_len)?.is_empty() {
        return Err(Error::Proto("utls: Certificate request_context 非空"));
    }
    let total = c.u24()? as usize;
    let _ = total;
    let mut certs = Vec::new();
    while !c.done() {
        let len = c.u24()? as usize;
        let der = c.take(len)?;
        certs.push(CertificateDer::from(der.to_vec()));
        let exts_len = c.u16()? as usize;
        c.take(exts_len)?; // OCSP status / SCT：忽略
    }
    if certs.is_empty() {
        return Err(Error::Proto("utls: 空证书链"));
    }
    let leaf = certs.remove(0);
    Ok((leaf, certs))
}

impl Cursor<'_> {
    fn u24(&mut self) -> Result<u32> {
        let v = self.take(3)?;
        Ok(((v[0] as u32) << 16) | ((v[1] as u32) << 8) | v[2] as u32)
    }
}

/// 从 X.509 DER 提取 SubjectPublicKeyInfo（最小 DER 遍历：
/// Certificate.SEQ → tbs.SEQ 第 7 元素）
fn extract_spki(cert: &CertificateDer<'_>) -> Result<Vec<u8>> {
    fn header(b: &[u8], pos: usize) -> Result<(u8, usize, usize)> {
        // (tag, 头长, 内容长)
        let tag = *b.get(pos).ok_or(Error::Proto("utls: DER 越界"))?;
        let mut len = *b.get(pos + 1).ok_or(Error::Proto("utls: DER 越界"))? as usize;
        let mut hl = 2;
        if len & 0x80 != 0 {
            let n = len & 0x7f;
            if n > 3 {
                return Err(Error::Proto("utls: DER 长度异常"));
            }
            len = 0;
            for i in 0..n {
                len = (len << 8) | *b.get(pos + 2 + i).ok_or(Error::Proto("utls: DER 越界"))? as usize;
            }
            hl = 2 + n;
        }
        Ok((tag, hl, len))
    }
    let raw = cert.as_ref();
    let (_, hl, clen) = header(raw, 0)?; // Certificate SEQ
    if raw.len() < hl + clen {
        return Err(Error::Proto("utls: 证书截断"));
    }
    // Certificate 内容 = [TBSCertificate SEQ, 签名算法 SEQ, 签名 BIT STRING]
    let body = &raw[hl..hl + clen];
    let (tag, hl2, tbs_len) = header(body, 0)?;
    if tag != 0x30 {
        return Err(Error::Proto("utls: DER 首元素非 SEQ"));
    }
    let tbs = &body[hl2..hl2 + tbs_len];
    // tbs 元素：[0] version（可选）、serial、sigAlg、issuer、validity、subject、spki
    let mut pos = 0usize;
    let mut spki: Option<Vec<u8>> = None;
    let mut count = 0;
    while pos < tbs.len() {
        let (tag, h, l) = header(tbs, pos)?;
        if pos + h + l > tbs.len() {
            return Err(Error::Proto("utls: DER 越界"));
        }
        count += 1;
        if tag == 0x30 && count == 7 {
            spki = Some(tbs[pos..pos + h + l].to_vec());
            break;
        }
        if count > 7 {
            break;
        }
        pos += h + l;
    }
    spki.ok_or_else(|| Error::Proto("utls: 未找到 SPKI"))
}

/// 验证 CertificateVerify 签名（ring 直接验，覆盖 TLS 1.3 允许的方案）
fn verify_cert_verify(
    leaf: &CertificateDer<'_>,
    scheme: u16,
    sig: &[u8],
    message: &[u8],
) -> Result<()> {
    use ring::signature::{self, UnparsedPublicKey};
    let alg: &'static dyn signature::VerificationAlgorithm = match scheme {
        0x0403 => &signature::ECDSA_P256_SHA256_ASN1,
        0x0503 => &signature::ECDSA_P384_SHA384_ASN1,
        0x0804 => &signature::RSA_PSS_2048_8192_SHA256,
        0x0805 => &signature::RSA_PSS_2048_8192_SHA384,
        0x0806 => &signature::RSA_PSS_2048_8192_SHA512,
        0x0807 => &signature::ED25519,
        _ => {
            return Err(Error::ProtoMsg(format!(
                "utls: 不支持的 CertificateVerify 方案 {scheme:#06x}"
            )))
        }
    };
    let spki = extract_spki(leaf)?;
    // ring 的 UnparsedPublicKey：RSA 用 SPKI DER；ECDSA/Ed25519 用裸公钥
    // （即 SPKI 内 BIT STRING 的内容，跳过首字节的 unused-bits 计数）
    let key = if matches!(scheme, 0x0804 | 0x0805 | 0x0806) {
        spki
    } else {
        // SPKI = SEQ { 算法 SEQ, BIT STRING }：进入外层 SEQ 内容找 BIT STRING
        let (t, h, l) = spki_header(&spki, 0)?;
        if t != 0x30 {
            return Err(Error::Proto("utls: SPKI 首元素非 SEQ"));
        }
        let mut pos = h;
        let end = h + l;
        let mut bits: Option<(usize, usize)> = None; // (内容起始, 长度)
        while pos < end {
            let (t2, h2, l2) = spki_header(&spki, pos)?;
            if t2 == 0x03 {
                // 跳过 1 字节 unused-bits
                bits = Some((pos + h2 + 1, l2 - 1));
            }
            pos += h2 + l2;
        }
        let (s, n) = bits.ok_or(Error::Proto("utls: SPKI 缺 BIT STRING"))?;
        spki[s..s + n].to_vec()
    };
    UnparsedPublicKey::new(alg, key)
        .verify(message, sig)
        .map_err(|_| Error::Proto("utls: CertificateVerify 签名验证失败"))
}

/// SPKI 内部复用的 DER 头解析（与 extract_spki::header 相同逻辑）
fn spki_header(b: &[u8], pos: usize) -> Result<(u8, usize, usize)> {
    let tag = *b.get(pos).ok_or(Error::Proto("utls: DER 越界"))?;
    let mut len = *b.get(pos + 1).ok_or(Error::Proto("utls: DER 越界"))? as usize;
    let mut hl = 2;
    if len & 0x80 != 0 {
        let n = len & 0x7f;
        if n > 3 {
            return Err(Error::Proto("utls: DER 长度异常"));
        }
        len = 0;
        for i in 0..n {
            len = (len << 8) | *b.get(pos + 2 + i).ok_or(Error::Proto("utls: DER 越界"))? as usize;
        }
        hl = 2 + n;
    }
    Ok((tag, hl, len))
}

// ---------------------------------------------------------------------------
// 握手主流程
// ---------------------------------------------------------------------------

fn root_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// 建立 uTLS 连接：完成完整 TLS 1.3 握手并返回可用的加密流
pub async fn utls_connect<S>(mut conn: S, host: &str, cfg: &UtlsConfig) -> Result<UtlsStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let sni = cfg.server_name.clone().unwrap_or_else(|| host.to_string());
    let ch = build_ch(&sni, &cfg.alpn)?;

    // 1. 发送 CH
    use tokio::io::AsyncWriteExt;
    conn.write_all(&ch.record).await.map_err(Error::Io)?;

    // transcript：CH 消息（记录体 = 握手消息）
    let mut transcript: Vec<u8> = ch.record[5..].to_vec();

    // 2. 读 ServerHello（明文握手记录）
    #[allow(unused_assignments)] // 循环内赋值，编译器无法静态确认
    let (mut suite, mut peer_share) = (0u16, Vec::new());
    loop {
        let frame = read_record(&mut conn, None).await?;
        let body = match frame {
            Frame::Data { inner, data } if inner == REC_HANDSHAKE => data,
            // dummy ChangeCipherSpec（中间盒兼容模式，RFC 8446 §5）：跳过
            Frame::Data { inner: 20, .. } => continue,
            Frame::Closed => return Err(Error::Proto("utls: 握手期对端关闭")),
            Frame::Data { inner, .. } => {
                return Err(Error::ProtoMsg(format!("utls: 握手期收到记录类型 {inner}")))
            }
        };
        let mut it = MsgIter::new();
        it.push(&body);
        if let Some((ty, msg)) = it.next_msg() {
            if ty != 2 {
                return Err(Error::ProtoMsg(format!("utls: 首条消息非 SH（{ty}）")));
            }
            let sh = parse_server_hello(&msg)?;
            if sh.selected_psk {
                return Err(Error::Proto("utls: 未提供 PSK 但服务器选择了 PSK"));
            }
            suite = sh.suite;
            peer_share = sh.peer_share;
            // transcript 需要完整握手消息（含 4 字节头）
            transcript.extend_from_slice(&[2, (msg.len() >> 16) as u8, (msg.len() >> 8) as u8, msg.len() as u8]);
            transcript.extend_from_slice(&msg);
            break;
        }
    }
    let (alg, _key_len) =
        suite_alg(suite).ok_or_else(|| Error::ProtoMsg(format!("utls: 服务器选择了不支持的套件 {suite:#06x}")))?;

    // 3. x25519 → 握手密钥
    let shared = ring::agreement::agree_ephemeral(
        ch.priv_key,
        &ring::agreement::UnparsedPublicKey::new(&ring::agreement::X25519, &peer_share),
        |s| Vec::from(s),
    )
    .map_err(|_| Error::Proto("utls: x25519 失败"))?;
    let zeros = [0u8; 32];
    let early = hkdf_extract(&zeros, &zeros)?;
    let empty_hash = sha256(&[]);
    let d1 = derive_secret(&early, "derived", &empty_hash)?;
    let hs = hkdf_extract(&d1, &shared)?;
    let th_sh = sha256(&transcript);
    let c_hs_secret = derive_secret(&hs, "c hs traffic", &th_sh)?;
    let s_hs_secret = derive_secret(&hs, "s hs traffic", &th_sh)?;
    let mut s_dir = traffic_direction(alg, &s_hs_secret)?;

    // 4. 加密握手：EE → Certificate(→CertificateStatus) → CertificateVerify → Finished
    let mut it = MsgIter::new();
    let mut chain: Option<(CertificateDer<'static>, Vec<CertificateDer<'static>>)> = None;
    let mut fin_ok = false;
    loop {
        let frame = read_record(&mut conn, Some(&mut s_dir)).await?;
        let data = match frame {
            Frame::Data { inner, data } if inner == REC_HANDSHAKE => data,
            Frame::Closed => return Err(Error::Proto("utls: 握手期对端关闭")),
            Frame::Data { inner, data } => {
                if inner == REC_ALERT {
                    return Err(Error::ProtoMsg(format!(
                        "utls: 握手期告警 {}",
                        data.get(1).copied().unwrap_or(0)
                    )));
                }
                if inner == 20 {
                    continue; // dummy CCS
                }
                return Err(Error::ProtoMsg(format!("utls: 握手期记录类型 {inner}")));
            }
        };
        it.push(&data);
        loop {
            let Some((ty, msg)) = it.next_msg() else { break };
            // transcript 需要完整握手消息（含 4 字节头）
            transcript.extend_from_slice(&[ty, (msg.len() >> 16) as u8, (msg.len() >> 8) as u8, msg.len() as u8]);
            transcript.extend_from_slice(&msg);
            match ty {
                HS_EE => {}
                HS_CERT_REQUEST => {
                    return Err(Error::Unsupported("utls: 不支持客户端证书请求".into()))
                }
                HS_CERT => chain = Some(parse_certificate(&msg)?),
                HS_CERT_STATUS => {}
                HS_CERT_VERIFY => {
                    let leaf = chain
                        .as_ref()
                        .ok_or(Error::Proto("utls: CertificateVerify 先于 Certificate"))?;
                    let mut c = Cursor::new(&msg);
                    let scheme = c.u16()?;
                    let sig_len = c.u16()? as usize;
                    let sig = c.take(sig_len)?.to_vec();
                    // message = 64*0x20 + 上下文 + 0x00 + transcript hash（不含 CV 本身）
                    let mut cv_msg = vec![0x20u8; 64];
                    cv_msg.extend_from_slice(b"TLS 1.3, server CertificateVerify");
                    cv_msg.push(0);
                    cv_msg.extend_from_slice(&sha256(&transcript[..transcript.len() - msg.len() - 4]));
                    verify_cert_verify(&leaf.0, scheme, &sig, &cv_msg)?;
                }
                HS_FINISHED => {
                    // verify_data = HMAC(finished_key(s_hs), hash(transcript 不含本消息))
                    let fk = hkdf_expand_label(
                        &ring::hkdf::Prk::new_less_safe(ring::hkdf::HKDF_SHA256, &s_hs_secret),
                        "finished",
                        &[],
                        32,
                    )?;
                    let expected = ring::hmac::sign(
                        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &fk),
                        &sha256(&transcript[..transcript.len() - msg.len() - 4]),
                    );
                    if msg.len() != expected.as_ref().len() || msg.as_slice() != expected.as_ref() {
                        return Err(Error::Proto("utls: Finished 校验失败"));
                    }
                    fin_ok = true;
                }
                _ => {
                    return Err(Error::ProtoMsg(format!(
                        "utls: 握手期意外消息 {ty}"
                    )))
                }
            }
            if fin_ok {
                break;
            }
        }
        if fin_ok {
            break;
        }
    }
    it.compact();

    // 5. 证书链 + SNI 校验（rustls webpki）
    let (leaf, inter) = chain.ok_or(Error::Proto("utls: 缺证书"))?;
    if !cfg.skip_cert_verify {
        let verifier = WebPkiServerVerifier::builder(Arc::new(root_store()))
            .build()
            .map_err(|_| Error::Proto("utls: verifier 构建失败"))?;
        let name = ServerName::try_from(sni.clone())
            .map_err(|_| Error::Addr(format!("非法 SNI: {sni:?}")))?;
        verifier
            .verify_server_cert(&leaf, &inter, &name, &[], UnixTime::now())
            .map_err(|e| Error::Io(std::io::Error::other(format!("证书校验失败: {e}"))))?;
    }

    // 6. 主密钥 → 应用流量密钥；客户端 Finished
    let d2 = derive_secret(&hs, "derived", &empty_hash)?;
    let master = hkdf_extract(&d2, &zeros)?;
    let th_fin = sha256(&transcript);
    let c_ap_secret = derive_secret(&master, "c ap traffic", &th_fin)?;
    let s_ap_secret = derive_secret(&master, "s ap traffic", &th_fin)?;
    let tx_dir = traffic_direction(alg, &c_ap_secret)?;
    let rx_dir = traffic_direction(alg, &s_ap_secret)?;

    // 客户端 Finished（c_hs finished key，transcript 含服务器 Finished）
    let c_fk = hkdf_expand_label(
        &ring::hkdf::Prk::new_less_safe(ring::hkdf::HKDF_SHA256, &c_hs_secret),
        "finished",
        &[],
        32,
    )?;
    let verify_data = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &c_fk),
        &th_fin,
    )
    .as_ref()
    .to_vec();
    let mut fin_msg = vec![HS_FINISHED, 0, 0, verify_data.len() as u8];
    fin_msg.extend_from_slice(&verify_data);

    // 加密握手记录：外层 0x17（密文），AAD 为记录头
    // 注意：客户端 Finished 必须用 c_hs（握手）密钥加密，应用数据才用 c_ap
    let mut c_hs_dir = traffic_direction(alg, &c_hs_secret)?;
    let mut content = fin_msg.clone();
    content.push(REC_HANDSHAKE); // inner type
    let mut rec = vec![REC_APPDATA, 0x03, 0x03, 0, 0];
    let clen = content.len() + 16; // + tag
    rec[3] = (clen >> 8) as u8;
    rec[4] = clen as u8;
    let mut sealed = BytesMut::from(content.as_slice());
    c_hs_dir.seal(&rec, &mut sealed)?;
    let mut out = rec.to_vec();
    out.extend_from_slice(&sealed);
    conn.write_all(&out).await.map_err(Error::Io)?;
    conn.flush().await.map_err(Error::Io)?;

    Ok(UtlsStream {
        conn,
        tx: tx_dir,
        rx: rx_dir,
        raw: BytesMut::with_capacity(16 * 1024),
        plaintext: BytesMut::with_capacity(16 * 1024),
        state: RxState::Header { need: 5, got: 0 },
        hdr: [0; 5],
        rx_closed: false,
        tx_closed: false,
    })
}

// ---------------------------------------------------------------------------
// 加密流（AsyncRead/AsyncWrite）
// ---------------------------------------------------------------------------

enum RxState {
    /// 收集记录头（need 5 字节）
    Header { need: usize, got: usize },
    /// 收集记录体（长度已解析）
    Body { len: usize, got: usize },
}

pub struct UtlsStream<S> {
    conn: S,
    tx: Direction,
    rx: Direction,
    raw: BytesMut,
    plaintext: BytesMut,
    state: RxState,
    hdr: [u8; 5],
    rx_closed: bool,
    tx_closed: bool,
}

impl<S: tokio::io::AsyncRead + Unpin> UtlsStream<S> {
    /// 处理一条完整记录的解密与分发；Ok(false) = 无应用数据（continue 循环）
    fn handle_record(&mut self) -> Result<bool> {
        let len = u16::from_be_bytes([self.hdr[3], self.hdr[4]]) as usize;
        let outer = self.hdr[0];
        if outer == REC_ALERT {
            // 明文告警（对端可能未加密发送——TLS 1.3 后期告警应加密，兼容处理）
            self.rx_closed = true;
            return Ok(false);
        }
        if outer != REC_APPDATA {
            return Err(Error::ProtoMsg(format!("utls: 数据期记录类型 {outer}")));
        }
        let h = self.hdr;
        let body = self.raw.split_to(len);
        let (inner, data) = self.rx.open(&h, &body)?;
        match inner {
            REC_APPDATA => {
                self.plaintext.extend_from_slice(&data);
                Ok(true)
            }
            REC_HANDSHAKE => {
                // KeyUpdate / NewSessionTicket
                if !data.is_empty() && data[0] == HS_KEY_UPDATE {
                    let req = data.get(1).copied().unwrap_or(0);
                    self.rx.update()?;
                    if req == 1 {
                        self.tx.update()?;
                    }
                }
                Ok(false)
            }
            REC_ALERT => {
                if data.len() >= 2 && data[1] == 0 {
                    self.rx_closed = true;
                    Ok(false)
                } else {
                    Err(Error::ProtoMsg(format!("utls: 对端告警 {}", data[1])))
                }
            }
            t => Err(Error::ProtoMsg(format!("utls: 记录内类型 {t}"))),
        }
    }

    fn try_progress(&mut self) -> Result<bool> {
        loop {
            match &self.state {
                RxState::Header { need, got } => {
                    if self.raw.len() < *need - *got {
                        return Ok(false);
                    }
                    let take = need - got;
                    let chunk = self.raw.split_to(take);
                    self.hdr[*got..*need].copy_from_slice(&chunk);
                    let len = u16::from_be_bytes([self.hdr[3], self.hdr[4]]) as usize;
                    if len > MAX_CIPHERTEXT {
                        return Err(Error::Proto("utls: 记录超长"));
                    }
                    self.state = RxState::Body { len, got: 0 };
                }
                RxState::Body { len, got } => {
                    if self.raw.len() < len - got {
                        return Ok(false);
                    }
                    // handle_record 消费整个 body
                    self.state = RxState::Header { need: 5, got: 0 };
                    match self.handle_record()? {
                        // 有应用数据：交给上层
                        true => return Ok(true),
                        // 非数据记录（NST/KeyUpdate/close_notify）：继续处理
                        // 缓冲中可能还有完整记录，不能让上层去等 socket
                        false => continue,
                    }
                }
            }
        }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for UtlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        loop {
            if !this.plaintext.is_empty() {
                let n = this.plaintext.len().min(buf.remaining());
                buf.put_slice(&this.plaintext[..n]);
                this.plaintext.advance(n);
                return Poll::Ready(Ok(()));
            }
            if this.rx_closed {
                return Poll::Ready(Ok(()));
            }
            // 推进状态机（可能产出明文）
            match this.try_progress() {
                Ok(true) => continue,
                Ok(false) => {}
                Err(e) => {
                    this.rx_closed = true;
                    return Poll::Ready(Err(io::Error::other(e.to_string())));
                }
            }
            // 需要更多原始字节
            this.raw.reserve(16 * 1024);
            let spare = this.raw.spare_capacity_mut();
            let mut rb = tokio::io::ReadBuf::uninit(spare);
            match Pin::new(&mut this.conn).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
            let filled = rb.filled().len();
            if filled == 0 {
                this.rx_closed = true;
                return Poll::Ready(Ok(()));
            }
            unsafe { this.raw.advance_mut(filled) };
        }
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for UtlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if this.tx_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "utls: 已关闭",
            )));
        }
        // 16KB 分帧加密后一次性写出
        let mut out = Vec::with_capacity(buf.len() + 64);
        let mut offset = 0;
        while offset < buf.len() {
            let end = (offset + 16 * 1024).min(buf.len());
            let mut content = BytesMut::from(&buf[offset..end]);
            content.put_u8(REC_APPDATA); // inner type
            let clen = content.len() + 16;
            let mut rec = [REC_APPDATA, 0x03, 0x03, 0, 0];
            rec[3] = (clen >> 8) as u8;
            rec[4] = clen as u8;
            this.tx
                .seal(&rec, &mut content)
                .map_err(|e| io::Error::other(e.to_string()))?;
            out.extend_from_slice(&rec);
            out.extend_from_slice(&content);
            offset = end;
        }
        if buf.is_empty() {
            let mut content = BytesMut::new();
            content.put_u8(REC_APPDATA);
            let clen = content.len() + 16;
            let mut rec = [REC_APPDATA, 0x03, 0x03, 0, 0];
            rec[3] = (clen >> 8) as u8;
            rec[4] = clen as u8;
            this.tx
                .seal(&rec, &mut content)
                .map_err(|e| io::Error::other(e.to_string()))?;
            out.extend_from_slice(&rec);
            out.extend_from_slice(&content);
        }
        let mut off = 0usize;
        while off < out.len() {
            let n = std::task::ready!(Pin::new(&mut this.conn).poll_write(cx, &out[off..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "utls: 写入 0 字节",
                )));
            }
            off += n;
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        // 发 close_notify：inner type 21，payload [1, 0]（尽力而为，一次）
        if !this.tx_closed {
            this.tx_closed = true;
            let mut content = BytesMut::from(&[0x01u8, 0x00][..]);
            content.put_u8(REC_ALERT);
            let clen = content.len() + 16;
            let mut rec = [REC_APPDATA, 0x03, 0x03, 0, 0];
            rec[3] = (clen >> 8) as u8;
            rec[4] = clen as u8;
            let mut out = Vec::new();
            if this.tx.seal(&rec, &mut content).is_ok() {
                out.extend_from_slice(&rec);
                out.extend_from_slice(&content);
            }
            let mut off = 0usize;
            while off < out.len() {
                let n = std::task::ready!(Pin::new(&mut this.conn).poll_write(cx, &out[off..]))?;
                if n == 0 {
                    break;
                }
                off += n;
            }
        }
        Pin::new(&mut this.conn).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn init_log() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init();
    }

    /// 解析 CH 扩展类型序列（测试辅助）
    fn ch_ext_types(ch: &ClientHello) -> Vec<u16> {
        let body = &ch.record[5..];
        let mut c = Cursor::new(body);
        let _ty = c.u8();
        let _len = ((c.b[c.pos] as usize) << 16) | ((c.b[c.pos + 1] as usize) << 8) | c.b[c.pos + 2] as usize;
        c.take(3).unwrap(); // 跳过长度字段（消息内容在后续字段里逐段消费）
        let _ = c.u16().unwrap(); // legacy_version
        c.take(32).unwrap(); // random
        let sid_len = c.u8().unwrap() as usize;
        c.take(sid_len).unwrap();
        let suites_len = c.u16().unwrap() as usize;
        c.take(suites_len).unwrap(); // 前缀即字节长度
        let _ = c.u8().unwrap(); // compression length
        let _ = c.u8().unwrap(); // null
        let ext_len = c.u16().unwrap() as usize;
        let exts = c.take(ext_len).unwrap();
        let mut e = Cursor::new(exts);
        let mut out = Vec::new();
        while !e.done() {
            let ty = e.u16().unwrap();
            let l = e.u16().unwrap() as usize;
            e.take(l).unwrap();
            out.push(ty);
        }
        out
    }











    /// 测试辅助：从 CH 记录中删除指定扩展并修正各长度



    #[test]
    fn ch_profile_chrome_like() {
        let ch = build_ch("example.com", &["h2".into(), "http/1.1".into()]).unwrap();
        // 记录头 + 握手类型
        assert_eq!(&ch.record[..4], &[REC_HANDSHAKE, 0x03, 0x01, 0x01]);
        // 扩展顺序（Chrome）
        assert_eq!(
            ch_ext_types(&ch),
            vec![0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43]
        );
        // 套件表（JA3 关键：1301 开头 + 14 项）
        assert_eq!(&CH_SUITES[..6], &[0x13, 0x01, 0x13, 0x02, 0x13, 0x03]);
        assert_eq!(CH_SUITES.len(), 28);
    }

    #[tokio::test]
    async fn e2e_echo_self_signed() {
        init_log();
        // rustls 服务端（rcgen 自签）+ echo
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem().into_bytes();
        let key_pem = cert.key_pair.serialize_pem().into_bytes();
        let _ = std::fs::write(std::env::temp_dir().join("utls_cert.pem"), &cert_pem);
        let _ = std::fs::write(std::env::temp_dir().join("utls_key.pem"), &key_pem);
        let acceptor = crate::tls::tls_acceptor(&cert_pem, &key_pem).unwrap();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = l.accept().await else { break };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(s).await else { return };
                    let mut b = vec![0u8; 32 * 1024];
                    loop {
                        let n = match tls.read(&mut b).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        if tls.write_all(&b[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut s = match utls_connect(
            tcp,
            "localhost",
            &UtlsConfig {
                fingerprint: Fingerprint::Chrome,
                server_name: Some("localhost".into()),
                alpn: Vec::new(),
                skip_cert_verify: true,
            },
        )
        .await
        {
            Ok(s) => s,
            Err(e) => panic!("utls 握手失败: {e}"),
        };

        // 小包
        s.write_all(b"hello-utls").await.unwrap();
        let mut buf = [0u8; 10];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello-utls");

        // 大包（跨多记录分帧 + 对端分片回读）
        let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        s.write_all(&payload).await.unwrap();
        let mut got = Vec::with_capacity(payload.len());
        let mut rb = [0u8; 64 * 1024];
        while got.len() < payload.len() {
            let n = s.read(&mut rb).await.unwrap();
            assert!(n > 0, "对端提前关闭");
            got.extend_from_slice(&rb[..n]);
        }
        assert_eq!(got, payload, "300KB 回显应逐字节一致");

        s.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn e2e_alpn_negotiated() {
        // 带 ALPN 的服务端：验证 ALPN 提议路径（EE/握手正常完成）
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem().into_bytes();
        let key_pem = cert.key_pair.serialize_pem().into_bytes();
        let certs: Vec<CertificateDer<'_>> =
            rustls_pemfile::certs(&mut &cert_pem[..]).map(|c| c.unwrap()).collect();
        let key = rustls_pemfile::private_key(&mut &key_pem[..]).unwrap().unwrap();
        let mut sc = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        sc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(sc));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let mut tls = acceptor.accept(s).await.unwrap();
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
            let mut b = [0u8; 64];
            let n = tls.read(&mut b).await.unwrap();
            let _ = tls.write_all(&b[..n]).await;
        });

        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut s = utls_connect(
            tcp,
            "localhost",
            &UtlsConfig {
                fingerprint: Fingerprint::Chrome,
                server_name: Some("localhost".into()),
                alpn: vec!["h2".into(), "http/1.1".into()],
                skip_cert_verify: true,
            },
        )
        .await
        .unwrap();
        s.write_all(b"alpn-ok").await.unwrap();
        let mut buf = [0u8; 7];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"alpn-ok");
    }

    #[tokio::test]
    async fn e2e_fingerprint_config_error() {
        assert!(Fingerprint::parse("chrome").is_ok());
        assert!(Fingerprint::parse("firefox").is_err());
    }
}


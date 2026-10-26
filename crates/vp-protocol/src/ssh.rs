//! ssh 出站（SSH-2.0 传输层 + direct-tcpip 通道）。
//!
//! 算法面（最小集，与 OpenSSH 默认配置交集）：
//! - kex: curve25519-sha256（RFC 8731）
//! - 主机密钥: ssh-ed25519
//! - 加密: chacha20-poly1305@openssh.com（openssh PROTOCOL.cipher 扩展：
//!   长度与载荷双 chacha20 实例 + poly1305，nonce = 包序号 LE64）
//! - 认证: password 或未加密 OpenSSH 格式 ed25519 私钥（publickey）
//! - 通道: direct-tcpip（RFC 4254），含窗口流控（WINDOW_ADJUST）
//!
//! 参考 RFC 4251/4253/4254。rekey/严格 KEX 不支持（明确报错）。

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use vp_common::{DstAddr, Error, Result};
use vp_config::SshCfg;
use vp_core::session::Session;
use vp_core::stream::ProxyStream;
use vp_core::Outbound;

use vp_transport as transport;

const MSG_DISCONNECT: u8 = 1;
const MSG_IGNORE: u8 = 2;
const MSG_UNIMPLEMENTED: u8 = 3;
const MSG_DEBUG: u8 = 4;
const MSG_SERVICE_REQUEST: u8 = 5;
const MSG_SERVICE_ACCEPT: u8 = 6;
const MSG_EXT_INFO: u8 = 7;
const MSG_KEXINIT: u8 = 20;
const MSG_NEWKEYS: u8 = 21;
const MSG_KEX_ECDH_INIT: u8 = 30;
const MSG_KEX_ECDH_REPLY: u8 = 31;
const MSG_USERAUTH_REQUEST: u8 = 50;
const MSG_USERAUTH_FAILURE: u8 = 51;
const MSG_USERAUTH_SUCCESS: u8 = 52;
// 全局请求：客户端场景仅忽略（不回复），常量保留作协议文档
#[allow(dead_code)]
const MSG_GLOBAL_REQUEST: u8 = 80;
#[allow(dead_code)]
const MSG_REQUEST_FAILURE: u8 = 82;
const MSG_CHANNEL_OPEN: u8 = 90;
const MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
const MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
const MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
const MSG_CHANNEL_DATA: u8 = 94;
const MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
const MSG_CHANNEL_EOF: u8 = 96;
const MSG_CHANNEL_CLOSE: u8 = 97;
const MSG_CHANNEL_REQUEST: u8 = 98;
#[allow(dead_code)]
const MSG_CHANNEL_FAILURE: u8 = 100;

const CLIENT_BANNER: &str = "SSH-2.0-VP_Core_0.1";
const MAX_PACKET: usize = 512 * 1024;
const BLOCK: usize = 8; // 无密码阶段块对齐（chacha 为流密码，同样用 8）
const CHANNEL_WINDOW: u32 = 2 * 1024 * 1024;
const CHANNEL_MAX_PACKET: u32 = 32768;
/// 本地窗口消费过半即回 WINDOW_ADJUST
const ADJUST_THRESHOLD: u32 = CHANNEL_WINDOW / 2;

// ---------------------------------------------------------------------------
// 线格式原语
// ---------------------------------------------------------------------------

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend((s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend(v.to_be_bytes());
}

fn put_mpint(out: &mut Vec<u8>, b: &[u8]) {
    let mut v = b.to_vec();
    if !v.is_empty() && v[0] & 0x80 != 0 {
        v.insert(0, 0);
    }
    put_string(out, &v);
}

/// 线格式游标
struct Cur<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Self {
        Cur { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.b.len() {
            return Err(Error::Proto("ssh: 包越界"));
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    #[allow(dead_code)] // 测试服务端使用
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn string(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

// ---------------------------------------------------------------------------
// chacha20（djb 变体：64 位计数器 + 64 位 nonce，openssh 所用）
// ---------------------------------------------------------------------------

fn chacha20_block(key: &[u8; 32], counter: u64, nonce: &[u8; 8]) -> [u8; 64] {
    const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
    let mut s = [0u32; 16];
    s[..4].copy_from_slice(&SIGMA);
    for i in 0..8 {
        s[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    s[12] = counter as u32;
    s[13] = (counter >> 32) as u32;
    s[14] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
    s[15] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
    let mut w = s;
    for _ in 0..10 {
        // 列轮
        qr(&mut w, 0, 4, 8, 12);
        qr(&mut w, 1, 5, 9, 13);
        qr(&mut w, 2, 6, 10, 14);
        qr(&mut w, 3, 7, 11, 15);
        // 对角轮
        qr(&mut w, 0, 5, 10, 15);
        qr(&mut w, 1, 6, 11, 12);
        qr(&mut w, 2, 7, 8, 13);
        qr(&mut w, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&w[i].wrapping_add(s[i]).to_le_bytes());
    }
    out
}

fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

fn chacha20_xor(key: &[u8; 32], counter: u64, nonce: &[u8; 8], data: &mut [u8]) {
    let mut ctr = counter;
    for chunk in data.chunks_mut(64) {
        let ks = chacha20_block(key, ctr, nonce);
        for (b, k) in chunk.iter_mut().zip(ks.iter()) {
            *b ^= k;
        }
        ctr += 1;
    }
}

fn poly1305_tag(key: &[u8], data: &[u8]) -> [u8; 16] {
    use poly1305::Poly1305;
    use universal_hash::KeyInit;
    let key = universal_hash::Key::<Poly1305>::from_slice(key);
    let tag = Poly1305::new(key).compute_unpadded(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_slice());
    out
}

/// chacha20-poly1305@openssh.com 包加密（单向，双端各持独立实例）
struct SshCipher {
    k1: [u8; 32], // 长度加密
    k2: [u8; 32], // 载荷 + poly key
    seq: u64,
}

impl SshCipher {
    fn new(keys64: &[u8]) -> Self {
        SshCipher {
            k1: keys64[..32].try_into().unwrap(),
            k2: keys64[32..64].try_into().unwrap(),
            seq: 0,
        }
    }

    fn seal(&mut self, payload: &[u8]) -> Vec<u8> {
        // 组 [padlen][payload][padding]，包长 = 1 + payload + pad（不含长度字段）
        let base = 1 + payload.len();
        let mut pad = BLOCK - (base % BLOCK);
        if pad < 4 {
            pad += BLOCK;
        }
        let pkt_len = base + pad;
        let mut body = Vec::with_capacity(pkt_len);
        body.push(pad as u8);
        body.extend_from_slice(payload);
        body.resize(pkt_len, 0);

        let nonce = self.seq.to_le_bytes();
        let mut len_enc = (pkt_len as u32).to_be_bytes();
        chacha20_xor(&self.k1, 0, &nonce, &mut len_enc);
        chacha20_xor(&self.k2, 1, &nonce, &mut body);
        let poly = chacha20_block(&self.k2, 0, &nonce);
        let mut mac_input = Vec::with_capacity(4 + body.len());
        mac_input.extend_from_slice(&len_enc);
        mac_input.extend_from_slice(&body);
        let tag = poly1305_tag(&poly[0..32], &mac_input);
        let mut out = Vec::with_capacity(4 + body.len() + 16);
        out.extend_from_slice(&len_enc);
        out.extend_from_slice(&body);
        out.extend_from_slice(&tag);
        self.seq += 1;
        out
    }

    fn open_len(&self, enc_len: &[u8; 4]) -> Result<usize> {
        let nonce = self.seq.to_le_bytes();
        let mut l = *enc_len;
        chacha20_xor(&self.k1, 0, &nonce, &mut l);
        let len = u32::from_be_bytes(l) as usize;
        if len > MAX_PACKET {
            return Err(Error::ProtoMsg(format!("ssh: 包过长 {len}")));
        }
        Ok(len)
    }

    fn open_body(&mut self, enc_len: &[u8; 4], enc_body: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.seq.to_le_bytes();
        let poly = chacha20_block(&self.k2, 0, &nonce);
        let mut mac_input = Vec::with_capacity(4 + enc_body.len());
        mac_input.extend_from_slice(enc_len);
        mac_input.extend_from_slice(enc_body);
        let expect = poly1305_tag(&poly[0..32], &mac_input);
        if expect.as_slice() != tag {
            return Err(Error::Proto("ssh: 包认证失败（密钥/流错位）"));
        }
        let mut body = enc_body.to_vec();
        chacha20_xor(&self.k2, 1, &nonce, &mut body);
        self.seq += 1;
        Ok(body)
    }
}

/// 组包：[u32 长度][pad_len][payload][padding]，对齐 BLOCK，padding ≥ 4
fn make_packet(payload: &[u8]) -> Vec<u8> {
    let base = 4 + 1 + payload.len();
    let mut pad = BLOCK - (base % BLOCK);
    if pad < 4 {
        pad += BLOCK;
    }
    let pkt_len = 1 + payload.len() + pad;
    let mut out = Vec::with_capacity(4 + pkt_len);
    out.extend((pkt_len as u32).to_be_bytes());
    out.push(pad as u8);
    out.extend_from_slice(payload);
    out.resize(4 + pkt_len, 0);
    out
}

/// 明文阶段读写（async；握手期专用）
async fn read_plain_packet<R: AsyncRead + Unpin>(io: &mut R) -> Result<Vec<u8>> {
    let mut l = [0u8; 4];
    io.read_exact(&mut l).await?;
    let len = u32::from_be_bytes(l) as usize;
    if len > MAX_PACKET || len < 2 {
        return Err(Error::ProtoMsg(format!("ssh: 明文包长度非法 {len}")));
    }
    let mut body = vec![0u8; len];
    io.read_exact(&mut body).await?;
    let pad = body[0] as usize;
    if pad + 1 > len {
        return Err(Error::Proto("ssh: padding 越界"));
    }
    Ok(body[1..len - pad].to_vec())
}

async fn write_plain_packet<W: AsyncWrite + Unpin>(io: &mut W, payload: &[u8]) -> Result<()> {
    io.write_all(&make_packet(payload)).await?;
    io.flush().await?;
    Ok(())
}

/// 加密阶段读（async；握手尾声与服务端共用）
async fn read_cipher_packet<R: AsyncRead + Unpin>(io: &mut R, rx: &mut SshCipher) -> Result<Vec<u8>> {
    let mut enc_len = [0u8; 4];
    io.read_exact(&mut enc_len).await?;
    let len = rx.open_len(&enc_len)?;
    if len < 2 {
        return Err(Error::ProtoMsg(format!("ssh: 加密包长度非法 {len}")));
    }
    let mut enc_body = vec![0u8; len + 16];
    io.read_exact(&mut enc_body).await?;
    let (b, tag) = enc_body.split_at(len);
    let (enc_body, tag) = (b, tag);
    let body = rx.open_body(&enc_len, enc_body, tag)?;
    let pad = body[0] as usize;
    if pad + 1 > body.len() {
        return Err(Error::Proto("ssh: padding 越界"));
    }
    Ok(body[1..body.len() - pad].to_vec())
}

async fn write_cipher_packet<W: AsyncWrite + Unpin>(io: &mut W, tx: &mut SshCipher, payload: &[u8]) -> Result<()> {
    io.write_all(&tx.seal(payload)).await?;
    io.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// KEX
// ---------------------------------------------------------------------------

fn kexinit_payload() -> Vec<u8> {
    let mut cookie = [0u8; 16];
    vp_common::rand_bytes(&mut cookie);
    let mut p = vec![MSG_KEXINIT];
    p.extend_from_slice(&cookie);
    for list in [
        "curve25519-sha256,curve25519-sha256@libssh.org", // kex
        "ssh-ed25519",                                     // hostkey
        "chacha20-poly1305@openssh.com",                   // enc c2s
        "chacha20-poly1305@openssh.com",                   // enc s2c
        "",                                                // mac c2s（AEAD 内置）
        "",                                                // mac s2c
        "none",                                            // comp c2s
        "none",                                            // comp s2c
        "",                                                // lang c2s
        "",                                                // lang s2c
    ] {
        put_string(&mut p, list.as_bytes());
    }
    p.push(0); // first_kex_packet_follows
    put_u32(&mut p, 0); // reserved
    p
}

/// 密钥派生：HASH(K || H || X || session_id)，不足则 HASH(K || H || Ki || sid) 续
fn derive_key(k_mpint: &[u8], h: &[u8], ch: u8, session_id: &[u8], need: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(need + 32);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < need {
        let mut d = Vec::with_capacity(k_mpint.len() + h.len() + session_id.len() + 64);
        d.extend_from_slice(k_mpint);
        d.extend_from_slice(h);
        if prev.is_empty() {
            d.push(ch);
        } else {
            d.extend_from_slice(&prev);
        }
        d.extend_from_slice(session_id);
        prev = sha256(&d).to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(need);
    out
}

fn hostkey_fingerprint(ks: &[u8]) -> String {
    use base64::Engine;
    format!("SHA256:{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(sha256(ks)))
}

/// 解析未加密 OpenSSH 格式 ed25519 私钥（openssh-key-v1，kdf=none）
fn parse_ed25519_private_key(pem: &str) -> Result<(Vec<u8>, [u8; 32])> {
    use base64::Engine;
    let body: String = pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|_| Error::Config("ssh: 私钥 base64 解码失败".into()))?;
    if !der.starts_with(b"openssh-key-v1\x00") {
        return Err(Error::Config("ssh: 仅支持 OpenSSH 格式（openssh-key-v1）ed25519 私钥".into()));
    }
    let mut c = Cur::new(&der);
    c.take(15)?;
    let cipher = c.string()?;
    let _kdf = c.string()?;
    let _kdfopts = c.string()?;
    let nkeys = c.u32()?;
    if nkeys != 1 {
        return Err(Error::Config("ssh: 仅支持单密钥私钥文件".into()));
    }
    let pubkey = c.string()?.to_vec();
    let section = c.string()?;
    if cipher != b"none" {
        return Err(Error::Config("ssh: 私钥已加密（bcrypt KDF），请提供无口令私钥".into()));
    }
    let mut s = Cur::new(section);
    let check1 = s.u32()?;
    let check2 = s.u32()?;
    if check1 != check2 {
        return Err(Error::Config("ssh: 私钥校验字段不一致".into()));
    }
    let ty = s.string()?;
    if ty != b"ssh-ed25519" {
        return Err(Error::ProtoMsg(format!(
            "ssh: 仅支持 ed25519 私钥，实际 {}",
            String::from_utf8_lossy(ty)
        )));
    }
    let seed = s.string()?;
    if seed.len() != 32 {
        return Err(Error::Proto("ssh: ed25519 种子长度非法"));
    }
    Ok((pubkey, seed.try_into().unwrap()))
}

// ---------------------------------------------------------------------------
// 出站
// ---------------------------------------------------------------------------

pub struct SshOutbound {
    name: Arc<str>,
    server: String,
    port: u16,
    username: String,
    password: Option<String>,
    private_key: Option<String>,
    host_key: Option<String>,
}

impl SshOutbound {
    pub fn new(cfg: &SshCfg) -> Result<Self> {
        Self::internal_new(None, cfg)
    }

    pub fn new_named(name: &str, cfg: &SshCfg) -> Result<Self> {
        Self::internal_new(Some(name), cfg)
    }

    fn internal_new(name: Option<&str>, cfg: &SshCfg) -> Result<Self> {
        if cfg.password.is_none() && cfg.private_key.is_none() {
            return Err(Error::Config("ssh 出站需要 password 或 private-key".into()));
        }
        Ok(SshOutbound {
            name: name.unwrap_or("ssh").into(),
            server: cfg.server.clone(),
            port: cfg.port,
            username: cfg.username.clone(),
            password: cfg.password.clone(),
            private_key: cfg.private_key.clone(),
            host_key: cfg.host_key.clone(),
        })
    }

    async fn connect_io(&self, dst: &DstAddr) -> Result<SshStream<Box<dyn ProxyStream>>> {
        let mut io: Box<dyn ProxyStream> =
            transport::dial(&self.server, self.port, &transport::TransportConfig::default()).await?;

        // 1. 版本交换
        io.write_all(format!("{CLIENT_BANNER}\r\n").as_bytes()).await?;
        let mut v_s = String::new();
        for _ in 0..16 {
            let mut line = Vec::with_capacity(64);
            loop {
                let mut b = [0u8; 1];
                io.read_exact(&mut b).await?;
                if b[0] == b'\n' {
                    break;
                }
                if b[0] != b'\r' {
                    line.push(b[0]);
                }
                if line.len() > 255 {
                    return Err(Error::Proto("ssh: banner 行过长"));
                }
            }
            let l = String::from_utf8_lossy(&line).to_string();
            if l.starts_with("SSH-") {
                v_s = l;
                break;
            }
        }
        if v_s.is_empty() {
            return Err(Error::Proto("ssh: 未收到版本串"));
        }

        // 2. KEXINIT 交换
        let i_c = kexinit_payload();
        write_plain_packet(&mut io, &i_c).await?;
        let i_s = read_plain_packet(&mut io).await?;
        if i_s.first() != Some(&MSG_KEXINIT) {
            return Err(Error::Proto("ssh: 未收到 KEXINIT"));
        }
        check_server_algos(&i_s)?;

        // 3. ECDH
        let rng = ring::rand::SystemRandom::new();
        let priv_key = ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::X25519, &rng)
            .map_err(|_| Error::Proto("ssh: x25519 生成失败"))?;
        let pk = priv_key
            .compute_public_key()
            .map_err(|_| Error::Proto("ssh: x25519 公钥失败"))?;
        let e: Vec<u8> = pk.as_ref().to_vec();

        let mut init = vec![MSG_KEX_ECDH_INIT];
        put_string(&mut init, &e);
        write_plain_packet(&mut io, &init).await?;

        let reply = read_plain_packet(&mut io).await?;
        if reply.first() != Some(&MSG_KEX_ECDH_REPLY) {
            return Err(Error::Proto("ssh: 未收到 KEX_ECDH_REPLY"));
        }
        let mut c = Cur::new(&reply[1..]);
        let k_s = c.string()?.to_vec();
        let f = c.string()?.to_vec();
        let sig = c.string()?.to_vec();
        if f.len() != 32 || k_s.is_empty() {
            return Err(Error::Proto("ssh: KEX 应答字段非法"));
        }
        if let Some(expect) = &self.host_key {
            verify_host_key(&k_s, expect)?;
        }

        let shared = ring::agreement::agree_ephemeral(
            priv_key,
            &ring::agreement::UnparsedPublicKey::new(&ring::agreement::X25519, &f),
            |s: &[u8]| Vec::from(s),
        )
        .map_err(|_| Error::Proto("ssh: x25519 共享密钥失败"))?;
        let mut k_mpint = Vec::new();
        put_mpint(&mut k_mpint, &shared);

        // 4. 交换哈希与签名校验
        let mut h_input = Vec::new();
        put_string(&mut h_input, CLIENT_BANNER.as_bytes());
        put_string(&mut h_input, v_s.as_bytes());
        put_string(&mut h_input, &i_c);
        put_string(&mut h_input, &i_s);
        put_string(&mut h_input, &k_s);
        put_string(&mut h_input, &e);
        put_string(&mut h_input, &f);
        put_string(&mut h_input, &k_mpint);
        let h = sha256(&h_input);

        verify_host_signature(&k_s, &h, &sig)?;

        let session_id = h;
        write_plain_packet(&mut io, &[MSG_NEWKEYS]).await?;
        let nk = read_plain_packet(&mut io).await?;
        if nk.first() != Some(&MSG_NEWKEYS) {
            return Err(Error::Proto("ssh: 未收到 NEWKEYS"));
        }

        let c2s = derive_key(&k_mpint, &h, b'C', &session_id, 64);
        let s2c = derive_key(&k_mpint, &h, b'D', &session_id, 64);
        let mut tx = SshCipher::new(&c2s);
        let mut rx = SshCipher::new(&s2c);

        // 5. 服务请求 + 认证
        let mut sr = vec![MSG_SERVICE_REQUEST];
        put_string(&mut sr, b"ssh-connection");
        write_cipher_packet(&mut io, &mut tx, &sr).await?;
        let acc = read_cipher_packet(&mut io, &mut rx).await?;
        if acc.first() != Some(&MSG_SERVICE_ACCEPT) {
            return Err(Error::Proto("ssh: 未收到 SERVICE_ACCEPT"));
        }

        match (&self.password, &self.private_key) {
            (Some(pw), _) => self.auth_password(&mut io, &mut tx, &mut rx, pw).await?,
            (None, Some(key)) => self.auth_publickey(&mut io, &mut tx, &mut rx, key, &session_id).await?,
            (None, None) => unreachable!(),
        }

        // 6. 打开 direct-tcpip 通道
        let mut open = vec![MSG_CHANNEL_OPEN];
        put_string(&mut open, b"direct-tcpip");
        put_u32(&mut open, 0); // 我方通道号
        put_u32(&mut open, CHANNEL_WINDOW);
        put_u32(&mut open, CHANNEL_MAX_PACKET);
        let host = match &dst.host {
            vp_common::addr::Host::Domain(d) => d.clone(),
            vp_common::addr::Host::Ip(ip) => ip.to_string(),
        };
        put_string(&mut open, host.as_bytes());
        put_u32(&mut open, dst.port as u32);
        put_string(&mut open, b"127.0.0.1");
        put_u32(&mut open, 0);
        write_cipher_packet(&mut io, &mut tx, &open).await?;

        let reply = read_cipher_packet(&mut io, &mut rx).await?;
        if reply.first() == Some(&MSG_CHANNEL_OPEN_FAILURE) {
            let mut c = Cur::new(&reply[1..]);
            let ch = c.u32()?;
            let reason = c.u32()?;
            let desc = c.string()?;
            return Err(Error::ProtoMsg(format!(
                "ssh: 通道打开失败 ch={ch} reason={reason}: {}",
                String::from_utf8_lossy(desc)
            )));
        }
        if reply.first() != Some(&MSG_CHANNEL_OPEN_CONFIRMATION) {
            return Err(Error::Proto("ssh: 未收到通道确认"));
        }
        let mut c = Cur::new(&reply[1..]);
        let _recipient = c.u32()?;
        let their_ch = c.u32()?;
        let remote_window = c.u32()?;

        Ok(SshStream::new(io, rx, tx, their_ch, remote_window))
    }

    async fn auth_password(
        &self,
        io: &mut Box<dyn ProxyStream>,
        tx: &mut SshCipher,
        rx: &mut SshCipher,
        password: &str,
    ) -> Result<()> {
        let mut req = vec![MSG_USERAUTH_REQUEST];
        put_string(&mut req, self.username.as_bytes());
        put_string(&mut req, b"ssh-connection");
        put_string(&mut req, b"password");
        req.push(0); // FALSE
        put_string(&mut req, password.as_bytes());
        write_cipher_packet(io, tx, &req).await?;
        let reply = read_cipher_packet(io, rx).await?;
        match reply.first() {
            Some(&MSG_USERAUTH_SUCCESS) => Ok(()),
            Some(&MSG_USERAUTH_FAILURE) => Err(Error::Proto("ssh: 密码认证被拒绝")),
            _ => { eprintln!("[dbg] auth reply: {reply:02x?}"); Err(Error::Proto("ssh: 认证应答异常")) }
        }
    }

    async fn auth_publickey(
        &self,
        io: &mut Box<dyn ProxyStream>,
        tx: &mut SshCipher,
        rx: &mut SshCipher,
        pem: &str,
        session_id: &[u8],
    ) -> Result<()> {
        let (pub_blob, seed) = parse_ed25519_private_key(pem)?;
        let keypair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed)
            .map_err(|_| Error::Config("ssh: ed25519 私钥解析失败".into()))?;

        let mut req = vec![MSG_USERAUTH_REQUEST];
        put_string(&mut req, self.username.as_bytes());
        put_string(&mut req, b"ssh-connection");
        put_string(&mut req, b"publickey");
        req.push(1); // TRUE（带签名）
        put_string(&mut req, b"ssh-ed25519");
        put_string(&mut req, &pub_blob);
        // 签名数据 = session_id || 请求报文（不含签名字段）
        let mut signed = session_id.to_vec();
        signed.extend_from_slice(&req);
        let mut sig_blob = Vec::new();
        put_string(&mut sig_blob, b"ssh-ed25519");
        put_string(&mut sig_blob, keypair.sign(&signed).as_ref());
        put_string(&mut req, &sig_blob);

        write_cipher_packet(io, tx, &req).await?;
        let reply = read_cipher_packet(io, rx).await?;
        match reply.first() {
            Some(&MSG_USERAUTH_SUCCESS) => Ok(()),
            Some(&MSG_USERAUTH_FAILURE) => Err(Error::Proto("ssh: 公钥认证被拒绝")),
            _ => Err(Error::Proto("ssh: 认证应答异常")),
        }
    }
}

fn namelist_has(list: &[u8], name: &[u8]) -> bool {
    list.split(|b| *b == b',').any(|n| n == name)
}

fn check_server_algos(i_s: &[u8]) -> Result<()> {
    // KEXINIT: cookie(16) + 10 个 name-list；只检查前 3 个关键列表
    let mut c = Cur::new(&i_s[1..]);
    c.take(16)?;
    let kex = c.string()?;
    if !namelist_has(kex, b"curve25519-sha256") && !namelist_has(kex, b"curve25519-sha256@libssh.org") {
        return Err(Error::Proto("ssh: 服务端不支持 curve25519-sha256"));
    }
    let hk = c.string()?;
    if !namelist_has(hk, b"ssh-ed25519") {
        return Err(Error::Proto("ssh: 服务端不支持 ssh-ed25519 主机密钥"));
    }
    Ok(())
}

fn verify_host_key(k_s: &[u8], expect: &str) -> Result<()> {
    let ok = if let Some(fp) = expect.strip_prefix("SHA256:") {
        fp == &hostkey_fingerprint(k_s)[7..]
    } else {
        expect.as_bytes() == k_s
    };
    if ok {
        Ok(())
    } else {
        Err(Error::ProtoMsg(format!(
            "ssh: 主机密钥不匹配（期望 {expect}，实际 {}）",
            hostkey_fingerprint(k_s)
        )))
    }
}

fn verify_host_signature(k_s: &[u8], h: &[u8; 32], sig: &[u8]) -> Result<()> {
    let mut c = Cur::new(k_s);
    let alg = c.string()?;
    let key = c.string()?;
    if alg != b"ssh-ed25519" || key.len() != 32 {
        return Err(Error::Proto("ssh: 主机密钥类型非法"));
    }
    let mut s = Cur::new(sig);
    let salg = s.string()?;
    let sval = s.string()?;
    if salg != b"ssh-ed25519" || sval.len() != 64 {
        return Err(Error::Proto("ssh: 签名格式非法"));
    }
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(h, sval)
        .map_err(|_| Error::Proto("ssh: 主机签名验证失败"))
}

// ---------------------------------------------------------------------------
// 客户端通道流（poll 状态机：单通道会话）
// ---------------------------------------------------------------------------

struct SshStream<S> {
    io: S,
    rx: SshCipher,
    tx: SshCipher,
    our_ch: u32,
    their_ch: u32,
    // 读状态
    hfill: usize,
    enc_len: [u8; 4],
    body: Vec<u8>,
    bfill: usize,
    in_body: bool,
    rbuf: Vec<u8>,
    rpos: usize,
    eof: bool,
    fatal: Option<String>,
    // 本地窗口：消费过半即回 WINDOW_ADJUST
    consumed: u32,
    // 写状态
    outq: VecDeque<Vec<u8>>,
    opos: usize,
    remote_window: u32,
    closed: bool,
}

impl<S> SshStream<S> {
    fn new(io: S, rx: SshCipher, tx: SshCipher, their_ch: u32, remote_window: u32) -> Self {
        SshStream {
            io,
            rx,
            tx,
            our_ch: 0,
            their_ch,
            hfill: 0,
            enc_len: [0; 4],
            body: Vec::new(),
            bfill: 0,
            in_body: false,
            rbuf: Vec::new(),
            rpos: 0,
            eof: false,
            fatal: None,
            consumed: 0,
            outq: VecDeque::new(),
            opos: 0,
            remote_window,
            closed: false,
        }
    }

    /// 处理完整报文；返回是否产生可读数据
    fn handle_msg(&mut self, payload: &[u8]) -> bool {
        if payload.is_empty() {
            return false;
        }
        match payload[0] {
            MSG_CHANNEL_DATA => {
                let mut c = Cur::new(&payload[1..]);
                let Ok(recipient) = c.u32() else { return false };
                let Ok(data) = c.string() else { return false };
                if recipient != self.our_ch {
                    return false;
                }
                self.rbuf.extend_from_slice(data);
                self.consumed += data.len() as u32;
                if self.consumed >= ADJUST_THRESHOLD {
                    let n = self.consumed;
                    self.consumed = 0;
                    let mut adj = vec![MSG_CHANNEL_WINDOW_ADJUST];
                    put_u32(&mut adj, self.their_ch);
                    put_u32(&mut adj, n);
                    self.enqueue_ctrl(&adj);
                }
                !data.is_empty()
            }
            MSG_CHANNEL_WINDOW_ADJUST => {
                let mut c = Cur::new(&payload[1..]);
                let (Ok(recipient), Ok(n)) = (c.u32(), c.u32()) else { return false };
                if recipient == self.our_ch {
                    self.remote_window = self.remote_window.saturating_add(n);
                }
                false
            }
            MSG_CHANNEL_EOF => {
                self.eof = true;
                false
            }
            MSG_CHANNEL_CLOSE => {
                self.eof = true;
                false
            }
            MSG_CHANNEL_OPEN_FAILURE => {
                self.fatal = Some("ssh: 通道被对端关闭".into());
                false
            }
            MSG_DISCONNECT => {
                let mut c = Cur::new(&payload[1..]);
                let reason = c.u32().unwrap_or(0);
                let desc = c.string().unwrap_or(b"");
                self.fatal = Some(format!(
                    "ssh: 对端断开 reason={reason}: {}",
                    String::from_utf8_lossy(desc)
                ));
                false
            }
            MSG_IGNORE | MSG_DEBUG | MSG_UNIMPLEMENTED | MSG_EXT_INFO | MSG_GLOBAL_REQUEST
            | MSG_CHANNEL_REQUEST | MSG_CHANNEL_EXTENDED_DATA => false,
            _ => false,
        }
    }

    fn enqueue_ctrl(&mut self, payload: &[u8]) {
        self.outq.push_back(self.tx.seal(payload));
    }

    /// 推进读状态机：解密下一个报文并分发
    fn pump_read(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncRead + Unpin,
    {
        if !self.in_body {
            while self.hfill < 4 {
                let mut rb = tokio::io::ReadBuf::new(&mut self.enc_len[self.hfill..]);
                match Pin::new(&mut self.io).poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) if rb.filled().is_empty() => {
                        self.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Ok(())) => self.hfill += rb.filled().len(),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            let len = self.rx.open_len(&self.enc_len).map_err(io::Error::other)?;
            if len < 2 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("ssh: 包长度非法 {len}"),
                )));
            }
            self.body = vec![0u8; len + 16];
            self.bfill = 0;
            self.in_body = true;
        }
        while self.bfill < self.body.len() {
            let mut rb = tokio::io::ReadBuf::new(&mut self.body[self.bfill..]);
            match Pin::new(&mut self.io).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) if rb.filled().is_empty() => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "ssh: 包体截断",
                    )));
                }
                Poll::Ready(Ok(())) => self.bfill += rb.filled().len(),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.in_body = false;
        self.hfill = 0;
        let len = self.body.len() - 16;
        let (enc_body, tag) = self.body.split_at(len);
        let payload = self
            .rx
            .open_body(&self.enc_len, enc_body, tag)
            .map_err(io::Error::other)?;
        let pad = payload[0] as usize;
        if pad + 1 > payload.len() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ssh: padding 越界",
            )));
        }
        self.handle_msg(&payload[1..payload.len() - pad]);
        Poll::Ready(Ok(()))
    }

    fn drive_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncWrite + Unpin,
    {
        while let Some(cur) = self.outq.front() {
            match Pin::new(&mut self.io).poll_write(cx, &cur[self.opos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "ssh: 写端关闭")));
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

impl<S: ProxyStream + Unpin> AsyncRead for SshStream<S> {
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
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, msg)));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            ready!(this.pump_read(cx))?;
        }
    }
}

impl<S: ProxyStream + Unpin> AsyncWrite for SshStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "ssh: 通道已关闭")));
        }
        if !this.outq.is_empty() {
            ready!(this.drive_out(cx))?;
        }
        if this.remote_window == 0 {
            return Poll::Pending;
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(CHANNEL_MAX_PACKET as usize).min(this.remote_window as usize);
        let mut pkt = vec![MSG_CHANNEL_DATA];
        put_u32(&mut pkt, this.their_ch);
        put_string(&mut pkt, &buf[..n]);
        this.remote_window -= n as u32;
        this.outq.push_back(this.tx.seal(&pkt));
        ready!(this.drive_out(cx))?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().drive_out(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.closed {
            this.closed = true;
            let mut close = vec![MSG_CHANNEL_CLOSE];
            put_u32(&mut close, this.their_ch);
            this.enqueue_ctrl(&close);
        }
        ready!(this.drive_out(cx))?;
        ready!(Pin::new(&mut this.io).poll_flush(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

#[async_trait]
impl Outbound for SshOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect_stream(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        let st = self.connect_io(dst).await?;
        Ok(Box::new(st))
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::{mpsc, Mutex};
    use tokio::time::{timeout, Duration};

    // ------------------------------------------------------------------
    // 密码学已知向量
    // ------------------------------------------------------------------

    #[test]
    fn chacha20_djb_differential() {
        // 与 RustCrypto chacha20（legacy 特性，djb 变体）差分对照
        use chacha20::ChaCha20Legacy;
        use cipher::{KeyIvInit, StreamCipher};
        for ctr in [0u64, 1, 7, 0x1234_5678] {
            for len in [0usize, 1, 63, 64, 65, 300] {
                let key = [7u8; 32];
                let nonce = [0xaau8; 8];
                let mut a = vec![0u8; len];
                vp_common::rand_bytes(&mut a);
                let mut b = a.clone();
                chacha20_xor(&key, ctr, &nonce, &mut a);
                let mut c = ChaCha20Legacy::new((&key).into(), (&nonce).into());
                // 语义对齐：O(1) 跳到第 ctr 个块
                use cipher::StreamCipherSeek;
                c.seek(ctr * 64);
                c.apply_keystream(&mut b);
                assert_eq!(a, b, "ctr={ctr} len={len}");
            }
        }
    }

    #[test]
    fn poly1305_rfc8439_vector() {
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let data = b"Cryptographic Forum Research Group";
        let tag = poly1305_tag(&key, data);
        let expect: [u8; 16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9,
        ];
        assert_eq!(tag, expect);
    }

    #[test]
    fn ed25519_private_key_parse() {
        // 构造未加密 openssh-key-v1 结构
        let seed = [9u8; 32];
        let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let mut blob = Vec::new();
        put_string(&mut blob, b"ssh-ed25519");
        put_string(&mut blob, pair.public_key().as_ref());
        let mut sec = Vec::new();
        sec.extend(0x11223344u32.to_be_bytes());
        sec.extend(0x11223344u32.to_be_bytes());
        put_string(&mut sec, b"ssh-ed25519");
        put_string(&mut sec, &seed);
        put_string(&mut sec, b"comment");
        let mut der = b"openssh-key-v1\x00".to_vec();
        put_string(&mut der, b"none");
        put_string(&mut der, b"none");
        put_string(&mut der, b"");
        put_u32(&mut der, 1);
        put_string(&mut der, &blob);
        put_string(&mut der, &sec);
        use base64::Engine;
        let pem = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(&der)
        );
        let (pub_out, seed_out) = parse_ed25519_private_key(&pem).unwrap();
        assert_eq!(pub_out, blob);
        assert_eq!(seed_out, seed);
    }

    // ------------------------------------------------------------------
    // 最小 SSH 服务端（自环 e2e；单通道场景，窗口固定 2MB）
    // ------------------------------------------------------------------

    struct TestSshServer {
        port: u16,
        fingerprint: String,
    }

    struct ServerWriter<W: AsyncWrite + Unpin> {
        io: W,
        tx: SshCipher,
    }

    impl<W: AsyncWrite + Unpin> ServerWriter<W> {
        async fn write(&mut self, payload: &[u8]) -> Result<()> {
            self.io.write_all(&self.tx.seal(payload)).await?;
            self.io.flush().await?;
            Ok(())
        }
    }

    async fn start_ssh_server(passwords: &[&str], echo_port: u16) -> TestSshServer {
        start_ssh_server_with_keys(passwords, &[], echo_port).await
    }

    async fn start_ssh_server_with_keys(
        passwords: &[&str],
        pubkeys: &[Vec<u8>],
        echo_port: u16,
    ) -> TestSshServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut seed = [0u8; 32];
        vp_common::rand_bytes(&mut seed);
        let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let mut k_s = Vec::new();
        put_string(&mut k_s, b"ssh-ed25519");
        put_string(&mut k_s, pair.public_key().as_ref());
        let fingerprint = hostkey_fingerprint(&k_s);
        let passwords: Vec<String> = passwords.iter().map(|s| s.to_string()).collect();
        let pubkeys: Vec<Vec<u8>> = pubkeys.to_vec();

        tokio::spawn(async move {
            loop {
                let Ok((io, _)) = listener.accept().await else { break };
                let k_s = k_s.clone();
                let passwords = passwords.clone();
                let pubkeys = pubkeys.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_ssh(io, echo_port, &k_s, &seed, &passwords, &pubkeys).await {
                        tracing::debug!("ssh test server 会话结束: {e}");
                    }
                });
            }
        });
        TestSshServer { port, fingerprint }
    }

    async fn serve_ssh(
        mut io: tokio::net::TcpStream,
        _echo_port: u16,
        k_s: &[u8],
        host_seed: &[u8; 32],
        passwords: &[String],
        pubkeys: &[Vec<u8>],
    ) -> Result<()> {
        // banner
        let mut v_c = String::new();
        loop {
            let mut b = [0u8; 1];
            io.read_exact(&mut b).await?;
            if b[0] == b'\n' {
                if v_c.starts_with("SSH-") {
                    break;
                }
                v_c.clear();
            } else if b[0] != b'\r' {
                v_c.push(b[0] as char);
            }
        }
        io.write_all(b"SSH-2.0-VP_Core_TestServer\r\n").await?;

        // kexinit
        let i_c = read_plain_packet(&mut io).await?;
        let i_s = kexinit_payload();
        write_plain_packet(&mut io, &i_s).await?;

        // ECDH INIT
        let msg = read_plain_packet(&mut io).await?;
        if msg.first() != Some(&MSG_KEX_ECDH_INIT) {
            return Err(Error::Proto("ssh-srv: 未收到 ECDH_INIT"));
        }
        let mut c = Cur::new(&msg[1..]);
        let e = c.string()?.to_vec();

        let rng = ring::rand::SystemRandom::new();
        let priv_key = ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::X25519, &rng)
            .map_err(|_| Error::Proto("ssh-srv: x25519 生成失败"))?;
        let pk = priv_key
            .compute_public_key()
            .map_err(|_| Error::Proto("ssh-srv: x25519 公钥失败"))?;
        let f: Vec<u8> = pk.as_ref().to_vec();
        let shared = ring::agreement::agree_ephemeral(
            priv_key,
            &ring::agreement::UnparsedPublicKey::new(&ring::agreement::X25519, &e),
            |s: &[u8]| Vec::from(s),
        )
        .map_err(|_| Error::Proto("ssh-srv: x25519 失败"))?;
        let mut k_mpint = Vec::new();
        put_mpint(&mut k_mpint, &shared);

        let mut h_input = Vec::new();
        put_string(&mut h_input, v_c.as_bytes());
        put_string(&mut h_input, b"SSH-2.0-VP_Core_TestServer");
        put_string(&mut h_input, &i_c);
        put_string(&mut h_input, &i_s);
        put_string(&mut h_input, k_s);
        put_string(&mut h_input, &e);
        put_string(&mut h_input, &f);
        put_string(&mut h_input, &k_mpint);
        let h = sha256(&h_input);

        let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(host_seed).unwrap();
        let mut sig_blob = Vec::new();
        put_string(&mut sig_blob, b"ssh-ed25519");
        put_string(&mut sig_blob, pair.sign(&h).as_ref());

        let mut reply = vec![MSG_KEX_ECDH_REPLY];
        put_string(&mut reply, k_s);
        put_string(&mut reply, &f);
        put_string(&mut reply, &sig_blob);
        write_plain_packet(&mut io, &reply).await?;
        write_plain_packet(&mut io, &[MSG_NEWKEYS]).await?;

        let s2c = derive_key(&k_mpint, &h, b'D', &h, 64);
        let c2s = derive_key(&k_mpint, &h, b'C', &h, 64);
        let nk = read_plain_packet(&mut io).await?;
        if nk.first() != Some(&MSG_NEWKEYS) {
            return Err(Error::Proto("ssh-srv: 未收到 NEWKEYS"));
        }
        let mut rx = SshCipher::new(&c2s);

        // 双向写共享一个 tx 密码器（序号连续）
        let (mut r, w) = io.into_split();
        let writer = Arc::new(Mutex::new(ServerWriter { io: w, tx: SshCipher::new(&s2c) }));
        let mut channels: HashMap<u32, mpsc::Sender<Vec<u8>>> = HashMap::new();
        let mut ch_counter: u32 = 0;
        let mut authed = false;

        loop {
            let pkt = match read_cipher_packet(&mut r, &mut rx).await {
                Ok(p) => p,
                Err(e) => {
                    return Err(e);
                }
            };
            match pkt.first().copied().unwrap_or(0) {
                MSG_SERVICE_REQUEST => {
                    let mut acc = vec![MSG_SERVICE_ACCEPT];
                    put_string(&mut acc, b"ssh-connection");
                    writer.lock().await.write(&acc).await?;
                }
                MSG_USERAUTH_REQUEST => {
                    let mut c = Cur::new(&pkt[1..]);
                    let _user = c.string()?;
                    let _svc = c.string()?;
                    let method = c.string()?.to_vec();
                    let ok = if method == b"password" {
                        let _flag = c.u8()?;
                        let pw = c.string()?;
                        passwords.iter().any(|p| p.as_bytes() == pw)
                    } else if method == b"publickey" {
                        // 签名数据 = session_id || 请求（至 sig 字符串前）
                        let _flag = c.u8()?;
                        let _alg = c.string()?;
                        let key = c.string()?.to_vec();
                        let signed_end = 1 + c.pos;
                        let sig = c.string()?.to_vec();
                        let mut sc = Cur::new(&sig);
                        let _salg = sc.string()?;
                        let sval = sc.string()?;
                        let mut signed = h.to_vec();
                        signed.extend_from_slice(&pkt[..signed_end.min(pkt.len())]);
                        // blob = string(alg) + string(raw 32B key)；ring 需要裸公钥
                        let raw_key = &key[key.len().saturating_sub(32)..];
                        let key_ok = pubkeys.iter().any(|pk| pk.as_slice() == key.as_slice());
                        let ver = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, raw_key)
                            .verify(&signed, sval);
                        key_ok && ver.is_ok()
                    } else {
                        false
                    };
                    if ok {
                        writer.lock().await.write(&[MSG_USERAUTH_SUCCESS]).await?;
                        authed = true;
                    } else {
                        let mut f = vec![MSG_USERAUTH_FAILURE];
                        put_string(&mut f, b"password");
                        f.push(0);
                        writer.lock().await.write(&f).await?;
                        return Err(Error::Proto("ssh-srv: 认证失败"));
                    }
                }
                MSG_CHANNEL_OPEN if authed => {
                    let mut c = Cur::new(&pkt[1..]);
                    let ty = c.string()?.to_vec();
                    let client_ch = c.u32()?;
                    if ty != b"direct-tcpip" {
                        let mut f = vec![MSG_CHANNEL_OPEN_FAILURE];
                        put_u32(&mut f, client_ch);
                        put_u32(&mut f, 3);
                        put_string(&mut f, b"unsupported");
                        put_string(&mut f, b"");
                        writer.lock().await.write(&f).await?;
                        continue;
                    }
                    let _win = c.u32()?;
                    let _maxpkt = c.u32()?;
                    let host = c.string()?.to_vec();
                    let port = c.u32()?;
                    let host_s = String::from_utf8_lossy(&host).to_string();
                    let dst = DstAddr::parse(&format!("{host_s}:{port}"))?;

                    let srv_ch = ch_counter;
                    ch_counter += 1;
                    let (tx_ch, mut rx_ch) = mpsc::channel::<Vec<u8>>(64);
                    channels.insert(client_ch, tx_ch);

                    let mut conf = vec![MSG_CHANNEL_OPEN_CONFIRMATION];
                    put_u32(&mut conf, client_ch);
                    put_u32(&mut conf, srv_ch);
                    put_u32(&mut conf, CHANNEL_WINDOW);
                    put_u32(&mut conf, CHANNEL_MAX_PACKET);
                    writer.lock().await.write(&conf).await?;

                    // 中继任务：目标 TCP → CHANNEL_DATA（经共享 writer）
                    let w = writer.clone();
                    let (dst_host, dst_port) = (dst.host.clone(), dst.port);
                    tokio::spawn(async move {
                        let Ok(mut target) =
                            tokio::net::TcpStream::connect((dst_host.to_string(), dst_port)).await
                        else {
                            return;
                        };
                        let mut b = vec![0u8; 16384];
                        let mut client_eof = false;
                        loop {
                            tokio::select! {
                                n = target.read(&mut b) => match n {
                                    Ok(0) | Err(_) => {
                                        let mut close = vec![MSG_CHANNEL_CLOSE];
                                        put_u32(&mut close, client_ch);
                                        let _ = w.lock().await.write(&close).await;
                                        break;
                                    }
                                    Ok(n) => {
                                        let mut d = vec![MSG_CHANNEL_DATA];
                                        put_u32(&mut d, client_ch);
                                        put_string(&mut d, &b[..n]);
                                        if w.lock().await.write(&d).await.is_err() {
                                            return;
                                        }
                                    }
                                },
                                r = rx_ch.recv(), if !client_eof => match r {
                                    Some(data) => {
                                        if target.write_all(&data).await.is_err() {
                                            return;
                                        }
                                    }
                                    None => {
                                        client_eof = true;
                                        let _ = target.shutdown().await;
                                    }
                                },
                            }
                        }
                    });
                }
                MSG_CHANNEL_DATA => {
                    let mut c = Cur::new(&pkt[1..]);
                    let recipient = c.u32()?;
                    let data = c.string()?.to_vec();
                    if let Some(tx_ch) = channels.get(&recipient) {
                        if tx_ch.send(data).await.is_err() {
                            channels.remove(&recipient);
                        }
                    }
                }
                MSG_CHANNEL_EOF | MSG_CHANNEL_CLOSE => {
                    let mut c = Cur::new(&pkt[1..]);
                    let recipient = c.u32()?;
                    channels.remove(&recipient);
                }
                MSG_DISCONNECT => return Ok(()),
                _ => {}
            }
        }
    }

    fn ssh_out(port: u16, password: &str, host_key: Option<String>) -> SshOutbound {
        SshOutbound::new(&SshCfg {
            server: "127.0.0.1".into(),
            port,
            username: "tester".into(),
            password: Some(password.into()),
            private_key: None,
            host_key,
        })
        .unwrap()
    }

    async fn echo_server() -> u16 {
        let l = std::sync::Arc::new(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap());
        let port = l.local_addr().unwrap().port();
        let l2 = l.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l2.accept().await else { break };
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
        port
    }

    #[tokio::test]
    async fn ssh_loopback() {
        let echo_port = echo_server().await;
        let srv = start_ssh_server(&["pw123"], echo_port).await;

        let out = ssh_out(srv.port, "pw123", Some(srv.fingerprint.clone()));
        let dst = DstAddr::new("127.0.0.1", echo_port);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = timeout(Duration::from_secs(5), out.connect_stream(&sess, &dst))
            .await
            .unwrap()
            .unwrap();

        s.write_all(b"ping-ssh").await.unwrap();
        let mut buf = [0u8; 8];
        timeout(Duration::from_secs(5), s.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"ping-ssh");

        // 大回显（跨 CHANNEL_DATA 分帧，逐字节一致）
        let big: Vec<u8> = (0..300_000u32).map(|i| (i.wrapping_mul(40503) >> 3) as u8).collect();
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
    async fn ssh_wrong_password() {
        let echo_port = echo_server().await;
        let srv = start_ssh_server(&["right"], echo_port).await;
        let out = ssh_out(srv.port, "wrong", None);
        let dst = DstAddr::new("127.0.0.1", echo_port);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let err = match timeout(Duration::from_secs(5), out.connect_stream(&sess, &dst)).await {
            Ok(Err(e)) => e,
            Ok(Ok(_)) => panic!("错误密码不应连接成功"),
            Err(_) => panic!("超时"),
        };
        assert!(err.to_string().contains("密码认证"), "{err}");
    }

    #[tokio::test]
    async fn ssh_host_key_mismatch() {
        let echo_port = echo_server().await;
        let srv = start_ssh_server(&["pw"], echo_port).await;
        let bad_fp = format!("SHA256:{}", "0".repeat(43));
        let out = ssh_out(srv.port, "pw", Some(bad_fp));
        let dst = DstAddr::new("127.0.0.1", echo_port);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let err = match timeout(Duration::from_secs(5), out.connect_stream(&sess, &dst)).await {
            Ok(Err(e)) => e,
            Ok(Ok(_)) => panic!("错误主机密钥不应连接成功"),
            Err(_) => panic!("超时"),
        };
        assert!(err.to_string().contains("主机密钥不匹配"), "{err}");
    }

    #[tokio::test]
    async fn ssh_publickey_auth() {
        let echo_port = echo_server().await;
        let seed = [42u8; 32];
        let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let mut pub_blob = Vec::new();
        put_string(&mut pub_blob, b"ssh-ed25519");
        put_string(&mut pub_blob, pair.public_key().as_ref());
        // 构造未加密 openssh-key-v1 PEM
        let mut sec = Vec::new();
        sec.extend(0x11223344u32.to_be_bytes());
        sec.extend(0x11223344u32.to_be_bytes());
        put_string(&mut sec, b"ssh-ed25519");
        put_string(&mut sec, &seed);
        put_string(&mut sec, b"");
        let mut der = b"openssh-key-v1\0".to_vec();
        put_string(&mut der, b"none");
        put_string(&mut der, b"none");
        put_string(&mut der, b"");
        put_u32(&mut der, 1);
        put_string(&mut der, &pub_blob);
        put_string(&mut der, &sec);
        use base64::Engine;
        let pem = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----
{}
-----END OPENSSH PRIVATE KEY-----
",
            base64::engine::general_purpose::STANDARD.encode(&der)
        );

        let srv = start_ssh_server_with_keys(&[], &[pub_blob.clone()], echo_port)
            .await;
        let out = SshOutbound::new(&SshCfg {
            server: "127.0.0.1".into(),
            port: srv.port,
            username: "tester".into(),
            password: None,
            private_key: Some(pem),
            host_key: None,
        })
        .unwrap();
        let dst = DstAddr::new("127.0.0.1", echo_port);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = timeout(Duration::from_secs(5), out.connect_stream(&sess, &dst))
            .await
            .unwrap()
            .unwrap();
        s.write_all(b"pubkey-echo").await.unwrap();
        let mut buf = [0u8; 11];
        timeout(Duration::from_secs(5), s.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"pubkey-echo");
    }

    #[test]
    fn ssh_uri_and_config() {
        let n = crate::sub::parse_uri("ssh://root:pw123@s.com:2222#ssh1").unwrap();
        assert_eq!(n.name(), "ssh1");
        let y = n.to_yaml();
        assert!(y.contains("type: ssh"), "{y}");
        assert!(y.contains("username: \"root\""));
        assert!(y.contains("password: \"pw123\""));
    }
}

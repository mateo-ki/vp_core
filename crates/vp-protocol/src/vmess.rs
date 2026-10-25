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
use vp_core::tunnel::{relay, RelayHook};
use vp_core::{Inbound, Outbound, ProxyStream};
use vp_crypto::ss::AeadChunkCodec;
use vp_crypto::vmess_kdf as kdf;
use vp_crypto::{AeadKind, AnyAead};

use crate::direct::DirectOutbound;
use vp_dns::Resolver;
use vp_transport as transport;

pub const OPT_CHUNK_STREAM: u8 = 0x01;
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
                Host::Ip(std::net::IpAddr::V4([buf[3], buf[4], buf[5], buf[6]].into())),
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
}

fn build_request_plaintext(r: &VmessRequest) -> Vec<u8> {
    let mut p = Vec::with_capacity(64);
    p.push(0x01); // version
    p.extend_from_slice(&r.body_iv);
    p.extend_from_slice(&r.body_key);
    p.push(r.resp_auth);
    p.push(OPT_CHUNK_STREAM);
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
    let _option = body[i];
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
    Ok(VmessRequest { body_key, body_iv, resp_auth, security, cmd, dst })
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
    let len_ct = len_aead.seal_nonce(&len_nonce12, &(plaintext.len() as u16).to_be_bytes(), &auth_id);

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
    let len_key =
        kdf::kdf16(cmd_key, &[kdf::SALT_HEADER_LEN_KEY.as_bytes(), auth_id, &nonce8]);
    let len_nonce =
        kdf::kdf_x(cmd_key, &[kdf::SALT_HEADER_LEN_IV.as_bytes(), auth_id, &nonce8], 12);
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
    let pay_key = kdf::kdf16(cmd_key, &[kdf::SALT_HEADER_KEY.as_bytes(), auth_id, &nonce8]);
    let pay_nonce =
        kdf::kdf_x(cmd_key, &[kdf::SALT_HEADER_IV.as_bytes(), auth_id, &nonce8], 12);
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

fn resp_keys(body_key: &[u8; 16], body_iv: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    (kdf::sha256_16(body_key), kdf::sha256_16(body_iv))
}

fn build_response_header(resp_auth: u8, resp_key: &[u8; 16], resp_iv: &[u8; 16]) -> Result<Vec<u8>> {
    let payload = [resp_auth, OPT_CHUNK_STREAM];
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

async fn read_response_header<S: AsyncRead + Unpin>(
    resp_auth_expect: u8,
    resp_key: &[u8; 16],
    resp_iv: &[u8; 16],
    io: &mut S,
) -> Result<()> {
    let mut len_ct = [0u8; 18];
    io.read_exact(&mut len_ct).await?;
    let len_key = kdf::kdf16(resp_key, &[kdf::SALT_RESP_LEN_KEY.as_bytes()]);
    let len_nonce = kdf::kdf_x(resp_iv, &[kdf::SALT_RESP_LEN_IV.as_bytes()], 12);
    let mut n12 = [0u8; 12];
    n12.copy_from_slice(&len_nonce);
    let aead = AnyAead::new(AeadKind::Aes128Gcm, &len_key)?;
    let len_pt = aead
        .open_nonce(&n12, &len_ct, b"")
        .map_err(|_| Error::Proto("vmess 响应头长度块解密失败"))?;
    let plen = u16::from_be_bytes([len_pt[0], len_pt[1]]) as usize;
    let mut pay_ct = vec![0u8; plen + 16];
    io.read_exact(&mut pay_ct).await?;
    let pay_key = kdf::kdf16(resp_key, &[kdf::SALT_RESP_KEY.as_bytes()]);
    let pay_nonce = kdf::kdf_x(resp_iv, &[kdf::SALT_RESP_IV.as_bytes()], 12);
    let mut pn12 = [0u8; 12];
    pn12.copy_from_slice(&pay_nonce);
    let pay_aead = AnyAead::new(AeadKind::Aes128Gcm, &pay_key)?;
    let payload = pay_aead
        .open_nonce(&pn12, &pay_ct, b"")
        .map_err(|_| Error::Proto("vmess 响应头解密失败"))?;
    if payload.len() < 2 || payload[0] != resp_auth_expect {
        return Err(Error::Proto("vmess 响应认证不匹配"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Body 流（AEAD 分块或明文+fnv 分块）
// ---------------------------------------------------------------------------

enum BodyCodec {
    Aead(AeadChunkCodec),
    Plain,
}

impl BodyCodec {
    fn new(security: Security, key16: &[u8; 16]) -> Result<Self> {
        Ok(match security {
            Security::Aes128Gcm | Security::ChaCha20 => {
                BodyCodec::Aead(AeadChunkCodec::from_aead(body_aead(security, key16)?))
            }
            Security::None => BodyCodec::Plain,
        })
    }

    fn seal_chunk(&mut self, payload: &[u8]) -> Vec<u8> {
        match self {
            BodyCodec::Aead(c) => c.seal_chunk(payload),
            BodyCodec::Plain => {
                let mut out = Vec::with_capacity(6 + payload.len());
                out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                out.extend_from_slice(&kdf::fnv1a32(payload).to_be_bytes());
                out.extend_from_slice(payload);
                out
            }
        }
    }

    fn try_open_chunk(&mut self, buf: &[u8]) -> Option<Result<(Vec<u8>, usize)>> {
        match self {
            BodyCodec::Aead(c) => c.try_open_chunk(buf),
            BodyCodec::Plain => {
                if buf.len() < 6 {
                    return None;
                }
                let plen = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                if buf.len() < 6 + plen {
                    return None;
                }
                let fnv = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
                let payload = &buf[6..6 + plen];
                if kdf::fnv1a32(payload) != fnv {
                    return Some(Err(Error::Proto("vmess 明文块 fnv 校验失败")));
                }
                Some(Ok((payload.to_vec(), 6 + plen)))
            }
        }
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
                    )))
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
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VmessStream<S> {
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
    cmd_key: [u8; 16],
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
        let t = crate::transport_of(
            cfg.tls,
            &cfg.server_name,
            cfg.skip_cert_verify,
            &cfg.network,
            &cfg.ws_opts,
        )?;
        Ok(VmessOutbound {
            name: name.unwrap_or("vmess").into(),
            server: cfg.server.clone(),
            port: cfg.port,
            cmd_key,
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
        };
        let pt = build_request_plaintext(&req);
        let header = seal_header(&self.cmd_key, &pt)?;
        use tokio::io::AsyncWriteExt;
        io.write_all(&header).await?;
        // 读取响应头
        let (resp_key, resp_iv) = resp_keys(&body_key, &body_iv);
        read_response_header(resp_auth[0], &resp_key, &resp_iv, &mut io).await?;
        let stream = VmessStream {
            inner: io,
            enc: BodyCodec::new(self.security, &body_key)?,
            dec: BodyCodec::new(self.security, &resp_key)?,
            raw: BytesMut::new(),
            pending: BytesMut::new(),
            out: BytesMut::new(),
            closed: false,
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
        self.handshake(underlying, dst).await
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
        // 响应头
        let (resp_key, resp_iv) = resp_keys(&req.body_key, &req.body_iv);
        let resp = build_response_header(req.resp_auth, &resp_key, &resp_iv)?;
        stream.write_all(&resp).await?;
        let client = VmessStream {
            inner: stream,
            enc: BodyCodec::new(req.security, &resp_key)?,
            dec: BodyCodec::new(req.security, &req.body_key)?,
            raw: BytesMut::new(),
            pending: BytesMut::new(),
            out: BytesMut::new(),
            closed: false,
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
        let server = VmessInbound::new("127.0.0.1", 0, "vm-srv", &[uuid.clone()]).unwrap();
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
            network: None,
            ws_opts: None,
            grpc_opts: None,
            udp: false,
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
        let server = VmessInbound::new("127.0.0.1", 0, "vm-srv", &[uuid.clone()]).unwrap();
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
            network: None,
            ws_opts: None,
            grpc_opts: None,
            udp: false,
        })
        .unwrap();
        let dst = DstAddr::ip("127.0.0.1".parse().unwrap(), 80);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        assert!(out.connect_stream(&sess, &dst).await.is_err());
    }
}

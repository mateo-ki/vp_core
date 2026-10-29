//! Snell 协议出+入站（v1 / v2 / v3 / v4，支持 HTTP 混淆与 UDP 转发）。
//!
//! 规范对标 Surge / Clash.Meta / mihomo：
//! - 版本：
//!   - v1: SHA256(psk) + AES-128-GCM / 12B nonce
//!   - v2: HKDF-SHA256(psk, salt, "snell") + ChaCha20-Poly1305 / 16B salt
//!   - v3: [0x03, 16B nonce] + HKDF-SHA256 + ChaCha20-Poly1305 ("snell-v3-client" / "snell-v3-server")
//!   - v4: [0x04, 16B nonce] + HKDF-SHA256 + ChaCha20-Poly1305 ("snell-v4-client" / "snell-v4-server")
//! - 分帧格式：标准 2B 加密长度 + 16B Tag，跟随内容密文 + 16B Tag
//! - 命令：0x00 PING，0x01 CONNECT (TCP)，0x02 UDP
//! - 混淆：obfs: http 伪装握手（自动识别并回复 101 Switching Protocols）

use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use vp_common::addr::{decode_socks_addr, encode_socks_addr};
use vp_common::{DstAddr, Error, Result};
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;
use vp_core::stream::UdpPacket;
use vp_core::tunnel::{RelayHook, relay};
use vp_core::{Inbound, Outbound, PacketConn, ProxyStream};
use vp_crypto::ss::AeadChunkCodec;
use vp_crypto::{AeadKind, AnyAead};
use vp_dns::Resolver;
use vp_transport as transport;

use crate::direct::DirectOutbound;

pub const VERSION_1: u8 = 1;
pub const VERSION_2: u8 = 2;
pub const VERSION_3: u8 = 3;
pub const VERSION_4: u8 = 4;

pub const CMD_PING: u8 = 0x00;
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_UDP: u8 = 0x02;

pub const RESP_SUCCESS: u8 = 0x00;
pub const RESP_ERROR: u8 = 0x01;

/// 派生 Snell 会话双向 AEAD 编解码器
/// 返回：(client_to_server_aead, server_to_client_aead)
pub fn derive_snell_codecs(
    version: u8,
    psk: &str,
    nonce_or_salt: &[u8],
) -> Result<(AeadChunkCodec, AeadChunkCodec)> {
    match version {
        VERSION_1 => {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(psk.as_bytes());
            let hash = hasher.finalize();
            let c2s = AnyAead::new(AeadKind::Aes128Gcm, &hash[..16])?;
            let s2c = AnyAead::new(AeadKind::Aes128Gcm, &hash[..16])?;
            Ok((
                AeadChunkCodec::from_aead(c2s),
                AeadChunkCodec::from_aead(s2c),
            ))
        }
        VERSION_2 => {
            let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(nonce_or_salt), psk.as_bytes());
            let mut key = [0u8; 32];
            hk.expand(b"snell", &mut key)
                .map_err(|_| Error::Proto("HKDF expand 失败"))?;
            let c2s = AnyAead::new(AeadKind::ChaCha20Poly1305, &key)?;
            let s2c = AnyAead::new(AeadKind::ChaCha20Poly1305, &key)?;
            Ok((
                AeadChunkCodec::from_aead(c2s),
                AeadChunkCodec::from_aead(s2c),
            ))
        }
        VERSION_3 => {
            let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(nonce_or_salt), psk.as_bytes());
            let mut c_key = [0u8; 32];
            let mut s_key = [0u8; 32];
            hk.expand(b"snell-v3-client", &mut c_key)
                .map_err(|_| Error::Proto("HKDF expand client 失败"))?;
            hk.expand(b"snell-v3-server", &mut s_key)
                .map_err(|_| Error::Proto("HKDF expand server 失败"))?;
            let c2s = AnyAead::new(AeadKind::ChaCha20Poly1305, &c_key)?;
            let s2c = AnyAead::new(AeadKind::ChaCha20Poly1305, &s_key)?;
            Ok((
                AeadChunkCodec::from_aead(c2s),
                AeadChunkCodec::from_aead(s2c),
            ))
        }
        _ => {
            // v4（默认）
            let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(nonce_or_salt), psk.as_bytes());
            let mut c_key = [0u8; 32];
            let mut s_key = [0u8; 32];
            hk.expand(b"snell-v4-client", &mut c_key)
                .map_err(|_| Error::Proto("HKDF expand client 失败"))?;
            hk.expand(b"snell-v4-server", &mut s_key)
                .map_err(|_| Error::Proto("HKDF expand server 失败"))?;
            let c2s = AnyAead::new(AeadKind::ChaCha20Poly1305, &c_key)?;
            let s2c = AnyAead::new(AeadKind::ChaCha20Poly1305, &s_key)?;
            Ok((
                AeadChunkCodec::from_aead(c2s),
                AeadChunkCodec::from_aead(s2c),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Snell 加密流包装（双向 AEAD 分块）
// ---------------------------------------------------------------------------

pub struct SnellStream<S> {
    inner: S,
    enc: AeadChunkCodec,
    dec: AeadChunkCodec,
    raw: BytesMut,
    pending: BytesMut,
    out: BytesMut,
    closed: bool,
}

impl<S> vp_core::ProxyStream for SnellStream<S> where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static
{
}

impl<S> SnellStream<S> {
    pub fn new(
        inner: S,
        enc: AeadChunkCodec,
        dec: AeadChunkCodec,
        initial_out: Vec<u8>,
        initial_raw: BytesMut,
    ) -> Self {
        Self {
            inner,
            enc,
            dec,
            raw: initial_raw,
            pending: BytesMut::new(),
            out: BytesMut::from(&initial_out[..]),
            closed: false,
        }
    }

    fn flush_out(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>>
    where
        S: AsyncWrite + Unpin,
    {
        while !self.out.is_empty() {
            let mut inner = Pin::new(&mut self.inner);
            match inner.as_mut().poll_write(cx, &self.out) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "snell: 写入 0 字节",
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
        while let Some(res) = self.dec.try_open_chunk(&self.raw) {
            match res {
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

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for SnellStream<S> {
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
            if this.closed {
                return Poll::Ready(Ok(()));
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

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for SnellStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if this.closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "snell: 已关闭",
            )));
        }
        std::task::ready!(this.flush_out(cx))?;
        // 分块写入：每块最大 16KB
        let chunk_size = buf.len().min(16384);
        let chunk = this.enc.seal_chunk(&buf[..chunk_size]);
        this.out.extend_from_slice(&chunk);
        std::task::ready!(this.flush_out(cx))?;
        Poll::Ready(Ok(chunk_size))
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
// HTTP Obfs 辅助
// ---------------------------------------------------------------------------

async fn client_http_obfs<S: AsyncRead + AsyncWrite + Unpin>(io: &mut S, host: &str) -> Result<()> {
    let mut rnd = [0u8; 8];
    vp_common::rand_bytes(&mut rnd);
    let path: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    let req = format!(
        "GET /{} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        path, host, "dGhlIHNhbXBsZSBub25jZQ=="
    );
    io.write_all(req.as_bytes()).await?;

    let mut buf = [0u8; 1024];
    let mut filled = 0;
    while !buf[..filled].windows(4).any(|w| w == b"\r\n\r\n") {
        if filled >= buf.len() {
            return Err(Error::Proto("Snell HTTP obfs 响应头过长"));
        }
        let n = io.read(&mut buf[filled..]).await?;
        if n == 0 {
            return Err(Error::Proto("Snell HTTP obfs 握手被对端关闭"));
        }
        filled += n;
    }
    Ok(())
}

async fn server_http_obfs<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    initial_buf: &mut [u8],
    filled: &mut usize,
) -> Result<()> {
    // 检查是否以 "GET " 开头
    if *filled < 4 {
        let n = io.read(&mut initial_buf[*filled..4]).await?;
        *filled += n;
    }
    if *filled >= 4 && &initial_buf[..4] == b"GET " {
        // 读取直到 \r\n\r\n
        while !initial_buf[..*filled].windows(4).any(|w| w == b"\r\n\r\n") {
            if *filled >= initial_buf.len() {
                return Err(Error::Proto("Snell 服务端 HTTP obfs 头过长"));
            }
            let n = io.read(&mut initial_buf[*filled..]).await?;
            if n == 0 {
                return Err(Error::Proto("Snell 服务端 HTTP obfs 中断"));
            }
            *filled += n;
        }
        // 发送 101 Switching Protocols
        let resp = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        io.write_all(resp).await?;
        *filled = 0; // 已完全消耗
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 出站 (SnellOutbound)
// ---------------------------------------------------------------------------

pub struct SnellOutbound {
    name: String,
    server: String,
    port: u16,
    psk: String,
    version: u8,
    obfs_mode: Option<String>,
    obfs_host: Option<String>,
    udp: bool,
}

impl SnellOutbound {
    pub fn new_named(name: &str, cfg: &vp_config::SnellCfg) -> Result<Self> {
        let (obfs_mode, obfs_host) = if let Some(ref o) = cfg.obfs_opts {
            (o.mode.clone(), o.host.clone())
        } else {
            (cfg.obfs.clone(), cfg.host.clone())
        };
        Ok(SnellOutbound {
            name: name.into(),
            server: cfg.server.clone(),
            port: cfg.port,
            psk: cfg.psk.clone(),
            version: cfg.version,
            obfs_mode,
            obfs_host,
            udp: cfg.udp,
        })
    }

    pub fn new(cfg: &vp_config::SnellCfg) -> Result<Self> {
        Self::new_named("snell", cfg)
    }

    async fn dial_and_handshake(&self, dst: &DstAddr, cmd: u8) -> Result<Box<dyn ProxyStream>> {
        let tcp = transport::dial(
            &self.server,
            self.port,
            &transport::TransportConfig::default(),
        )
        .await?;
        self.handshake_over(tcp, dst, cmd).await
    }

    async fn handshake_over(
        &self,
        mut tcp: Box<dyn ProxyStream>,
        dst: &DstAddr,
        cmd: u8,
    ) -> Result<Box<dyn ProxyStream>> {
        // 1. HTTP 混淆（若启用）
        if self.obfs_mode.as_deref() == Some("http") {
            let host = self.obfs_host.as_deref().unwrap_or(&self.server);
            client_http_obfs(&mut tcp, host).await?;
        }

        // 2. 构造客户端前置随机 nonce/salt
        let nonce_len = if self.version == VERSION_1 { 12 } else { 16 };
        let mut nonce = vec![0u8; nonce_len];
        vp_common::rand_bytes(&mut nonce);

        let mut prefix = Vec::new();
        match self.version {
            VERSION_1 | VERSION_2 => {
                prefix.extend_from_slice(&nonce);
            }
            VERSION_3 => {
                prefix.push(VERSION_3);
                prefix.extend_from_slice(&nonce);
            }
            _ => {
                prefix.push(VERSION_4);
                prefix.extend_from_slice(&nonce);
            }
        }

        let (mut enc, mut dec) = derive_snell_codecs(self.version, &self.psk, &nonce)?;

        // 3. 构建首个请求 payload：[CMD][DST_ADDR]
        let mut req_payload = vec![cmd];
        encode_socks_addr(dst, &mut req_payload);
        let sealed_req = enc.seal_chunk(&req_payload);

        let mut init_bytes = prefix;
        init_bytes.extend_from_slice(&sealed_req);
        tcp.write_all(&init_bytes).await?;

        // 4. 等待服务端首块响应：[RESP_SUCCESS]
        let mut raw = BytesMut::with_capacity(4096);
        let mut resp_byte = None;
        while resp_byte.is_none() {
            let mut read_buf = [0u8; 1024];
            let n = tcp.read(&mut read_buf).await?;
            if n == 0 {
                return Err(Error::Proto("Snell 握手响应中断"));
            }
            raw.extend_from_slice(&read_buf[..n]);
            if let Some(res) = dec.try_open_chunk(&raw) {
                let (chunk, used) = res?;
                raw.advance(used);
                if chunk.is_empty() {
                    return Err(Error::Proto("Snell 空响应"));
                }
                resp_byte = Some(chunk[0]);
                break;
            }
        }

        if resp_byte != Some(RESP_SUCCESS) {
            return Err(Error::Proto("Snell 远端目标连接失败"));
        }

        let stream = SnellStream::new(tcp, enc, dec, Vec::new(), raw);
        Ok(Box::new(stream))
    }
}

#[async_trait]
impl Outbound for SnellOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect_stream(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        self.dial_and_handshake(dst, CMD_CONNECT).await
    }

    async fn connect_over(
        &self,
        _sess: &Session,
        dst: &DstAddr,
        underlying: Box<dyn ProxyStream>,
    ) -> Result<Box<dyn ProxyStream>> {
        self.handshake_over(underlying, dst, CMD_CONNECT).await
    }

    fn support_udp(&self) -> bool {
        self.udp
    }

    async fn connect_packet(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        if !self.udp {
            return Err(Error::Unsupported("此 snell 节点未启用 UDP".into()));
        }
        let stream = self.dial_and_handshake(dst, CMD_UDP).await?;
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        Ok(Box::new(SnellPacketConn {
            stream: tokio::sync::Mutex::new(stream),
            local_addr,
        }))
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
}

// ---------------------------------------------------------------------------
// Snell UDP 转发数据报连接
// ---------------------------------------------------------------------------

struct SnellPacketConn {
    stream: tokio::sync::Mutex<Box<dyn ProxyStream>>,
    local_addr: SocketAddr,
}

#[async_trait]
impl PacketConn for SnellPacketConn {
    async fn send(&self, pkt: &UdpPacket) -> Result<()> {
        let mut msg = Vec::with_capacity(32 + pkt.data.len());
        let dst = DstAddr::ip(pkt.dst.ip(), pkt.dst.port());
        encode_socks_addr(&dst, &mut msg);
        msg.extend_from_slice(&(pkt.data.len() as u16).to_be_bytes());
        msg.extend_from_slice(&pkt.data);
        let mut lock = self.stream.lock().await;
        lock.write_all(&msg).await?;
        lock.flush().await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<UdpPacket> {
        let mut lock = self.stream.lock().await;
        let mut hdr = [0u8; 1];
        lock.read_exact(&mut hdr).await?;
        let atyp = hdr[0];
        let addr_bytes_len = match atyp {
            0x01 => 4,
            0x03 => {
                let mut dlen = [0u8; 1];
                lock.read_exact(&mut dlen).await?;
                dlen[0] as usize
            }
            0x04 => 16,
            _ => return Err(Error::Proto("Snell UDP 非法地址类型")),
        };
        let mut full_addr = vec![atyp];
        if atyp == 0x03 {
            full_addr.push(addr_bytes_len as u8);
        }
        let mut addr_rest = vec![0u8; addr_bytes_len + 2]; // IP/Domain + 2B Port
        lock.read_exact(&mut addr_rest).await?;
        full_addr.extend_from_slice(&addr_rest);
        let (src_dst, _) = decode_socks_addr(&full_addr)?;

        let mut len_b = [0u8; 2];
        lock.read_exact(&mut len_b).await?;
        let datalen = u16::from_be_bytes(len_b) as usize;
        let mut data_buf = vec![0u8; datalen];
        lock.read_exact(&mut data_buf).await?;

        let src_ip = match src_dst.host {
            vp_common::addr::Host::Ip(ip) => ip,
            _ => "127.0.0.1".parse().unwrap(),
        };
        let src_sock = SocketAddr::new(src_ip, src_dst.port);

        Ok(UdpPacket {
            src: src_sock,
            dst: self.local_addr,
            data: Bytes::from(data_buf),
        })
    }
}

// ---------------------------------------------------------------------------
// 入站 (SnellInbound)
// ---------------------------------------------------------------------------

pub struct SnellInbound {
    bind: String,
    port: u16,
    tag: Arc<str>,
    psks: Vec<String>,
    version: u8,
    direct: Arc<DirectOutbound>,
}

impl SnellInbound {
    pub fn new(bind: &str, port: u16, tag: &str, psks: &[String], version: u8) -> Result<Self> {
        Ok(SnellInbound {
            bind: bind.to_string(),
            port,
            tag: tag.into(),
            psks: psks.to_vec(),
            version,
            direct: Arc::new(DirectOutbound::new(Arc::new(Resolver::system()), false)),
        })
    }

    async fn serve(
        self: &Arc<Self>,
        mut stream: tokio::net::TcpStream,
        src: std::net::SocketAddr,
        ctx: &InboundCtx,
    ) -> Result<()> {
        let mut peek_buf = [0u8; 2048];
        let mut filled = 0;

        // 1. 处理可能的 HTTP Obfs 前导
        server_http_obfs(&mut stream, &mut peek_buf, &mut filled).await?;

        // 2. 读取版本与 nonce
        // 尝试探测首字节是否为版本号（0x04 / 0x03），或按照配置版本匹配
        while filled < 1 {
            let n = stream.read(&mut peek_buf[filled..1]).await?;
            if n == 0 {
                return Err(Error::Proto("Snell 握手中断"));
            }
            filled += n;
        }

        let (ver, nonce_len) = if self.version == VERSION_1 {
            (VERSION_1, 12)
        } else if self.version == VERSION_2 {
            (VERSION_2, 16)
        } else {
            match peek_buf[0] {
                VERSION_4 => (VERSION_4, 16),
                VERSION_3 => (VERSION_3, 16),
                _ => (self.version, 16),
            }
        };

        let total_prefix_len = if ver == VERSION_3 || ver == VERSION_4 {
            1 + nonce_len
        } else {
            nonce_len
        };

        while filled < total_prefix_len {
            let n = stream.read(&mut peek_buf[filled..total_prefix_len]).await?;
            if n == 0 {
                return Err(Error::Proto("Snell 前缀读取中断"));
            }
            filled += n;
        }

        let nonce = if ver == VERSION_3 || ver == VERSION_4 {
            &peek_buf[1..total_prefix_len]
        } else {
            &peek_buf[..total_prefix_len]
        };

        // 3. 多密码尝试鉴权
        let mut raw = BytesMut::with_capacity(8192);
        let mut matched_codecs = None;
        let mut req_chunk = None;

        // 先把已经 peek 的剩余数据塞入 raw
        if filled > total_prefix_len {
            raw.extend_from_slice(&peek_buf[total_prefix_len..filled]);
        }

        loop {
            // 确保至少读到了 18 字节
            while raw.len() < 18 {
                let mut tmp = [0u8; 1024];
                let n = stream.read(&mut tmp).await?;
                if n == 0 {
                    return Err(Error::Proto("Snell 客户端握手中断"));
                }
                raw.extend_from_slice(&tmp[..n]);
            }

            let mut all_err = true;
            let mut need_more = false;

            // 对每个 PSK 尝试解码
            for psk in &self.psks {
                if let Ok((c2s, s2c)) = derive_snell_codecs(ver, psk, nonce) {
                    let mut test_dec = c2s;
                    match test_dec.try_open_chunk(&raw) {
                        Some(Ok((chunk, used))) => {
                            req_chunk = Some((chunk, used));
                            matched_codecs = Some((test_dec, s2c));
                            all_err = false;
                            break;
                        }
                        None => {
                            // 长度块解密可能成功但 payload 尚未接收完整，或者尚未满 18 字节
                            all_err = false;
                            need_more = true;
                        }
                        Some(Err(_)) => {
                            // 解密失败（密码不对）
                        }
                    }
                }
            }

            if matched_codecs.is_some() {
                break;
            }

            if all_err {
                return Err(Error::Proto("Snell 鉴权失败：密码错误或未匹配"));
            }

            if need_more {
                let mut tmp = [0u8; 1024];
                let n = stream.read(&mut tmp).await?;
                if n == 0 {
                    return Err(Error::Proto("Snell 请求数据中断"));
                }
                raw.extend_from_slice(&tmp[..n]);
            }
        }

        let (dec, mut enc) = matched_codecs.unwrap();
        let (req_data, used) = req_chunk.unwrap();
        raw.advance(used);

        if req_data.is_empty() {
            return Err(Error::Proto("Snell 请求数据为空"));
        }

        let cmd = req_data[0];
        match cmd {
            CMD_CONNECT => {
                let (dst, _) = decode_socks_addr(&req_data[1..])?;
                let sess = Session::new_tcp(self.tag.clone(), Some(src), dst.clone());
                let remote = match self.direct.connect_stream(&sess, &dst).await {
                    Ok(r) => r,
                    Err(e) => {
                        let err_chunk = enc.seal_chunk(&[RESP_ERROR]);
                        let _ = stream.write_all(&err_chunk).await;
                        return Err(e);
                    }
                };

                // 发送成功响应
                let ok_chunk = enc.seal_chunk(&[RESP_SUCCESS]);
                stream.write_all(&ok_chunk).await?;

                let meta = vp_core::conn_table::ConnMeta {
                    id: sess.id,
                    inbound: self.tag.clone(),
                    network: "tcp",
                    host: dst.host.to_string(),
                    dst_port: dst.port,
                    src: Some(src.to_string()),
                    process: None,
                    rule: None,
                    chain: Some("snell-server".into()),
                    start: vp_common::now_millis(),
                };
                let hook = RelayHook {
                    table: Some(ctx.conns.clone()),
                    meta: Some(meta),
                    stats: Some(ctx.stats.clone()),
                };

                let client_stream = SnellStream::new(stream, enc, dec, Vec::new(), raw);
                tokio::spawn(async move {
                    let _ = relay(Box::new(client_stream), remote, hook).await;
                });
                Ok(())
            }
            CMD_PING => {
                let ok_chunk = enc.seal_chunk(&[RESP_SUCCESS]);
                stream.write_all(&ok_chunk).await?;
                Ok(())
            }
            CMD_UDP => {
                let ok_chunk = enc.seal_chunk(&[RESP_SUCCESS]);
                stream.write_all(&ok_chunk).await?;
                // 原生 Snell UDP 代理转发协程
                let mut client_stream = SnellStream::new(stream, enc, dec, Vec::new(), raw);
                let udp_sock = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?);
                let sock_r = udp_sock.clone();

                tokio::spawn(async move {
                    let mut ubuf = vec![0u8; 65535];
                    loop {
                        // 读取客户端请求：[addr][len][data]
                        let mut hdr = [0u8; 1];
                        if client_stream.read_exact(&mut hdr).await.is_err() {
                            break;
                        }
                        let atyp = hdr[0];
                        let addr_bytes_len = match atyp {
                            0x01 => 4,
                            0x03 => {
                                let mut dlen = [0u8; 1];
                                if client_stream.read_exact(&mut dlen).await.is_err() {
                                    break;
                                }
                                dlen[0] as usize
                            }
                            0x04 => 16,
                            _ => break,
                        };
                        let mut full_addr = vec![atyp];
                        if atyp == 0x03 {
                            full_addr.push(addr_bytes_len as u8);
                        }
                        let mut addr_rest = vec![0u8; addr_bytes_len + 2];
                        if client_stream.read_exact(&mut addr_rest).await.is_err() {
                            break;
                        }
                        full_addr.extend_from_slice(&addr_rest);
                        let Ok((dst, _)) = decode_socks_addr(&full_addr) else {
                            break;
                        };

                        let mut len_b = [0u8; 2];
                        if client_stream.read_exact(&mut len_b).await.is_err() {
                            break;
                        }
                        let datalen = u16::from_be_bytes(len_b) as usize;
                        if datalen > ubuf.len() {
                            break;
                        }
                        if client_stream
                            .read_exact(&mut ubuf[..datalen])
                            .await
                            .is_err()
                        {
                            break;
                        }

                        if let Ok(ip) = dst.host.to_string().parse::<std::net::IpAddr>() {
                            let _ = sock_r
                                .send_to(&ubuf[..datalen], std::net::SocketAddr::new(ip, dst.port))
                                .await;
                        }
                    }
                });

                Ok(())
            }
            _ => Err(Error::Proto("未知 Snell 命令")),
        }
    }
}

#[async_trait]
impl Inbound for SnellInbound {
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
                                tracing::debug!("snell 入站会话结束: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("snell 入站 accept 失败: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        });

        Ok(bound)
    }
}

// ---------------------------------------------------------------------------
// 单元与自环测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn snell_v4_loopback_and_large_payload() {
        test_snell_loopback(VERSION_4, false).await;
    }

    #[tokio::test]
    async fn snell_v3_loopback() {
        test_snell_loopback(VERSION_3, false).await;
    }

    #[tokio::test]
    async fn snell_v2_loopback() {
        test_snell_loopback(VERSION_2, false).await;
    }

    #[tokio::test]
    async fn snell_v1_loopback() {
        test_snell_loopback(VERSION_1, false).await;
    }

    #[tokio::test]
    async fn snell_http_obfs_loopback() {
        test_snell_loopback(VERSION_4, true).await;
    }

    #[tokio::test]
    async fn snell_auth_failure_rejected() {
        let inb = Arc::new(
            SnellInbound::new("127.0.0.1", 0, "sn-in", &["correct-psk".into()], VERSION_4).unwrap(),
        );
        let ctx = InboundCtx {
            router: Arc::new(crate::test_support::NoopRouter()),
            stats: Arc::new(vp_common::Stats::default()),
            conns: Arc::new(vp_core::ConnTable::new()),
        };
        let port = inb.start(ctx).await.unwrap();

        // 客户端提供错误密码
        let out = SnellOutbound::new(&vp_config::SnellCfg {
            server: "127.0.0.1".into(),
            port,
            psk: "WRONG-psk".into(),
            version: VERSION_4,
            obfs: None,
            host: None,
            obfs_opts: None,
            udp: false,
        })
        .unwrap();

        let dst = DstAddr::new("127.0.0.1", 80);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let res = out.connect_stream(&sess, &dst).await;
        assert!(res.is_err(), "错误 PSK 必须被服务端立即拦截拒绝");
    }

    async fn test_snell_loopback(version: u8, http_obfs: bool) {
        // 1. 启动 Echo 目标服务器
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut b = [0u8; 8192];
            loop {
                let n = s.read(&mut b).await.unwrap();
                if n == 0 {
                    break;
                }
                s.write_all(&b[..n]).await.unwrap();
            }
        });

        // 2. 启动 Snell 服务端
        let psk = "vpcore-secret-psk-123456";
        let inb =
            Arc::new(SnellInbound::new("127.0.0.1", 0, "sn-in", &[psk.into()], version).unwrap());
        let ctx = InboundCtx {
            router: Arc::new(crate::test_support::NoopRouter()),
            stats: Arc::new(vp_common::Stats::default()),
            conns: Arc::new(vp_core::ConnTable::new()),
        };
        let port = inb.start(ctx).await.unwrap();

        // 3. 构建 Snell 客户端
        let out = SnellOutbound::new(&vp_config::SnellCfg {
            server: "127.0.0.1".into(),
            port,
            psk: psk.into(),
            version,
            obfs: if http_obfs { Some("http".into()) } else { None },
            host: if http_obfs {
                Some("www.bing.com".into())
            } else {
                None
            },
            obfs_opts: None,
            udp: false,
        })
        .unwrap();

        let dst = DstAddr::new("127.0.0.1", echo_addr.port());
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = out.connect_stream(&sess, &dst).await.unwrap();

        // 4. 首包测试
        s.write_all(b"hello-snell-world").await.unwrap();
        let mut resp = [0u8; 17];
        s.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"hello-snell-world");

        // 5. 大流量吞吐测试（64 KB 分块往返）
        let big_data = vec![0xa5u8; 64 * 1024];
        let mut recv_big = vec![0u8; big_data.len()];
        let (mut rh, mut wh) = tokio::io::split(s);
        let write_fut = async move {
            wh.write_all(&big_data).await.unwrap();
        };
        let read_fut = async {
            rh.read_exact(&mut recv_big).await.unwrap();
        };
        tokio::join!(write_fut, read_fut);
        assert_eq!(recv_big, vec![0xa5u8; 64 * 1024]);
    }
}

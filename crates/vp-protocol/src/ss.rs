//! Shadowsocks 出站/入站（legacy AEAD + 2022-blake3，TCP）。

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tracing::warn;

use vp_common::addr::{decode_socks_addr, encode_socks_addr};
use vp_common::{DstAddr, Error, Result};
use vp_config::SsCfg;
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;
use vp_core::tunnel::{RelayHook, relay};
use vp_core::{Inbound, Outbound, PacketConn, ProxyStream};
use vp_crypto::ss::{AeadChunkCodec, Cipher};
use vp_transport as transport;

// ---------------------------------------------------------------------------
// 加密流
// ---------------------------------------------------------------------------

pub struct SsCryptoStream<S> {
    inner: S,
    cipher: Cipher,
    key: Vec<u8>,
    enc: Option<AeadChunkCodec>,
    dec: Option<AeadChunkCodec>,
    /// 是否需要从对端读取 salt（客户端方向）
    expect_peer_salt: bool,
    raw: BytesMut,
    pending: BytesMut,
    out: BytesMut,
    closed: bool,
}

impl<S> vp_core::ProxyStream for SsCryptoStream<S> where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static
{
}

impl<S> SsCryptoStream<S> {
    /// 客户端：立即发送自身 salt + 首块（目标地址），接收方向等待对端 salt
    pub fn new_client(
        inner: S,
        cipher: Cipher,
        key: Vec<u8>,
        first_payload: Vec<u8>,
    ) -> Result<Self> {
        let mut salt = vec![0u8; cipher.salt_len()];
        vp_common::rand_bytes(&mut salt);
        let sub = cipher.subkey(&key, &salt)?;
        let mut enc = AeadChunkCodec::new(&cipher, &sub)?;
        let mut out = BytesMut::from(&salt[..]);
        enc.seal_chunk_into_bytes(&first_payload, &mut out);
        Ok(SsCryptoStream {
            inner,
            cipher,
            key,
            enc: Some(enc),
            dec: None,
            expect_peer_salt: true,
            raw: BytesMut::new(),
            pending: BytesMut::new(),
            out,
            closed: false,
        })
    }

    /// 服务端：接收方向的 codec 已在外部消耗过首块（保留计数），发送方向使用自己的新 salt
    pub fn new_server(
        inner: S,
        cipher: Cipher,
        key: Vec<u8>,
        dec: AeadChunkCodec,
        initial_raw: BytesMut,
    ) -> Result<Self> {
        let mut own_salt = vec![0u8; cipher.salt_len()];
        vp_common::rand_bytes(&mut own_salt);
        let own_sub = cipher.subkey(&key, &own_salt)?;
        let enc = AeadChunkCodec::new(&cipher, &own_sub)?;
        Ok(SsCryptoStream {
            inner,
            cipher,
            key,
            enc: Some(enc),
            dec: Some(dec),
            expect_peer_salt: false,
            raw: initial_raw,
            pending: BytesMut::new(),
            out: BytesMut::from(&own_salt[..]),
            closed: false,
        })
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
                        "ss: 写入 0 字节",
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
        if self.dec.is_none() && self.expect_peer_salt {
            if self.raw.len() >= self.cipher.salt_len() {
                let salt = self.raw.split_to(self.cipher.salt_len()).to_vec();
                match self
                    .cipher
                    .subkey(&self.key, &salt)
                    .and_then(|sub| AeadChunkCodec::new(&self.cipher, &sub))
                {
                    Ok(c) => self.dec = Some(c),
                    Err(_) => self.closed = true,
                }
            } else {
                return;
            }
        }
        while let Some(dec) = self.dec.as_mut() {
            match dec.try_open_chunk(&self.raw) {
                None => break,
                Some(Ok((payload, used))) => {
                    self.raw.advance(used);
                    self.pending.extend_from_slice(&payload);
                }
                Some(Err(_)) => {
                    self.closed = true;
                    break;
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for SsCryptoStream<S> {
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

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for SsCryptoStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if this.closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "ss: 已关闭",
            )));
        }
        std::task::ready!(this.flush_out(cx))?;
        if let Some(enc) = this.enc.as_mut() {
            // SIP008 / RFC 规范：单块载荷上限 0x3FFF（16383 字节），高两位恒 0
            for chunk in buf.chunks(0x3FFF) {
                enc.seal_chunk_into_bytes(chunk, &mut this.out);
            }
        } else {
            this.out.extend_from_slice(buf);
        }
        let _ = this.flush_out(cx);
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
            if let Some(enc) = this.enc.as_mut() {
                // 0 长度块作为结束信号
                enc.seal_chunk_into_bytes(&[], &mut this.out);
            }
            this.closed = true;
        }
        let _ = this.flush_out(cx);
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// 出站
// ---------------------------------------------------------------------------

pub struct SsOutbound {
    name: Arc<str>,
    server: String,
    port: u16,
    cipher: Cipher,
    key: Vec<u8>,
    udp: bool,
    shadow_tls: Option<crate::shadowtls::ShadowTlsDial>,
}

impl SsOutbound {
    pub fn new_named(name: &str, cfg: &SsCfg) -> Result<Self> {
        Self::internal_new(Some(name), cfg)
    }

    pub fn new(cfg: &SsCfg) -> Result<Self> {
        Self::internal_new(None, cfg)
    }

    fn internal_new(name: Option<&str>, cfg: &SsCfg) -> Result<Self> {
        let cipher = Cipher::parse(&cfg.cipher)?;
        let shadow_tls = match cfg.plugin.as_deref() {
            Some(p) if p.contains("shadow-tls") => {
                let o = cfg.plugin_opts.as_ref().ok_or_else(|| {
                    Error::Config("shadow-tls 插件缺少 plugin-opts（host/password）".into())
                })?;
                // 客户端握手仅实现 v3（strict 模式）；v1/v2 明确报错而非神秘握手失败
                if let Some(v) = o.version {
                    if v != 3 {
                        return Err(Error::Config(format!(
                            "shadow-tls v{v} 暂不支持（内核仅实现 v3）"
                        )));
                    }
                }
                let host = o
                    .host
                    .clone()
                    .ok_or_else(|| Error::Config("shadow-tls plugin-opts 缺少 host".into()))?;
                let password = o
                    .password
                    .clone()
                    .ok_or_else(|| Error::Config("shadow-tls plugin-opts 缺少 password".into()))?;
                Some(crate::shadowtls::ShadowTlsDial {
                    host,
                    port: o.port.unwrap_or(443),
                    password,
                })
            }
            Some(p) => {
                warn!("ss 节点 plugin {p:?} 不支持（已忽略；支持 shadow-tls）");
                None
            }
            None => None,
        };
        let key = cipher.derive_key(&cfg.password)?;
        Ok(SsOutbound {
            name: name.unwrap_or("shadowsocks").into(),
            server: cfg.server.clone(),
            port: cfg.port,
            cipher,
            key,
            udp: cfg.udp,
            shadow_tls,
        })
    }

    fn first_payload(&self, dst: &DstAddr) -> Vec<u8> {
        let mut p = Vec::with_capacity(64);
        if self.cipher.is_2022 {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            p.extend_from_slice(&ts.to_be_bytes());
        }
        encode_socks_addr(dst, &mut p);
        p
    }

    async fn handshake<S>(&self, io: S, dst: &DstAddr) -> Result<Box<dyn ProxyStream>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Ok(Box::new(SsCryptoStream::new_client(
            io,
            self.cipher.clone(),
            self.key.clone(),
            self.first_payload(dst),
        )?))
    }
}

#[async_trait]
impl Outbound for SsOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect_stream(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        let tcp = transport::dial(
            &self.server,
            self.port,
            &transport::TransportConfig::default(),
        )
        .await?;
        let io = match &self.shadow_tls {
            Some(st) => {
                Box::new(crate::shadowtls::client_handshake(tcp, &st.password, &st.host).await?)
                    as Box<dyn ProxyStream>
            }
            None => tcp,
        };
        self.handshake(io, dst).await
    }

    async fn connect_over(
        &self,
        _sess: &Session,
        dst: &DstAddr,
        underlying: Box<dyn ProxyStream>,
    ) -> Result<Box<dyn ProxyStream>> {
        let io = match &self.shadow_tls {
            Some(st) => Box::new(
                crate::shadowtls::client_handshake(underlying, &st.password, &st.host).await?,
            ) as Box<dyn ProxyStream>,
            None => underlying,
        };
        self.handshake(io, dst).await
    }

    fn support_udp(&self) -> bool {
        self.udp
    }

    async fn connect_packet(&self, _sess: &Session, _dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        let conn = crate::udp_out::SsUdpConn::bind(
            &self.server,
            self.port,
            self.cipher.clone(),
            self.key.clone(),
        )
        .await?;
        Ok(Box::new(conn))
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
}

// ---------------------------------------------------------------------------
// 入站（自建服务端 + 自环测试）
// ---------------------------------------------------------------------------

pub struct SsInbound {
    bind: String,
    port: u16,
    tag: Arc<str>,
    cipher: Cipher,
    key: Vec<u8>,
    user_manager: Option<Arc<vp_core::UserManager>>,
    user_keys: Vec<(Arc<vp_core::UserAccount>, Vec<u8>)>,
    shadow_tls: Option<crate::shadowtls::ShadowTlsDial>,
    gate: Option<Arc<vp_core::InboundGate>>,
}

impl SsInbound {
    pub fn new(bind: &str, port: u16, tag: &str, cipher: &str, password: &str) -> Result<Self> {
        Self::new_with_shadow_tls(bind, port, tag, cipher, password, None)
    }

    /// 带 shadow-tls v3 外层伪装的入站（伪装流量转发至 host:port）。
    pub fn new_with_shadow_tls(
        bind: &str,
        port: u16,
        tag: &str,
        cipher: &str,
        password: &str,
        shadow_tls: Option<crate::shadowtls::ShadowTlsDial>,
    ) -> Result<Self> {
        Self::with_options(bind, port, tag, cipher, password, shadow_tls, None)
    }

    /// 完整选项构造器（支持多用户凭据识别与限速）
    pub fn with_options(
        bind: &str,
        port: u16,
        tag: &str,
        cipher: &str,
        default_password: &str,
        shadow_tls: Option<crate::shadowtls::ShadowTlsDial>,
        user_manager: Option<Arc<vp_core::UserManager>>,
    ) -> Result<Self> {
        Self::with_gate(
            bind,
            port,
            tag,
            cipher,
            default_password,
            shadow_tls,
            user_manager,
            None,
        )
    }

    /// 支持安全门禁与 RRL 防放大的构造器
    #[allow(clippy::too_many_arguments)]
    pub fn with_gate(
        bind: &str,
        port: u16,
        tag: &str,
        cipher: &str,
        default_password: &str,
        shadow_tls: Option<crate::shadowtls::ShadowTlsDial>,
        user_manager: Option<Arc<vp_core::UserManager>>,
        gate: Option<Arc<vp_core::InboundGate>>,
    ) -> Result<Self> {
        let cipher = Cipher::parse(cipher)?;

        let mut user_keys = Vec::new();
        if let Some(ref um) = user_manager {
            for u in um.all_users() {
                if let Ok(ukey) = cipher.derive_key(&u.secret) {
                    user_keys.push((u, ukey));
                }
            }
        }

        let key = if !default_password.is_empty() {
            cipher.derive_key(default_password)?
        } else if let Some(first_user) = user_keys.first() {
            first_user.1.clone()
        } else {
            return Err(Error::Config("ss listener 缺少有效密钥".into()));
        };

        Ok(SsInbound {
            bind: bind.to_string(),
            port,
            tag: tag.into(),
            cipher,
            key,
            user_manager,
            user_keys,
            shadow_tls,
            gate,
        })
    }

    pub fn user_manager(&self) -> Option<&Arc<vp_core::UserManager>> {
        self.user_manager.as_ref()
    }

    /// ss UDP 服务端：每包独立 salt；client→target 直连转发；回包重新加密
    #[allow(clippy::type_complexity)]
    async fn serve_udp(self: Arc<Self>, sock: tokio::net::UdpSocket) -> Result<()> {
        use std::collections::HashMap;
        let sock = Arc::new(sock);
        let mut buf = vec![0u8; 65535];
        let nat: Arc<std::sync::Mutex<HashMap<std::net::SocketAddr, Arc<tokio::net::UdpSocket>>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                continue;
            };
            // 门禁前置检查：未通过 GeoIP / ASN / 端口敲门过滤的直接丢弃
            if let Some(ref g) = self.gate {
                if !g.check_accept(from.ip()) {
                    continue;
                }
            }
            let salt_len = self.cipher.salt_len();
            if n <= salt_len {
                continue;
            }
            let salt = &buf[..salt_len];
            let chunk = &buf[salt_len..n];

            // 尝试单端口多用户 PSK 解密
            let mut matched_udp: Option<(Option<Arc<vp_core::UserAccount>>, Vec<u8>, Vec<u8>)> =
                None;
            if !self.user_keys.is_empty() {
                for (user, k) in &self.user_keys {
                    if user.is_quota_exceeded() {
                        continue;
                    }
                    let Ok(sub) = self.cipher.subkey(k, salt) else {
                        continue;
                    };
                    let Ok(mut codec) = AeadChunkCodec::new(&self.cipher, &sub) else {
                        continue;
                    };
                    if let Some(Ok((plain, _))) = codec.try_open_chunk(chunk) {
                        user.add_up(n as u64);
                        matched_udp = Some((Some(user.clone()), k.clone(), plain.to_vec()));
                        break;
                    }
                }
            } else if let Ok(sub) = self.cipher.subkey(&self.key, salt) {
                if let Ok(mut codec) = AeadChunkCodec::new(&self.cipher, &sub) {
                    if let Some(Ok((plain, _))) = codec.try_open_chunk(chunk) {
                        matched_udp = Some((None, self.key.clone(), plain.to_vec()));
                    }
                }
            }

            let (matched_user, use_key, plain) = match matched_udp {
                Some(m) => m,
                None => continue,
            };

            if let Some(ref g) = self.gate {
                g.mark_authenticated(from.ip());
            }

            let Ok((dst, used)) = decode_socks_addr(&plain) else {
                continue;
            };
            let payload = plain[used..].to_vec();

            // 客户端 → 目标 socket（每客户端一个，惰性创建；锁内不做 await）
            let existing = nat.lock().unwrap().get(&from).cloned();
            let (target, is_new) = match existing {
                Some(t) => (t, false),
                None => {
                    let t = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?);
                    let mut nat = nat.lock().unwrap();
                    match nat.get(&from) {
                        Some(prev) => (prev.clone(), false), // 并发竞争：他方先插入
                        None => {
                            nat.insert(from, t.clone());
                            (t, true)
                        }
                    }
                }
            };

            if is_new {
                let target = target.clone();
                let sock2 = sock.clone();
                let cipher = self.cipher.clone();
                let key = use_key;
                let nat2 = nat.clone();
                let client = from;
                let return_user = matched_user.clone();
                let self_gate = self.gate.clone();
                tokio::spawn(async move {
                    let mut rbuf = [0u8; 65535];
                    loop {
                        let recv = match tokio::time::timeout(
                            std::time::Duration::from_secs(300),
                            target.recv_from(&mut rbuf),
                        )
                        .await
                        {
                            Ok(r) => r,
                            Err(_) => break, // 空闲超时
                        };
                        let Ok((rn, rfrom)) = recv else { break };
                        if let Some(ref u) = return_user {
                            u.add_down(rn as u64);
                        }
                        // RRL 防放大检查：如果该客户端超速且未认证，按 RRL 丢弃
                        if let Some(ref g) = self_gate {
                            match g.check_rrl(client.ip()) {
                                vp_core::RrlDecision::Drop => continue,
                                vp_core::RrlDecision::Allow | vp_core::RrlDecision::Slip => {}
                            }
                        }
                        // 回包：[salt][chunk(socks addr + payload)]
                        let mut plain = Vec::with_capacity(rn + 24);
                        encode_socks_addr(&DstAddr::ip(rfrom.ip(), rfrom.port()), &mut plain);
                        plain.extend_from_slice(&rbuf[..rn]);
                        let mut salt = vec![0u8; cipher.salt_len()];
                        vp_common::rand_bytes(&mut salt);
                        let Ok(sub) = cipher.subkey(&key, &salt) else {
                            continue;
                        };
                        let Ok(mut codec) = AeadChunkCodec::new(&cipher, &sub) else {
                            continue;
                        };
                        let mut dgram = salt;
                        codec.seal_chunk_into(&plain, &mut dgram);
                        let _ = sock2.send_to(&dgram, client).await;
                    }
                    nat2.lock().unwrap().remove(&client);
                });
            }

            let dst_addr: std::net::SocketAddr = match &dst.host {
                vp_common::Host::Ip(ip) => std::net::SocketAddr::new(*ip, dst.port),
                vp_common::Host::Domain(d) => {
                    match tokio::net::lookup_host((d.as_str(), dst.port)).await {
                        Ok(mut it) => it
                            .next()
                            .unwrap_or(std::net::SocketAddr::new([127, 0, 0, 1].into(), dst.port)),
                        Err(_) => continue,
                    }
                }
            };
            let _ = target.send_to(&payload, dst_addr).await;
        }
    }

    #[allow(clippy::type_complexity)]
    async fn serve<S>(
        self: &Arc<Self>,
        mut stream: S,
        src: std::net::SocketAddr,
        ctx: &InboundCtx,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        // 读客户端 salt
        let mut salt = vec![0u8; self.cipher.salt_len()];
        stream.read_exact(&mut salt).await?;

        // 读首个分块并尝试解密匹配用户
        let mut raw = BytesMut::new();
        raw.reserve(16 * 1024);
        let n = stream.read_buf(&mut raw).await?;
        if n == 0 {
            return Err(Error::Proto("ss 入站: 首包中断"));
        }

        let mut matched: Option<(
            Option<Arc<vp_core::UserAccount>>,
            Vec<u8>,
            AeadChunkCodec,
            Vec<u8>,
            usize,
        )> = None;
        if !self.user_keys.is_empty() {
            for (user, k) in &self.user_keys {
                if user.is_quota_exceeded() {
                    continue;
                }
                let Ok(sub) = self.cipher.subkey(k, &salt) else {
                    continue;
                };
                let Ok(mut dec) = AeadChunkCodec::new(&self.cipher, &sub) else {
                    continue;
                };
                if let Some(Ok((payload, used))) = dec.try_open_chunk(&raw) {
                    matched = Some((Some(user.clone()), k.clone(), dec, payload, used));
                    break;
                }
            }
        } else {
            let sub = self.cipher.subkey(&self.key, &salt)?;
            let mut dec = AeadChunkCodec::new(&self.cipher, &sub)?;
            if let Some(Ok((payload, used))) = dec.try_open_chunk(&raw) {
                matched = Some((None, self.key.clone(), dec, payload, used));
            }
        }

        let (matched_user, use_key, dec, first, used) = match matched {
            Some(m) => m,
            None => return Err(Error::Proto("ss 入站: 身份验证失败或秘钥不匹配")),
        };
        if let Some(ref g) = self.gate {
            g.mark_authenticated(src.ip());
        }
        raw.advance(used);

        let addr_buf: &[u8] = if self.cipher.is_2022 {
            if first.len() < 8 {
                return Err(Error::Proto("ss 入站: 2022 首块缺时间戳"));
            }
            let ts = u64::from_be_bytes(first[..8].try_into().unwrap());
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if now.abs_diff(ts) > 60 {
                return Err(Error::Proto("ss 入站: 2022 时间戳超窗"));
            }
            &first[8..]
        } else {
            &first[..]
        };
        let (dst, used_addr) = decode_socks_addr(addr_buf)?;
        if addr_buf.len() > used_addr {
            raw.extend_from_slice(&addr_buf[used_addr..]);
        }

        // 策略路由决策
        let mut sess = Session::new_tcp(self.tag.clone(), Some(src), dst.clone());
        if let Some(ref u) = matched_user {
            sess.inbound_user = Some(u.username.clone());
        }
        let res = ctx.router.pick(&sess).await;
        let rule_tag = res.rule.as_ref().map(|r| r.rule.clone());
        let chain_tag = if res.outbound.name() != res.via.as_ref() {
            format!("{}[{}]", res.via, res.outbound.name())
        } else {
            res.outbound.name().to_string()
        };
        let remote = res.outbound.connect_stream(&sess, &dst).await?;

        let client = SsCryptoStream::new_server(stream, self.cipher.clone(), use_key, dec, raw)?;
        let meta = vp_core::conn_table::ConnMeta {
            id: sess.id,
            inbound: self.tag.clone(),
            network: "tcp",
            host: dst.host.to_string(),
            dst_port: dst.port,
            src: Some(src.to_string()),
            process: None,
            user: matched_user.as_ref().map(|u| u.username.clone()),
            rule: rule_tag,
            chain: Some(chain_tag.into()),
            start: vp_common::now_millis(),
        };
        let hook = RelayHook {
            table: Some(ctx.conns.clone()),
            meta: Some(meta),
            stats: Some(ctx.stats.clone()),
            user: matched_user.clone(),
            limiter: matched_user.as_ref().and_then(|u| u.limiter.clone()),
            brutal: matched_user.as_ref().and_then(|u| u.brutal_pacer.clone()),
        };
        tokio::spawn(async move {
            let _ = relay(Box::new(client), remote, hook).await;
        });
        Ok(())
    }
}

#[async_trait]
impl Inbound for SsInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, ctx: InboundCtx) -> Result<u16> {
        // TCP 与 UDP 必须同端口；随机端口撞车（Windows 动态端口范围）时整体重试
        let mut last_err: Option<std::io::Error> = None;
        let mut _held_udp = Vec::new();
        let mut _held_tcp = Vec::new();

        for attempt in 0..40 {
            let (listener, udp, bound) = if self.port == 0 {
                // Windows 下 UDP 端口权限更严格，先尝试绑定 UDP 随机端口
                let udp = match tokio::net::UdpSocket::bind((self.bind.as_str(), 0)).await {
                    Ok(u) => u,
                    Err(e) => {
                        last_err = Some(e);
                        tokio::time::sleep(std::time::Duration::from_millis(
                            5 + attempt as u64 * 10,
                        ))
                        .await;
                        continue;
                    }
                };
                let port = match udp.local_addr() {
                    Ok(a) => a.port(),
                    Err(e) => {
                        last_err = Some(e);
                        continue;
                    }
                };
                match tokio::net::TcpListener::bind((self.bind.as_str(), port)).await {
                    Ok(l) => (l, udp, port),
                    Err(e) => {
                        last_err = Some(e);
                        // 暂留 udp 避免下一次重试立即拿到同一个冲突端口
                        _held_udp.push(udp);
                        tokio::time::sleep(std::time::Duration::from_millis(
                            5 + attempt as u64 * 10,
                        ))
                        .await;
                        continue;
                    }
                }
            } else {
                use std::net::ToSocketAddrs;
                let addr = match (self.bind.as_str(), self.port).to_socket_addrs() {
                    Ok(mut it) => it.next().ok_or_else(|| {
                        Error::Config(format!("无法解析绑定地址 {}:{}", self.bind, self.port))
                    })?,
                    Err(e) => {
                        return Err(Error::Config(format!(
                            "无法解析绑定地址 {}:{}: {e}",
                            self.bind, self.port
                        )));
                    }
                };
                let listener = vp_transport::bind_tcp_listener(addr)?;
                let bound = listener.local_addr()?.port();
                match tokio::net::UdpSocket::bind((self.bind.as_str(), bound)).await {
                    Ok(u) => (listener, u, bound),
                    Err(e) => {
                        last_err = Some(e);
                        _held_tcp.push(listener);
                        tokio::time::sleep(std::time::Duration::from_millis(
                            5 + attempt as u64 * 10,
                        ))
                        .await;
                        continue;
                    }
                }
            };

            let this = self.clone();
            tokio::spawn(async move {
                if let Err(e) = this.serve_udp(udp).await {
                    warn!("ss udp 入站结束: {e}");
                }
            });
            let this = self.clone();
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, src)) => {
                            if let Some(ref g) = this.gate {
                                if !g.check_accept(src.ip()) {
                                    continue;
                                }
                            }
                            vp_transport::tune(&stream);
                            let this = this.clone();
                            let ctx = ctx.clone();
                            tokio::spawn(async move {
                                let handled = match &this.shadow_tls {
                                    Some(st) => {
                                        match crate::shadowtls::server_handshake(
                                            stream,
                                            &st.password,
                                            &st.host,
                                            st.port,
                                        )
                                        .await
                                        {
                                            Ok(wrapped) => this.serve(wrapped, src, &ctx).await,
                                            Err(
                                                crate::shadowtls::ServerHandshakeError::Fallback,
                                            ) => Ok(()),
                                            Err(e) => {
                                                warn!("shadowtls 入站握手失败: {e}");
                                                Ok(())
                                            }
                                        }
                                    }
                                    None => this.serve(stream, src, &ctx).await,
                                };
                                if let Err(e) = handled {
                                    warn!("ss 入站会话结束: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            warn!("ss 入站 accept 失败: {e}");
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        }
                    }
                }
            });
            return Ok(bound);
        }
        Err(vp_common::Error::Io(last_err.unwrap_or_else(|| {
            std::io::Error::other("udp bind 重试耗尽")
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// 起一个 ss 服务端 + echo 源站，客户端经 ss 出站往返
    async fn roundtrip(cipher: &str, password: &str) {
        let _ = tracing_subscriber::fmt::try_init();
        // echo 源站
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
        let server = SsInbound::new("127.0.0.1", 0, "ss-srv", cipher, password).unwrap();
        let port = Arc::new(server).start(ctx).await.unwrap();

        let out = SsOutbound::new(&SsCfg {
            server: "127.0.0.1".into(),
            port,
            cipher: cipher.into(),
            password: password.into(),
            udp: false,
            plugin: None,
            plugin_opts: None,
        })
        .unwrap();
        let dst = DstAddr::ip("127.0.0.1".parse().unwrap(), echo_addr.port());
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = out.connect_stream(&sess, &dst).await.unwrap();
        s.write_all(b"ping-ss").await.unwrap();
        let mut buf = [0u8; 7];
        use tokio::io::AsyncReadExt;
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-ss");
    }

    #[tokio::test]
    async fn ss_loopback_all_ciphers() {
        roundtrip("aes-128-gcm", "test-pass").await;
        roundtrip("aes-256-gcm", "test-pass").await;
        roundtrip("chacha20-ietf-poly1305", "test-pass").await;
    }

    #[tokio::test]
    async fn ss_loopback_2022() {
        use base64::Engine;
        let k128 = base64::engine::general_purpose::STANDARD.encode([7u8; 16]);
        let k256 = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
        roundtrip("2022-blake3-aes-128-gcm", &k128).await;
        roundtrip("2022-blake3-aes-256-gcm", &k256).await;
    }

    #[tokio::test]
    async fn test_ss_2022_server_multi_user() {
        use base64::Engine;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut b = [0u8; 1024];
            while let Ok(n) = s.read(&mut b).await {
                if n == 0 || s.write_all(&b[..n]).await.is_err() {
                    break;
                }
            }
        });

        let k1 = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        let k2 = base64::engine::general_purpose::STANDARD.encode([2u8; 16]);

        let user_mgr = Arc::new(vp_core::UserManager::new());
        let user1 = Arc::new(vp_core::UserAccount::new(
            "ss-user-1",
            k1.as_str(),
            Some(1024 * 1024),
            None,
        ));
        let user2 = Arc::new(vp_core::UserAccount::new(
            "ss-user-2",
            k2.as_str(),
            Some(1024 * 1024),
            None,
        ));
        user_mgr.add_user(user1.clone());
        user_mgr.add_user(user2.clone());

        let ctx = InboundCtx {
            router: Arc::new(crate::test_support::NoopRouter()),
            stats: Arc::new(vp_common::Stats::default()),
            conns: Arc::new(vp_core::ConnTable::new()),
        };

        let server = SsInbound::with_options(
            "127.0.0.1",
            0,
            "ss-2022-srv",
            "2022-blake3-aes-128-gcm",
            "",
            None,
            Some(user_mgr),
        )
        .unwrap();
        let port = Arc::new(server).start(ctx).await.unwrap();

        // 客户端 1 经 k1 连接
        let out1 = SsOutbound::new(&SsCfg {
            server: "127.0.0.1".into(),
            port,
            cipher: "2022-blake3-aes-128-gcm".into(),
            password: k1,
            udp: false,
            plugin: None,
            plugin_opts: None,
        })
        .unwrap();

        let dst = DstAddr::ip("127.0.0.1".parse().unwrap(), echo_addr.port());
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = out1.connect_stream(&sess, &dst).await.unwrap();
        s.write_all(b"msg-from-user1").await.unwrap();
        let mut buf = [0u8; 14];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"msg-from-user1");

        // 校验 user1 产生流量，user2 无流量
        let mut recorded = false;
        for _ in 0..20 {
            if user1.upload.load(std::sync::atomic::Ordering::Relaxed) > 0 {
                recorded = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(15)).await;
        }
        assert!(recorded);
        assert_eq!(user2.upload.load(std::sync::atomic::Ordering::Relaxed), 0);
    }
}

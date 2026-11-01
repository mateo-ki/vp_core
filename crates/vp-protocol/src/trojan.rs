//! Trojan 出入站（sha224 密码 + SOCKS 地址格式）。

use std::sync::Arc;

use async_trait::async_trait;
use sha2::Digest;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use vp_common::addr::{decode_socks_addr, encode_socks_addr};
use vp_common::{DstAddr, Error, Result};
use vp_config::TrojanCfg;
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;
use vp_core::tunnel::{RelayHook, relay};
use vp_core::{Inbound, Outbound, ProxyStream};

use crate::direct::DirectOutbound;
use vp_dns::Resolver;
use vp_transport as transport;

pub(crate) fn password_hash(pw: &str) -> [u8; 28] {
    let d: [u8; 28] = sha2::Sha224::digest(pw.as_bytes()).into();
    d
}

// ---------------------------------------------------------------------------
// 出站
// ---------------------------------------------------------------------------

pub struct TrojanOutbound {
    name: Arc<str>,
    server: String,
    port: u16,
    hash: [u8; 28],
    transport: transport::TransportConfig,
}

impl TrojanOutbound {
    pub fn new(cfg: &TrojanCfg) -> Result<Self> {
        Self::internal_new(None, cfg)
    }

    pub fn new_named(name: &str, cfg: &TrojanCfg) -> Result<Self> {
        Self::internal_new(Some(name), cfg)
    }

    fn internal_new(name: Option<&str>, cfg: &TrojanCfg) -> Result<Self> {
        let mut t = crate::transport_of_full(
            cfg.tls,
            &cfg.server_name,
            cfg.skip_cert_verify,
            &cfg.network,
            &cfg.ws_opts,
            &cfg.grpc_opts,
            &cfg.client_fingerprint,
            &cfg.reality_opts,
            &cfg.http_opts,
            &cfg.ech_opts,
        )?;
        t.alpn = cfg.alpn.clone().unwrap_or_default();
        Ok(TrojanOutbound {
            name: name.unwrap_or("trojan").into(),
            server: cfg.server.clone(),
            port: cfg.port,
            hash: password_hash(&cfg.password),
            transport: t,
        })
    }

    async fn handshake<S>(
        &self,
        mut io: S,
        dst: &DstAddr,
        initial: Option<&[u8]>,
    ) -> Result<Box<dyn ProxyStream>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static + ProxyStream,
    {
        let mut req = Vec::with_capacity(96);
        // hex(sha224) 56 字符
        req.extend_from_slice(
            self.hash
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
                .as_bytes(),
        );
        req.extend_from_slice(b"\r\n");
        req.push(0x01); // CONNECT
        encode_socks_addr(dst, &mut req);
        req.extend_from_slice(b"\r\n");
        if let Some(init) = initial {
            req.extend_from_slice(init);
        }
        io.write_all(&req).await?;
        Ok(Box::new(io))
    }
}

#[async_trait]
impl Outbound for TrojanOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect_stream(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        let io = transport::dial(&self.server, self.port, &self.transport).await?;
        self.handshake(io, dst, None).await
    }

    async fn connect_over(
        &self,
        _sess: &Session,
        dst: &DstAddr,
        underlying: Box<dyn ProxyStream>,
    ) -> Result<Box<dyn ProxyStream>> {
        let io = transport::wrap_transport(underlying, &self.server, &self.transport).await?;
        self.handshake(io, dst, None).await
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
}

// ---------------------------------------------------------------------------
// 入站（默认要求 TLS；测试/明文场景可关）
// ---------------------------------------------------------------------------

pub struct TrojanInbound {
    bind: String,
    port: u16,
    tag: Arc<str>,
    passwords: Vec<[u8; 28]>,
    fallback: Option<String>,
    users_by_hash: std::collections::HashMap<String, Arc<vp_core::UserAccount>>,
    user_mgr: Option<Arc<vp_core::UserManager>>,
    gate: Option<Arc<vp_core::InboundGate>>,
    direct: Arc<DirectOutbound>,
}

impl TrojanInbound {
    pub fn new(bind: &str, port: u16, tag: &str, passwords: &[String]) -> Result<Self> {
        Self::with_options(bind, port, tag, passwords, None, None)
    }

    pub fn with_options(
        bind: &str,
        port: u16,
        tag: &str,
        passwords: &[String],
        fallback: Option<String>,
        user_mgr: Option<Arc<vp_core::UserManager>>,
    ) -> Result<Self> {
        Self::with_gate(bind, port, tag, passwords, fallback, user_mgr, None)
    }

    pub fn with_gate(
        bind: &str,
        port: u16,
        tag: &str,
        passwords: &[String],
        fallback: Option<String>,
        user_mgr: Option<Arc<vp_core::UserManager>>,
        gate: Option<Arc<vp_core::InboundGate>>,
    ) -> Result<Self> {
        let mut hashes = Vec::new();
        let mut users_by_hash = std::collections::HashMap::new();

        for p in passwords {
            let h = password_hash(p);
            let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
            hashes.push(h);
            if let Some(mgr) = &user_mgr {
                if let Some(u) = mgr.get_user(p) {
                    users_by_hash.insert(hex, u);
                }
            }
        }
        if let Some(mgr) = &user_mgr {
            for u in mgr.all_users() {
                let h = password_hash(&u.secret);
                let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
                if !hashes.contains(&h) {
                    hashes.push(h);
                }
                users_by_hash.insert(hex, u);
            }
        }
        if hashes.is_empty() && fallback.is_none() {
            return Err(Error::Config(
                "trojan 入站需要至少一个密码或回落目标".into(),
            ));
        }
        Ok(TrojanInbound {
            bind: bind.to_string(),
            port,
            tag: tag.into(),
            passwords: hashes,
            fallback,
            users_by_hash,
            user_mgr,
            gate,
            direct: Arc::new(DirectOutbound::new(Arc::new(Resolver::system()), false)),
        })
    }

    async fn try_handshake(
        &self,
        stream: &mut tokio::net::TcpStream,
        peek_buf: &mut Vec<u8>,
    ) -> Result<(DstAddr, Option<Arc<vp_core::UserAccount>>)> {
        // [56B hex hash][CRLF][cmd][atyp addr port][CRLF]
        let mut head = [0u8; 58];
        let mut filled = 0;
        while filled < 58 {
            let n = match tokio::time::timeout(
                std::time::Duration::from_millis(500),
                stream.read(&mut head[filled..]),
            )
            .await
            {
                Ok(Ok(0)) => return Err(Error::Proto("trojan: 握手流过早中断")),
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => return Err(Error::Proto("trojan: 握手读取超时")),
            };
            peek_buf.extend_from_slice(&head[filled..filled + n]);
            // 快速探测检查：前 56 字节必须全部为 ASCII 十六进制字符
            for (idx, &b) in head[filled..filled + n].iter().enumerate() {
                let pos = filled + idx;
                if pos < 56 && !b.is_ascii_hexdigit() {
                    return Err(Error::Proto(
                        "trojan: 首包非十六进制凭据（非 Trojan 协议探测）",
                    ));
                }
            }
            filled += n;
        }

        let hex =
            std::str::from_utf8(&head[..56]).map_err(|_| Error::Proto("trojan 密码非 ascii"))?;

        let (matched, user) = if let Some(mgr) = &self.user_mgr {
            if let Some(u) = mgr.get_user_by_trojan_hex(hex) {
                if u.is_quota_exceeded() {
                    return Err(Error::Proto("trojan: 用户配额已超限"));
                }
                (true, Some(u))
            } else {
                let m = self.passwords.iter().any(|h| {
                    let expect: String = h.iter().map(|b| format!("{b:02x}")).collect();
                    expect == hex
                });
                (m, None)
            }
        } else {
            let m = self.passwords.iter().any(|h| {
                let expect: String = h.iter().map(|b| format!("{b:02x}")).collect();
                expect == hex
            });
            let u = if let Some(u) = self.users_by_hash.get(hex) {
                if u.is_quota_exceeded() {
                    return Err(Error::Proto("trojan: 用户配额已超限"));
                }
                Some(u.clone())
            } else {
                None
            };
            (m, u)
        };
        if !matched {
            return Err(Error::Proto("trojan: 密码错误"));
        }

        if &head[56..58] != b"\r\n" {
            return Err(Error::Proto("trojan: 请求格式错误"));
        }
        let mut cmd = [0u8; 1];
        stream.read_exact(&mut cmd).await?;
        peek_buf.push(cmd[0]);
        if cmd[0] != 0x01 {
            return Err(Error::Unsupported("trojan 入站仅支持 TCP".into()));
        }

        // SOCKS 地址增量读
        let mut addr_buf: Vec<u8> = Vec::with_capacity(300);
        let (dst, _used) = loop {
            match decode_socks_addr(&addr_buf) {
                Ok(x) => break x,
                Err(Error::Proto("address truncated")) | Err(Error::Proto("empty domain")) => {
                    let mut b = [0u8; 1];
                    stream.read_exact(&mut b).await?;
                    peek_buf.push(b[0]);
                    addr_buf.push(b[0]);
                    if addr_buf.len() > 262 {
                        return Err(Error::Proto("trojan 地址过长"));
                    }
                }
                Err(e) => return Err(e),
            }
        };

        // 尾部 CRLF
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await?;
        peek_buf.extend_from_slice(&crlf);
        if &crlf != b"\r\n" {
            return Err(Error::Proto("trojan: 缺少结尾 CRLF"));
        }

        Ok((dst, user))
    }

    async fn serve(
        self: &Arc<Self>,
        mut stream: tokio::net::TcpStream,
        src: std::net::SocketAddr,
        ctx: &InboundCtx,
    ) -> Result<()> {
        let mut peek_buf = Vec::with_capacity(512);
        match self.try_handshake(&mut stream, &mut peek_buf).await {
            Ok((dst, user)) => {
                if let Some(ref g) = self.gate {
                    g.mark_authenticated(src.ip());
                }
                let sess = Session::new_tcp(self.tag.clone(), Some(src), dst.clone());
                let remote = self.direct.connect_stream(&sess, &dst).await?;
                let meta = vp_core::conn_table::ConnMeta {
                    id: sess.id,
                    inbound: self.tag.clone(),
                    network: "tcp",
                    host: dst.host.to_string(),
                    dst_port: dst.port,
                    src: Some(src.to_string()),
                    process: None,
                    user: user.as_ref().map(|u| u.username.clone()),
                    rule: None,
                    chain: Some("trojan-server".into()),
                    start: vp_common::now_millis(),
                };
                let hook = RelayHook {
                    table: Some(ctx.conns.clone()),
                    meta: Some(meta),
                    stats: Some(ctx.stats.clone()),
                    user,
                    limiter: None,
                    brutal: None,
                };
                let client: Box<dyn ProxyStream> = Box::new(stream);
                tokio::spawn(async move {
                    let _ = relay(client, remote, hook).await;
                });
                Ok(())
            }
            Err(e) => {
                if let Some(fb_target) = &self.fallback {
                    tracing::debug!(src = %src, fallback = %fb_target, "Trojan 未认证或探测流量，执行 Fallback 回落: {e}");
                    match tokio::net::TcpStream::connect(fb_target).await {
                        Ok(fb_stream) => {
                            vp_transport::tune(&fb_stream);
                            let client: Box<dyn ProxyStream> =
                                Box::new(vp_core::PeekedStream::new(stream, peek_buf));
                            let remote: Box<dyn ProxyStream> = Box::new(fb_stream);
                            tokio::spawn(async move {
                                let _ = relay(client, remote, RelayHook::default()).await;
                            });
                            Ok(())
                        }
                        Err(conn_err) => {
                            tracing::warn!("Trojan 连接回落目标 {fb_target} 失败: {conn_err}");
                            Err(e)
                        }
                    }
                } else {
                    Err(e)
                }
            }
        }
    }
}

#[async_trait]
impl Inbound for TrojanInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, ctx: InboundCtx) -> Result<u16> {
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
                            if let Err(e) = this.serve(stream, src, &ctx).await {
                                tracing::debug!("trojan 入站会话结束: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("trojan 入站 accept 失败: {e}");
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

    #[tokio::test]
    async fn trojan_loopback() {
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
        let server = TrojanInbound::new("127.0.0.1", 0, "tr-srv", &["pw123".to_string()]).unwrap();
        let port = Arc::new(server).start(ctx).await.unwrap();

        let out = TrojanOutbound::new(&TrojanCfg {
            server: "127.0.0.1".into(),
            port,
            password: "pw123".into(),
            tls: false,
            server_name: None,
            skip_cert_verify: false,
            client_fingerprint: None,
            alpn: None,
            network: None,
            ws_opts: None,
            grpc_opts: None,
            http_opts: None,
            reality_opts: None,
            ech_opts: None,
            udp: false,
        })
        .unwrap();
        let dst = DstAddr::new("127.0.0.1", echo_addr.port());
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = out.connect_stream(&sess, &dst).await.unwrap();
        s.write_all(b"ping-trojan").await.unwrap();
        let mut buf = [0u8; 11];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-trojan");
    }
}

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
use vp_core::{Inbound, Outbound, PacketConn, ProxyStream};

use crate::uot::{PacketFraming, StreamPacketConn, UdpEgress};

use crate::direct::DirectOutbound;
use vp_dns::Resolver;
use vp_transport as transport;

const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

fn password_hash(pw: &str) -> [u8; 28] {
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
    udp: bool,
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
            udp: cfg.udp,
        })
    }

    async fn handshake<S>(&self, mut io: S, dst: &DstAddr, cmd: u8) -> Result<Box<dyn ProxyStream>>
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
        req.push(cmd);
        encode_socks_addr(dst, &mut req);
        req.extend_from_slice(b"\r\n");
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
        self.handshake(io, dst, CMD_CONNECT).await
    }

    async fn connect_over(
        &self,
        _sess: &Session,
        dst: &DstAddr,
        underlying: Box<dyn ProxyStream>,
    ) -> Result<Box<dyn ProxyStream>> {
        let io = transport::wrap_transport(underlying, &self.server, &self.transport).await?;
        self.handshake(io, dst, CMD_CONNECT).await
    }

    fn support_udp(&self) -> bool {
        self.udp
    }

    /// 原生 UDP（UDP ASSOCIATE）：一条流承载多目标数据报，帧为 `[SOCKS 地址][len][CRLF][data]`
    async fn connect_packet(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        let io = transport::dial(&self.server, self.port, &self.transport).await?;
        let stream = self.handshake(io, dst, CMD_UDP_ASSOCIATE).await?;
        Ok(Box::new(StreamPacketConn::new(
            stream,
            dst,
            PacketFraming::Trojan,
        )))
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
    direct: Arc<DirectOutbound>,
}

impl TrojanInbound {
    pub fn new(bind: &str, port: u16, tag: &str, passwords: &[String]) -> Result<Self> {
        let mut hashes = Vec::new();
        for p in passwords {
            hashes.push(password_hash(p));
        }
        if hashes.is_empty() {
            return Err(Error::Config("trojan 入站需要至少一个密码".into()));
        }
        Ok(TrojanInbound {
            bind: bind.to_string(),
            port,
            tag: tag.into(),
            passwords: hashes,
            direct: Arc::new(DirectOutbound::new(Arc::new(Resolver::system()), false)),
        })
    }

    async fn serve(
        self: &Arc<Self>,
        mut stream: tokio::net::TcpStream,
        src: std::net::SocketAddr,
        ctx: &InboundCtx,
    ) -> Result<()> {
        // [56B hex hash][CRLF][cmd][atyp addr port][CRLF]
        let mut head = [0u8; 58];
        stream.read_exact(&mut head).await?;
        let hex =
            std::str::from_utf8(&head[..56]).map_err(|_| Error::Proto("trojan 密码非 ascii"))?;
        if !self.passwords.iter().any(|h| {
            let expect: String = h.iter().map(|b| format!("{b:02x}")).collect();
            expect == hex
        }) {
            return Err(Error::Proto("trojan: 密码错误"));
        }
        if &head[56..58] != b"\r\n" {
            return Err(Error::Proto("trojan: 请求格式错误"));
        }
        let mut cmd = [0u8; 1];
        stream.read_exact(&mut cmd).await?;
        if cmd[0] != CMD_CONNECT && cmd[0] != CMD_UDP_ASSOCIATE {
            return Err(Error::Unsupported(format!(
                "trojan 入站: 不支持的命令 {}",
                cmd[0]
            )));
        }
        // SOCKS 地址增量读
        let mut addr_buf: Vec<u8> = Vec::with_capacity(300);
        let (dst, _used) = loop {
            match decode_socks_addr(&addr_buf) {
                Ok(x) => break x,
                Err(Error::Proto("address truncated")) | Err(Error::Proto("empty domain")) => {
                    let mut b = [0u8; 1];
                    stream.read_exact(&mut b).await?;
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
        if &crlf != b"\r\n" {
            return Err(Error::Proto("trojan: 缺少结尾 CRLF"));
        }

        if cmd[0] == CMD_UDP_ASSOCIATE {
            // 请求头里的地址只是占位，每个数据报自带目标地址
            let sess = Session::new_udp(self.tag.clone(), Some(src), dst);
            let egress = UdpEgress::Fixed(self.direct.clone());
            tokio::spawn(async move {
                let framing = PacketFraming::Trojan;
                let _ = crate::uot::serve_packets(egress, sess, Box::new(stream), framing).await;
            });
            return Ok(());
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
            rule: None,
            chain: Some("trojan-server".into()),
            start: vp_common::now_millis(),
        };
        let hook = RelayHook {
            table: Some(ctx.conns.clone()),
            meta: Some(meta),
            stats: Some(ctx.stats.clone()),
        };
        let client: Box<dyn ProxyStream> = Box::new(stream);
        tokio::spawn(async move {
            let _ = relay(client, remote, hook).await;
        });
        Ok(())
    }
}

#[async_trait]
impl Inbound for TrojanInbound {
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
                                tracing::warn!("trojan 入站会话结束: {e}");
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

    /// UDP：出站 connect_packet（UDP ASSOCIATE）↔ 本地 trojan 入站 ↔ UDP echo
    #[tokio::test]
    async fn trojan_udp_roundtrip() {
        let echo = crate::test_support::udp_echo().await;
        let ctx = InboundCtx {
            router: Arc::new(crate::test_support::NoopRouter()),
            stats: Arc::new(vp_common::Stats::default()),
            conns: Arc::new(vp_core::ConnTable::new()),
        };
        let server = TrojanInbound::new("127.0.0.1", 0, "tr-udp", &["pw123".to_string()]).unwrap();
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
            udp: true,
        })
        .unwrap();
        assert!(out.support_udp());
        let dst = DstAddr::ip(echo.ip(), echo.port());
        let sess = Session::new_udp("t".into(), None, dst.clone());
        let mut conn = out.connect_packet(&sess, &dst).await.unwrap();
        crate::test_support::assert_udp_roundtrip(&mut conn, echo).await;
    }

    /// 帧格式：[SOCKS 地址][len][CRLF][data]（trojan-gfw 规范）
    #[test]
    fn trojan_udp_frame_layout() {
        let addr = DstAddr::ip("8.8.8.8".parse().unwrap(), 53);
        let f = PacketFraming::Trojan.encode(&addr, b"ab").unwrap();
        assert_eq!(f, b"\x01\x08\x08\x08\x08\x00\x35\x00\x02\r\nab".to_vec());
    }
}

//! VLESS 出入站（version 0，port-then-address，atyp 1/2/3）。

use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use vp_common::{DstAddr, Error, Host, Result};
use vp_config::VlessCfg;
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;
use vp_core::tunnel::{relay, RelayHook};
use vp_core::{Inbound, Outbound, ProxyStream};
use vp_crypto::vmess_kdf::parse_uuid;

use crate::direct::DirectOutbound;
use vp_dns::Resolver;
use vp_transport as transport;

const VERSION: u8 = 0x00;
const CMD_TCP: u8 = 0x01;

fn encode_addr(dst: &DstAddr, out: &mut Vec<u8>) {
    // [addons len][cmd][port][atyp][addr]（版本与 UUID 由调用方前置）
    out.push(0); // addons len
    out.push(CMD_TCP);
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

fn decode_request(buf: &[u8]) -> Result<([u8; 16], DstAddr, usize)> {
    if buf.len() < 3 + 16 + 1 + 1 + 2 + 1 {
        return Err(Error::Proto("vless 请求头过短"));
    }
    if buf[0] != VERSION {
        return Err(Error::Proto("vless 版本不支持"));
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&buf[1..17]);
    let addons_len = buf[17] as usize;
    let mut i = 18 + addons_len;
    if buf.len() < i + 4 {
        return Err(Error::Proto("vless 请求头截断"));
    }
    let cmd = buf[i];
    i += 1;
    if cmd != CMD_TCP {
        return Err(Error::Unsupported("vless 入站仅支持 TCP".into()));
    }
    let port = u16::from_be_bytes([buf[i], buf[i + 1]]);
    i += 2;
    let atyp = buf[i];
    i += 1;
    let host = match atyp {
        0x01 => {
            if buf.len() < i + 4 {
                return Err(Error::Proto("vless 地址截断"));
            }
            let o: [u8; 4] = buf[i..i + 4].try_into().unwrap();
            i += 4;
            Host::Ip(std::net::IpAddr::V4(o.into()))
        }
        0x02 => {
            if buf.len() < i + 1 {
                return Err(Error::Proto("vless 地址截断"));
            }
            let n = buf[i] as usize;
            i += 1;
            if buf.len() < i + n {
                return Err(Error::Proto("vless 地址截断"));
            }
            let d = std::str::from_utf8(&buf[i..i + n])
                .map_err(|_| Error::Proto("域名非 utf-8"))?
                .to_ascii_lowercase();
            i += n;
            Host::Domain(d)
        }
        0x03 => {
            if buf.len() < i + 16 {
                return Err(Error::Proto("vless 地址截断"));
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[i..i + 16]);
            i += 16;
            Host::Ip(std::net::IpAddr::V6(o.into()))
        }
        _ => return Err(Error::Proto("vless atyp 非法")),
    };
    Ok((uuid, DstAddr { host, port }, i))
}

// ---------------------------------------------------------------------------
// 出站
// ---------------------------------------------------------------------------

pub struct VlessOutbound {
    name: Arc<str>,
    server: String,
    port: u16,
    uuid: [u8; 16],
    transport: transport::TransportConfig,
}

impl VlessOutbound {
    pub fn new(cfg: &VlessCfg) -> Result<Self> {
        Self::internal_new(None, cfg)
    }

    pub fn new_named(name: &str, cfg: &VlessCfg) -> Result<Self> {
        Self::internal_new(Some(name), cfg)
    }

    fn internal_new(name: Option<&str>, cfg: &VlessCfg) -> Result<Self> {
        let uuid = parse_uuid(&cfg.uuid)?;
        let t = crate::transport_of(
            cfg.tls,
            &cfg.server_name,
            cfg.skip_cert_verify,
            &cfg.network,
            &cfg.ws_opts,
        )?;
        Ok(VlessOutbound {
            name: name.unwrap_or("vless").into(),
            server: cfg.server.clone(),
            port: cfg.port,
            uuid,
            transport: t,
        })
    }

    async fn handshake<S>(&self, mut io: S, dst: &DstAddr) -> Result<Box<dyn ProxyStream>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut req = Vec::with_capacity(48);
        encode_addr(dst, &mut req);
        let mut full = Vec::with_capacity(1 + 16 + req.len());
        full.push(VERSION);
        full.extend_from_slice(&self.uuid);
        full.extend_from_slice(&req);
        io.write_all(&full).await?;
        // 响应头：[ver][addon_len]
        let mut resp = [0u8; 2];
        io.read_exact(&mut resp).await?;
        if resp[0] != VERSION {
            return Err(Error::Proto("vless 响应版本不匹配"));
        }
        let addon_len = resp[1] as usize;
        if addon_len > 0 {
            let mut skip = vec![0u8; addon_len];
            io.read_exact(&mut skip).await?;
        }
        Ok(Box::new(io))
    }
}

#[async_trait]
impl Outbound for VlessOutbound {
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

pub struct VlessInbound {
    bind: String,
    port: u16,
    tag: Arc<str>,
    uuids: Vec<[u8; 16]>,
    direct: Arc<DirectOutbound>,
}

impl VlessInbound {
    pub fn new(bind: &str, port: u16, tag: &str, uuids: &[String]) -> Result<Self> {
        let mut ids = Vec::new();
        for u in uuids {
            ids.push(parse_uuid(u)?);
        }
        if ids.is_empty() {
            return Err(Error::Config("vless 入站需要至少一个用户".into()));
        }
        Ok(VlessInbound {
            bind: bind.to_string(),
            port,
            tag: tag.into(),
            uuids: ids,
            direct: Arc::new(DirectOutbound::new(Arc::new(Resolver::system()), false)),
        })
    }

    async fn serve(
        self: &Arc<Self>,
        mut stream: tokio::net::TcpStream,
        src: std::net::SocketAddr,
        ctx: &InboundCtx,
    ) -> Result<()> {
        // 头部最长：1+16+1+1+2+1+255
        let mut buf = vec![0u8; 19 + 256];
        let mut filled = 0;
        loop {
            if filled >= buf.len() {
                return Err(Error::Proto("vless 请求头过长"));
            }
            let n = stream.read(&mut buf[filled..]).await?;
            if n == 0 {
                return Err(Error::Proto("vless 请求头中断"));
            }
            filled += n;
            match decode_request(&buf[..filled]) {
                Ok((uuid, dst, used)) => {
                    if !self.uuids.contains(&uuid) {
                        return Err(Error::Proto("vless: 用户认证失败"));
                    }
                    let extra = filled - used;
                    let sess = Session::new_tcp(self.tag.clone(), Some(src), dst.clone());
                    let remote = self.direct.connect_stream(&sess, &dst).await?;
                    // 响应：[ver=0][addon_len=0] + 回填额外数据
                    stream.write_all(&[VERSION, 0]).await?;
                    if extra > 0 {
                        stream.write_all(&buf[used..filled]).await?;
                    }
                    let meta = vp_core::conn_table::ConnMeta {
                        id: sess.id,
                        inbound: self.tag.clone(),
                        network: "tcp",
                        host: dst.host.to_string(),
                        dst_port: dst.port,
                        src: Some(src.to_string()),
                        process: None,
                        rule: None,
                        chain: Some("vless-server".into()),
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
                    return Ok(());
                }
                Err(Error::Proto("vless 请求头过短" | "vless 请求头截断" | "vless 地址截断")) => {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

#[async_trait]
impl Inbound for VlessInbound {
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
                        let this = this.clone();
                        let ctx = ctx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = this.serve(stream, src, &ctx).await {
                                tracing::warn!("vless 入站会话结束: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("vless 入站 accept 失败: {e}");
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
    async fn vless_loopback() {
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
        let server = VlessInbound::new("127.0.0.1", 0, "vl-srv", &[uuid.clone()]).unwrap();
        let port = Arc::new(server).start(ctx).await.unwrap();

        let out = VlessOutbound::new(&VlessCfg {
            server: "127.0.0.1".into(),
            port,
            uuid,
            flow: None,
            tls: false,
            server_name: None,
            skip_cert_verify: false,
            network: None,
            ws_opts: None,
            udp: false,
        })
        .unwrap();
        let dst = DstAddr::new("127.0.0.1", echo_addr.port());
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = out.connect_stream(&sess, &dst).await.unwrap();
        s.write_all(b"ping-vless").await.unwrap();
        let mut buf = [0u8; 10];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-vless");
    }
}

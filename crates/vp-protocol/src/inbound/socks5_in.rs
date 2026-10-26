//! SOCKS5 服务端入站。

use std::sync::Arc;

use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, warn};

use vp_common::addr::decode_socks_addr;
use vp_common::{DstAddr, Error, Result};
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;
use vp_core::stream::UdpPacket;

use super::dispatch::{ClientReply, dispatch_stream};
use super::udp_nat::UdpNat;

pub struct Socks5Inbound {
    bind: String,
    port: u16,
    tag: Arc<str>,
}

impl Socks5Inbound {
    pub fn new(bind: String, port: u16, tag: &str) -> Self {
        Socks5Inbound {
            bind,
            port,
            tag: tag.into(),
        }
    }
}

#[async_trait]
impl vp_core::Inbound for Socks5Inbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, ctx: InboundCtx) -> Result<u16> {
        let listener = TcpListener::bind((self.bind.as_str(), self.port)).await?;
        let bound = listener.local_addr()?.port();
        let tag = self.tag.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, src)) => {
                        vp_transport::tune(&stream);
                        let ctx = ctx.clone();
                        let tag = tag.clone();
                        tokio::spawn(async move {
                            if let Err(e) = serve_socks5(stream, src, tag, &ctx).await {
                                debug!("socks5 入站会话结束: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        warn!("socks5 入站 accept 失败: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        });
        Ok(bound)
    }
}

/// SOCKS5 服务端协议处理（泛型流，mixed 入站复用）
pub async fn serve_socks5<S>(
    mut stream: S,
    src: std::net::SocketAddr,
    tag: Arc<str>,
    ctx: &InboundCtx,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // 方法协商
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(Error::Proto("socks5 入站: 版本错误"));
    }
    let n = head[1] as usize;
    if n == 0 || n > 8 {
        return Err(Error::Proto("socks5 入站: 方法数非法"));
    }
    let mut methods = vec![0u8; n];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[0x05, 0x00]).await?; // 无认证

    // 请求头：[ver][cmd][rsv]（atyp 起由 read_socks_addr 解析）
    let mut req = [0u8; 3];
    stream.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        return Err(Error::Proto("socks5 入站: 请求版本错误"));
    }
    let dst = read_socks_addr(&mut stream).await?;
    match req[1] {
        0x01 => {
            let sess = Session::new_tcp(tag, Some(src), dst);
            dispatch_stream(ctx, sess, Box::new(stream), ClientReply::Socks5(0x00)).await;
            Ok(())
        }
        0x03 => {
            // UDP ASSOCIATE：申请中继 socket，回复绑定地址，转入 UDP 泵
            let relay = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(_) => {
                    stream
                        .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await?;
                    return Ok(());
                }
            };
            let bound = relay.local_addr()?;
            // 回复对客户端可达的地址：默认回环（本机客户端场景）；
            // 远程客户端需内核开启 allow-lan 时由其自行访问绑定端口
            let local_ip = std::net::IpAddr::V4([127, 0, 0, 1].into());
            let reply_addr = std::net::SocketAddr::new(local_ip, bound.port());
            let mut rep = Vec::with_capacity(18);
            rep.extend_from_slice(&[0x05, 0x00, 0x00]);
            vp_common::addr::encode_socks_addr(&DstAddr::ip(local_ip, bound.port()), &mut rep);
            stream.write_all(&rep).await?;
            debug!("socks5 UDP ASSOCIATE {src} -> {reply_addr}");
            let relay = Arc::new(relay);
            let nat = UdpNat::new(ctx.clone(), tag.clone(), relay.clone());
            nat.set_reply_formatter(Arc::new(|from_srv: std::net::SocketAddr, data: &[u8]| {
                // [rsv rsv frag][socks addr of server][payload]
                let mut pkt = vec![0x00, 0x00, 0x00];
                vp_common::addr::encode_socks_addr(
                    &DstAddr::ip(from_srv.ip(), from_srv.port()),
                    &mut pkt,
                );
                pkt.extend_from_slice(data);
                pkt
            }));
            let mut tcp_buf = [0u8; 1];
            // 客户端 → 中继 socket（限定来源地址）
            let mut buf = vec![0u8; 65535];
            let mut idle = tokio::time::interval(Duration::from_secs(300));
            idle.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            idle.tick().await; // interval 首个 tick 立即就绪，先消耗
            loop {
                tokio::select! {
                    r = relay.recv_from(&mut buf) => {
                        let Ok((n, from)) = r else { break };
                        tracing::debug!("udp relay 收到 {n}B from {from} (src={src})");
                        // RFC1928 允许客户端使用不同于控制连接的 UDP 端口，
                        // 仅校验同 IP（防外部注入）；严格校验随 M3 配置项提供
                        if from.ip() != src.ip() {
                            tracing::debug!("udp 来源 IP 不匹配 {from} != {src}");
                            continue;
                        }
                        if n < 4 {
                            continue;
                        }
                        // socks udp: [rsv2][frag1][socks addr][payload]
                        if buf[2] != 0x00 {
                            continue; // 分片不支持
                        }
                        let (dst_addr, used) = match vp_common::addr::decode_socks_addr(&buf[3..n]) {
                            Ok(x) => x,
                            Err(_) => continue,
                        };
                        let pkt = UdpPacket {
                            src: from,
                            dst: std::net::SocketAddr::new(
                                match &dst_addr.host {
                                    vp_common::Host::Ip(ip) => *ip,
                                    // 域名目标（socks5 UDP 支持域名）：让 NAT 决策时解析
                                    vp_common::Host::Domain(_) => [0, 0, 0, 0].into(),
                                },
                                dst_addr.port,
                            ),
                            data: buf[3 + used..n].to_vec().into(),
                        };
                        let fake = match &dst_addr.host {
                            vp_common::Host::Domain(d) => Some(d.clone()),
                            vp_common::Host::Ip(_) => None,
                        };
                        if let Err(e) = nat.dispatch(pkt, fake).await {
                            debug!("udp 分发失败: {e}");
                        }
                    }
                    // TCP 控制连接断开即结束
                    _ = stream.read(&mut tcp_buf) => break,
                    _ = idle.tick() => break,
                }
            }
            Ok(())
        }
        other => Err(Error::ProtoMsg(format!(
            "socks5 入站: 不支持的命令 {other}"
        ))),
    }
}

/// 增量读取 SOCKS 地址
pub async fn read_socks_addr<S>(io: &mut S) -> Result<DstAddr>
where
    S: AsyncRead + Unpin,
{
    let mut rest: Vec<u8> = Vec::with_capacity(300);
    loop {
        match decode_socks_addr(&rest) {
            Ok((dst, _)) => return Ok(dst),
            Err(Error::Proto("address truncated")) | Err(Error::Proto("empty domain")) => {
                let mut b = [0u8; 1];
                io.read_exact(&mut b).await?;
                rest.push(b[0]);
                if rest.len() > 262 {
                    return Err(Error::Proto("地址过长"));
                }
            }
            Err(e) => return Err(e),
        }
    }
}

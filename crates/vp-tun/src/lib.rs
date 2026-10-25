//! vp-tun：TUN 透明代理。
//!
//! 数据面：
//! ```text
//! 应用 ──IP 包──▶ TUN 设备 ──▶ ipstack 用户态栈
//!                                ├─ TCP ──▶ router.pick → Outbound.connect_stream
//!                                ├─ UDP ──▶ router.pick → Outbound.connect_packet
//!                                └─ UDP:53 ──▶ 内置应答（fake-ip 劫持）
//! fake-ip 还原：连接目标为 fake-ip 段时反查域名，以域名发起会话
//! ```

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use ipstack::{IpNumber, IpStack, IpStackConfig, IpStackStream};
use tracing::{debug, info, warn};

use vp_common::{Error, Result};
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;
use vp_core::stream::UdpPacket;
use vp_dns::{FakeIpPool, Resolver};

pub mod auto_route;

#[derive(Clone)]
pub struct TunConfig {
    /// TUN 接口地址（如 198.18.0.1）
    pub address: IpAddr,
    pub netmask: IpAddr,
    pub mtu: u16,
    /// fake-ip 池网段
    pub fake_ip_range: String,
    pub dns_hijack: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        TunConfig {
            address: "198.18.0.1".parse().unwrap(),
            netmask: "255.255.0.0".parse().unwrap(),
            mtu: 1500,
            fake_ip_range: "198.18.0.0/16".into(),
            dns_hijack: true,
        }
    }
}

pub struct TunInbound {
    cfg: TunConfig,
    tag: Arc<str>,
}

impl TunInbound {
    pub fn new(cfg: TunConfig, tag: &str) -> Self {
        TunInbound { cfg, tag: tag.into() }
    }
}

#[async_trait::async_trait]
impl vp_core::Inbound for TunInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, ctx: InboundCtx) -> Result<u16> {
        let tag = self.tag.clone();
        let cfg = self.cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = run(cfg, tag, ctx).await {
                warn!("TUN 数据面退出: {e}");
            }
        });
        // TUN 无监听端口
        Ok(0)
    }
}

async fn run(cfg: TunConfig, tag: Arc<str>, ctx: InboundCtx) -> Result<()> {
    let pool = Arc::new(
        FakeIpPool::new(&cfg.fake_ip_range)
            .ok_or_else(|| Error::Config(format!("fake-ip 网段非法: {}", cfg.fake_ip_range)))?,
    );
    let resolver = Arc::new(Resolver::system());

    let mut tcfg = tun::Configuration::default();
    match cfg.address {
        IpAddr::V4(v4) => {
            tcfg.address(v4);
            if let IpAddr::V4(mask) = cfg.netmask {
                tcfg.netmask(mask);
            }
        }
        IpAddr::V6(v6) => {
            tcfg.address(v6);
        }
    }
    tcfg.mtu(cfg.mtu);
    tcfg.up();
    let dev = tun::create_as_async(&tcfg)
        .map_err(|e| Error::Other(format!("创建 TUN 设备失败（需要管理员权限）: {e}")))?;

    let mut stack_cfg = IpStackConfig::default();
    stack_cfg.mtu(cfg.mtu).map_err(|e| Error::Config(format!("MTU 非法: {e}")))?;
    stack_cfg.packet_information(false);
    let mut stack = IpStack::new(stack_cfg, dev);
    info!(
        "TUN 已启动: {} mtu={} fakeip={}",
        cfg.address, cfg.mtu, cfg.fake_ip_range
    );

    loop {
        let stream = match stack.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("ipstack accept 失败: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };
        let ctx = ctx.clone();
        let tag = tag.clone();
        let pool = pool.clone();
        let resolver = resolver.clone();
        let dns_hijack = cfg.dns_hijack;
        tokio::spawn(async move {
            match stream {
                IpStackStream::Tcp(tcp) => {
                    let dst_ip = tcp.peer_addr().ip();
                    let dst_port = tcp.peer_addr().port();
                    let fake_domain = pool.reverse(dst_ip);
                    let dst = match &fake_domain {
                        Some(d) => vp_common::DstAddr::new(d.clone(), dst_port),
                        None => vp_common::DstAddr::ip(dst_ip, dst_port),
                    };
                    debug!("tun tcp {:?} -> {dst}", tcp.local_addr());
                    let src = Some(tcp.local_addr());
                    let sess = Session::new_tcp(tag.clone(), src, dst.clone());
                    dispatch_tcp(&ctx, sess, Box::new(tcp)).await;
                }
                IpStackStream::Udp(udp) => {
                    let dst_ip = udp.peer_addr().ip();
                    let dst_port = udp.peer_addr().port();
                    if dns_hijack && dst_port == 53 {
                        handle_dns(udp, pool, resolver).await;
                        return;
                    }
                    let fake_domain = pool.reverse(dst_ip);
                    let dst = match &fake_domain {
                        Some(d) => vp_common::DstAddr::new(d.clone(), dst_port),
                        None => vp_common::DstAddr::ip(dst_ip, dst_port),
                    };
                    debug!("tun udp {:?} -> {dst}", udp.local_addr());
                    let src = Some(udp.local_addr());
                    let sess = Session::new_udp(tag.clone(), src, dst.clone());
                    if let Err(e) = dispatch_udp(&ctx, sess, udp).await {
                        debug!("tun udp 分发失败: {e}");
                    }
                }
                IpStackStream::UnknownTransport(u) => {
                    if u.ip_protocol() == IpNumber::ICMP {
                        if let Ok((hdr, payload)) =
                            etherparse::Icmpv4Header::from_slice(u.payload())
                        {
                            if let etherparse::Icmpv4Type::EchoRequest(echo) = hdr.icmp_type {
                                let mut resp = etherparse::Icmpv4Header::new(
                                    etherparse::Icmpv4Type::EchoReply(echo),
                                );
                                resp.update_checksum(payload);
                                let mut out = resp.to_bytes().to_vec();
                                out.extend_from_slice(payload);
                                let _ = u.send(out);
                            }
                        }
                    }
                }
                IpStackStream::UnknownNetwork(_) => {}
            }
        });
    }
}

async fn dispatch_tcp(ctx: &InboundCtx, sess: Session, client: Box<dyn vp_core::ProxyStream>) {
    let res = ctx.router.pick(&sess).await;
    let meta = vp_core::ConnMeta {
        id: sess.id,
        inbound: sess.inbound.clone(),
        network: "tcp",
        host: sess.dst.host.to_string(),
        dst_port: sess.dst.port,
        src: sess.src.map(|s| s.to_string()),
        process: sess.process.clone(),
        rule: res.rule.as_ref().map(|r| format!("{} => {}", r.rule, r.target)),
        chain: Some(res.via.clone()),
        start: vp_common::now_millis(),
    };
    match res.outbound.connect_stream(&sess, &sess.dst).await {
        Ok(remote) => {
            let hook = vp_core::RelayHook {
                table: Some(ctx.conns.clone()),
                meta: Some(meta),
                stats: Some(ctx.stats.clone()),
            };
            let _ = vp_core::relay(client, remote, hook).await;
        }
        Err(e) => {
            debug!("tun tcp 出站失败: {e}");
        }
    }
}

/// TUN UDP：ipstack 的 UdpStream 面向单目标且实现 AsyncRead/AsyncWrite（流式）。
/// 与 PacketConn（收发带地址）桥接：同任务内 select 双泵。
async fn dispatch_udp(
    ctx: &InboundCtx,
    sess: Session,
    mut udp: ipstack::IpStackUdpStream,
) -> Result<()> {
    use tokio::io::AsyncReadExt;
    let res = ctx.router.pick(&sess).await;
    if !res.outbound.support_udp() {
        return Err(Error::Unsupported(format!(
            "出站 {} 无 UDP",
            res.outbound.name()
        )));
    }
    let mut conn = res.outbound.connect_packet(&sess, &sess.dst).await?;
    let dst_addr: SocketAddr = match &sess.dst.host {
        vp_common::Host::Ip(ip) => SocketAddr::new(*ip, sess.dst.port),
        vp_common::Host::Domain(_) => SocketAddr::new([127, 0, 0, 1].into(), sess.dst.port),
    };
    let mut up_buf = [0u8; 65535];
    loop {
        tokio::select! {
            biased;
            up = udp.read(&mut up_buf) => {
                match up {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let pkt = UdpPacket {
                            src: dst_addr,
                            dst: dst_addr,
                            data: up_buf[..n].to_vec().into(),
                        };
                        if conn.send(&pkt).await.is_err() {
                            break;
                        }
                    }
                }
            }
            r = conn.recv() => {
                match r {
                    Ok(pkt) => {
                        use tokio::io::AsyncWriteExt;
                        if udp.write_all(&pkt.data).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
    Ok(())
}

/// DNS 劫持：就地应答（fake-ip / PTR / 上游转发）
async fn handle_dns(mut udp: ipstack::IpStackUdpStream, pool: Arc<FakeIpPool>, resolver: Arc<Resolver>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 1500];
    loop {
        let n = match udp.read(&mut buf).await {
            Ok(n) if n > 0 => n,
            _ => break,
        };
        let resp = build_dns_reply(&buf[..n], &pool, &resolver).await;
        if udp.write_all(&resp).await.is_err() {
            break;
        }
    }
}

async fn build_dns_reply(query: &[u8], pool: &Arc<FakeIpPool>, resolver: &Arc<Resolver>) -> Vec<u8> {
    let Some((_id, name, qtype)) = vp_dns::wire::parse_query(query) else {
        return vp_dns::wire::build_empty_response(query);
    };
    const A: u16 = 1;
    const AAAA: u16 = 28;
    const PTR: u16 = 12;
    if qtype == A {
        if let Some(ip) = pool.allocate(&name) {
            return vp_dns::wire::build_a_response(query, ip);
        }
    } else if qtype == AAAA {
        return vp_dns::wire::build_empty_response(query);
    } else if qtype == PTR {
        if let Some(ip) = parse_ptr_name(&name) {
            if let Some(domain) = pool.reverse(IpAddr::V4(ip)) {
                return vp_dns::wire::build_ptr_response(query, &domain);
            }
        }
    }
    if let Some(up) = resolver.first_udp_server() {
        if let Ok(fwd) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            if fwd.connect(up).await.is_ok() && fwd.send(query).await.is_ok() {
                let mut buf = vec![0u8; 1500];
                if let Ok(Ok(n)) =
                    tokio::time::timeout(std::time::Duration::from_secs(3), fwd.recv(&mut buf)).await
                {
                    let mut out = buf[..n].to_vec();
                    if query.len() >= 2 && out.len() >= 2 {
                        out[0] = query[0];
                        out[1] = query[1];
                    }
                    return out;
                }
            }
        }
    }
    vp_dns::wire::build_empty_response(query)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vp_dns::wire;

    // build_dns_reply 的纯逻辑验证（不涉真实 TUN 设备）：
    // fake-ip 分配 / AAAA 空 / PTR 反查 / 上游转发
    #[tokio::test]
    async fn dns_hijack_fake_ip_flow() {
        let pool = Arc::new(FakeIpPool::new("198.18.0.0/16").unwrap());
        let resolver = Arc::new(Resolver::system());
        let q = wire::build_query(0xabcd, "www.google.com", wire::QType::A);
        let reply = build_dns_reply(&q, &pool, &resolver).await;
        let msg = wire::parse_response(&reply).unwrap();
        assert_eq!(msg.id, 0xabcd);
        let ips = wire::extract_ips(&msg, wire::TYPE_A);
        assert_eq!(ips.len(), 1);
        assert!(pool.contains(ips[0].0), "应返回 fake-ip");
        // 稳定性
        let reply2 = build_dns_reply(&q, &pool, &resolver).await;
        let ip2 = wire::extract_ips(&wire::parse_response(&reply2).unwrap(), wire::TYPE_A)[0].0;
        assert_eq!(ips[0].0, ip2);

        // AAAA → 空应答
        let q6 = wire::build_query(0x0002, "www.google.com", wire::QType::Aaaa);
        let r6 = build_dns_reply(&q6, &pool, &resolver).await;
        assert!(wire::extract_ips(&wire::parse_response(&r6).unwrap(), wire::TYPE_AAAA).is_empty());
    }

    #[tokio::test]
    async fn dns_hijack_ptr() {
        let pool = Arc::new(FakeIpPool::new("198.18.0.0/16").unwrap());
        let ip = pool.allocate("ptr.test").unwrap();
        let resolver = Arc::new(Resolver::system());
        let o = ip.octets();
        let name = format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]);
        let q = wire::build_query(0x33, &name, wire::QType::A);
        // PTR 查询要 qtype=12；手工改写 qtype 字节
        let mut q = q;
        let len = q.len();
        q[len - 4] = 0;
        q[len - 3] = 12;
        let reply = build_dns_reply(&q, &pool, &resolver).await;
        // rdata 末段: [len hi][len lo][labels...]
        let msg = wire::parse_response(&reply).unwrap();
        assert_eq!(msg.answers.len(), 1);
        // rdata 尾部标签序列: [3]ptr[4]test[0]
        let expect: Vec<u8> = [vec![3], b"ptr".to_vec(), vec![4], b"test".to_vec(), vec![0]].concat();
        let tail = &reply[reply.len() - expect.len()..];
        assert_eq!(tail, &expect[..], "PTR rdata 应含域名标签");
    }
}

fn parse_ptr_name(name: &str) -> Option<std::net::Ipv4Addr> {
    let prefix = name.strip_suffix(".in-addr.arpa")?;
    let parts: Vec<&str> = prefix.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    Some(std::net::Ipv4Addr::new(
        parts[3].parse().ok()?,
        parts[2].parse().ok()?,
        parts[1].parse().ok()?,
        parts[0].parse().ok()?,
    ))
}

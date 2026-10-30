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
pub mod wintun_installer;

#[derive(Clone)]
pub struct TunConfig {
    /// TUN 接口地址（如 198.18.0.1）
    pub address: IpAddr,
    pub netmask: IpAddr,
    pub mtu: u16,
    /// fake-ip 池网段
    pub fake_ip_range: String,
    pub dns_hijack: bool,
    /// 移动端 (Android VpnService / iOS) 注入的文件描述符
    pub fd: Option<i32>,
    /// Windows Wintun 环形缓冲区容量（字节，必须为 2 的幂，范围 128KB ~ 64MB，默认 4MB: 0x400000）
    pub ring_capacity: Option<u32>,
}

impl Default for TunConfig {
    fn default() -> Self {
        TunConfig {
            address: "198.18.0.1".parse().unwrap(),
            netmask: "255.255.0.0".parse().unwrap(),
            mtu: 9000,
            fake_ip_range: "198.18.0.0/16".into(),
            dns_hijack: true,
            fd: None,
            ring_capacity: None,
        }
    }
}

pub struct TunInbound {
    cfg: TunConfig,
    tag: Arc<str>,
    pool: Option<Arc<FakeIpPool>>,
    resolver: Option<Arc<Resolver>>,
    fake_ip_filter: Vec<String>,
    ipv6: bool,
}

impl TunInbound {
    pub fn new(cfg: TunConfig, tag: &str) -> Self {
        TunInbound {
            cfg,
            tag: tag.into(),
            pool: None,
            resolver: None,
            fake_ip_filter: Vec::new(),
            ipv6: false,
        }
    }

    pub fn with_dns(
        mut self,
        pool: Arc<FakeIpPool>,
        resolver: Arc<Resolver>,
        fake_ip_filter: Vec<String>,
        ipv6: bool,
    ) -> Self {
        self.pool = Some(pool);
        self.resolver = Some(resolver);
        self.fake_ip_filter = fake_ip_filter;
        self.ipv6 = ipv6;
        self
    }

    pub fn new_with_fd(cfg: TunConfig, tag: &str, fd: i32) -> Self {
        let mut cfg = cfg;
        cfg.fd = Some(fd);
        TunInbound {
            cfg,
            tag: tag.into(),
            pool: None,
            resolver: None,
            fake_ip_filter: Vec::new(),
            ipv6: false,
        }
    }
}

#[async_trait::async_trait]
impl vp_core::Inbound for TunInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, ctx: InboundCtx) -> Result<u16> {
        self.start_with_handle(ctx).await?;
        // TUN 无监听端口
        Ok(0)
    }
}

impl TunInbound {
    /// 启动 TUN 数据面并返回任务句柄。
    /// 与 trait `start` 的区别：设备创建失败会同步返回 Err（热重载路径据此
    /// 向控制端上报失败），且任务句柄可被 abort —— TUN 热停用就靠它。
    pub async fn start_with_handle(
        self: Arc<Self>,
        ctx: InboundCtx,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let tag = self.tag.clone();
        let cfg = self.cfg.clone();
        let dev = create_tun_device(&cfg).await?;
        let pool = match &self.pool {
            Some(p) => p.clone(),
            None => Arc::new(FakeIpPool::new(&cfg.fake_ip_range).ok_or_else(|| {
                Error::Config(format!("fake-ip 网段非法: {}", cfg.fake_ip_range))
            })?),
        };
        let resolver = match &self.resolver {
            Some(r) => r.clone(),
            None => Arc::new(Resolver::system()),
        };
        let filter = Arc::new(self.fake_ip_filter.clone());
        let ipv6 = self.ipv6;
        info!(
            "TUN 已启动: {} mtu={} fakeip={}",
            cfg.address, cfg.mtu, cfg.fake_ip_range
        );
        Ok(tokio::spawn(async move {
            if let Err(e) = run_with_device(cfg, tag, ctx, pool, resolver, filter, ipv6, dev).await
            {
                warn!("TUN 数据面退出: {e}");
            }
        }))
    }
}

/// 创建 TUN 设备（fd 注入 / Wintun / tun crate 三路），失败即报错不吞。
async fn create_tun_device(cfg: &TunConfig) -> Result<Box<dyn vp_core::ProxyStream>> {
    if let Some(fd) = cfg.fd {
        #[cfg(unix)]
        {
            use std::os::fd::FromRawFd;
            let file = unsafe { std::fs::File::from_raw_fd(fd) };
            let tokio_file = tokio::fs::File::from_std(file);
            info!(
                "TUN 移动端模式（外部 FD={fd}）: fakeip={}",
                cfg.fake_ip_range
            );
            return Ok(Box::new(vp_core::stream::Opaque(tokio_file)));
        }
        #[cfg(not(unix))]
        {
            let _ = fd;
            return Err(Error::Unsupported(
                "外部 FD 注入仅在 Unix/移动端系统支持".into(),
            ));
        }
    }

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
    tcfg.tun_name("vpcore-tun");
    tcfg.mtu(cfg.mtu);
    tcfg.up();

    #[cfg(windows)]
    {
        let dns_server = cfg.address;
        match wintun_installer::windows::ensure_wintun_dll() {
            Ok(dll_path) => {
                info!("Windows TUN 加载 Wintun 驱动: {}", dll_path.display());
                tcfg.platform_config(move |p| {
                    p.wintun_file(dll_path);
                    // 关键修复：给 vpcore-tun 指定一个固定的确定性 GUID（避免 Windows 每次生成随机 GUID 导致序号递增）
                    // 例如固定为 "vpcoretun0000001" 对应的静态 u128：
                    p.device_guid(0x7670636f_7265_7475_6e30_303030303031_u128);
                    // 关键修复：向 Wintun 注入 TUN 接口自身地址作为主 DNS 服务器
                    p.dns_servers(&[dns_server]);
                });
            }
            Err(e) => {
                warn!("Wintun 驱动准备提示: {e}");
            }
        }
        // 关键修复：赋予最低跃点数（Metric: 0），让操作系统优选该虚拟网卡处理流量与 DNS
        tcfg.metric(0);
        // 关键内存优化：Wintun 驱动默认分配 64MB (MAX_RING_CAPACITY) 发送环与接收环，
        // 映射后直接占用 128MB+ 物理工作集。
        // 将其调整为 4MB (0x400000) 即可支撑万兆吞吐，同时直接降低约 120MB 常驻内存！
        let cap = cfg.ring_capacity.unwrap_or(0x400000);
        tcfg.ring_capacity(cap);
    }

    let dev = tun::create_as_async(&tcfg)
        .map_err(|e| Error::Other(format!("创建 TUN 设备失败（需要管理员权限）: {e}")))?;
    Ok(Box::new(vp_core::stream::Opaque(dev)))
}

#[allow(clippy::too_many_arguments)]
async fn run_with_device<D>(
    cfg: TunConfig,
    tag: Arc<str>,
    ctx: InboundCtx,
    pool: Arc<FakeIpPool>,
    resolver: Arc<Resolver>,
    filter: Arc<Vec<String>>,
    ipv6: bool,
    dev: D,
) -> Result<()>
where
    D: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut stack_cfg = IpStackConfig::default();
    stack_cfg
        .mtu(cfg.mtu)
        .map_err(|e| Error::Config(format!("MTU 非法: {e}")))?;
    stack_cfg.packet_information(false);
    let mut stack = IpStack::new(stack_cfg, dev);

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
        let filter = filter.clone();
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
                    dispatch_tcp(&ctx, sess, Box::new(vp_core::stream::Opaque(tcp))).await;
                }
                IpStackStream::Udp(udp) => {
                    let dst_ip = udp.peer_addr().ip();
                    let dst_port = udp.peer_addr().port();
                    if dns_hijack && dst_port == 53 {
                        handle_dns(udp, pool, resolver, filter, ipv6).await;
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

async fn dispatch_tcp(
    ctx: &InboundCtx,
    mut sess: Session,
    mut client: Box<dyn vp_core::ProxyStream>,
) {
    // 协议嗅探优化：仅对常见 Web 端口（80, 443, 8080, 8443 等）纯 IP 目标窥探首包 SNI / HTTP Host
    // 非 Web 端口（如 22 SSH、3306 MySQL 等服务端先发包协议）跳过嗅探，彻底消除 100ms 无谓等待延迟
    if matches!(sess.dst.host, vp_common::Host::Ip(_))
        && matches!(sess.dst.port, 80 | 443 | 8080 | 8443 | 8444 | 9443)
    {
        let (sniffed, peeked) =
            vp_core::sniff_stream(client, std::time::Duration::from_millis(30)).await;
        client = peeked;
        if let Some(domain) = sniffed {
            debug!("tun sniff: 嗅探到真实域名 {} -> {}", sess.dst, domain);
            sess.dst.host = vp_common::Host::Domain(domain);
        }
    }

    let res = ctx.router.pick(&sess).await;
    let rule_tag = res
        .rule
        .as_ref()
        .map(|r| r.rule.as_str())
        .unwrap_or("Match()");
    let chain_tag = if res.outbound.name() != res.via.as_ref() {
        format!("{}[{}]", res.via, res.outbound.name())
    } else {
        res.outbound.name().to_string()
    };
    let src_str = sess
        .src
        .map(|s| s.to_string())
        .unwrap_or_else(|| "tun".into());
    tracing::info!(
        "[TCP] {} --> {} match {} using {}",
        src_str,
        sess.dst,
        rule_tag,
        chain_tag
    );
    let meta = vp_core::ConnMeta {
        id: sess.id,
        inbound: sess.inbound.clone(),
        network: "tcp",
        host: sess.dst.host.to_string(),
        dst_port: sess.dst.port,
        src: sess.src.map(|s| s.to_string()),
        process: sess.process.clone(),
        rule: res
            .rule
            .as_ref()
            .map(|r| format!("{} => {}", r.rule, r.target)),
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
            tracing::warn!("[TCP] {} 出站 {} 失败: {e}", sess.dst, res.outbound.name());
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
    let rule_tag = res
        .rule
        .as_ref()
        .map(|r| r.rule.as_str())
        .unwrap_or("Match()");
    let chain_tag = if res.outbound.name() != res.via.as_ref() {
        format!("{}[{}]", res.via, res.outbound.name())
    } else {
        res.outbound.name().to_string()
    };
    let src_str = sess
        .src
        .map(|s| s.to_string())
        .unwrap_or_else(|| "tun".into());
    tracing::info!(
        "[UDP] {} --> {} match {} using {}",
        src_str,
        sess.dst,
        rule_tag,
        chain_tag
    );
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

/// DNS 劫持：就地并发应答（fake-ip / PTR / Type 65 极速空应答 / 防环路物理出站上游转发）
async fn handle_dns(
    udp: ipstack::IpStackUdpStream,
    pool: Arc<FakeIpPool>,
    resolver: Arc<Resolver>,
    filter: Arc<Vec<String>>,
    ipv6: bool,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut reader, mut writer) = tokio::io::split(udp);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    let writer_task = tokio::spawn(async move {
        while let Some(resp) = rx.recv().await {
            if writer.write_all(&resp).await.is_err() {
                break;
            }
        }
    });

    let mut buf = vec![0u8; 1500];
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(n) if n > 0 => n,
            _ => break,
        };
        let query = buf[..n].to_vec();
        let pool = pool.clone();
        let resolver = resolver.clone();
        let filter = filter.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let resp = build_dns_reply(&query, &pool, &resolver, &filter, ipv6).await;
            let _ = tx.send(resp).await;
        });
    }

    drop(tx);
    let _ = writer_task.await;
}

pub async fn build_dns_reply(
    query: &[u8],
    pool: &Arc<FakeIpPool>,
    resolver: &Arc<Resolver>,
    filter: &[String],
    ipv6: bool,
) -> Vec<u8> {
    let Some((_id, name, qtype)) = vp_dns::wire::parse_query(query) else {
        return vp_dns::wire::build_empty_response(query);
    };
    const A: u16 = 1;
    const PTR: u16 = 12;
    const AAAA: u16 = 28;
    const SVCB: u16 = 64;
    const HTTPS: u16 = 65;

    let fake_mode = !vp_dns::is_fake_ip_filtered(&name, filter);

    if qtype == PTR {
        if let Some(ip) = parse_ptr_name(&name) {
            if let Some(domain) = pool.reverse(IpAddr::V4(ip)) {
                return vp_dns::wire::build_ptr_response(query, &domain);
            }
        }
    } else if qtype == A && fake_mode {
        if let Some(ip) = pool.allocate(&name) {
            return vp_dns::wire::build_a_response(query, ip);
        }
    } else if qtype == AAAA && fake_mode && !ipv6 {
        return vp_dns::wire::build_empty_response(query);
    } else if (qtype == HTTPS || qtype == SVCB) && fake_mode {
        // 关键性能优化：对 fake-ip 域名直接应答空记录（NOERROR 且 0 应答），
        // 彻底根除现代浏览器并发查询 Type 65 导致的 1~3 秒白屏/转圈卡顿，
        // 同时避免通过 IPv4Hint / IPv6Hint 拿到真 IP 绕过虚拟网卡分流
        return vp_dns::wire::build_empty_response(query);
    }

    // 过滤名单域名或其它记录类型：通过物理网卡防环路 UDP 套接字转发上游
    if let Some(up) = resolver.first_udp_server() {
        if let Ok(fwd) = vp_transport::create_udp_socket("0.0.0.0:0".parse().unwrap()) {
            if fwd.connect(up).await.is_ok() && fwd.send(query).await.is_ok() {
                let mut buf = vec![0u8; 1500];
                if let Ok(Ok(n)) =
                    tokio::time::timeout(std::time::Duration::from_millis(1500), fwd.recv(&mut buf))
                        .await
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
        let filter: Vec<String> = Vec::new();
        let q = wire::build_query(0xabcd, "www.google.com", wire::QType::A);
        let reply = build_dns_reply(&q, &pool, &resolver, &filter, false).await;
        let msg = wire::parse_response(&reply).unwrap();
        assert_eq!(msg.id, 0xabcd);
        let ips = wire::extract_ips(&msg, wire::TYPE_A);
        assert_eq!(ips.len(), 1);
        assert!(pool.contains(ips[0].0), "应返回 fake-ip");
        // 稳定性
        let reply2 = build_dns_reply(&q, &pool, &resolver, &filter, false).await;
        let ip2 = wire::extract_ips(&wire::parse_response(&reply2).unwrap(), wire::TYPE_A)[0].0;
        assert_eq!(ips[0].0, ip2);

        // AAAA → 空应答
        let q6 = wire::build_query(0x0002, "www.google.com", wire::QType::Aaaa);
        let r6 = build_dns_reply(&q6, &pool, &resolver, &filter, false).await;
        assert!(wire::extract_ips(&wire::parse_response(&r6).unwrap(), wire::TYPE_AAAA).is_empty());

        // HTTPS (Type 65) → 极速空应答（根除浏览器 3 秒卡顿）
        let q_https = wire::build_query(0x0065, "www.google.com", wire::QType::Https);
        let r_https = build_dns_reply(&q_https, &pool, &resolver, &filter, false).await;
        let msg_https = wire::parse_response(&r_https).unwrap();
        assert_eq!(msg_https.id, 0x0065);
        assert!(
            msg_https.answers.is_empty(),
            "Fake-IP 域名 Type 65 应立即返回空应答"
        );
    }

    #[tokio::test]
    async fn dns_hijack_ptr() {
        let pool = Arc::new(FakeIpPool::new("198.18.0.0/16").unwrap());
        let ip = pool.allocate("ptr.test").unwrap();
        let resolver = Arc::new(Resolver::system());
        let filter: Vec<String> = Vec::new();
        let o = ip.octets();
        let name = format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]);
        let q = wire::build_query(0x33, &name, wire::QType::A);
        // PTR 查询要 qtype=12；手工改写 qtype 字节
        let mut q = q;
        let len = q.len();
        q[len - 4] = 0;
        q[len - 3] = 12;
        let reply = build_dns_reply(&q, &pool, &resolver, &filter, false).await;
        // rdata 末段: [len hi][len lo][labels...]
        let msg = wire::parse_response(&reply).unwrap();
        assert_eq!(msg.answers.len(), 1);
        // rdata 尾部标签序列: [3]ptr[4]test[0]
        let expect: Vec<u8> =
            [vec![3], b"ptr".to_vec(), vec![4], b"test".to_vec(), vec![0]].concat();
        let tail = &reply[reply.len() - expect.len()..];
        assert_eq!(tail, &expect[..], "PTR rdata 应含域名标签");
    }
}

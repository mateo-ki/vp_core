//! UDP 全链路 e2e：
//! 1) socks5 入站 UDP ASSOCIATE → DIRECT 出站 → UDP echo
//! 2) socks5 出站 UDP（对端为我们的 mixed 入站）
//! 3) ss 出站 UDP（对端为我们的 ss 入站，每包独立 salt）

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use vp_common::Stats;
use vp_core::{ConnTable, Inbound, InboundCtx, Outbound as _};
use vp_dns::Resolver;
use vp_protocol::direct::DirectOutbound;
use vp_protocol::{build_inbound, InboundKind};
use vp_router::{GroupSpec, GroupType, LbStrategy, Router, RouterSpec};

async fn spawn_udp_echo() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    let s = Arc::new(s);
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((n, from)) = s.recv_from(&mut buf).await else { break };
            let mut resp = b"echo:".to_vec();
            resp.extend_from_slice(&buf[..n]);
            let _ = s.send_to(&resp, from).await;
        }
    });
    addr
}

struct TestRouter(Arc<Router>);

#[async_trait::async_trait]
impl vp_core::Router for TestRouter {
    async fn pick(&self, sess: &vp_core::Session) -> vp_core::Resolution {
        self.0.pick(sess).await
    }
}

async fn build_udp_router_with(
    outbounds: Vec<(String, Arc<dyn vp_core::Outbound>)>,
) -> (Arc<Router>, InboundCtx) {
    let mut map: HashMap<String, Arc<dyn vp_core::Outbound>> = HashMap::new();
    map.insert(
        "DIRECT".into(),
        Arc::new(DirectOutbound::new(Arc::new(Resolver::system()), false)),
    );
    for (name, ob) in outbounds {
        map.insert(name, ob);
    }
    let rules = vec!["MATCH,DIRECT".to_string()];
    let env = vp_rule::CompileEnv {
        is_known_target: &|t| matches!(t, "DIRECT" | "REJECT" | "PROXY"),
        geosite: &None,
        geoip: &None,
        providers: &HashMap::new(),
        sub_rules: &HashMap::new(),
    };
    let rules = vp_rule::compile(&rules, &env).unwrap();
    let router = Router::build(RouterSpec {
        outbounds: map,
        groups: vec![GroupSpec {
            name: "PROXY".into(),
            ty: GroupType::Select,
            members: vec!["DIRECT".into()],
            test_url: None,
            interval: 300,
            tolerance: 0,
            lazy: true,
            lb_strategy: LbStrategy::RoundRobin,
        }],
        rules,
        mode: vp_config::Mode::Rule,
        dns: Arc::new(Resolver::system()),
        ipv6: false,
    })
    .unwrap();
    let ctx = InboundCtx {
        router: Arc::new(TestRouter(router.clone())),
        stats: Arc::new(Stats::default()),
        conns: Arc::new(ConnTable::new()),
    };
    (router, ctx)
}

/// 手写 socks5 UDP ASSOCIATE 客户端：返回 (中继地址, 控制连接)
async fn udp_associate(port: u16) -> (SocketAddr, tokio::net::TcpStream) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut b = [0u8; 2];
    s.read_exact(&mut b).await.unwrap();
    let req = [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    s.write_all(&req).await.unwrap();
    // 响应: [ver rep rsv atyp] + 可变地址 + 2B 端口
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.unwrap();
    assert_eq!(head[1], 0x00, "UDP ASSOCIATE 失败");
    let mut full = head.to_vec();
    match head[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            s.read_exact(&mut rest).await.unwrap();
            full.extend_from_slice(&rest);
        }
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.unwrap();
            full.extend_from_slice(&l);
            let mut rest = vec![0u8; l[0] as usize + 2];
            s.read_exact(&mut rest).await.unwrap();
            full.extend_from_slice(&rest);
        }
        0x04 => {
            let mut rest = [0u8; 18];
            s.read_exact(&mut rest).await.unwrap();
            full.extend_from_slice(&rest);
        }
        _ => panic!("atyp"),
    }
    let (addr, _) = vp_common::addr::decode_socks_addr(&full[3..]).unwrap();
    let ip = match addr.host {
        vp_common::Host::Ip(ip) => ip,
        vp_common::Host::Domain(d) => d.parse().unwrap(),
    };
    (SocketAddr::new(ip, addr.port), s)
}

fn socks_udp_packet(dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0x00, 0x00, 0x00];
    match dst.ip() {
        std::net::IpAddr::V4(v4) => {
            pkt.push(0x01);
            pkt.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            pkt.push(0x04);
            pkt.extend_from_slice(&v6.octets());
        }
    }
    pkt.extend_from_slice(&dst.port().to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

#[tokio::test]
async fn socks5_inbound_udp_relay_via_direct() {
    let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
    let echo = spawn_udp_echo().await;
    let (_router, ctx) = build_udp_router_with(vec![]).await;
    let mixed = build_inbound(InboundKind::Mixed, "127.0.0.1".into(), 0, "m");
    let port = mixed.clone().start(ctx).await.unwrap();

    let (relay, _ctrl) = udp_associate(port).await;
    eprintln!("[t] relay = {relay}");
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&socks_udp_packet(echo, b"hello-udp"), relay).await.unwrap();
    let mut buf = [0u8; 1500];
    let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("超时")
        .unwrap();
    // socks-udp 回包：[rsv rsv frag][socks addr][payload]
    let (src, used) = vp_common::addr::decode_socks_addr(&buf[3..n]).unwrap();
    assert_eq!(&buf[3 + used..n], b"echo:hello-udp");
    assert_eq!(src.port, echo.port());
}

#[tokio::test]
async fn ss_udp_loopback() {
    use vp_config::SsCfg;
    use vp_protocol::ss::{SsInbound, SsOutbound};

    let echo = spawn_udp_echo().await;
    let ctx = InboundCtx {
        router: Arc::new(crate::noop_router()),
        stats: Arc::new(Stats::default()),
        conns: Arc::new(ConnTable::new()),
    };
    let server = SsInbound::new("127.0.0.1", 0, "ss-u", "aes-128-gcm", "udp-pass").unwrap();
    let port = Arc::new(server).start(ctx).await.unwrap();

    let out = SsOutbound::new(&SsCfg {
        server: "127.0.0.1".into(),
        port,
        cipher: "aes-128-gcm".into(),
        password: "udp-pass".into(),
        udp: true,
        plugin: None,
    })
    .unwrap();
    assert!(out.support_udp());
    let sess = vp_core::Session::new_udp("t".into(), None, vp_common::DstAddr::ip(echo.ip(), echo.port()));
    let mut conn = out
        .connect_packet(&sess, &vp_common::DstAddr::ip(echo.ip(), echo.port()))
        .await
        .unwrap();

    conn.send(&vp_core::UdpPacket {
        src: "127.0.0.1:0".parse().unwrap(),
        dst: echo,
        data: b"ss-udp".to_vec().into(),
    })
    .await
    .unwrap();
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), conn.recv())
        .await
        .expect("超时")
        .unwrap();
    assert_eq!(&resp.data[..], b"echo:ss-udp");

    // 第二个包（新 salt）
    conn.send(&vp_core::UdpPacket {
        src: "127.0.0.1:0".parse().unwrap(),
        dst: echo,
        data: b"second".to_vec().into(),
    })
    .await
    .unwrap();
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), conn.recv())
        .await
        .expect("超时2")
        .unwrap();
    assert_eq!(&resp.data[..], b"echo:second");
}

#[tokio::test]
async fn socks5_outbound_udp_via_mixed() {
    let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
    use vp_protocol::basic_out::Socks5Outbound;
    let echo = spawn_udp_echo().await;
    let (_router, ctx) = build_udp_router_with(vec![]).await;
    let mixed = build_inbound(InboundKind::Mixed, "127.0.0.1".into(), 0, "m");
    let port = mixed.clone().start(ctx).await.unwrap();

    let out = Socks5Outbound {
        server: "127.0.0.1".into(),
        port,
        username: None,
        password: None,
        udp: true,
    };
    assert!(out.support_udp());
    let sess = vp_core::Session::new_udp("t".into(), None, vp_common::DstAddr::ip(echo.ip(), echo.port()));
    let mut conn = out
        .connect_packet(&sess, &vp_common::DstAddr::ip(echo.ip(), echo.port()))
        .await
        .unwrap();
    conn.send(&vp_core::UdpPacket {
        src: "127.0.0.1:0".parse().unwrap(),
        dst: echo,
        data: b"s5-udp".to_vec().into(),
    })
    .await
    .unwrap();
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), conn.recv())
        .await
        .expect("超时")
        .unwrap();
    assert_eq!(&resp.data[..], b"echo:s5-udp");
}

pub(crate) fn noop_router() -> impl vp_core::Router {
    struct N();
    #[async_trait::async_trait]
    impl vp_core::Router for N {
        async fn pick(&self, _s: &vp_core::Session) -> vp_core::Resolution {
            unreachable!()
        }
    }
    N()
}

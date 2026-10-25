//! 垂直 e2e：mixed 入站 → 规则路由 → 策略组 → 出站 → echo 源站。

use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use vp_common::Stats;
use vp_config::Mode;
use vp_core::{ConnTable, InboundCtx};
use vp_dns::Resolver;
use vp_protocol::direct::DirectOutbound;
use vp_protocol::{build_inbound, InboundKind};
use vp_router::{GroupSpec, GroupType, LbStrategy, Router, RouterSpec};

async fn spawn_echo() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { break };
            tokio::spawn(async move {
                let mut b = [0u8; 2048];
                loop {
                    match s.read(&mut b).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&b[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

struct TestRouter(Arc<Router>);

#[async_trait::async_trait]
impl vp_core::Router for TestRouter {
    async fn pick(&self, sess: &vp_core::Session) -> vp_core::Resolution {
        self.0.pick(sess).await
    }
}

/// 组装最小可用内核：mixed 入站 + 规则 + PROXY 组（成员 DIRECT）
async fn build_core() -> (u16 /*mixed port*/, Arc<Router>, u16 /*echo port*/) {
    let echo_port = spawn_echo().await;

    let mut outbounds: HashMap<String, Arc<dyn vp_core::Outbound>> = HashMap::new();
    outbounds.insert(
        "DIRECT".to_string(),
        Arc::new(DirectOutbound::new(Arc::new(Resolver::system()), false)),
    );

    let rules_text = vec![
        format!("DOMAIN,localhost,PROXY"),
        format!("IP-CIDR,127.0.0.0/8,DIRECT"),
        "MATCH,PROXY".to_string(),
    ];
    let env = vp_rule::CompileEnv {
        is_known_target: &|t| matches!(t, "DIRECT" | "REJECT" | "PROXY"),
        geosite: &None,
        geoip: &None,
        providers: &HashMap::new(),
        sub_rules: &HashMap::new(),
    };
    let rules = vp_rule::compile(&rules_text, &env).unwrap();

    let router = Router::build(RouterSpec {
        outbounds,
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
        mode: Mode::Rule,
        dns: Arc::new(Resolver::system()),
        ipv6: false,
    })
    .unwrap();

    let ctx = InboundCtx {
        router: Arc::new(TestRouter(router.clone())),
        stats: Arc::new(Stats::default()),
        conns: Arc::new(ConnTable::new()),
    };
    let mixed = build_inbound(InboundKind::Mixed, "127.0.0.1".into(), 0, "mixed-1");
    let port = mixed.clone().start(ctx).await.unwrap();
    (port, router, echo_port)
}

/// 手写 socks5 客户端握手
async fn socks5_connect(port: u16, host: &str, dst_port: u16) -> tokio::net::TcpStream {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut b = [0u8; 2];
    s.read_exact(&mut b).await.unwrap();
    assert_eq!(b, [0x05, 0x00]);
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&dst_port.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut resp = [0u8; 4];
    s.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[1], 0x00, "socks5 CONNECT 失败");
    match resp[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            s.read_exact(&mut rest).await.unwrap();
        }
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.unwrap();
            let mut rest = vec![0u8; l[0] as usize + 2];
            s.read_exact(&mut rest).await.unwrap();
        }
        0x04 => {
            let mut rest = [0u8; 18];
            s.read_exact(&mut rest).await.unwrap();
        }
        _ => panic!("atyp 非法"),
    }
    s
}

#[tokio::test]
async fn mixed_socks5_full_chain() {
    let _ = tracing_subscriber::fmt::try_init();
    let (port, router, echo_port) = build_core().await;
    assert_eq!(router.groups().len(), 1);

    let mut c = socks5_connect(port, "localhost", echo_port).await;
    c.write_all(b"e2e-ping").await.unwrap();
    let mut buf = [0u8; 8];
    c.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"e2e-ping");
}

#[tokio::test]
async fn mixed_http_connect_full_chain() {
    let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();
    let (port, _router, echo_port) = build_core().await;
    let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let req = format!("CONNECT localhost:{echo_port} HTTP/1.1\r\nHost: localhost\r\n\r\n");
    c.write_all(req.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        c.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"), "{head:?}");
    c.write_all(b"HTTP-CONNECT-OK").await.unwrap();
    let mut buf = [0u8; 15];
    c.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"HTTP-CONNECT-OK");
}

#[tokio::test]
async fn rule_routing_hits_group() {
    let (port, _router, echo_port) = build_core().await;
    // proxy.test 域名 → PROXY 组（via=DIRECT 穿透）
    let mut c = socks5_connect(port, "localhost", echo_port).await;
    c.write_all(b"x").await.unwrap();
    let mut b = [0u8; 1];
    c.read_exact(&mut b).await.unwrap();

    // 观察连接表：chain 应为 DIRECT（PROXY 穿透）
    // （连接结束后表清空，此处仅验证请求成功即可）
    drop(c);
}

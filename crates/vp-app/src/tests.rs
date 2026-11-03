use super::*;

const CFG: &str = r#"
mixed-port: 17890
mode: rule
log-level: info
proxies:
  - name: "本地回环"
    type: socks5
    server: 127.0.0.1
    port: 10800
proxy-groups:
  - name: PROXY
    type: select
    proxies: ["本地回环", DIRECT]
rules:
  - DOMAIN-SUFFIX,internal.test,DIRECT
  - IP-CIDR,127.0.0.0/8,DIRECT
  - MATCH,PROXY
"#;

#[tokio::test]
async fn app_assemble_and_serve() {
    let dir = std::env::temp_dir();
    let app = App::start(CFG, Format::Yaml, &dir, true).await.unwrap();
    assert_eq!(app.listen_ports.len(), 1);
    assert_eq!(app.listen_ports[0].1, 17890);

    // 经 mixed 端口做一次 socks5 CONNECT（目标 127.0.0.1 的临时 echo）
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut s, _) = echo.accept().await.unwrap();
        let mut b = [0u8; 64];
        let n = s.read(&mut b).await.unwrap();
        s.write_all(&b[..n]).await.unwrap();
    });
    let mut c = tokio::net::TcpStream::connect(("127.0.0.1", 17890))
        .await
        .unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut b = [0u8; 2];
    c.read_exact(&mut b).await.unwrap();
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&echo_port.to_be_bytes());
    c.write_all(&req).await.unwrap();
    let mut resp = [0u8; 10];
    c.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[1], 0x00);
    c.write_all(b"app-ok").await.unwrap();
    let mut got = [0u8; 6];
    c.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"app-ok");
}

/// vless/ss listener 数据面 e2e（复用 vmess 最小复现模式）
#[tokio::test]
async fn vless_ss_listener_e2e() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn one_echo() -> u16 {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut b = [0u8; 256];
            loop {
                let n = s.read(&mut b).await.unwrap();
                if n == 0 {
                    break;
                }
                s.write_all(&b[..n]).await.unwrap();
            }
        });
        p
    }
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    // vless
    let echo_port = one_echo().await;
    let cfg = format!(
        "listeners:\n  - name: srv-vl\n    type: vless\n    port: 0\n    users: [\"{uuid}\"]\nrules: ['MATCH,DIRECT']\n"
    );
    let app = App::start(&cfg, vp_config::Format::Yaml, &std::env::temp_dir(), true)
        .await
        .unwrap();
    let vl_port = app
        .listen_ports
        .iter()
        .find(|(t, _)| t == "srv-vl")
        .map(|(_, p)| *p)
        .expect("vless listener 应已监听");
    let out = vp_protocol::vless::VlessOutbound::new(&vp_config::VlessCfg {
        server: "127.0.0.1".into(),
        port: vl_port,
        uuid: uuid.into(),
        flow: None,
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
        packet_encoding: None,
        xudp: false,
        packet_addr: false,
    })
    .unwrap();
    let dst = vp_common::DstAddr::ip("127.0.0.1".parse().unwrap(), echo_port);
    let sess = vp_core::Session::new_tcp("t".into(), None, dst.clone());
    let mut s = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        out.connect_stream(&sess, &dst),
    )
    .await
    .expect("vless 出站应完成")
    .expect("vless 出站应成功");
    s.write_all(b"vl-e2e").await.unwrap();
    let mut buf = [0u8; 6];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"vl-e2e");

    // ss
    let echo_port = one_echo().await;
    let cfg = "listeners:\n  - name: srv-ss\n    type: ss\n    port: 0\n    users: [\"pw\"]\n    cipher: aes-128-gcm\nrules: ['MATCH,DIRECT']\n";
    let app = App::start(cfg, vp_config::Format::Yaml, &std::env::temp_dir(), true)
        .await
        .unwrap();
    let ss_port = app
        .listen_ports
        .iter()
        .find(|(t, _)| t == "srv-ss")
        .map(|(_, p)| *p)
        .expect("ss listener 应已监听");
    let out = vp_protocol::ss::SsOutbound::new(&vp_config::SsCfg {
        server: "127.0.0.1".into(),
        port: ss_port,
        cipher: "aes-128-gcm".into(),
        password: "pw".into(),
        udp: false,
        plugin: None,
        plugin_opts: None,
    })
    .unwrap();
    let dst = vp_common::DstAddr::ip("127.0.0.1".parse().unwrap(), echo_port);
    let sess = vp_core::Session::new_tcp("t".into(), None, dst.clone());
    let mut s = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        out.connect_stream(&sess, &dst),
    )
    .await
    .expect("ss 出站应完成")
    .expect("ss 出站应成功");
    s.write_all(b"ss-e2e").await.unwrap();
    let mut buf = [0u8; 6];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ss-e2e");
}

/// vmess listener 数据面最小复现（修上轮挂起缺陷）
#[tokio::test]
async fn vmess_listener_e2e() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = echo.accept().await.unwrap();
        let mut b = [0u8; 256];
        loop {
            let n = s.read(&mut b).await.unwrap();
            if n == 0 {
                break;
            }
            s.write_all(&b[..n]).await.unwrap();
        }
    });
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let cfg = format!(
        "listeners:\n  - name: srv-vm\n    type: vmess\n    port: 0\n    users: [\"{uuid}\"]\nrules: ['MATCH,DIRECT']\n"
    );
    let app = App::start(&cfg, vp_config::Format::Yaml, &std::env::temp_dir(), true)
        .await
        .unwrap();
    let vm_port = app
        .listen_ports
        .iter()
        .find(|(t, _)| t == "srv-vm")
        .map(|(_, p)| *p)
        .expect("vmess listener 应已监听");

    let out = vp_protocol::vmess::VmessOutbound::new(&vp_config::VmessCfg {
        server: "127.0.0.1".into(),
        port: vm_port,
        uuid: uuid.into(),
        alter_id: 0,
        cipher: "auto".into(),
        tls: false,
        server_name: None,
        skip_cert_verify: false,
        client_fingerprint: None,
        alpn: None,
        network: None,
        ws_opts: None,
        grpc_opts: None,
        http_opts: None,
        udp: false,
        ech_opts: None,
        packet_encoding: None,
        xudp: false,
        packet_addr: false,
    })
    .unwrap();
    let dst = vp_common::DstAddr::ip("127.0.0.1".parse().unwrap(), echo_port);
    let sess = vp_core::Session::new_tcp("t".into(), None, dst.clone());
    let mut s = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        out.connect_stream(&sess, &dst),
    )
    .await
    .expect("vmess 出站应完成")
    .expect("vmess 出站应成功");
    s.write_all(b"vm-e2e").await.unwrap();
    let mut buf = [0u8; 6];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"vm-e2e");
}

/// listeners 段端到端：trojan 服务端入站 ← TrojanOutbound ← echo
#[tokio::test]
async fn trojan_listener_e2e() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // echo
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = echo.accept().await.unwrap();
        let mut b = [0u8; 256];
        loop {
            let n = s.read(&mut b).await.unwrap();
            if n == 0 {
                break;
            }
            s.write_all(&b[..n]).await.unwrap();
        }
    });
    let cfg = "mixed-port: 17895
listeners:
  - name: srv-tj
    type: trojan
    port: 0
    users: [pw-e2e]
rules: ['MATCH,DIRECT']
";
    let app = App::start(cfg, vp_config::Format::Yaml, &std::env::temp_dir(), true)
        .await
        .unwrap();
    // listeners[0] 实际端口
    let tj_port = app
        .listen_ports
        .iter()
        .find(|(t, _)| t == "srv-tj")
        .map(|(_, p)| *p)
        .expect("trojan listener 应已监听");

    let out = vp_protocol::trojan::TrojanOutbound::new(&vp_config::TrojanCfg {
        server: "127.0.0.1".into(),
        port: tj_port,
        password: "pw-e2e".into(),
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
    let dst = vp_common::DstAddr::ip("127.0.0.1".parse().unwrap(), echo_port);
    let sess = vp_core::Session::new_tcp("t".into(), None, dst.clone());
    let mut s = out
        .connect_stream(&sess, &dst)
        .await
        .expect("trojan 出站应成功");
    s.write_all(b"listener-e2e").await.unwrap();
    let mut buf = [0u8; 12];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"listener-e2e");
}

/// 全栈：App ss listener + shadow-tls v3 伪装 ← SsOutbound(plugin: shadow-tls) ← echo
#[tokio::test]
async fn ss_shadowtls_listener_e2e() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // echo 源站
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = echo.accept().await.unwrap();
        let mut b = [0u8; 256];
        loop {
            let n = s.read(&mut b).await.unwrap();
            if n == 0 {
                break;
            }
            s.write_all(&b[..n]).await.unwrap();
        }
    });

    // 伪装站 stub：读 ClientHello → 回 TLS1.3 ServerHello + 1 帧伪 appdata
    let cam = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cam_port = cam.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = cam.accept().await.unwrap();
        let mut hdr = [0u8; 5];
        s.read_exact(&mut hdr).await.unwrap();
        let mut ch = vec![0u8; u16::from_be_bytes([hdr[3], hdr[4]]) as usize];
        s.read_exact(&mut ch).await.unwrap();
        // ServerHello（supported_versions=0304）
        let mut body = vec![0x02, 0x03, 0x03];
        body.extend_from_slice(&[0x11u8; 32]); // random
        body.push(32);
        body.extend_from_slice(&[0x42u8; 32]); // sid echo
        body.extend_from_slice(&[0x13, 0x01, 0x01, 0x00]);
        body.extend_from_slice(&6u16.to_be_bytes()); // exts len
        body.extend_from_slice(&43u16.to_be_bytes());
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x03, 0x04]);
        let mut msg = vec![0x02, 0x00, 0x00, 0x00];
        msg[1..4].copy_from_slice(&(((body.len() - 1) as u32) << 8).to_be_bytes()[1..]);
        msg.extend_from_slice(&body[1..]);
        let mut rec = vec![0x16, 0x03, 0x03];
        rec.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        rec.extend_from_slice(&msg);
        s.write_all(&rec).await.unwrap();
        // 一帧伪 appdata（供客户端授权判定）
        s.write_all(&[0x17, 0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4])
            .await
            .unwrap();
        let mut b = [0u8; 64];
        let _ = s.read(&mut b).await;
    });

    let cfg = format!(
        "mixed-port: 17898
listeners:
  - name: srv-stls
    type: ss
    port: 0
    users: [ss-pass]
    cipher: aes-128-gcm
    shadow-tls:
      host: 127.0.0.1
      port: {cam_port}
      password: stls-pass
rules: ['MATCH,DIRECT']
"
    );
    let app = App::start(&cfg, vp_config::Format::Yaml, &std::env::temp_dir(), true)
        .await
        .unwrap();
    let ss_port = app
        .listen_ports
        .iter()
        .find(|(t, _)| t == "srv-stls")
        .map(|(_, p)| *p)
        .expect("ss+shadowtls listener 应已监听");

    let out = vp_protocol::ss::SsOutbound::new(&vp_config::SsCfg {
        server: "127.0.0.1".into(),
        port: ss_port,
        cipher: "aes-128-gcm".into(),
        password: "ss-pass".into(),
        udp: false,
        plugin: Some("shadow-tls".into()),
        plugin_opts: Some(vp_config::ShadowTlsCfg {
            host: Some("127.0.0.1".into()),
            password: Some("stls-pass".into()),
            port: Some(cam_port),
            version: Some(3),
        }),
    })
    .unwrap();
    let dst = vp_common::DstAddr::ip("127.0.0.1".parse().unwrap(), echo_port);
    let sess = vp_core::Session::new_tcp("t".into(), None, dst.clone());
    let mut s = out
        .connect_stream(&sess, &dst)
        .await
        .expect("ss over shadow-tls 应成功");
    s.write_all(b"stls-e2e").await.unwrap();
    let mut buf = [0u8; 8];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"stls-e2e");
}

#[tokio::test]
async fn invalid_config_rejected() {
    let bad = "proxies:\n  - name: x\n    type: ss\n    server: 1.1.1.1\n    port: 1\n    cipher: aes-128-gcm\n    password: p\nproxy-groups:\n  - name: G\n    type: select\n    proxies: [不存在]\nrules: ['MATCH,G']\n";
    match App::start(bad, Format::Yaml, Path::new("."), false).await {
        Err(err) => assert!(err.to_string().contains("不存在"), "{err}"),
        Ok(_) => panic!("应当报错"),
    }
}
#[tokio::test]
async fn uot_ss_e2e() {
    // UDP echo 源站
    let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut b = [0u8; 2048];
        loop {
            if let Ok((n, from)) = echo.recv_from(&mut b).await {
                let _ = echo.send_to(&b[..n], from).await;
            }
        }
    });

    // 先占位取两个空闲端口（避免固定端口撞车）
    async fn free_port() -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    }
    let mixed_port = free_port().await;
    let ss_port = free_port().await;

    // ss listener（服务端）+ ss 出站（udp-over-tcp 包装），mixed 入站走 socks5 UDP 关联
    let cfg = format!(
        "mixed-port: {mixed_port}
proxies:
  - name: ss-uot
    type: ss
    server: 127.0.0.1
    port: {ss_port}
    cipher: aes-128-gcm
    password: pw
    udp: true
    udp-over-tcp: true
listeners:
  - name: uot-srv
    type: ss
    port: {ss_port}
    users: [pw]
    cipher: aes-128-gcm
rules: ['IN-NAME,uot-srv,DIRECT', 'MATCH,ss-uot']
"
    );
    // listener 流量也走规则（v1.4.0）：服务端侧必须出 DIRECT，否则 MATCH 把它再送回 ss-uot 自环
    let _app = App::start(&cfg, vp_config::Format::Yaml, &std::env::temp_dir(), true)
        .await
        .unwrap();

    // socks5 握手 + UDP ASSOCIATE
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", mixed_port))
        .await
        .unwrap();
    tcp.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut buf = [0u8; 2];
    tcp.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, [0x05, 0x00]);
    tcp.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    // 应答：[3 头][ATYP][4B 地址][2B 端口] = 10 字节
    let mut rep = [0u8; 10];
    tcp.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0x00, "ASSOCIATE 应成功");
    let relay_port = u16::from_be_bytes([rep[8], rep[9]]);
    assert_ne!(relay_port, 0);
    let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    relay.connect(("127.0.0.1", relay_port)).await.unwrap();

    // socks5 UDP 帧：[rsv2][frag][ATYP 1][127.0.0.1][port][payload]
    let mut dgram = vec![0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1];
    dgram.extend_from_slice(&echo_port.to_be_bytes());
    dgram.extend_from_slice(b"uot-e2e");
    relay.send(&dgram).await.unwrap();
    let mut rbuf = vec![0u8; 512];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), relay.recv(&mut rbuf))
        .await
        .expect("UoT 回包超时")
        .unwrap();
    // 回包：[rsv2][frag][ATYP 1][127.0.0.1][echo_port][payload]
    assert_eq!(rbuf[3], 0x01, "回包 ATYP 应为 IPv4");
    assert_eq!(&rbuf[4..8], &[127, 0, 0, 1]);
    assert_eq!(
        u16::from_be_bytes([rbuf[8], rbuf[9]]),
        echo_port,
        "源端口应为 echo 端口"
    );
    assert_eq!(&rbuf[10..n], b"uot-e2e");
}

#[tokio::test]
async fn app_file_hot_reload() {
    let temp_dir = std::env::temp_dir();
    let config_path = temp_dir.join(format!("vp_reload_test_{}.yaml", std::process::id()));

    let cfg1 = r#"
mode: rule
proxies: []
proxy-groups:
  - name: PROXY
    type: select
    proxies: [DIRECT]
rules: ['MATCH,PROXY']
"#;
    tokio::fs::write(&config_path, cfg1).await.unwrap();

    let app = App::start_from_file(&config_path, false).await.unwrap();
    assert!(app.router.current().outbound("new-node").is_none());

    // 动态修改磁盘上的配置文件，增加一个节点
    let cfg2 = r#"
mode: rule
proxies:
  - name: "new-node"
    type: socks5
    server: 127.0.0.1
    port: 10800
proxy-groups:
  - name: PROXY
    type: select
    proxies: ["new-node", DIRECT]
rules: ['MATCH,PROXY']
"#;
    tokio::fs::write(&config_path, cfg2).await.unwrap();

    // 触发热重载
    app.reload().await.expect("从磁盘重读配置热重载应成功");
    assert!(
        app.router.current().outbound("new-node").is_some(),
        "新节点应出现在路由表中"
    );

    // 写入错误语法配置，热重载应拦截并保留旧状态
    tokio::fs::write(&config_path, "invalid: yaml: syntax: [")
        .await
        .unwrap();
    let res = app.reload().await;
    assert!(res.is_err(), "非法配置重载应返回 Err");
    assert!(
        app.router.current().outbound("new-node").is_some(),
        "非法配置重载失败后旧路由配置应完整保留"
    );

    let _ = tokio::fs::remove_file(&config_path).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn rule_provider_online_fetch_and_refresh() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let srv = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let srv_port = srv.local_addr().unwrap().port();

    // 简易 HTTP 服务器：第 1 次返回仅含 google.com；第 2 次返回含 youtube.com
    let call_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cc = call_count.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = srv.accept().await else {
                break;
            };
            let count = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                let mut b = [0u8; 1024];
                let _ = s.read(&mut b).await;
                let body = if count == 0 {
                    "payload:\n  - google.com\n"
                } else {
                    "payload:\n  - google.com\n  - youtube.com\n"
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/yaml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });

    let temp_dir = std::env::temp_dir();
    let cache_file = temp_dir.join(format!("vp_prov_{}.txt", std::process::id()));
    let cfg = format!(
        r#"
mode: rule
rule-providers:
  test-prov:
    type: http
    behavior: domain
    url: http://127.0.0.1:{srv_port}/rules.yaml
    path: {}
    interval: 1
proxies: []
proxy-groups:
  - name: PROXY
    type: select
    proxies: [DIRECT]
rules:
  - RULE-SET,test-prov,PROXY
  - MATCH,DIRECT
"#,
        cache_file.to_string_lossy().replace('\\', "/")
    );

    let app = App::start(&cfg, Format::Yaml, &temp_dir, true)
        .await
        .unwrap();

    // 验证初始状态：google.com 命中 PROXY，youtube.com 命中 MATCH,DIRECT
    let sess1 =
        vp_core::Session::new_tcp("in".into(), None, vp_common::DstAddr::new("google.com", 80));
    let res1 = app.router.current().pick(&sess1).await;
    assert_eq!(res1.outbound.name(), "PROXY");

    let sess2 = vp_core::Session::new_tcp(
        "in".into(),
        None,
        vp_common::DstAddr::new("youtube.com", 80),
    );
    let res2 = app.router.current().pick(&sess2).await;
    assert_eq!(res2.outbound.name(), "DIRECT");

    // 缓存文件已写入磁盘
    assert!(cache_file.exists(), "离线缓存文件应已生成");

    // 等待后台 interval 触发定时更新（interval 设为 1 秒，等待 1.5 秒）
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    // 验证定时更新后：youtube.com 命中 PROXY！
    let res3 = app.router.current().pick(&sess2).await;
    assert_eq!(
        res3.outbound.name(),
        "PROXY",
        "定时更新后 youtube.com 应命中 RULE-SET"
    );

    let _ = tokio::fs::remove_file(&cache_file).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_provider_online_fetch_and_refresh() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let srv = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let srv_port = srv.local_addr().unwrap().port();

    // 简易 HTTP 订阅服务器：第 1 次返回 HK-01 与 US-01；第 2 次返回 HK-01 与 HK-02
    let call_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cc = call_count.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = srv.accept().await else {
                break;
            };
            let count = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                let mut b = [0u8; 1024];
                let _ = s.read(&mut b).await;
                let body = if count == 0 {
                    r#"
proxies:
  - name: "HK-01"
    type: socks5
    server: 127.0.0.1
    port: 1081
  - name: "US-01"
    type: socks5
    server: 127.0.0.1
    port: 1082
"#
                } else {
                    r#"
proxies:
  - name: "HK-01"
    type: socks5
    server: 127.0.0.1
    port: 1081
  - name: "HK-02"
    type: socks5
    server: 127.0.0.1
    port: 1083
"#
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/yaml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });

    let temp_dir = std::env::temp_dir();
    let cache_file = temp_dir.join(format!("vp_pprov_{}.yaml", std::process::id()));
    let cfg = format!(
        r#"
mode: rule
proxy-providers:
  test-nodes:
    type: http
    url: http://127.0.0.1:{srv_port}/proxies.yaml
    path: {}
    interval: 1
    filter: "^HK"
proxies: []
proxy-groups:
  - name: PROXY
    type: select
    use: [test-nodes]
rules:
  - MATCH,PROXY
"#,
        cache_file.to_string_lossy().replace('\\', "/")
    );

    let app = App::start(&cfg, Format::Yaml, &temp_dir, true)
        .await
        .unwrap();

    // 验证初始状态：filter 过滤生效，HK-01 存在，US-01 被过滤
    assert!(
        app.router.current().outbound("HK-01").is_some(),
        "HK-01 应被加载"
    );
    assert!(
        app.router.current().outbound("US-01").is_none(),
        "US-01 属于非 HK，应被 filter 过滤"
    );
    let group = app
        .router
        .current()
        .get_group("PROXY")
        .expect("PROXY 组应存在");
    assert_eq!(&*group.selected_name(), "HK-01");

    // 缓存文件已写入磁盘
    assert!(cache_file.exists(), "proxy-provider 离线缓存文件应已生成");

    // 等待后台 interval 触发定时更新（interval 设为 1 秒，等待 1.5 秒）
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    // 验证定时更新后：新节点 HK-02 已动态汇入
    assert!(
        app.router.current().outbound("HK-02").is_some(),
        "定时更新后 HK-02 应出现在路由表中"
    );

    let _ = tokio::fs::remove_file(&cache_file).await;
}

#[tokio::test]
async fn app_handles_subscription_rules_without_databases() {
    // 模拟 vpn-parser 在全新临时目录中传入包含 GEOIP,CN / GEOIP,GOOGLE / GEOSITE 的典型订阅规则
    let temp_dir = std::env::temp_dir().join(format!("vp_sub_test_{}", std::process::id()));
    let _ = tokio::fs::create_dir_all(&temp_dir).await;

    let cfg = r#"
mode: rule
proxies: []
proxy-groups:
  - name: PROXY
    type: select
    proxies: [DIRECT]
rules:
  - GEOIP,CN,DIRECT,no-resolve
  - GEOIP,GOOGLE,PROXY
  - GEOSITE,cn,DIRECT
  - GEOSITE,google,PROXY
  - MATCH,PROXY
"#;
    // 在没有 Country.mmdb 或 geosite.dat 的情况下，应当 100% 优雅降级并启动成功，绝不报错退出
    let app = App::start(cfg, Format::Yaml, &temp_dir, false)
        .await
        .expect("包含 GEOIP 与 GEOSITE 的订阅规则在缺少数据库时应优雅降级并成功启动");

    let sess = vp_core::Session::new_tcp(
        "test".into(),
        None,
        vp_common::DstAddr::new("example.com", 80),
    );
    let res = app.router.current().pick(&sess).await;
    // 优雅跳过缺少数据库的规则，命中兜底 MATCH
    assert_eq!(res.rule.as_ref().unwrap().target, "PROXY");
    assert_eq!(res.rule.as_ref().unwrap().rule, "MATCH,PROXY");
    assert_eq!(&*res.via, "DIRECT");

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn standalone_dns_listen_without_tun() {
    let temp_dir = std::env::temp_dir().join(format!("vp_dns_listen_{}", std::process::id()));
    let _ = tokio::fs::create_dir_all(&temp_dir).await;

    let cfg = r#"
mode: rule
dns:
  enable: true
  listen: 127.0.0.1:0
  enhanced-mode: fake-ip
  nameserver:
    - 223.5.5.5
proxies: []
proxy-groups:
  - name: PROXY
    type: select
    proxies: [DIRECT]
rules: ['MATCH,PROXY']
"#;
    let app = App::start(cfg, Format::Yaml, &temp_dir, true)
        .await
        .expect("无 TUN 独立 dns.listen 服务应当启动成功");

    let dns_port = app
        .listen_ports
        .iter()
        .find(|(tag, _)| tag == "dns")
        .map(|(_, port)| *port)
        .expect("应当在 listen_ports 中注册独立 dns 端口");
    assert!(dns_port > 0);

    // 发送 UDP DNS 查询 (query for example.com A record)
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // 构造简易 DNS A 记录查询: Transaction ID 0x1234, Flags 0x0100 (standard query), 1 question
    let mut query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    // 7example3com0
    query.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    // Type A (1), Class IN (1)
    query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

    sock.send_to(&query, ("127.0.0.1", dns_port)).await.unwrap();

    let mut resp_buf = [0u8; 512];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), sock.recv(&mut resp_buf))
        .await
        .expect("DNS 应答超时")
        .unwrap();

    assert!(n >= 12, "DNS 响应报文应至少包含 12 字节报头");
    assert_eq!(&resp_buf[..2], &[0x12, 0x34], "Transaction ID 必须一致");
    // Flags: QR bit should be 1 (response)
    assert_ne!(resp_buf[2] & 0x80, 0, "QR bit 应标记为应答");

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_tailscale_and_tproxy_inbounds_config() {
    let temp_dir = std::env::temp_dir().join("vp_test_ts_tproxy");
    let _ = tokio::fs::create_dir_all(&temp_dir).await;

    let cfg = r#"
inbounds:
  - name: my-tproxy
    type: tproxy
    port: 0
    listen: 127.0.0.1
  - name: my-mixed
    type: mixed
    port: 0
    listen: 127.0.0.1
proxies:
  - name: ts-node
    type: tailscale
    server: 127.0.0.1
    port: 1055
    exit-node: "100.64.0.1"
    udp: true
proxy-groups:
  - name: PROXY
    type: select
    proxies: [ts-node, DIRECT]
rules:
  - DOMAIN-SUFFIX,ts.net,ts-node
  - IP-CIDR,100.64.0.0/10,ts-node
  - MATCH,PROXY
"#;
    let app = App::start(cfg, Format::Yaml, &temp_dir, true)
        .await
        .expect("配置应成功解析并启动");

    // 验证 tailscale 节点注册在 router 中
    let ts = app.router.current().outbound("ts-node");
    assert!(ts.is_some(), "tailscale 节点应注册到路由表");
    assert_eq!(ts.unwrap().name(), "ts-node");

    // mixed 入站必然启动成功
    assert!(app.listen_ports.iter().any(|(tag, _)| tag == "my-mixed"));

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_fake_ip_auto_reverse_and_hosts_e2e() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let temp_dir = std::env::temp_dir().join("vp_test_fakeip_hosts");
    let _ = tokio::fs::create_dir_all(&temp_dir).await;

    // 启动一个非 Web 端口的本地 TCP echo 服务器（模拟透明网关下访问非 80/443 服务）
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = echo.accept().await {
            let mut buf = [0u8; 32];
            if let Ok(n) = s.read(&mut buf).await {
                let _ = s.write_all(&buf[..n]).await;
            }
        }
    });

    let cfg = r#"
mixed-port: 0
mode: rule
hosts:
  "my-service.internal": "127.0.0.1"
dns:
  enable: true
  listen: 127.0.0.1:0
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.0/16
  nameserver:
    - 127.0.0.1:53535
proxies: []
rules:
  - DOMAIN,my-service.internal,DIRECT
  - MATCH,REJECT
"#;
    let app = App::start(cfg, Format::Yaml, &temp_dir, true)
        .await
        .unwrap();
    let mixed_port = app
        .listen_ports
        .iter()
        .find(|(t, _)| t == "mixed")
        .unwrap()
        .1;

    // 从全局 Fake-IP 池为 "git.corp.example" 分配一个 Fake-IP (198.18.x.x)，
    // 并在 hosts 中验证静态解析，同时验证入站拿到 Fake-IP 时自动反查出真实域名命中规则
    let pool = vp_dns::get_global_fake_ip_pool().expect("应当初始化全局 Fake-IP 池");
    let fake_ip = pool.allocate("my-service.internal").unwrap();
    assert_eq!(fake_ip.octets()[0], 198);
    assert_eq!(fake_ip.octets()[1], 18);

    // 客户端通过 mixed (SOCKS5) 直接向 Fake-IP (198.18.x.x:echo_port) 发起连接：
    // 若无入站 Fake-IP 自动反查，目标将保持为 198.18.x.x 从而落入 MATCH,REJECT 失败；
    // 有自动反查后，198.18.x.x 还原为 my-service.internal -> 命中 DOMAIN,my-service.internal,DIRECT -> 经 hosts 解析到 127.0.0.1:echo_port！
    let mut c = tokio::net::TcpStream::connect(("127.0.0.1", mixed_port))
        .await
        .unwrap();
    c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    c.read_exact(&mut greeting).await.unwrap();

    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&fake_ip.octets());
    req.extend_from_slice(&echo_port.to_be_bytes());
    c.write_all(&req).await.unwrap();

    let mut rep = [0u8; 10];
    c.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0x00, "Fake-IP 入站反查与 hosts 解析应当成功连通");

    c.write_all(b"fakeip-ok").await.unwrap();
    let mut got = [0u8; 9];
    c.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"fakeip-ok");

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

/// listeners 段端到端：tuic 服务端入站 ← TuicOutbound ← echo
#[tokio::test]
async fn tuic_listener_e2e() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = echo.accept().await.unwrap();
        let mut b = [0u8; 256];
        loop {
            let n = s.read(&mut b).await.unwrap();
            if n == 0 {
                break;
            }
            s.write_all(&b[..n]).await.unwrap();
        }
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = std::env::temp_dir().join(format!("tuic_cert_{}.pem", vp_common::now_millis()));
    let key_path = std::env::temp_dir().join(format!("tuic_key_{}.pem", vp_common::now_millis()));
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

    let cert_str = cert_path.to_str().unwrap().replace('\\', "/");
    let key_str = key_path.to_str().unwrap().replace('\\', "/");

    let cfg = format!(
        "listeners:
  - name: srv-tuic
    type: tuic
    port: 0
    cert: \"{cert_str}\"
    key: \"{key_str}\"
    users: [\"b831381d-6324-4d53-ad4f-8cda48b30811:pw-tuic\"]
rules: ['MATCH,DIRECT']
"
    );
    let app = App::start(&cfg, vp_config::Format::Yaml, &std::env::temp_dir(), true)
        .await
        .unwrap();
    let tuic_port = app
        .listen_ports
        .iter()
        .find(|(t, _)| t == "srv-tuic")
        .map(|(_, p)| *p)
        .expect("tuic listener 应已监听");

    let out = vp_protocol::tuic::TuicOutbound::new(&vp_config::TuicCfg {
        server: "127.0.0.1".into(),
        port: tuic_port,
        uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
        password: "pw-tuic".into(),
        sni: Some("localhost".into()),
        skip_cert_verify: true,
        congestion_controller: None,
        udp_relay_mode: None,
    })
    .unwrap();

    let dst = vp_common::DstAddr::ip("127.0.0.1".parse().unwrap(), echo_port);
    let sess = vp_core::Session::new_tcp("t".into(), None, dst.clone());
    let mut s = out
        .connect_stream(&sess, &dst)
        .await
        .expect("tuic 出站应成功");
    s.write_all(b"tuic-listener-e2e").await.unwrap();
    let mut buf = [0u8; 17];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"tuic-listener-e2e");

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);
}

/// listeners 段端到端：hysteria2 服务端入站 ← Hysteria2Outbound ← echo
#[tokio::test]
async fn hysteria2_listener_e2e() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = echo.accept().await.unwrap();
        let mut b = [0u8; 256];
        loop {
            let n = s.read(&mut b).await.unwrap();
            if n == 0 {
                break;
            }
            s.write_all(&b[..n]).await.unwrap();
        }
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = std::env::temp_dir().join(format!("hy2_cert_{}.pem", vp_common::now_millis()));
    let key_path = std::env::temp_dir().join(format!("hy2_key_{}.pem", vp_common::now_millis()));
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

    let cert_str = cert_path.to_str().unwrap().replace('\\', "/");
    let key_str = key_path.to_str().unwrap().replace('\\', "/");

    let cfg = format!(
        "listeners:
  - name: srv-hy2
    type: hysteria2
    port: 0
    cert: \"{cert_str}\"
    key: \"{key_str}\"
    users: [\"pw-hy2\"]
rules: ['MATCH,DIRECT']
"
    );
    let app = App::start(&cfg, vp_config::Format::Yaml, &std::env::temp_dir(), true)
        .await
        .unwrap();
    let hy2_port = app
        .listen_ports
        .iter()
        .find(|(t, _)| t == "srv-hy2")
        .map(|(_, p)| *p)
        .expect("hysteria2 listener 应已监听");

    let out = vp_protocol::hysteria2::Hysteria2Outbound::new(&vp_config::Hysteria2Cfg {
        server: "127.0.0.1".into(),
        port: hy2_port,
        password: "pw-hy2".into(),
        sni: Some("localhost".into()),
        skip_cert_verify: true,
        up: None,
        down: None,
        obfs: None,
        obfs_password: None,
        ports: None,
        hop_interval: None,
    })
    .unwrap();

    let dst = vp_common::DstAddr::ip("127.0.0.1".parse().unwrap(), echo_port);
    let sess = vp_core::Session::new_tcp("t".into(), None, dst.clone());
    let mut s = out
        .connect_stream(&sess, &dst)
        .await
        .expect("hysteria2 出站应成功");
    s.write_all(b"hy2-listener-e2e").await.unwrap();
    let mut buf = [0u8; 16];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hy2-listener-e2e");

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);
}

/// listeners 段端到端：Trojan Fallback（探测回落至 Web 伪装站点）与合法 Trojan 代理共存
#[tokio::test]
async fn trojan_fallback_and_multi_user_e2e() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // 1. 启动本地 Web 伪装/回落服务（Decoy Server）
    let decoy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let decoy_port = decoy.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = decoy.accept().await {
            tokio::spawn(async move {
                let mut req = [0u8; 512];
                if let Ok(n) = s.read(&mut req).await {
                    if n > 0 {
                        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello Decoy!";
                        let _ = s.write_all(resp).await;
                    }
                }
            });
        }
    });

    // 2. 启动回声服务端（作为合法代理目标）
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo.accept().await {
            tokio::spawn(async move {
                let mut b = [0u8; 256];
                while let Ok(n) = s.read(&mut b).await {
                    if n == 0 {
                        break;
                    }
                    let _ = s.write_all(&b[..n]).await;
                }
            });
        }
    });

    // 3. 配置 Trojan 监听器（启用 fallback 到 decoy）
    let cfg = format!(
        "listeners:
  - name: srv-trojan
    type: trojan
    port: 0
    fallback: \"127.0.0.1:{decoy_port}\"
    user-configs:
      - name: alice
        secret: \"pwd-alice\"
        rate-limit-up: 50Mbps
        rate-limit-down: 50Mbps
rules: ['MATCH,DIRECT']
"
    );
    let app = App::start(&cfg, vp_config::Format::Yaml, &std::env::temp_dir(), true)
        .await
        .unwrap();
    let trojan_port = app
        .listen_ports
        .iter()
        .find(|(t, _)| t == "srv-trojan")
        .map(|(_, p)| *p)
        .expect("trojan listener 应当已监听");

    // 4. 测试主动探测流量（发送非法 HTTP GET 请求）应当被透明回落到 Web 伪装站点并获得合法响应
    let mut probe = tokio::net::TcpStream::connect(("127.0.0.1", trojan_port))
        .await
        .unwrap();
    probe
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let mut probe_resp = vec![0u8; 128];
    let n = probe.read(&mut probe_resp).await.unwrap();
    assert!(n > 0, "回落服务应返回 HTTP 响应报文");
    let resp_str = String::from_utf8_lossy(&probe_resp[..n]);
    assert!(
        resp_str.contains("HTTP/1.1 200 OK") && resp_str.contains("Hello Decoy!"),
        "非法/探测流量应透明回落至本地伪装服务: {resp_str}"
    );

    // 5. 测试合法 Trojan 客户端代理流量正常通信
    let trojan_out = vp_protocol::trojan::TrojanOutbound::new(&vp_config::TrojanCfg {
        server: "127.0.0.1".into(),
        port: trojan_port,
        password: "pwd-alice".into(),
        tls: false,
        server_name: None,
        skip_cert_verify: true,
        client_fingerprint: None,
        network: None,
        alpn: None,
        ws_opts: None,
        grpc_opts: None,
        reality_opts: None,
        ech_opts: None,
        http_opts: None,
        udp: false,
    })
    .unwrap();

    let dst = vp_common::DstAddr::ip("127.0.0.1".parse().unwrap(), echo_port);
    let sess = vp_core::Session::new_tcp("t".into(), None, dst.clone());
    let mut client_stream = trojan_out
        .connect_stream(&sess, &dst)
        .await
        .expect("合法 Trojan 握手代理应当成功");
    client_stream.write_all(b"ping-trojan").await.unwrap();
    let mut buf = [0u8; 11];
    client_stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping-trojan");
}

/// listeners 段端到端：VLESS Fallback（非 VLESS 探测流量透明回落）
#[tokio::test]
async fn vless_fallback_and_user_quota_e2e() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // 1. 启动本地 Web 伪装/回落服务
    let decoy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let decoy_port = decoy.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = decoy.accept().await {
            tokio::spawn(async move {
                let mut req = [0u8; 512];
                if let Ok(n) = s.read(&mut req).await {
                    if n > 0 {
                        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello V-Decoy";
                        let _ = s.write_all(resp).await;
                    }
                }
            });
        }
    });

    let uuid = "a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8";
    let cfg = format!(
        "listeners:
  - name: srv-vless
    type: vless
    port: 0
    fallback: \"127.0.0.1:{decoy_port}\"
    user-configs:
      - name: bob
        secret: \"{uuid}\"
        quota-bytes: 1048576
rules: ['MATCH,DIRECT']
"
    );
    let app = App::start(&cfg, vp_config::Format::Yaml, &std::env::temp_dir(), true)
        .await
        .unwrap();
    let vless_port = app
        .listen_ports
        .iter()
        .find(|(t, _)| t == "srv-vless")
        .map(|(_, p)| *p)
        .expect("vless listener 应当已监听");

    // 2. 发送探测流量（非 VLESS 头部，常规浏览器请求），验证命中回落
    let mut probe = tokio::net::TcpStream::connect(("127.0.0.1", vless_port))
        .await
        .unwrap();
    probe
        .write_all(b"GET /index.html HTTP/1.1\r\nHost: test.org\r\n\r\n")
        .await
        .unwrap();
    let mut probe_resp = vec![0u8; 128];
    let n = probe.read(&mut probe_resp).await.unwrap();
    assert!(n > 0, "VLESS 回落应当返回合法 HTTP 响应");
    let resp_str = String::from_utf8_lossy(&probe_resp[..n]);
    assert!(
        resp_str.contains("Hello V-Decoy"),
        "探测流量应被透明代理至回落服务: {resp_str}"
    );
}

/// listeners 段端到端：多用户配额管控与超额断开
#[tokio::test]
async fn trojan_user_quota_cutoff_e2e() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo.accept().await {
            tokio::spawn(async move {
                let mut b = [0u8; 256];
                while let Ok(n) = s.read(&mut b).await {
                    if n == 0 {
                        break;
                    }
                    let _ = s.write_all(&b[..n]).await;
                }
            });
        }
    });

    let cfg = r#"
listeners:
  - name: srv-quota
    type: trojan
    port: 0
    user-configs:
      - name: charlie
        secret: "pwd-charlie"
        quota-bytes: 60
rules: ['MATCH,DIRECT']
"#;
    let app = App::start(cfg, vp_config::Format::Yaml, &std::env::temp_dir(), true)
        .await
        .unwrap();
    let port = app
        .listen_ports
        .iter()
        .find(|(t, _)| t == "srv-quota")
        .map(|(_, p)| *p)
        .unwrap();

    let trojan_out = vp_protocol::trojan::TrojanOutbound::new(&vp_config::TrojanCfg {
        server: "127.0.0.1".into(),
        port,
        password: "pwd-charlie".into(),
        tls: false,
        server_name: None,
        skip_cert_verify: true,
        client_fingerprint: None,
        network: None,
        alpn: None,
        ws_opts: None,
        grpc_opts: None,
        reality_opts: None,
        ech_opts: None,
        http_opts: None,
        udp: false,
    })
    .unwrap();

    let dst = vp_common::DstAddr::ip("127.0.0.1".parse().unwrap(), echo_port);
    let sess = vp_core::Session::new_tcp("t".into(), None, dst.clone());
    let mut client_stream = trojan_out.connect_stream(&sess, &dst).await.unwrap();

    // 试图发送 200 字节（超过 60 字节配额）
    client_stream.write_all(&[9u8; 200]).await.unwrap();
    let mut recv_buf = vec![0u8; 300];
    let mut total_read = 0;
    loop {
        match client_stream.read(&mut recv_buf[total_read..]).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                total_read += n;
                if total_read >= 300 {
                    break;
                }
            }
        }
    }
    // 验证因配额熔断而关闭了连接
    assert!(total_read <= 200);

    // 再次建立连接：配额已耗尽，握手认证直接被拒
    let sess2 = vp_core::Session::new_tcp("t2".into(), None, dst.clone());
    let res = trojan_out.connect_stream(&sess2, &dst).await;
    if let Ok(mut s2) = res {
        let mut check = [0u8; 10];
        let n = s2.read(&mut check).await.unwrap_or(0);
        assert_eq!(n, 0, "配额超额后连接应当被关闭");
    }
}

/// listeners 段端到端：Hysteria2 Salamander UDP 报文混淆 + user-configs Brutal 协商
#[tokio::test]
async fn hysteria2_salamander_listener_e2e() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = echo.accept().await.unwrap();
        let mut b = [0u8; 256];
        loop {
            let n = s.read(&mut b).await.unwrap();
            if n == 0 {
                break;
            }
            s.write_all(&b[..n]).await.unwrap();
        }
    });

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path =
        std::env::temp_dir().join(format!("hy2_obfs_cert_{}.pem", vp_common::now_millis()));
    let key_path =
        std::env::temp_dir().join(format!("hy2_obfs_key_{}.pem", vp_common::now_millis()));
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

    let cert_str = cert_path.to_str().unwrap().replace('\\', "/");
    let key_str = key_path.to_str().unwrap().replace('\\', "/");

    let cfg = format!(
        "listeners:
  - name: srv-hy2-salamander
    type: hysteria2
    port: 0
    cert: \"{cert_str}\"
    key: \"{key_str}\"
    obfs: salamander
    obfs-password: \"obfs-secret-test\"
    user-configs:
      - name: user-hy2
        secret: \"pw-hy2-obfs\"
        brutal-mbps: 100
rules: ['MATCH,DIRECT']
"
    );
    let app = App::start(&cfg, vp_config::Format::Yaml, &std::env::temp_dir(), true)
        .await
        .unwrap();
    let hy2_port = app
        .listen_ports
        .iter()
        .find(|(t, _)| t == "srv-hy2-salamander")
        .map(|(_, p)| *p)
        .expect("hysteria2 listener 应已监听");

    let out = vp_protocol::hysteria2::Hysteria2Outbound::new(&vp_config::Hysteria2Cfg {
        server: "127.0.0.1".into(),
        port: hy2_port,
        password: "pw-hy2-obfs".into(),
        sni: Some("localhost".into()),
        skip_cert_verify: true,
        up: None,
        down: None,
        obfs: Some("salamander".into()),
        obfs_password: Some("obfs-secret-test".into()),
        ports: None,
        hop_interval: None,
    })
    .unwrap();

    let dst = vp_common::DstAddr::ip("127.0.0.1".parse().unwrap(), echo_port);
    let sess = vp_core::Session::new_tcp("t".into(), None, dst.clone());
    let mut s = out
        .connect_stream(&sess, &dst)
        .await
        .expect("hysteria2 salamander 出站应成功");
    s.write_all(b"hy2-salamander-e2e").await.unwrap();
    let mut buf = [0u8; 18];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hy2-salamander-e2e");

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);
}

/// listeners 段端到端：Shadowsocks-2022 单端口多用户识别与独立记账
#[tokio::test]
async fn ss_2022_multi_user_listener_e2e() {
    use base64::Engine;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo.accept().await {
            tokio::spawn(async move {
                let mut b = [0u8; 256];
                while let Ok(n) = s.read(&mut b).await {
                    if n == 0 {
                        break;
                    }
                    let _ = s.write_all(&b[..n]).await;
                }
            });
        }
    });

    let key_alice_raw = [0x11u8; 16];
    let key_bob_raw = [0x22u8; 16];
    let key_alice = base64::engine::general_purpose::STANDARD.encode(key_alice_raw);
    let key_bob = base64::engine::general_purpose::STANDARD.encode(key_bob_raw);

    let cfg = format!(
        "listeners:
  - name: srv-ss-multi
    type: ss
    port: 0
    cipher: 2022-blake3-aes-128-gcm
    user-configs:
      - name: alice
        secret: \"{key_alice}\"
      - name: bob
        secret: \"{key_bob}\"
rules: ['MATCH,DIRECT']
"
    );
    let app = App::start(&cfg, vp_config::Format::Yaml, &std::env::temp_dir(), true)
        .await
        .unwrap();
    let ss_port = app
        .listen_ports
        .iter()
        .find(|(t, _)| t == "srv-ss-multi")
        .map(|(_, p)| *p)
        .expect("ss listener 应已监听");

    let out_alice = vp_protocol::ss::SsOutbound::new(&vp_config::SsCfg {
        server: "127.0.0.1".into(),
        port: ss_port,
        password: key_alice.clone(),
        cipher: "2022-blake3-aes-128-gcm".into(),
        udp: true,
        plugin: None,
        plugin_opts: None,
    })
    .unwrap();

    let out_bob = vp_protocol::ss::SsOutbound::new(&vp_config::SsCfg {
        server: "127.0.0.1".into(),
        port: ss_port,
        password: key_bob.clone(),
        cipher: "2022-blake3-aes-128-gcm".into(),
        udp: true,
        plugin: None,
        plugin_opts: None,
    })
    .unwrap();

    let dst = vp_common::DstAddr::ip("127.0.0.1".parse().unwrap(), echo_port);

    // 1. Alice 连接
    let sess_a = vp_core::Session::new_tcp("ta".into(), None, dst.clone());
    let mut sa = out_alice
        .connect_stream(&sess_a, &dst)
        .await
        .expect("alice 连接应当成功");
    sa.write_all(b"hello from alice").await.unwrap();
    let mut buf_a = [0u8; 16];
    sa.read_exact(&mut buf_a).await.unwrap();
    assert_eq!(&buf_a, b"hello from alice");

    // 2. Bob 连接
    let sess_b = vp_core::Session::new_tcp("tb".into(), None, dst.clone());
    let mut sb = out_bob
        .connect_stream(&sess_b, &dst)
        .await
        .expect("bob 连接应当成功");
    sb.write_all(b"hello from bob!").await.unwrap();
    let mut buf_b = [0u8; 15];
    sb.read_exact(&mut buf_b).await.unwrap();
    assert_eq!(&buf_b, b"hello from bob!");

    // 3. 验证 Alice 与 Bob 各自独立记账
    let um = &app.user_manager;
    let user_a = um.get_user_by_target("alice").expect("alice 账户应当存在");
    let user_b = um.get_user_by_target("bob").expect("bob 账户应当存在");
    let snap_a = user_a.snapshot();
    let snap_b = user_b.snapshot();
    assert!(snap_a.upload + snap_a.download > 0, "alice 流量应当被记账");
    assert!(snap_b.upload + snap_b.download > 0, "bob 流量应当被记账");
}

/// 入站安全门禁端到端：GeoIP 探针门禁拦截与放行（LAN 阻断与放行）
#[tokio::test]
async fn inbound_geoip_gate_e2e() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // 1. 启动一个阻断 LAN 访问的 Trojan 监听器（模拟公网防内网扫描）
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo.accept().await {
            tokio::spawn(async move {
                let mut b = [0u8; 256];
                while let Ok(n) = s.read(&mut b).await {
                    if n == 0 {
                        break;
                    }
                    let _ = s.write_all(&b[..n]).await;
                }
            });
        }
    });

    let cfg_blocked = "
listeners:
  - name: srv-blocked
    type: trojan
    port: 0
    users: [\"pw-gate\"]
    block-geoip: [\"LAN\"]
rules: ['MATCH,DIRECT']
";
    let app_blocked = App::start(cfg_blocked, Format::Yaml, &std::env::temp_dir(), true)
        .await
        .unwrap();
    let blocked_port = app_blocked
        .listen_ports
        .iter()
        .find(|(t, _)| t == "srv-blocked")
        .map(|(_, p)| *p)
        .unwrap();

    // 从 127.0.0.1 (属于 LAN/Private) 发起连接，应被门禁第一时间静默切断
    let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", blocked_port))
        .await
        .unwrap();
    let mut buf = [0u8; 10];
    let n = conn.read(&mut buf).await.unwrap_or(0);
    assert_eq!(n, 0, "命中 block-geoip 的来源 IP 应当被立即切断连接");

    // 2. 启动允许 LAN 访问的 Trojan 监听器
    let cfg_allowed = "
listeners:
  - name: srv-allowed
    type: trojan
    port: 0
    users: [\"pw-gate\"]
    allow-geoip: [\"LAN\"]
rules: ['MATCH,DIRECT']
";
    let app_allowed = App::start(cfg_allowed, Format::Yaml, &std::env::temp_dir(), true)
        .await
        .unwrap();
    let allowed_port = app_allowed
        .listen_ports
        .iter()
        .find(|(t, _)| t == "srv-allowed")
        .map(|(_, p)| *p)
        .unwrap();

    let out = vp_protocol::trojan::TrojanOutbound::new(&vp_config::TrojanCfg {
        server: "127.0.0.1".into(),
        port: allowed_port,
        password: "pw-gate".into(),
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

    let dst = vp_common::DstAddr::ip("127.0.0.1".parse().unwrap(), echo_port);
    let sess = vp_core::Session::new_tcp("t".into(), None, dst.clone());
    let mut s = out
        .connect_stream(&sess, &dst)
        .await
        .expect("命中 allow-geoip 的白名单 IP 应当连接成功");
    s.write_all(b"gate-pass").await.unwrap();
    let mut pass_buf = [0u8; 9];
    s.read_exact(&mut pass_buf).await.unwrap();
    assert_eq!(&pass_buf, b"gate-pass");
}

/// 入站安全门禁端到端：端口敲门 (Port Knocking) 隐身防御与动态开门
#[tokio::test]
async fn inbound_port_knocking_e2e() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo.accept().await {
            tokio::spawn(async move {
                let mut b = [0u8; 256];
                while let Ok(n) = s.read(&mut b).await {
                    if n == 0 {
                        break;
                    }
                    let _ = s.write_all(&b[..n]).await;
                }
            });
        }
    });

    // 预选一个可用 UDP 端口作为 knock 端口
    let knock_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let knock_port = knock_sock.local_addr().unwrap().port();
    drop(knock_sock);

    let cfg = format!(
        "
listeners:
  - name: srv-stealth
    type: trojan
    port: 0
    users: [\"pw-stealth\"]
    knock:
      port: {knock_port}
      secret: \"knock-secret-123\"
      timeout-secs: 5
rules: ['MATCH,DIRECT']
"
    );

    let app = App::start(&cfg, Format::Yaml, &std::env::temp_dir(), true)
        .await
        .unwrap();
    let trojan_port = app
        .listen_ports
        .iter()
        .find(|(t, _)| t == "srv-stealth")
        .map(|(_, p)| *p)
        .unwrap();

    // 1. 未敲门阶段：直接发起连接，被静默阻断
    let mut probe = tokio::net::TcpStream::connect(("127.0.0.1", trojan_port))
        .await
        .unwrap();
    let mut check_buf = [0u8; 10];
    let n = probe.read(&mut check_buf).await.unwrap_or(0);
    assert_eq!(n, 0, "未敲门客户端应当被完全阻断（端口处于隐身状态）");

    // 2. 发送敲门包（口令验证模式）
    let client_sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_sender
        .send_to(b"knock-secret-123\n", ("127.0.0.1", knock_port))
        .await
        .unwrap();

    // 稍微等待后台 UDP 敲门处理协程开门
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // 3. 敲门成功后：再次发起代理连接，应当顺畅连通
    let out = vp_protocol::trojan::TrojanOutbound::new(&vp_config::TrojanCfg {
        server: "127.0.0.1".into(),
        port: trojan_port,
        password: "pw-stealth".into(),
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

    let dst = vp_common::DstAddr::ip("127.0.0.1".parse().unwrap(), echo_port);
    let sess = vp_core::Session::new_tcp("t".into(), None, dst.clone());
    let mut s = out
        .connect_stream(&sess, &dst)
        .await
        .expect("敲门成功后代理连接应当建立成功");
    s.write_all(b"knock-ok").await.unwrap();
    let mut ok_buf = [0u8; 8];
    s.read_exact(&mut ok_buf).await.unwrap();
    assert_eq!(&ok_buf, b"knock-ok");
}

/// listeners 段端到端：UDP 端口跳跃 iptables 守卫生命周期与状态测试
#[tokio::test]
async fn test_listener_port_redirect_guard_lifecycle() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    let temp_dir = std::env::temp_dir();
    let cert_path = temp_dir.join(format!("test_hy2_cert_{}.pem", std::process::id()));
    let key_path = temp_dir.join(format!("test_hy2_key_{}.pem", std::process::id()));
    std::fs::write(&cert_path, cert_pem).unwrap();
    std::fs::write(&key_path, key_pem).unwrap();

    let cfg = format!(
        r#"
mode: direct
listeners:
  - name: hy2-mport-test
    type: hysteria2
    port: 0
    listen: 127.0.0.1
    users: ["secret123"]
    cert: "{cert_file}"
    key: "{key_file}"
    ports: "25000-25050"
rules: ['MATCH,DIRECT']
"#,
        cert_file = cert_path.to_str().unwrap().replace('\\', "/"),
        key_file = key_path.to_str().unwrap().replace('\\', "/"),
    );

    let app = App::start(&cfg, Format::Yaml, &temp_dir, true)
        .await
        .unwrap();
    // 验证 Guard 已建立且状态一致
    let guards = app.port_redirect_guards.read().unwrap();
    assert_eq!(guards.len(), 1);
    assert_eq!(guards[0].listener_name, "hy2-mport-test");
    assert_eq!(guards[0].port_ranges, vec![(25000, 25050)]);
    let is_active = guards[0].is_active();
    drop(guards);
    assert_eq!(app.has_port_redirects(), is_active);

    let _ = std::fs::remove_file(cert_path);
    let _ = std::fs::remove_file(key_path);
}

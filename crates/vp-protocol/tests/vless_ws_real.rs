//! 真实节点调试（`#[ignore]`）：对生产订阅里的 VLESS+WS+TLS 节点
//! 分别用 uTLS（chrome 指纹）与标准 rustls 走完整链路，
//! 失败时十六进制转储响应首字节，用于定位坏层。

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vp_common::{DstAddr, Host};
use vp_config::VlessCfg;
use vp_core::Outbound;
use vp_protocol::vless::VlessOutbound;

const NODE_YAML: &str = r#"
server: saas.sin.fan
port: 443
uuid: d9d939c9-1a6b-47d1-80d0-4bf008fee7ff
tls: true
servername: llc.983698.xyz
network: ws
client-fingerprint: chrome
ws-opts:
  path: /d9d939c9-1a6b-47d1-80d0-4bf008fee7ff?ed=2048
  headers:
    Host: llc.983698.xyz
"#;

fn node_with_fp(fp: Option<&str>) -> VlessCfg {
    let mut cfg: VlessCfg = serde_yaml::from_str(NODE_YAML).expect("parse node yaml");
    cfg.client_fingerprint = fp.map(|s| s.to_string());
    cfg
}

async fn probe(label: &str, cfg: VlessCfg) {
    // 明文 HTTP 目标（80 端口）：避免“往 443 发明文 HTTP 被目标断开”的干扰
    let dst = DstAddr {
        host: Host::Domain("www.gstatic.com".into()),
        port: 80,
    };
    let out = match VlessOutbound::new(&cfg) {
        Ok(o) => o,
        Err(e) => {
            println!("{label}: build error: {e}");
            return;
        }
    };
    let sess = vp_core::Session::new_tcp("debug".into(), None, dst.clone());
    let io = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        out.connect_stream(&sess, &dst),
    )
    .await;
    let mut stream = match io {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            println!("{label}: connect error: {e}");
            return;
        }
        Err(_) => {
            println!("{label}: connect timeout (10s)");
            return;
        }
    };
    // 发一个最小 TLS ClientHello 目标请求：直接经 vless 隧道发 HTTP
    let req = b"GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n";
    if let Err(e) = stream.write_all(req).await {
        println!("{label}: write error: {e}");
        return;
    }
    let mut buf = [0u8; 64];
    let r = tokio::time::timeout(std::time::Duration::from_secs(8), stream.read(&mut buf)).await;
    match r {
        Ok(Ok(0)) => println!("{label}: EOF after request"),
        Ok(Ok(n)) => println!(
            "{label}: {} bytes: {}",
            n,
            String::from_utf8_lossy(&buf[..n]).replace('\r', "").replace('\n', "/")
        ),
        Ok(Err(e)) => println!("{label}: read error: {e}"),
        Err(_) => println!("{label}: read timeout (8s) — 服务器无响应"),
    }
}

#[tokio::test]
#[ignore = "真实节点调试：需要外网"]
async fn vless_real_node_utls_vs_rustls() {
    probe("utls-chrome", node_with_fp(Some("chrome"))).await;
    probe("rustls-std ", node_with_fp(None)).await;
}

/// 只测 传输层：WS 握手后直接发 HTTP（绕开 VLESS 协议层），
/// 用于区分“TLS/WS 坏”还是“VLESS 层坏”。
#[tokio::test]
#[ignore = "真实节点调试：需要外网"]
async fn ws_tls_transport_only() {
    use vp_transport::{TransportConfig, ws};
    let cfg = TransportConfig {
        tls: true,
        server_name: Some("llc.983698.xyz".into()),
        skip_cert_verify: false,
        fingerprint: None,
        ws: Some(ws::WsConfig {
            path: "/d9d939c9-1a6b-47d1-80d0-4bf008fee7ff?ed=2048".into(),
            headers: vec![("Host".into(), "llc.983698.xyz".into())],
        }),
        grpc: None,
        reality: None,
    };
    let mut s = match vp_transport::dial("saas.sin.fan", 443, &cfg).await {
        Ok(s) => s,
        Err(e) => {
            println!("ws transport dial error: {e}");
            return;
        }
    };
    // 经 CDN 的 ws 隧道：VLESS 服务器期待 VLESS 请求，这里只发 0 长度探测
    // ——发一个非法的 1 字节让服务器回 EOF/告警，确认隧道活性。
    let _ = s.write_all(&[0x00]).await;
    let mut buf = vec![0u8; 32];
    let r = tokio::time::timeout(std::time::Duration::from_secs(8), s.read(&mut buf)).await;
    match r {
        Ok(Ok(0)) => println!("ws transport: EOF (server rejected invalid vless) — 隧道活性正常"),
        Ok(Ok(n)) => println!("ws transport: {n} bytes: {:02x?}", &buf[..n]),
        Ok(Err(e)) => println!("ws transport read error: {e}"),
        Err(_) => println!("ws transport read timeout (8s)"),
    }
}

/// 分段计时复刻 VlessOutbound::connect_stream 全链路，定位卡死阶段。
#[tokio::test]
#[ignore = "真实节点调试：需要外网"]
async fn vless_staged_timing() {
    use std::time::Duration;
    use vp_transport::utls::{self, UtlsConfig, Fingerprint};

    let dst = DstAddr {
        host: Host::Domain("www.gstatic.com".into()),
        port: 80,
    };
    let cfg = node_with_fp(Some("chrome"));
    let out = VlessOutbound::new(&cfg).expect("build");
    let sess = vp_core::Session::new_tcp("debug".into(), None, dst.clone());

    let t0 = std::time::Instant::now();
    let tcp = tokio::net::TcpStream::connect(("saas.sin.fan", 443))
        .await
        .expect("tcp");
    vp_transport::tune(&tcp);
    println!("[{:>6.2}s] tcp ok", t0.elapsed().as_secs_f32());

    let tls = tokio::time::timeout(
        Duration::from_secs(5),
        utls::utls_connect(
            Box::new(tcp),
            "saas.sin.fan",
            &UtlsConfig {
                fingerprint: Fingerprint::Chrome,
                server_name: Some("llc.983698.xyz".into()),
                alpn: Vec::new(),
                skip_cert_verify: false,
                reality: None,
            },
        ),
    )
    .await
    .expect("utls 5s 超时")
    .expect("utls err");
    println!("[{:>6.2}s] utls ok", t0.elapsed().as_secs_f32());

    let ws = tokio::time::timeout(
        Duration::from_secs(5),
        vp_transport::ws::ws_handshake_client(
            tls,
            "saas.sin.fan",
            &vp_transport::ws::WsConfig {
                path: "/d9d939c9-1a6b-47d1-80d0-4bf008fee7ff?ed=2048".into(),
                headers: vec![("Host".into(), "llc.983698.xyz".into())],
            },
        ),
    )
    .await
    .expect("ws 5s 超时")
    .expect("ws err");
    println!("[{:>6.2}s] ws 101 ok", t0.elapsed().as_secs_f32());

    let vless = tokio::time::timeout(
        Duration::from_secs(5),
        out.connect_over(&sess, &dst, Box::new(ws)),
    )
    .await;
    let mut stream = match vless {
        Err(_) => {
            println!("[{:>6.2}s] vless handshake 5s 超时 —— 卡在 VLESS 握手", t0.elapsed().as_secs_f32());
            return;
        }
        Ok(Err(e)) => {
            println!("[{:>6.2}s] vless handshake error: {e}", t0.elapsed().as_secs_f32());
            return;
        }
        Ok(Ok(s)) => {
            println!("[{:>6.2}s] vless handshake ok", t0.elapsed().as_secs_f32());
            s
        }
    };

    let req = b"GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n";
    stream.write_all(req).await.expect("write");
    println!("[{:>6.2}s] http request sent", t0.elapsed().as_secs_f32());
    let mut buf = [0u8; 64];
    let r = tokio::time::timeout(Duration::from_secs(8), stream.read(&mut buf)).await;
    match r {
        Ok(Ok(0)) => println!("[{:>6.2}s] EOF", t0.elapsed().as_secs_f32()),
        Ok(Ok(n)) => println!(
            "[{:>6.2}s] {} bytes: {}",
            t0.elapsed().as_secs_f32(),
            n,
            String::from_utf8_lossy(&buf[..n]).replace('\r', "").replace('\n', "/")
        ),
        Ok(Err(e)) => println!("[{:>6.2}s] read error: {e}", t0.elapsed().as_secs_f32()),
        Err(_) => println!("[{:>6.2}s] read timeout", t0.elapsed().as_secs_f32()),
    }
}


#[allow(dead_code)]
fn _hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// 交叉实验：同一进程内 rustls 与 utls 各连两次，排除限速/时序因素。
#[tokio::test]
#[ignore = "真实节点调试：需要外网"]
async fn vless_cross_experiment() {
    use std::time::Duration;
    use vp_transport::utls::{self, Fingerprint, UtlsConfig};

    let dst = DstAddr {
        host: Host::Domain("www.gstatic.com".into()),
        port: 80,
    };
    let sess = vp_core::Session::new_tcp("debug".into(), None, dst.clone());

    for round in 1..=2 {
        // rustls 路径
        {
            let cfg = node_with_fp(None);
            let out = VlessOutbound::new(&cfg).expect("build");
            let r = tokio::time::timeout(Duration::from_secs(8), out.connect_stream(&sess, &dst)).await;
            match r {
                Err(_) => println!("round{round} rustls: 8s connect timeout"),
                Ok(Err(e)) => println!("round{round} rustls: connect error: {e}"),
                Ok(Ok(mut s)) => {
                    let _ = s.write_all(b"GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n").await;
                    let mut buf = [0u8; 40];
                    let rr = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await;
                    println!("round{round} rustls: {:?}", rr.map(|x| x.map(|n| String::from_utf8_lossy(&buf[..n.min(20)]).to_string())));
                }
            }
        }
        // utls 路径
        {
            let cfg = node_with_fp(Some("chrome"));
            let out = VlessOutbound::new(&cfg).expect("build");
            let r = tokio::time::timeout(Duration::from_secs(8), out.connect_stream(&sess, &dst)).await;
            match r {
                Err(_) => println!("round{round} utls  : 8s connect timeout"),
                Ok(Err(e)) => println!("round{round} utls  : connect error: {e}"),
                Ok(Ok(mut s)) => {
                    let _ = s.write_all(b"GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n").await;
                    let mut buf = [0u8; 40];
                    let rr = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await;
                    println!("round{round} utls  : {:?}", rr.map(|x| x.map(|n| String::from_utf8_lossy(&buf[..n.min(20)]).to_string())));
                }
            }
        }
    }
    let _ = Fingerprint::Chrome;
}

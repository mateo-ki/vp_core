//! Hysteria v1 真实节点探针：
//! cargo run -p vp-protocol --example hy1_probe -- <host> <port> <auth> [sni] [alpn]
//! 通过节点访问 http://www.gstatic.com/generate_204 并分阶段输出耗时。

use std::time::Instant;

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("用法: hy1_probe <host> <port> <auth> [sni] [alpn]");
        std::process::exit(2);
    }
    let server = args[1].clone();
    let port: u16 = args[2].parse()?;
    let auth = args[3].clone();
    let sni = args.get(4).cloned();
    let alpn: Vec<String> = args
        .get(5)
        .map(|s| s.split(',').map(|p| p.trim().to_owned()).collect())
        .unwrap_or_default();

    let yaml = format!(
        "server: {server}\nport: {port}\nauth-str: \"{auth}\"\nup: \"11 Mbps\"\ndown: \"55 Mbps\"\nprotocol: udp\nsni: {}\nskip-cert-verify: true\nalpn: [{}]\n",
        sni.unwrap_or_default(),
        alpn.join(", ")
    );
    let cfg: vp_config::Hysteria1Cfg = serde_yaml::from_str(&yaml)?;
    let out = vp_protocol::hysteria::Hysteria1Outbound::new(&cfg)?;
    println!("[1] 出站构建 OK");

    let t0 = Instant::now();
    let sess = out.connect_quic_for_probe().await?;
    println!("[2] QUIC 握手完成: {:?}", t0.elapsed());

    let t1 = Instant::now();
    out.auth_for_probe(&sess.0).await?;
    println!("[3] 认证完成: {:?}", t1.elapsed());

    let t2 = Instant::now();
    let dst = vp_common::DstAddr::new("www.gstatic.com", 80);
    let sess_ctx = vp_core::session::Session::new_tcp("probe".into(), None, dst.clone());
    let mut stream =
        <vp_protocol::hysteria::Hysteria1Outbound as vp_core::Outbound>::connect_stream(
            &out, &sess_ctx, &dst,
        )
        .await?;
    println!("[4] TCP 流建立: {:?}", t2.elapsed());

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let t3 = Instant::now();
    stream
        .write_all(
            b"GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        stream.read_to_end(&mut buf),
    )
    .await;
    let head = String::from_utf8_lossy(&buf[..buf.len().min(120)]).into_owned();
    println!(
        "[5] HTTP 响应: {:?} — {}",
        t3.elapsed(),
        head.lines().next().unwrap_or("<空>")
    );
    Ok(())
}

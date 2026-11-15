//! 真实节点调试（`#[ignore]`）：对 `VPCORE_DEBUG_SS_YAML` / `VPCORE_DEBUG_HY2_YAML`
//! 指定的 SS-2022 / Hysteria2 节点用 VP-Core 原生出站走完整链路（generate_204），
//! 用于区分「链路通但协议失败」与「链路本身不通」。节点凭据只经 yaml 注入，不写入源码。

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vp_common::{DstAddr, Host};
use vp_core::Outbound;

async fn probe_http<S>(label: &str, mut s: Box<S>)
where
    S: tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin + ?Sized,
{
    let req = b"GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n";
    if let Err(e) = s.write_all(req).await {
        println!("{label}: write error: {e}");
        return;
    }
    let mut buf = [0u8; 256];
    match tokio::time::timeout(std::time::Duration::from_secs(10), s.read(&mut buf)).await {
        Ok(Ok(0)) => println!("{label}: EOF after request"),
        Ok(Ok(n)) => println!(
            "{label}: {} bytes: {}",
            n,
            String::from_utf8_lossy(&buf[..n]).replace('\n', "/")
        ),
        Ok(Err(e)) => println!("{label}: read error: {e}"),
        Err(_) => println!("{label}: read timeout"),
    }
}

fn read_yaml(env_key: &str, fallback: &str) -> Option<String> {
    std::env::var(env_key)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::fs::read_to_string(fallback).ok())
}

#[tokio::test]
#[ignore]
async fn ss2022_real_node_probe() {
    let Some(raw) = read_yaml("VPCORE_DEBUG_SS_YAML", "../../target/debug_ss_node.yaml") else {
        println!("跳过：未提供 VPCORE_DEBUG_SS_YAML");
        return;
    };
    let cfg: vp_config::SsCfg = serde_yaml::from_str(&raw).expect("parse ss yaml");
    let out = match vp_protocol::ss::SsOutbound::new(&cfg) {
        Ok(o) => o,
        Err(e) => {
            println!("ss build error: {e}");
            return;
        }
    };
    let dst = DstAddr {
        host: Host::Domain("www.gstatic.com".into()),
        port: 80,
    };
    let sess = vp_core::Session::new_tcp("ss-probe".into(), None, dst.clone());
    match tokio::time::timeout(
        std::time::Duration::from_secs(20),
        out.connect_stream(&sess, &dst),
    )
    .await
    {
        Ok(Ok(s)) => probe_http("ss2022", s).await,
        Ok(Err(e)) => println!("ss connect error: {e}"),
        Err(_) => println!("ss connect timeout"),
    }
}

#[tokio::test]
#[ignore]
async fn hy2_real_node_probe() {
    let Some(raw) = read_yaml("VPCORE_DEBUG_HY2_YAML", "../../target/debug_hy2_node.yaml") else {
        println!("跳过：未提供 VPCORE_DEBUG_HY2_YAML");
        return;
    };
    let cfg: vp_config::Hysteria2Cfg = serde_yaml::from_str(&raw).expect("parse hy2 yaml");
    let out = match vp_protocol::hysteria2::Hysteria2Outbound::new(&cfg) {
        Ok(o) => o,
        Err(e) => {
            println!("hy2 build error: {e}");
            return;
        }
    };
    let dst = DstAddr {
        host: Host::Domain("www.gstatic.com".into()),
        port: 80,
    };
    let sess = vp_core::Session::new_tcp("hy2-probe".into(), None, dst.clone());
    match tokio::time::timeout(
        std::time::Duration::from_secs(20),
        out.connect_stream(&sess, &dst),
    )
    .await
    {
        Ok(Ok(s)) => probe_http("hy2", s).await,
        Ok(Err(e)) => println!("hy2 connect error: {e}"),
        Err(_) => println!("hy2 connect timeout"),
    }
}

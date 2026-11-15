//! 一次性全节点探针（跑完即删）：对 clash proxies JSON 数组逐节点用 VP-Core 原生出站
//! 测 generate_204，输出与 mihomo 探针同构的结果 JSON，供双内核逐节点对比。
//!
//! 输入 VPCORE_PROBE_INPUT：[{id, name, protocol, server, port, config(clash proxy json)}]
//! 输出 VPCORE_PROBE_OUT：[{id, protocol, ok, latency_ms, err}]

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vp_common::{DstAddr, Host};

const CONCURRENCY: usize = 128;
const TIMEOUT: Duration = Duration::from_secs(8);

#[tokio::test]
#[ignore]
async fn probe_all_nodes_vpcore() {
    let Ok(input) = std::env::var("VPCORE_PROBE_INPUT") else {
        println!("跳过：未设置 VPCORE_PROBE_INPUT");
        return;
    };
    let out_path = std::env::var("VPCORE_PROBE_OUT")
        .unwrap_or_else(|_| "target/probe_results_vpcore.json".into());
    let raw = std::fs::read_to_string(&input).expect("read input");
    let nodes: Vec<serde_json::Value> = serde_json::from_str(&raw).expect("parse input");
    println!("VP-Core 探针：{} 节点，并发 {CONCURRENCY}", nodes.len());

    let dns = Arc::new(vp_dns::Resolver::system());
    vp_transport::set_global_node_resolver(dns.clone(), false);
    let deps = vp_protocol::OutboundDeps { dns, ipv6: false };
    let dst = DstAddr {
        host: Host::Domain("www.gstatic.com".into()),
        port: 80,
    };
    let req = b"GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n";

    let sem = Arc::new(tokio::sync::Semaphore::new(CONCURRENCY));
    let mut tasks = tokio::task::JoinSet::new();
    for (idx, node) in nodes.iter().enumerate() {
        let id = node["id"].as_str().unwrap_or_default().to_string();
        let proto = node["protocol"].as_str().unwrap_or("unknown").to_string();
        let cfgv = node["config"].clone();
        let deps = deps.clone();
        let dst = dst.clone();
        let sem = sem.clone();
        tasks.spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let fail = |err: String| {
                serde_json::json!({"id": id, "protocol": proto, "ok": false, "latency_ms": null, "err": err})
            };
            let cfg: vp_config::ProxyCfg = match serde_json::from_value(cfgv) {
                Ok(c) => c,
                Err(e) => return fail(format!("config: {e}")),
            };
            let ob = match vp_protocol::build_outbound(&cfg, &deps) {
                Ok(o) => o,
                Err(e) => return fail(format!("build: {e}")),
            };
            let sess = vp_core::Session::new_tcp(cfg.name.clone().into(), None, dst.clone());
            let t0 = Instant::now();
            let stream = match tokio::time::timeout(TIMEOUT, ob.connect_stream(&sess, &dst)).await {
                Err(_) => return fail("connect timeout".into()),
                Ok(Err(e)) => return fail(format!("connect: {e}")),
                Ok(Ok(s)) => s,
            };
            let connect_ms = t0.elapsed().as_millis() as u64;
            let mut s = stream;
            if let Err(e) = s.write_all(req).await {
                return fail(format!("write: {e}"));
            }
            let mut buf = [0u8; 256];
            let n = match tokio::time::timeout(Duration::from_secs(6), s.read(&mut buf)).await {
                Err(_) => return fail("read timeout".into()),
                Ok(Err(e)) => return fail(format!("read: {e}")),
                Ok(Ok(n)) => n,
            };
            let head = String::from_utf8_lossy(&buf[..n.min(64)]).to_string();
            if !head.starts_with("HTTP/1.1 204") && !head.starts_with("HTTP/1.0 204") {
                return fail(format!("http: {}", head.replace('\n', "/")));
            }
            serde_json::json!({"id": id, "protocol": proto, "ok": true,
                "latency_ms": connect_ms as i64, "err": null})
        });
        if (idx + 1) % 2000 == 0 {
            println!("  已派发 {}/{}", idx + 1, nodes.len());
        }
    }

    let mut results = Vec::with_capacity(nodes.len());
    let mut done = 0usize;
    while let Some(j) = tasks.join_next().await {
        match j {
            Ok(v) => results.push(v),
            Err(e) => results
                .push(serde_json::json!({"id": null, "ok": false, "err": format!("join: {e}")})),
        }
        done += 1;
        if done % 1000 == 0 {
            println!("  已完成 {done}/{}", nodes.len());
        }
    }
    std::fs::write(&out_path, serde_json::to_string(&results).unwrap()).unwrap();
    let ok = results.iter().filter(|r| r["ok"] == true).count();
    println!("VP-Core 探针完成：{ok}/{} ok → {out_path}", results.len());
}

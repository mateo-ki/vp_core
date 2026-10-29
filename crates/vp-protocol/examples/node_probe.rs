//! 真实节点连通探针：
//! cargo run --release -p vp-protocol --example node_probe -- <nodes.txt> [并发数]
//!
//! nodes.txt 每行一个节点分享链接（vless:// / ssr:// 等，同订阅格式），
//! 空行与 # 注释跳过。对每个节点：解析 → 构建出站 → 经节点请求
//! http://www.gstatic.com/generate_204，输出各阶段耗时与结果。

use std::sync::Arc;
use std::time::{Duration, Instant};

use vp_protocol::{OutboundDeps, build_outbound_eager};

async fn probe_inner(cfg: vp_config::ProxyCfg, deps: Arc<OutboundDeps>) -> Result<u64, String> {
    let t0 = Instant::now();
    let ob = build_outbound_eager(&cfg, &deps).map_err(|e| format!("构建出站失败: {e}"))?;
    let build_ms = t0.elapsed().as_millis() as u64;

    let dst = vp_common::DstAddr::new("www.gstatic.com", 80);
    let sess = vp_core::session::Session::new_tcp("probe".into(), None, dst.clone());
    let t1 = Instant::now();
    let mut stream = tokio::time::timeout(Duration::from_secs(20), ob.connect_stream(&sess, &dst))
        .await
        .map_err(|_| "握手超时".to_string())?
        .map_err(|e| format!("连接失败: {e}"))?;
    let handshake_ms = t1.elapsed().as_millis() as u64;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let t2 = Instant::now();
    stream
        .write_all(
            b"GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n",
        )
        .await
        .map_err(|e| format!("发送失败: {e}"))?;
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut buf))
        .await
        .map_err(|_| "响应超时".to_string())?
        .map_err(|e| format!("读取失败: {e}"))?;
    let http_ms = t2.elapsed().as_millis() as u64;
    let head = String::from_utf8_lossy(&buf[..buf.len().min(200)]).into_owned();
    let status = head.lines().next().unwrap_or_default().trim().to_string();
    if !status.starts_with("HTTP/1.1 204") && !status.starts_with("HTTP/1.0 204") {
        return Err(format!(
            "异常响应: {status}（body 前 80 字节: {:?}）",
            String::from_utf8_lossy(&buf[..buf.len().min(80)])
        ));
    }
    println!("    [阶段] 构建 {build_ms} ms · 握手 {handshake_ms} ms · HTTP 往返 {http_ms} ms");
    Ok(handshake_ms + http_ms)
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("用法: node_probe <nodes.txt> [并发数=4]");
        std::process::exit(2);
    }
    let text = std::fs::read_to_string(&args[1])?;
    let limit: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(4);

    let uris: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect();
    println!("待测节点 {n} 个，并发 {limit}", n = uris.len());

    // 订阅文本 → ProxyCfg（与生产一致的解析链）
    let cfgs = vp_protocol::sub::parse_provider_proxies(&uris.join("\n"), None)
        .map_err(|e| format!("解析失败: {e}"))?;
    println!("解析成功 {n} 个节点", n = cfgs.len());

    let deps = Arc::new(OutboundDeps {
        dns: Arc::new(vp_dns::Resolver::new(vec![
            "https://dns.alidns.com/dns-query".into(),
        ])),
        ipv6: false,
    });

    let sem = Arc::new(tokio::sync::Semaphore::new(limit));
    let mut handles = Vec::new();
    for cfg in cfgs {
        let name = cfg.name.clone();
        let deps = deps.clone();
        let sem = sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            let r = probe_inner(cfg, deps).await;
            (name, r)
        }));
    }
    let mut results = Vec::new();
    for h in handles {
        let (name, r) = h.await?;
        match &r {
            Ok(ms) => println!("✅ {name} — 握手+HTTP {ms} ms"),
            Err(e) => println!("❌ {name} — {e}"),
        }
        results.push((name, r));
    }

    let ok = results.iter().filter(|(_, r)| r.is_ok()).count();
    println!("\n==== 汇总：{}/{} 成功 ====", ok, results.len());
    for (name, r) in &results {
        match r {
            Ok(ms) => println!("  ✅ {name} ({ms} ms)"),
            Err(e) => println!("  ❌ {name} — {e}"),
        }
    }
    if ok == 0 && !results.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

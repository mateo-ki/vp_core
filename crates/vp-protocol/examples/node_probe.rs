//! 真实节点连通探针：
//! cargo run --release -p vp-protocol --example node_probe -- <nodes.txt|config.yaml> [并发数]
//!
//! 输入二选一：每行一个节点分享链接（vless:// / ssr:// 等，同订阅格式，空行与 # 注释跳过），
//! 或 Clash YAML 配置（取其中的 proxies）。对每个节点：构建出站 → 经节点请求
//! http://www.gstatic.com/generate_204，输出各阶段耗时与结果。
//!
//! 环境变量：
//! - NODE_PROBE_FILTER=子串：只测名称包含该子串的节点
//! - NODE_PROBE_HTTPS=1：改测 https://www.gstatic.com/generate_204（内层 TLS 1.3，
//!   能覆盖 XTLS Vision 的 PaddingDirect 直拷路径）
//! - NODE_PROBE_UDP=1：改测 UDP——经节点向 8.8.8.8:53 发 DNS 查询并校验应答
//! - NODE_PROBE_IFACE=网卡名：节点连接绑定该网卡。本机已有别的 TUN（如 FlClash）时用它绕开，
//!   测出节点自身的表现，而不是"被那个 TUN 再转一手"的结果

use std::sync::Arc;
use std::time::{Duration, Instant};

use vp_protocol::{OutboundDeps, build_outbound_eager};

async fn probe_inner(cfg: vp_config::ProxyCfg, deps: Arc<OutboundDeps>) -> Result<u64, String> {
    // HTTPS 模式：内层再套一层 TLS 1.3（XTLS Vision 的服务端此时会切到 PaddingDirect 直拷）
    let https = std::env::var("NODE_PROBE_HTTPS").is_ok();
    let t0 = Instant::now();
    let ob = build_outbound_eager(&cfg, &deps).map_err(|e| format!("构建出站失败: {e}"))?;
    let build_ms = t0.elapsed().as_millis() as u64;

    let dst = vp_common::DstAddr::new("www.gstatic.com", if https { 443 } else { 80 });
    let sess = vp_core::session::Session::new_tcp("probe".into(), None, dst.clone());
    let t1 = Instant::now();
    let mut stream = tokio::time::timeout(Duration::from_secs(20), ob.connect_stream(&sess, &dst))
        .await
        .map_err(|_| "握手超时".to_string())?
        .map_err(|e| format!("连接失败: {e}"))?;
    if https {
        let tls = tokio::time::timeout(
            Duration::from_secs(20),
            vp_transport::tls::tls_connect(
                stream,
                "www.gstatic.com",
                &vp_transport::tls::TlsClientConfig {
                    skip_cert_verify: false,
                    server_name: None,
                    alpn: vec!["http/1.1".into()],
                    ech_config: None,
                },
            ),
        )
        .await
        .map_err(|_| "内层 TLS 握手超时".to_string())?
        .map_err(|e| format!("内层 TLS 失败: {e}"))?;
        stream = Box::new(vp_core::stream::Opaque(tls));
    }
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
    let read = tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut buf))
        .await
        .map_err(|_| "响应超时".to_string())?;
    // HTTPS 下对端关连接时可能不发 close_notify：已收到响应就以状态码为准
    if let Err(e) = read {
        if buf.is_empty() {
            return Err(format!("读取失败: {e}"));
        }
    }
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

/// UDP：经节点向 8.8.8.8:53 查询 www.google.com 的 A 记录，校验 ID / RCODE / 应答数
async fn probe_udp(cfg: vp_config::ProxyCfg, deps: Arc<OutboundDeps>) -> Result<u64, String> {
    let ob = build_outbound_eager(&cfg, &deps).map_err(|e| format!("构建出站失败: {e}"))?;
    if !ob.support_udp() {
        return Err("出站未声明 UDP 支持".into());
    }
    let dst = vp_common::DstAddr::new("8.8.8.8", 53);
    let sess = vp_core::session::Session::new_udp("probe".into(), None, dst.clone());
    let t0 = Instant::now();
    let mut pc = tokio::time::timeout(Duration::from_secs(10), ob.connect_packet(&sess, &dst))
        .await
        .map_err(|_| "建立 UDP 会话超时".to_string())?
        .map_err(|e| format!("建立 UDP 会话失败: {e}"))?;
    let id: u16 = 0x5a5a;
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD，1 个问题
    for label in "www.google.com".split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]); // 根 + A + IN
    let pkt = vp_core::UdpPacket {
        src: "0.0.0.0:0".parse().unwrap(),
        dst: "8.8.8.8:53".parse().unwrap(),
        data: q.into(),
    };
    // 同真实 DNS 客户端：UDP 不保证送达，最多发 3 次、每次等 3 秒
    let mut resp = None;
    let mut tries = 0;
    while resp.is_none() && tries < 3 {
        tries += 1;
        pc.send(&pkt)
            .await
            .map_err(|e| format!("UDP 发送失败: {e}"))?;
        if let Ok(r) = tokio::time::timeout(Duration::from_secs(3), pc.recv()).await {
            resp = Some(r.map_err(|e| format!("UDP 接收失败: {e}"))?);
        }
    }
    let resp = resp.ok_or_else(|| "UDP 应答超时（3 次）".to_string())?;
    let d = &resp.data;
    if d.len() < 12 || d[..2] != id.to_be_bytes() || d[3] & 0x0f != 0 || d[6..8] == [0, 0] {
        return Err(format!("DNS 应答异常（{} 字节）", d.len()));
    }
    let ms = t0.elapsed().as_millis() as u64;
    println!("    [阶段] UDP DNS 往返 {ms} ms（第 {tries} 次发送得到应答）");
    Ok(ms)
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("用法: node_probe <nodes.txt|config.yaml> [并发数=4]");
        std::process::exit(2);
    }
    let text = std::fs::read_to_string(&args[1])?;
    let limit: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(4);

    let mut cfgs = if args[1].ends_with(".yaml") || args[1].ends_with(".yml") {
        vp_config::parse(&text, vp_config::Format::Yaml)
            .map_err(|e| format!("解析失败: {e}"))?
            .proxies
    } else {
        let uris: Vec<String> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(String::from)
            .collect();
        // 订阅文本 → ProxyCfg（与生产一致的解析链）
        vp_protocol::sub::parse_provider_proxies(&uris.join("\n"), None)
            .map_err(|e| format!("解析失败: {e}"))?
    };
    if let Ok(f) = std::env::var("NODE_PROBE_FILTER") {
        cfgs.retain(|c| c.name.contains(&f));
    }
    if let Ok(iface) = std::env::var("NODE_PROBE_IFACE") {
        // 全局也绑：内置 DNS 的上游查询同样要绕开别的 TUN
        vp_transport::set_bind_interface_name(Some(iface.clone()));
        for c in &mut cfgs {
            c.interface_name = Some(iface.clone());
        }
    }
    println!("待测节点 {n} 个，并发 {limit}", n = cfgs.len());

    let deps = Arc::new(OutboundDeps {
        dns: Arc::new(vp_dns::Resolver::new(vec![
            "https://dns.alidns.com/dns-query".into(),
        ])),
        ipv6: false,
    });
    // 节点域名走内置 DNS（同 vp-app）：系统 DNS 在 Fake-IP 型 TUN 下只给 198.18.x.x，绑物理网卡后不可达
    vp_transport::set_global_node_resolver(deps.dns.clone(), false);

    let sem = Arc::new(tokio::sync::Semaphore::new(limit));
    let mut handles = Vec::new();
    for cfg in cfgs {
        let name = cfg.name.clone();
        let deps = deps.clone();
        let sem = sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            let r = if std::env::var("NODE_PROBE_UDP").is_ok() {
                probe_udp(cfg, deps).await
            } else {
                probe_inner(cfg, deps).await
            };
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

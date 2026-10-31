//! Clash 兼容外部控制器 API（REST，手写 HTTP 服务）。

use std::sync::{Arc, RwLock};

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use vp_common::Result;
use vp_core::ConnTable;

use crate::RouterHandle;

pub struct ApiState {
    pub router: Arc<RouterHandle>,
    pub stats: Arc<vp_common::Stats>,
    pub conns: Arc<ConnTable>,
    pub secret: Option<String>,
    pub config_meta: Arc<RwLock<Option<crate::ConfigMeta>>>,
    /// TUN 运行时：PUT /configs 热重载按配置差量动态启停 TUN（免重启热切换）
    pub tun_runtime: Arc<RwLock<Option<crate::TunRuntime>>>,
    /// TUN 实时运行状态
    pub tun_status: Arc<RwLock<crate::TunStatus>>,
    /// 独立 DNS 服务端实时运行状态
    pub dns_status: Arc<RwLock<crate::DnsStatus>>,
    /// 全局 DNS 解析器：热开启 TUN 时复用它建 fake-ip 劫持服务器
    pub dns: Arc<vp_dns::Resolver>,
}

/// 监听已建立的 controller：启动 accept 循环（同步返回，切断类型环）
pub fn spawn_on(listener: TcpListener, state: Arc<ApiState>) {
    tokio::spawn(accept_loop(listener, state));
}

async fn accept_loop(listener: TcpListener, st: Arc<ApiState>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let st = st.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve(stream, &st).await {
                        let _ = e;
                    }
                });
            }
            Err(e) => {
                tracing::warn!("controller accept 失败: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
}

struct Req {
    method: String,
    path: String,
    query: String,
    body: Vec<u8>,
    auth: Option<String>,
    ws_key: Option<String>,
    is_ws: bool,
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<Req> {
    let mut buf = Vec::with_capacity(2048);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.push(byte[0]);
        if buf.len() > 64 * 1024 {
            return None;
        }
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let mut lines = head.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let mut auth = None;
    let mut ws_key = None;
    let mut is_ws = false;
    let mut content_length = 0usize;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            if k == "authorization" {
                auth = Some(v.to_string());
            } else if k == "content-length" {
                content_length = v.parse().unwrap_or(0);
            } else if k == "sec-websocket-key" {
                ws_key = Some(v.to_string());
            } else if k == "upgrade" && v.eq_ignore_ascii_case("websocket") {
                is_ws = true;
            }
        }
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };
    let mut body = vec![0u8; content_length.min(1 << 20)];
    if !body.is_empty() {
        stream.read_exact(&mut body).await.ok()?;
    }
    Some(Req {
        method,
        path,
        query,
        body,
        auth,
        ws_key,
        is_ws,
    })
}

/// 热重载：重建 Router 并替换（失败保留旧配置）；配置 tun 段有开关差量时
/// 同步动态启停 TUN 入站（免重启热切换）。
async fn reload_into(
    st: &ApiState,
    path: Option<std::path::PathBuf>,
    text: &str,
    fmt: vp_config::Format,
    dir: std::path::PathBuf,
) -> std::result::Result<(), String> {
    // Box::pin 打断 spawn→serve→reload→assemble→spawn 的 opaque 类型环
    let app = match Box::pin(crate::App::assemble_for_reload(text, fmt, &dir)).await {
        Ok(a) => a,
        Err(e) => return Err(e.to_string()),
    };

    // TUN 开关差量同步（先于路由替换：失败则整体放弃重载，旧状态原样保留）
    let new_cfg: vp_config::Config = vp_config::parse(text, fmt).map_err(|e| format!("{e}"))?;
    crate::sync_tun_state(
        &st.tun_runtime,
        &st.router,
        &st.stats,
        &st.conns,
        &st.dns,
        &new_cfg,
    )
    .await
    .map_err(|e| format!("TUN 热切换失败: {e}"))?;

    st.router.swap(app.router.current());
    *st.config_meta.write().unwrap() = Some(crate::ConfigMeta {
        path,
        text: text.to_string(),
        fmt,
        base_dir: dir,
    });
    tracing::info!("API 热重载完成");
    Ok(())
}

async fn upgrade_to_ws(
    mut stream: tokio::net::TcpStream,
    ws_key: Option<&str>,
) -> Option<vp_transport::WsStream<tokio::net::TcpStream>> {
    use tokio::io::AsyncWriteExt;
    let accept = ws_key
        .map(vp_transport::ws::compute_ws_accept)
        .unwrap_or_else(|| "vpcore".to_string());
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nAccess-Control-Allow-Origin: *\r\n\r\n"
    );
    if stream.write_all(resp.as_bytes()).await.is_err() {
        return None;
    }
    let mut ws = vp_transport::ws::ws_handshake_after_101(stream)
        .await
        .ok()?;
    // RFC 6455: 0x1 为文本帧，保证浏览器前端（YACD / Metacubexd）JSON.parse 正确解析而非收到 Blob
    ws.set_write_opcode(0x1);
    Some(ws)
}

/// 获取当前进程常驻内存或活跃池化缓冲近似内存（字节）
fn current_memory_inuse(st: &ApiState) -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/self/statm") {
            if let Some(rss_pages) = s.split_whitespace().nth(1) {
                if let Ok(pages) = rss_pages.parse::<u64>() {
                    return pages * 4096;
                }
            }
        }
    }
    let active_conns = st.conns.list().len() as u64;
    let bstats = vp_common::bufpool::stats();
    // 基准常驻 + 活跃/闲置池化缓冲块 + 活跃连接开销
    (8 * 1024 * 1024)
        + ((bstats.active + bstats.idle) as u64) * (vp_common::bufpool::BUF_SIZE as u64)
        + active_conns * 8192
}

/// GET /traffic：WebSocket 升级后每秒推送流量 JSON
async fn serve_traffic_ws(stream: tokio::net::TcpStream, ws_key: Option<&str>, st: &ApiState) {
    use tokio::io::AsyncWriteExt;
    let Some(mut ws) = upgrade_to_ws(stream, ws_key).await else {
        return;
    };
    let mut last_up = 0u64;
    let mut last_down = 0u64;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let s = st.stats.snapshot();
        let up = s.upload.saturating_sub(last_up);
        let down = s.download.saturating_sub(last_down);
        last_up = s.upload;
        last_down = s.download;
        let payload = format!("{{\"up\":{up},\"down\":{down}}}");
        if ws.write_all(payload.as_bytes()).await.is_err() {
            break;
        }
    }
}

/// GET /memory：WebSocket 升级后每秒推送内存占用 JSON
async fn serve_memory_ws(stream: tokio::net::TcpStream, ws_key: Option<&str>, st: &ApiState) {
    use tokio::io::AsyncWriteExt;
    let Some(mut ws) = upgrade_to_ws(stream, ws_key).await else {
        return;
    };
    loop {
        let inuse = current_memory_inuse(st);
        let payload = format!("{{\"inuse\":{inuse},\"oslimit\":0}}");
        if ws.write_all(payload.as_bytes()).await.is_err() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// GET /logs：WebSocket 升级后实时推送内核连接/状态事件日志
async fn serve_logs_ws(stream: tokio::net::TcpStream, ws_key: Option<&str>, st: &ApiState) {
    use tokio::io::AsyncWriteExt;
    let Some(mut ws) = upgrade_to_ws(stream, ws_key).await else {
        return;
    };
    let mut seen_ids = std::collections::HashSet::new();
    let init_msg = json!({
        "type": "info",
        "payload": format!("VP_Core v{} log stream connected (mode: {:?})", env!("CARGO_PKG_VERSION"), st.router.current().mode())
    });
    if ws.write_all(init_msg.to_string().as_bytes()).await.is_err() {
        return;
    }
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        for c in st.conns.list() {
            if seen_ids.insert(c.meta.id) {
                let chain = c.meta.chain.as_deref().unwrap_or("DIRECT");
                let rule = c.meta.rule.as_deref().unwrap_or("MATCH");
                let msg = json!({
                    "type": "info",
                    "payload": format!("[{}] {}:{} ({}) match {} using {}", c.meta.network.to_ascii_uppercase(), c.meta.host, c.meta.dst_port, c.meta.inbound, rule, chain)
                });
                if ws.write_all(msg.to_string().as_bytes()).await.is_err() {
                    return;
                }
            }
        }
        if seen_ids.len() > 4096 {
            seen_ids.clear();
        }
    }
}

async fn serve(mut stream: tokio::net::TcpStream, st: &ApiState) -> Result<()> {
    let Some(req) = read_request(&mut stream).await else {
        return Ok(());
    };
    // CORS 预检请求直接放行（浏览器 OPTIONS 预检不携带 Authorization）
    if req.method.eq_ignore_ascii_case("OPTIONS") {
        reply(&mut stream, 204, "No Content", &json!({})).await;
        return Ok(());
    }
    // 鉴权（兼容 Header `Authorization: Bearer <secret>` 与 WebSocket URL `?token=<secret>`）
    if let Some(secret) = &st.secret {
        let header_ok = req
            .auth
            .as_deref()
            .and_then(|a| a.strip_prefix("Bearer ").or(Some(a)))
            .is_some_and(|t| t.trim() == secret);
        let token_ok = query_param(&req.query, "token").is_some_and(|t| t == *secret);
        if !header_ok && !token_ok {
            reply(
                &mut stream,
                401,
                "Unauthorized",
                &json!({"message": "unauthorized"}),
            )
            .await;
            return Ok(());
        }
    }
    let router = st.router.current();
    let decoded_path = url_decode(&req.path);
    let segs: Vec<&str> = decoded_path.trim_matches('/').split('/').collect();

    match (req.method.as_str(), segs.as_slice()) {
        ("GET", ["version"]) => {
            reply(
                &mut stream,
                200,
                "OK",
                &json!({
                    "meta": true, "version": env!("CARGO_PKG_VERSION"), "premium": false
                }),
            )
            .await;
        }
        ("GET", ["proxies"]) => {
            let mut proxies = serde_json::Map::new();
            for (name, g) in router.groups() {
                let mut item = json!({
                    "name": name,
                    "type": g.ty().as_str(),
                    "now": g.selected_name(),
                    "all": g.member_names().iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                });
                let states = g.member_states();
                let selected = g.selected_name();
                if let Some((_, delay, alive)) = states.iter().find(|(n, _, _)| *n == selected) {
                    if let Some(obj) = item.as_object_mut() {
                        obj.insert("alive".into(), json!(alive));
                        if let Some(ms) = delay {
                            obj.insert("history".into(), json!([{"time": "now", "delay": ms}]));
                        }
                    }
                }
                proxies.insert(name.clone(), item);
            }
            // 直连节点与各组探测到的成员延迟状态
            for g in router.groups().values() {
                let states = g.member_states();
                for (m, delay, alive) in states {
                    let entry = proxies.entry(m.to_string()).or_insert_with(
                        || json!({ "type": "Static", "name": m.to_string(), "all": [] }),
                    );
                    if let Some(obj) = entry.as_object_mut() {
                        obj.insert("alive".into(), json!(alive));
                        if let Some(ms) = delay {
                            obj.insert("history".into(), json!([{"time": "now", "delay": ms}]));
                        }
                    }
                }
            }
            reply(&mut stream, 200, "OK", &json!({ "proxies": proxies })).await;
        }
        ("GET", ["proxies", name]) => {
            if let Some(g) = router.get_group(name) {
                let mut item = json!({
                    "name": name,
                    "type": g.ty().as_str(),
                    "now": g.selected_name(),
                    "all": g.member_names().iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                });
                let states = g.member_states();
                let selected = g.selected_name();
                if let Some((_, delay, alive)) = states.iter().find(|(n, _, _)| *n == selected) {
                    if let Some(obj) = item.as_object_mut() {
                        obj.insert("alive".into(), json!(alive));
                        if let Some(ms) = delay {
                            obj.insert("history".into(), json!([{"time": "now", "delay": ms}]));
                        }
                    }
                }
                reply(&mut stream, 200, "OK", &item).await;
            } else if let Some(ob) = router.outbound(name) {
                let mut item = json!({
                    "name": name,
                    "type": "Static",
                    "udp": ob.support_udp(),
                    "all": [],
                    "history": [],
                });
                for g in router.groups().values() {
                    if let Some((_, delay, alive)) = g
                        .member_states()
                        .into_iter()
                        .find(|(n, _, _)| &**n == *name)
                    {
                        if let Some(obj) = item.as_object_mut() {
                            obj.insert("alive".into(), json!(alive));
                            if let Some(ms) = delay {
                                obj.insert("history".into(), json!([{"time": "now", "delay": ms}]));
                            }
                        }
                        break;
                    }
                }
                reply(&mut stream, 200, "OK", &item).await;
            } else {
                reply(
                    &mut stream,
                    404,
                    "Not Found",
                    &json!({"message": "not found"}),
                )
                .await;
            }
        }
        ("PUT", ["proxies", name]) => {
            let g = router.get_group(name);
            match g {
                Some(g) => {
                    let body: serde_json::Value =
                        serde_json::from_slice(&req.body).unwrap_or(json!({}));
                    let target = body["name"].as_str().unwrap_or_default().to_string();
                    if g.set_selected(&target) {
                        reply(&mut stream, 204, "No Content", &json!({})).await;
                    } else {
                        reply(
                            &mut stream,
                            400,
                            "Bad Request",
                            &json!({"message": format!("选择 {target:?} 失败")}),
                        )
                        .await;
                    }
                }
                None => {
                    reply(
                        &mut stream,
                        404,
                        "Not Found",
                        &json!({"message": "not found"}),
                    )
                    .await
                }
            }
        }
        ("DELETE", ["proxies", name]) => {
            if let Some(g) = router.get_group(name) {
                g.unfix_selected();
                reply(&mut stream, 204, "No Content", &json!({})).await;
            } else {
                reply(
                    &mut stream,
                    404,
                    "Not Found",
                    &json!({"message": "not found"}),
                )
                .await;
            }
        }
        ("GET", ["group", name, "delay"]) => {
            let timeout_ms: u64 = query_param(&req.query, "timeout")
                .and_then(|s| s.parse().ok())
                .unwrap_or(5000);
            if let Some(g) = router.get_group(name) {
                let members = g.member_names().to_vec();
                let mut set = tokio::task::JoinSet::new();
                for member_arc in members {
                    let g_clone = g.clone();
                    let member = member_arc.to_string();
                    set.spawn(async move {
                        let res = tokio::time::timeout(
                            std::time::Duration::from_millis(timeout_ms),
                            g_clone.url_test_member(&member),
                        )
                        .await;
                        let delay = match res {
                            Ok(Ok(ms)) => ms,
                            _ => 0,
                        };
                        (member, delay)
                    });
                }
                let mut results = serde_json::Map::new();
                while let Some(res) = set.join_next().await {
                    if let Ok((m, delay)) = res {
                        results.insert(m, json!(delay));
                    }
                }
                reply(&mut stream, 200, "OK", &serde_json::Value::Object(results)).await;
            } else {
                reply(
                    &mut stream,
                    404,
                    "Not Found",
                    &json!({"message": "not found"}),
                )
                .await;
            }
        }
        ("GET", ["ui"]) => {
            reply(
                &mut stream,
                200,
                "OK",
                &json!({
                    "message": "VP_Core External Controller API",
                    "dashboards": [
                        "https://metacubex.github.io/metacubexd/",
                        "https://yacd.haishan.me/",
                        "https://board.zash.run.place/"
                    ]
                }),
            )
            .await;
        }
        ("GET", ["proxies", name, "delay"]) => {
            let url = query_param(&req.query, "url")
                .unwrap_or_else(|| "http://www.gstatic.com/generate_204".into());
            if let Some(g) = router.get_group(name) {
                let member = query_param(&req.query, "member");
                let ms = match member {
                    Some(m) => g.url_test_member(&m).await,
                    None => g.url_test_member(&g.selected_name()).await,
                };
                match ms {
                    Ok(ms) => {
                        reply(&mut stream, 200, "OK", &json!({"delay": ms, "url": url})).await
                    }
                    Err(_) => {
                        reply(&mut stream, 408, "Timeout", &json!({"message": "测速失败"})).await
                    }
                }
            } else if router.outbound(name).is_some() {
                match router.url_test_node(name, &url).await {
                    Ok(ms) => {
                        reply(&mut stream, 200, "OK", &json!({"delay": ms, "url": url})).await
                    }
                    Err(_) => {
                        reply(&mut stream, 408, "Timeout", &json!({"message": "测速失败"})).await
                    }
                }
            } else {
                reply(
                    &mut stream,
                    404,
                    "Not Found",
                    &json!({"message": "not found"}),
                )
                .await
            }
        }
        ("GET", ["rules"]) => {
            let mut out = Vec::new();
            for r in router.rules().rules() {
                let parts: Vec<&str> = r.raw.split(',').collect();
                out.push(json!({
                    "type": parts.first().copied().unwrap_or(""),
                    "payload": parts.get(1).copied().unwrap_or(""),
                    "proxy": r.target,
                }));
            }
            reply(&mut stream, 200, "OK", &json!({ "rules": out })).await;
        }
        ("GET", ["connections"]) => {
            let conns: Vec<serde_json::Value> = st
                .conns
                .list()
                .into_iter()
                .map(|c| {
                    let (rule_type, rule_payload) = match c.meta.rule.as_deref() {
                        Some(r) => {
                            let base = r.split(" => ").next().unwrap_or(r).trim();
                            if let Some((t, p)) = base.split_once(',') {
                                (Some(t.trim().to_string()), Some(p.trim().to_string()))
                            } else {
                                (Some(base.to_string()), None)
                            }
                        }
                        None => (None, None),
                    };
                    let chains: Vec<String> = c
                        .meta
                        .chain
                        .as_deref()
                        .map(|s| s.split(" > ").map(String::from).collect())
                        .unwrap_or_default();
                    json!({
                        "id": c.meta.id.to_string(),
                        "metadata": {
                            "network": c.meta.network,
                            "type": c.meta.inbound,
                            "host": c.meta.host,
                            "destinationIP": "",
                            "destinationPort": c.meta.dst_port.to_string(),
                            "source": c.meta.src,
                            "process": c.meta.process,
                        },
                        "upload": c.upload,
                        "download": c.download,
                        "start": vp_core::conn_table::iso8601(c.meta.start),
                        "chains": chains,
                        "rule": rule_type,
                        "rulePayload": rule_payload,
                    })
                })
                .collect();
            let snap = st.stats.snapshot();
            reply(
                &mut stream,
                200,
                "OK",
                &json!({
                    "connections": conns,
                    "uploadTotal": snap.upload,
                    "downloadTotal": snap.download,
                }),
            )
            .await;
        }
        ("DELETE", ["connections", id]) => {
            let ok = st.conns.kill(id.parse().unwrap_or(0));
            reply(
                &mut stream,
                if ok { 204 } else { 404 },
                if ok { "No Content" } else { "Not Found" },
                &json!({}),
            )
            .await;
        }
        ("DELETE", ["connections"]) => {
            // 批量断开全部连接（Clash GUI）
            let n = st.conns.close_all();
            reply(&mut stream, 204, "No Content", &json!({"closed": n})).await;
        }
        ("GET", ["connections", id]) => {
            let hit = st
                .conns
                .list()
                .into_iter()
                .find(|c| c.meta.id.to_string() == *id);
            match hit {
                Some(c) => reply(&mut stream, 200, "OK", &json!({"connection": c})).await,
                None => {
                    reply(
                        &mut stream,
                        404,
                        "Not Found",
                        &json!({"message": "not found"}),
                    )
                    .await
                }
            }
        }
        ("GET", ["configs"]) => {
            let tun_st = st.tun_status.read().unwrap().clone();
            let dns_st = st.dns_status.read().unwrap().clone();
            reply(
                &mut stream,
                200,
                "OK",
                &json!({
                    "mode": format!("{:?}", router.mode()).to_lowercase(),
                    "tun": tun_st,
                    "dns": dns_st,
                }),
            )
            .await;
        }
        ("PATCH", ["configs"]) => {
            // 免停热切分流模式：PATCH /configs {"mode": "rule"|"global"|"direct"}
            let mut patched = false;
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&req.body) {
                if let Some(mode_str) = val.get("mode").and_then(|v| v.as_str()) {
                    let target_mode = match mode_str.to_ascii_lowercase().as_str() {
                        "rule" => Some(vp_config::Mode::Rule),
                        "global" => Some(vp_config::Mode::Global),
                        "direct" => Some(vp_config::Mode::Direct),
                        _ => None,
                    };
                    if let Some(new_mode) = target_mode {
                        let cur_router = st.router.current();
                        let new_router = cur_router.clone_with_mode(new_mode);
                        st.router.swap(new_router);

                        // 同步持久化至内存与磁盘 YAML 配置
                        let cur_meta = st.config_meta.read().unwrap().clone();
                        if let Some(mut meta) = cur_meta {
                            if let Some(ref path) = meta.path {
                                if let Ok(content) = tokio::fs::read_to_string(path).await {
                                    if let Ok(re) = regex::Regex::new(r"(?m)^(\s*mode\s*:\s*).*$") {
                                        let new_content = re
                                            .replace(&content, format!("${{1}}{mode_str}"))
                                            .to_string();
                                        let _ = tokio::fs::write(path, &new_content).await;
                                        meta.text = new_content;
                                        *st.config_meta.write().unwrap() = Some(meta);
                                    }
                                }
                            }
                        }
                        patched = true;
                    }
                }
            }

            if patched {
                reply(&mut stream, 204, "No Content", &json!({})).await;
            } else {
                reply(
                    &mut stream,
                    400,
                    "Bad Request",
                    &json!({"message": "无效的配置 PATCH 请求体或不支持的模式"}),
                )
                .await;
            }
        }
        ("PUT", ["configs"]) => {
            // 热重载：PUT /configs?path=... 或 JSON body {"path": "..."} 或重新读取当前配置
            let mut target_path = query_param(&req.query, "path");
            if target_path.is_none() && !req.body.is_empty() {
                if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&req.body) {
                    if let Some(p) = val.get("path").and_then(|v| v.as_str()) {
                        target_path = Some(p.to_string());
                    }
                }
            }

            let reloaded = if let Some(p) = target_path {
                let base = std::path::PathBuf::from(&p);
                match tokio::fs::read_to_string(&base).await {
                    Ok(t) => {
                        let fmt = vp_config::Format::from_path(&p);
                        let dir = base.parent().map(|d| d.to_path_buf()).unwrap_or_default();
                        reload_into(st, Some(base), &t, fmt, dir).await.is_ok()
                    }
                    Err(e) => {
                        tracing::warn!("读取路径 {p:?} 失败: {e}");
                        false
                    }
                }
            } else {
                let cur = st.config_meta.read().unwrap().clone();
                match cur {
                    Some(meta) => {
                        let (new_text, new_fmt, new_dir) = if let Some(ref path) = meta.path {
                            match tokio::fs::read_to_string(path).await {
                                Ok(t) => {
                                    let fmt = vp_config::Format::from_path(&path.to_string_lossy());
                                    let dir = path
                                        .parent()
                                        .unwrap_or(std::path::Path::new("."))
                                        .to_path_buf();
                                    (t, fmt, dir)
                                }
                                Err(e) => {
                                    tracing::warn!("重读配置失败: {e}");
                                    (meta.text, meta.fmt, meta.base_dir)
                                }
                            }
                        } else {
                            (meta.text, meta.fmt, meta.base_dir)
                        };
                        reload_into(st, meta.path, &new_text, new_fmt, new_dir)
                            .await
                            .is_ok()
                    }
                    None => false,
                }
            };
            if reloaded {
                reply(&mut stream, 204, "No Content", &json!({})).await;
            } else {
                reply(
                    &mut stream,
                    500,
                    "Internal Server Error",
                    &json!({"message": "重载失败（保留旧配置）"}),
                )
                .await;
            }
        }
        ("GET", ["providers", "proxies"]) => {
            let meta = st.config_meta.read().unwrap().clone();
            let mut providers_map = serde_json::Map::new();
            if let Some(meta) = meta {
                if let Ok(cfg) = vp_config::parse(&meta.text, meta.fmt) {
                    for (name, p) in cfg.proxy_providers {
                        let mut proxy_list = Vec::new();
                        let cache_path = p
                            .path
                            .as_ref()
                            .map(|p| meta.base_dir.join(p))
                            .unwrap_or_else(|| {
                                meta.base_dir.join(".cache").join(format!("{name}.yaml"))
                            });
                        if let Ok(text) = std::fs::read_to_string(&cache_path) {
                            if let Ok(proxies) =
                                vp_protocol::sub::parse_provider_proxies(&text, p.filter.as_deref())
                            {
                                for pr in proxies {
                                    proxy_list.push(json!({
                                        "name": pr.name,
                                        "type": pr.kind.type_name(),
                                    }));
                                }
                            }
                        }
                        providers_map.insert(
                            name.clone(),
                            json!({
                                "name": name,
                                "type": "Proxy",
                                "vehicleType": p.kind.unwrap_or_else(|| "HTTP".into()),
                                "proxies": proxy_list,
                                "updatedAt": vp_core::conn_table::iso8601(
                                    std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_millis() as u64,
                                ),
                            }),
                        );
                    }
                }
            }
            reply(
                &mut stream,
                200,
                "OK",
                &json!({ "providers": providers_map }),
            )
            .await;
        }
        ("GET", ["providers", "proxies", name]) => {
            let meta = st.config_meta.read().unwrap().clone();
            let mut found = None;
            if let Some(meta) = meta {
                if let Ok(cfg) = vp_config::parse(&meta.text, meta.fmt) {
                    if let Some(p) = cfg.proxy_providers.get(*name) {
                        let mut proxy_list = Vec::new();
                        let cache_path = p
                            .path
                            .as_ref()
                            .map(|p| meta.base_dir.join(p))
                            .unwrap_or_else(|| {
                                meta.base_dir.join(".cache").join(format!("{name}.yaml"))
                            });
                        if let Ok(text) = std::fs::read_to_string(&cache_path) {
                            if let Ok(proxies) =
                                vp_protocol::sub::parse_provider_proxies(&text, p.filter.as_deref())
                            {
                                for pr in proxies {
                                    proxy_list.push(json!({
                                        "name": pr.name,
                                        "type": pr.kind.type_name(),
                                    }));
                                }
                            }
                        }
                        found = Some(json!({
                            "name": name,
                            "type": "Proxy",
                            "vehicleType": p.kind.as_deref().unwrap_or("HTTP"),
                            "proxies": proxy_list,
                            "updatedAt": vp_core::conn_table::iso8601(
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_millis() as u64,
                            ),
                        }));
                    }
                }
            }
            match found {
                Some(val) => reply(&mut stream, 200, "OK", &val).await,
                None => {
                    reply(
                        &mut stream,
                        404,
                        "Not Found",
                        &json!({"message": "provider not found"}),
                    )
                    .await
                }
            }
        }
        ("PUT", ["providers", "proxies", name]) => {
            let cur = st.config_meta.read().unwrap().clone();
            match cur {
                Some(meta) => {
                    // 若该 proxy-provider 配置了远端 URL，先主动拉取最新订阅并更新本地缓存文件
                    if let Ok(cfg) = vp_config::parse(&meta.text, meta.fmt) {
                        if let Some(p) = cfg.proxy_providers.get(*name) {
                            if let Some(ref url) = p.url {
                                let url = url.clone();
                                let cache_path = p
                                    .path
                                    .as_ref()
                                    .map(|path| meta.base_dir.join(path))
                                    .unwrap_or_else(|| {
                                        meta.base_dir.join(".cache").join(format!("{name}.yaml"))
                                    });
                                if let Ok(Ok(body)) = tokio::task::spawn_blocking(move || {
                                    crate::fetch_remote_provider(&url, "clash.meta/v1.18.0")
                                })
                                .await
                                {
                                    if let Some(parent) = cache_path.parent() {
                                        let _ = std::fs::create_dir_all(parent);
                                    }
                                    let _ = std::fs::write(&cache_path, &body);
                                }
                            }
                        }
                    }
                    let reloaded = reload_into(st, meta.path, &meta.text, meta.fmt, meta.base_dir)
                        .await
                        .is_ok();
                    if reloaded {
                        reply(&mut stream, 204, "No Content", &json!({})).await;
                    } else {
                        reply(
                            &mut stream,
                            500,
                            "Internal Server Error",
                            &json!({"message": format!("刷新 {name} 失败")}),
                        )
                        .await;
                    }
                }
                None => {
                    reply(
                        &mut stream,
                        404,
                        "Not Found",
                        &json!({"message": "no config loaded"}),
                    )
                    .await
                }
            }
        }
        ("GET", ["providers", "rules"]) => {
            let meta = st.config_meta.read().unwrap().clone();
            let mut providers_map = serde_json::Map::new();
            if let Some(meta) = meta {
                if let Ok(cfg) = vp_config::parse(&meta.text, meta.fmt) {
                    for (name, r) in cfg.rule_providers {
                        let cache_path = r
                            .path
                            .as_ref()
                            .map(|p| meta.base_dir.join(p))
                            .unwrap_or_else(|| {
                                meta.base_dir
                                    .join(".cache")
                                    .join("rules")
                                    .join(format!("{name}.yaml"))
                            });
                        let rule_count = std::fs::read_to_string(&cache_path)
                            .map(|t| {
                                t.lines()
                                    .filter(|l| {
                                        let s = l.trim();
                                        !s.is_empty() && !s.starts_with('#') && s != "payload:"
                                    })
                                    .count()
                            })
                            .unwrap_or(0);
                        providers_map.insert(
                            name.clone(),
                            json!({
                                "name": name,
                                "type": "Rule",
                                "behavior": r.behavior,
                                "format": r.format.unwrap_or_else(|| "yaml".into()),
                                "vehicleType": r.kind.unwrap_or_else(|| "HTTP".into()),
                                "ruleCount": rule_count,
                                "updatedAt": vp_core::conn_table::iso8601(
                                    std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_millis() as u64,
                                ),
                            }),
                        );
                    }
                }
            }
            reply(
                &mut stream,
                200,
                "OK",
                &json!({ "providers": providers_map }),
            )
            .await;
        }
        ("GET", ["providers", "rules", name]) => {
            let meta = st.config_meta.read().unwrap().clone();
            let mut found = None;
            if let Some(meta) = meta {
                if let Ok(cfg) = vp_config::parse(&meta.text, meta.fmt) {
                    if let Some(r) = cfg.rule_providers.get(*name) {
                        found = Some(json!({
                            "name": name,
                            "type": "Rule",
                            "behavior": r.behavior,
                            "format": r.format.as_deref().unwrap_or("yaml"),
                            "vehicleType": r.kind.as_deref().unwrap_or("HTTP"),
                            "updatedAt": vp_core::conn_table::iso8601(
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_millis() as u64,
                            ),
                        }));
                    }
                }
            }
            match found {
                Some(val) => reply(&mut stream, 200, "OK", &val).await,
                None => {
                    reply(
                        &mut stream,
                        404,
                        "Not Found",
                        &json!({"message": "rule provider not found"}),
                    )
                    .await
                }
            }
        }
        ("PUT", ["providers", "rules", name]) => {
            let cur = st.config_meta.read().unwrap().clone();
            match cur {
                Some(meta) => {
                    if let Ok(cfg) = vp_config::parse(&meta.text, meta.fmt) {
                        if let Some(r) = cfg.rule_providers.get(*name) {
                            if let Some(ref url) = r.url {
                                let url = url.clone();
                                let cache_path = r
                                    .path
                                    .as_ref()
                                    .map(|path| meta.base_dir.join(path))
                                    .unwrap_or_else(|| {
                                        meta.base_dir
                                            .join(".cache")
                                            .join("rules")
                                            .join(format!("{name}.yaml"))
                                    });
                                if let Ok(Ok(body)) = tokio::task::spawn_blocking(move || {
                                    crate::fetch_remote_provider(&url, "vpcore/0.1")
                                })
                                .await
                                {
                                    if let Some(parent) = cache_path.parent() {
                                        let _ = std::fs::create_dir_all(parent);
                                    }
                                    let _ = std::fs::write(&cache_path, &body);
                                }
                            }
                        }
                    }
                    let reloaded = reload_into(st, meta.path, &meta.text, meta.fmt, meta.base_dir)
                        .await
                        .is_ok();
                    if reloaded {
                        reply(&mut stream, 204, "No Content", &json!({})).await;
                    } else {
                        reply(
                            &mut stream,
                            500,
                            "Internal Server Error",
                            &json!({"message": format!("刷新规则集 {name} 失败")}),
                        )
                        .await;
                    }
                }
                None => {
                    reply(
                        &mut stream,
                        404,
                        "Not Found",
                        &json!({"message": "no config loaded"}),
                    )
                    .await
                }
            }
        }
        ("POST", ["dns", "flush"]) | ("PUT", ["dns", "flush"]) => {
            st.dns.flush_cache();
            reply(
                &mut stream,
                200,
                "OK",
                &json!({"message": "dns cache flushed"}),
            )
            .await;
        }
        ("POST", ["cache", "fakeip", "flush"]) => {
            vp_dns::flush_global_fake_ip_pool();
            st.dns.flush_cache();
            reply(&mut stream, 204, "No Content", &json!({})).await;
        }
        ("GET", ["traffic"]) => {
            // WebSocket /traffic：每秒推送 {"up":..,"down":..}
            serve_traffic_ws(stream, req.ws_key.as_deref(), st).await;
        }
        ("GET", ["memory"]) => {
            if req.is_ws {
                serve_memory_ws(stream, req.ws_key.as_deref(), st).await;
            } else {
                let inuse = current_memory_inuse(st);
                reply(
                    &mut stream,
                    200,
                    "OK",
                    &json!({"inuse": inuse, "oslimit": 0}),
                )
                .await;
            }
        }
        ("GET", ["logs"]) => {
            if req.is_ws {
                serve_logs_ws(stream, req.ws_key.as_deref(), st).await;
            } else {
                reply(&mut stream, 200, "OK", &json!({"logs": []})).await;
            }
        }
        _ => {
            reply(
                &mut stream,
                404,
                "Not Found",
                &json!({"message": "not found"}),
            )
            .await;
        }
    }
    Ok(())
}

fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        if k == key { Some(url_decode(v)) } else { None }
    })
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push(b);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn reply(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    reason: &str,
    body: &serde_json::Value,
) {
    let payload = serde_json::to_vec(body).unwrap_or_default();
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS\r\nAccess-Control-Allow-Headers: Authorization, Content-Type\r\nContent-Length: {}\r\n\r\n",
        payload.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(&payload).await;
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::App;

    #[tokio::test]
    async fn controller_api_works() {
        async fn free_port() -> u16 {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        }
        let mixed_port = free_port().await;
        let ctl_port = free_port().await;
        let ctl_addr = format!("127.0.0.1:{ctl_port}");

        let cfg = format!(
            r#"
mixed-port: {mixed_port}
external-controller: {ctl_addr}
secret: "s3cret"
proxies: []
proxy-groups:
  - name: PROXY
    type: select
    proxies: [DIRECT]
rules: ['MATCH,PROXY']
"#
        );
        let app = App::start(&cfg, vp_config::Format::Yaml, &std::env::temp_dir(), true)
            .await
            .unwrap();

        // 无鉴权 → 401
        let resp = http_get(&ctl_addr, "/version", None).await;
        assert_eq!(resp.0, 401);

        // 带鉴权
        let resp = http_get(&ctl_addr, "/version", Some("s3cret")).await;
        assert_eq!(resp.0, 200);
        assert!(resp.1.contains("version"));

        // proxies
        let resp = http_get(&ctl_addr, "/proxies", Some("s3cret")).await;
        assert!(resp.1.contains("PROXY"));

        // providers/proxies 与 providers/rules
        let resp = http_get(&ctl_addr, "/providers/proxies", Some("s3cret")).await;
        assert_eq!(resp.0, 200);
        assert!(resp.1.contains("providers"));

        let resp = http_get(&ctl_addr, "/providers/rules", Some("s3cret")).await;
        assert_eq!(resp.0, 200);
        assert!(resp.1.contains("providers"));

        // 单节点详情查询 /proxies/DIRECT 与 ?token= 鉴权
        let resp = http_get(&ctl_addr, "/proxies/DIRECT?token=s3cret", None).await;
        assert_eq!(resp.0, 200);
        assert!(resp.1.contains("DIRECT"));

        // /memory 与 /logs
        let resp = http_get(&ctl_addr, "/memory", Some("s3cret")).await;
        assert_eq!(resp.0, 200);
        assert!(resp.1.contains("inuse"));

        let resp = http_get(&ctl_addr, "/logs", Some("s3cret")).await;
        assert_eq!(resp.0, 200);

        // dns/flush
        let resp = http_put_raw(&ctl_addr, "/dns/flush", Some("s3cret"), "").await;
        assert_eq!(resp.0, 200);

        // rules
        let resp = http_get(&ctl_addr, "/rules", Some("s3cret")).await;
        assert!(resp.1.contains("MATCH"));

        // connections
        let resp = http_get(&ctl_addr, "/connections", Some("s3cret")).await;
        assert!(resp.1.contains("connections"));

        // 热重载（PUT /configs）
        let resp = http_put_raw(&ctl_addr, "/configs?force=true", Some("s3cret"), "").await;
        assert_eq!(resp.0, 204, "热重载应 204: {resp:?}");

        // 批量断连（DELETE /connections，无连接也返回 204）
        let resp = http_del(&ctl_addr, "/connections", Some("s3cret")).await;
        assert_eq!(resp.0, 204);

        // 切换 selector（DIRECT→DIRECT 幂等）
        let resp = http_put(
            &ctl_addr,
            "/proxies/PROXY",
            Some("s3cret"),
            r#"{"name":"DIRECT"}"#,
        )
        .await;
        assert!(resp.0 == 204, "{resp:?}");

        // 验证 URL 编码策略组名访问（例如 %50%52%4F%58%59 即 PROXY）
        let resp = http_get(&ctl_addr, "/proxies/%50%52%4F%58%59", Some("s3cret")).await;
        assert_eq!(resp.0, 200);
        assert!(resp.1.contains("PROXY"));

        // GET /configs 初始模式应为 rule
        let resp = http_get(&ctl_addr, "/configs", Some("s3cret")).await;
        assert_eq!(resp.0, 200);
        assert!(resp.1.contains("\"mode\":\"rule\"") || resp.1.contains("\"mode\": \"rule\""));

        // PATCH /configs 免停热切至 global
        let resp = http_patch(
            &ctl_addr,
            "/configs",
            Some("s3cret"),
            r#"{"mode":"global"}"#,
        )
        .await;
        assert_eq!(resp.0, 204, "PATCH 模式热切应返回 204: {resp:?}");

        // 验证热切后模式变更为 global
        let resp = http_get(&ctl_addr, "/configs", Some("s3cret")).await;
        assert_eq!(resp.0, 200);
        assert!(resp.1.contains("\"mode\":\"global\"") || resp.1.contains("\"mode\": \"global\""));

        // PATCH /configs 免停热切至 direct
        let resp = http_patch(
            &ctl_addr,
            "/configs",
            Some("s3cret"),
            r#"{"mode":"direct"}"#,
        )
        .await;
        assert_eq!(resp.0, 204);

        let resp = http_get(&ctl_addr, "/configs", Some("s3cret")).await;
        assert_eq!(resp.0, 200);
        assert!(resp.1.contains("\"mode\":\"direct\"") || resp.1.contains("\"mode\": \"direct\""));

        let _ = app;
    }

    #[test]
    fn test_url_decode_percent_utf8() {
        assert_eq!(
            url_decode("%E7%BE%8E%E5%9B%BD%E8%8A%82%E7%82%B9"),
            "美国节点"
        );
        assert_eq!(url_decode("%E6%B5%8B%E8%AF%95+name"), "测试 name");
        assert_eq!(url_decode("PROXY"), "PROXY");
    }

    async fn http_patch(addr: &str, path: &str, secret: Option<&str>, body: &str) -> (u16, String) {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let auth = secret
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        let req = format!(
            "PATCH {path} HTTP/1.1\r\nHost: {addr}\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        parse_http(&buf)
    }

    async fn http_put_raw(
        addr: &str,
        path: &str,
        secret: Option<&str>,
        body: &str,
    ) -> (u16, String) {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let auth = secret
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        let req = format!(
            "PUT {path} HTTP/1.1\r\nHost: {addr}\r\n{auth}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        parse_http(&buf)
    }

    async fn http_del(addr: &str, path: &str, secret: Option<&str>) -> (u16, String) {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let auth = secret
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        let req =
            format!("DELETE {path} HTTP/1.1\r\nHost: {addr}\r\n{auth}Connection: close\r\n\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        parse_http(&buf)
    }

    async fn http_get(addr: &str, path: &str, secret: Option<&str>) -> (u16, String) {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let auth = secret
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n{auth}Connection: close\r\n\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        parse_http(&buf)
    }

    async fn http_put(addr: &str, path: &str, secret: Option<&str>, body: &str) -> (u16, String) {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let auth = secret
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        let req = format!(
            "PUT {path} HTTP/1.1\r\nHost: {addr}\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        parse_http(&buf)
    }

    fn parse_http(buf: &[u8]) -> (u16, String) {
        let text = String::from_utf8_lossy(buf);
        let status: u16 = text
            .lines()
            .next()
            .and_then(|l| l.split(' ').nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body = text
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default();
        (status, body)
    }
}

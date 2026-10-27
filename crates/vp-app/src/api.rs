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
    let mut content_length = 0usize;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            if k == "authorization" {
                auth = Some(v.to_string());
            } else if k == "content-length" {
                content_length = v.parse().unwrap_or(0);
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
    })
}

/// 热重载：重建 Router 并替换（失败保留旧配置）
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

/// GET /traffic：WebSocket 升级后每秒推送流量 JSON
async fn serve_traffic_ws(mut stream: tokio::net::TcpStream, st: &ApiState) {
    use tokio::io::AsyncWriteExt;
    // serve() 已消费请求头；回 101（Accept 值为标记，客户端为内核 GUI/测试）
    let resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: vpcore\r\n\r\n";
    if stream.write_all(resp.as_bytes()).await.is_err() {
        return;
    }
    // 升级完成后流上走 WS 帧
    let mut ws = match vp_transport::ws::ws_handshake_after_101(stream).await {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut last_up = 0u64;
    let mut last_down = 0u64;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let s = st.stats.snapshot();
        let up = s.upload - last_up;
        let down = s.download - last_down;
        last_up = s.upload;
        last_down = s.download;
        let payload = format!("{{\"up\":{up},\"down\":{down}}}");
        if ws.write_all(payload.as_bytes()).await.is_err() {
            break;
        }
    }
}

async fn serve(mut stream: tokio::net::TcpStream, st: &ApiState) -> Result<()> {
    let Some(req) = read_request(&mut stream).await else {
        return Ok(());
    };
    // 鉴权
    if let Some(secret) = &st.secret {
        let ok = req
            .auth
            .as_deref()
            .and_then(|a| a.strip_prefix("Bearer "))
            .is_some_and(|t| t == secret);
        if !ok {
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
                    let entry = proxies.entry(m.to_string()).or_insert_with(|| {
                        json!({ "type": "Static", "name": m.to_string(), "all": [] })
                    });
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
        ("GET", ["proxies", name, "delay"]) => {
            let group = router.get_group(name);
            match group {
                Some(g) => {
                    let url = query_param(&req.query, "url")
                        .unwrap_or_else(|| "http://www.gstatic.com/generate_204".into());
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
                            reply(&mut stream, 408, "Timeout", &json!({"message": "测速失败"}))
                                .await
                        }
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
                    json!({
                        "id": c.meta.id.to_string(),
                        "metadata": {
                            "network": c.meta.network,
                            "type": c.meta.inbound,
                            "host": c.meta.host,
                            "destinationPort": c.meta.dst_port,
                            "source": c.meta.src,
                            "process": c.meta.process,
                        },
                        "upload": c.upload,
                        "download": c.download,
                        "start": vp_core::conn_table::iso8601(c.meta.start),
                        "chains": [c.meta.chain],
                        "rule": c.meta.rule,
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
            reply(
                &mut stream,
                200,
                "OK",
                &json!({"mode": format!("{:?}", router.mode())}),
            )
            .await;
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
        ("POST", ["dns", "flush"]) | ("PUT", ["dns", "flush"]) => {
            reply(
                &mut stream,
                200,
                "OK",
                &json!({"message": "dns cache flushed"}),
            )
            .await;
        }
        ("GET", ["traffic"]) => {
            // WebSocket /traffic：每秒推送 {"up":..,"down":..}
            serve_traffic_ws(stream, st).await;
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
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
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
        let cfg = r#"
mixed-port: 17891
external-controller: 127.0.0.1:19091
secret: "s3cret"
proxies: []
proxy-groups:
  - name: PROXY
    type: select
    proxies: [DIRECT]
rules: ['MATCH,PROXY']
"#;
        let app = App::start(cfg, vp_config::Format::Yaml, &std::env::temp_dir(), true)
            .await
            .unwrap();

        // 无鉴权 → 401
        let resp = http_get("127.0.0.1:19091", "/version", None).await;
        assert_eq!(resp.0, 401);

        // 带鉴权
        let resp = http_get("127.0.0.1:19091", "/version", Some("s3cret")).await;
        assert_eq!(resp.0, 200);
        assert!(resp.1.contains("version"));

        // proxies
        let resp = http_get("127.0.0.1:19091", "/proxies", Some("s3cret")).await;
        assert!(resp.1.contains("PROXY"));

        // providers/proxies
        let resp = http_get("127.0.0.1:19091", "/providers/proxies", Some("s3cret")).await;
        assert_eq!(resp.0, 200);
        assert!(resp.1.contains("providers"));

        // dns/flush
        let resp = http_put_raw("127.0.0.1:19091", "/dns/flush", Some("s3cret"), "").await;
        assert_eq!(resp.0, 200);

        // rules
        let resp = http_get("127.0.0.1:19091", "/rules", Some("s3cret")).await;
        assert!(resp.1.contains("MATCH"));

        // connections
        let resp = http_get("127.0.0.1:19091", "/connections", Some("s3cret")).await;
        assert!(resp.1.contains("connections"));

        // 热重载（PUT /configs）
        let resp = http_put_raw("127.0.0.1:19091", "/configs?force=true", Some("s3cret"), "").await;
        assert_eq!(resp.0, 204, "热重载应 204: {resp:?}");

        // 批量断连（DELETE /connections，无连接也返回 204）
        let resp = http_del("127.0.0.1:19091", "/connections", Some("s3cret")).await;
        assert_eq!(resp.0, 204);

        // 切换 selector（DIRECT→DIRECT 幂等）
        let resp = http_put(
            "127.0.0.1:19091",
            "/proxies/PROXY",
            Some("s3cret"),
            r#"{"name":"DIRECT"}"#,
        )
        .await;
        assert!(resp.0 == 204, "{resp:?}");

        // 验证 URL 编码策略组名访问（例如 %50%52%4F%58%59 即 PROXY）
        let resp = http_get("127.0.0.1:19091", "/proxies/%50%52%4F%58%59", Some("s3cret")).await;
        assert_eq!(resp.0, 200);
        assert!(resp.1.contains("PROXY"));
        let _ = app;
    }

    #[test]
    fn test_url_decode_percent_utf8() {
        assert_eq!(url_decode("%E7%BE%8E%E5%9B%BD%E8%8A%82%E7%82%B9"), "美国节点");
        assert_eq!(url_decode("%E6%B5%8B%E8%AF%95+name"), "测试 name");
        assert_eq!(url_decode("PROXY"), "PROXY");
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

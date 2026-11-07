//! Clash 兼容外部控制器 API（REST，模块化 HTTP 服务）。

use std::sync::{Arc, RwLock};

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use vp_common::Result;
use vp_core::ConnTable;

use crate::RouterHandle;

mod configs;
mod connections;
pub mod explain;
mod metrics;
mod providers;
mod proxies;
mod sub;
mod users;
mod ws;

#[cfg(test)]
mod tests;

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
    /// 多用户管理器（控制面动态管理 + 认证配额限速）
    pub user_manager: Arc<vp_core::UserManager>,
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

pub(crate) struct Req {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) query: String,
    pub(crate) body: Vec<u8>,
    pub(crate) auth: Option<String>,
    pub(crate) user_agent: Option<String>,
    pub(crate) host: Option<String>,
    pub(crate) ws_key: Option<String>,
    pub(crate) is_ws: bool,
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
    let mut user_agent = None;
    let mut host = None;
    let mut ws_key = None;
    let mut is_ws = false;
    let mut content_length = 0usize;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            if k == "authorization" {
                auth = Some(v.to_string());
            } else if k == "user-agent" {
                user_agent = Some(v.to_string());
            } else if k == "host" {
                host = Some(v.to_string());
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
        user_agent,
        host,
        ws_key,
        is_ws,
    })
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
        ("GET", ["ui"]) => {
            configs::handle_ui(&mut stream).await;
        }
        ("GET", ["sub"]) | ("GET", ["sub", "clash"]) | ("GET", ["subscription"]) => {
            sub::handle_sub(&mut stream, st, &req, &segs).await;
        }
        ("GET", ["proxies"]) => {
            proxies::handle_proxies_list(&mut stream, &router).await;
        }
        ("GET", ["proxies", name]) => {
            proxies::handle_proxy_get(&mut stream, &router, name).await;
        }
        ("PUT", ["proxies", name]) => {
            proxies::handle_proxy_put(&mut stream, &router, name, &req.body).await;
        }
        ("DELETE", ["proxies", name]) => {
            proxies::handle_proxy_delete(&mut stream, &router, name).await;
        }
        ("GET", ["group", name, "delay"]) => {
            proxies::handle_group_delay(&mut stream, &router, name, &req.query).await;
        }
        ("GET", ["proxies", name, "delay"]) => {
            proxies::handle_proxy_delay(&mut stream, &router, name, &req.query).await;
        }
        ("GET", ["rules"]) => {
            configs::handle_rules_get(&mut stream, &router).await;
        }
        ("GET", ["routes", "explain"]) | ("POST", ["routes", "explain"]) => {
            explain::handle_routes_explain(&mut stream, &router, &req).await;
        }
        ("GET", ["rules", "explain"]) | ("POST", ["rules", "explain"]) => {
            explain::handle_routes_explain(&mut stream, &router, &req).await;
        }
        ("GET", ["connections"]) => {
            connections::handle_connections_list(&mut stream, st).await;
        }
        ("DELETE", ["connections", id]) => {
            connections::handle_connection_delete(&mut stream, st, id).await;
        }
        ("DELETE", ["connections"]) => {
            connections::handle_connections_close_all(&mut stream, st).await;
        }
        ("GET", ["connections", id]) => {
            connections::handle_connection_get(&mut stream, st, id).await;
        }
        ("GET", ["configs"]) => {
            configs::handle_configs_get(&mut stream, st, &router).await;
        }
        ("PATCH", ["configs"]) => {
            configs::handle_configs_patch(&mut stream, st, &req.body).await;
        }
        ("PUT", ["configs"]) => {
            configs::handle_configs_put(&mut stream, st, &req.query, &req.body).await;
        }
        ("GET", ["providers", "proxies"]) => {
            providers::handle_proxy_providers_list(&mut stream, st).await;
        }
        ("GET", ["providers", "proxies", name]) => {
            providers::handle_proxy_provider_get(&mut stream, st, name).await;
        }
        ("PUT", ["providers", "proxies", name]) => {
            providers::handle_proxy_provider_put(&mut stream, st, name).await;
        }
        ("GET", ["providers", "rules"]) => {
            providers::handle_rule_providers_list(&mut stream, st).await;
        }
        ("GET", ["providers", "rules", name]) => {
            providers::handle_rule_provider_get(&mut stream, st, name).await;
        }
        ("PUT", ["providers", "rules", name]) => {
            providers::handle_rule_provider_put(&mut stream, st, name).await;
        }
        ("POST", ["dns", "flush"]) | ("PUT", ["dns", "flush"]) => {
            configs::handle_dns_flush(&mut stream, st).await;
        }
        ("POST", ["cache", "fakeip", "flush"]) => {
            configs::handle_fakeip_flush(&mut stream, st).await;
        }
        ("GET", ["traffic"]) => {
            // WebSocket /traffic：每秒推送 {"up":..,"down":..}
            ws::serve_traffic_ws(stream, req.ws_key.as_deref(), st).await;
        }
        ("GET", ["memory"]) => {
            if req.is_ws {
                ws::serve_memory_ws(stream, req.ws_key.as_deref(), st).await;
            } else {
                let inuse = ws::current_memory_inuse(st);
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
                ws::serve_logs_ws(stream, req.ws_key.as_deref(), st).await;
            } else {
                reply(&mut stream, 200, "OK", &json!({"logs": []})).await;
            }
        }
        ("GET", ["metrics"]) => {
            metrics::handle_metrics(&mut stream, st).await;
        }
        ("GET", ["users"]) | ("GET", ["api", "v1", "users"]) => {
            users::handle_users_list(&mut stream, st).await;
        }
        ("GET", ["users", target]) | ("GET", ["api", "v1", "users", target]) => {
            users::handle_user_get(&mut stream, st, target).await;
        }
        ("POST", ["users"]) | ("POST", ["api", "v1", "users"]) => {
            users::handle_user_add(&mut stream, st, &req.body).await;
        }
        ("DELETE", ["users", target]) | ("DELETE", ["api", "v1", "users", target]) => {
            users::handle_user_delete(&mut stream, st, target).await;
        }
        ("POST", ["users", target, "reset"])
        | ("POST", ["api", "v1", "users", target, "reset"]) => {
            users::handle_user_reset(&mut stream, st, target).await;
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

pub(crate) fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        if k == key { Some(url_decode(v)) } else { None }
    })
}

pub(crate) fn url_decode(s: &str) -> String {
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

pub(crate) async fn reply(
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

pub(crate) async fn reply_text(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    reason: &str,
    body: &str,
    content_type: &str,
) {
    let payload = body.as_bytes();
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS\r\nAccess-Control-Allow-Headers: Authorization, Content-Type\r\nContent-Length: {}\r\n\r\n",
        payload.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(payload).await;
    let _ = stream.shutdown().await;
}

pub(crate) async fn reply_subscription(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    reason: &str,
    body: &str,
    content_type: &str,
    filename: &str,
) {
    let payload = body.as_bytes();
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Disposition: attachment; filename=\"{filename}\"\r\n\
         Subscription-Userinfo: upload=0; download=0; total=1073741824000; expire=0\r\n\
         Profile-Update-Interval: 24\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: GET, OPTIONS\r\n\
         Access-Control-Allow-Headers: Authorization, Content-Type\r\n\
         Content-Length: {}\r\n\r\n",
        payload.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(payload).await;
    let _ = stream.shutdown().await;
}

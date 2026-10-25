//! Clash 兼容外部控制器 API（REST，手写 HTTP 服务）。

use std::sync::{Arc, RwLock};

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

use vp_common::Result;
use vp_core::ConnTable;

use crate::RouterHandle;

pub struct ApiState {
    pub router: Arc<RouterHandle>,
    pub stats: Arc<vp_common::Stats>,
    pub conns: Arc<ConnTable>,
    pub secret: Option<String>,
    pub config_text: RwLock<Option<(String, vp_config::Format, std::path::PathBuf)>>,
}

pub async fn spawn(addr: String, state: Arc<ApiState>) -> Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let st = state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve(stream, &st).await {
                            let _ = e;
                        }
                    });
                }
                Err(e) => {
                    warn!("controller accept 失败: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
    });
    info!("controller listening on {addr}");
    Ok(())
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
    Some(Req { method, path, query, body, auth })
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
            reply(&mut stream, 401, "Unauthorized", &json!({"message": "unauthorized"})).await;
            return Ok(());
        }
    }
    let router = st.router.current();
    let segs: Vec<&str> = req.path.trim_matches('/').split('/').collect();

    match (req.method.as_str(), segs.as_slice()) {
        ("GET", ["version"]) => {
            reply(&mut stream, 200, "OK", &json!({
                "meta": true, "version": env!("CARGO_PKG_VERSION"), "premium": false
            }))
            .await;
        }
        ("GET", ["proxies"]) => {
            let mut proxies = serde_json::Map::new();
            for (name, g) in router.groups() {
                proxies.insert(
                    name.clone(),
                    json!({
                        "type": g.ty().as_str(),
                        "now": g.selected_name(),
                        "all": g.member_names().iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                    }),
                );
            }
            // 直连节点
            for g in router.groups().values() {
                for m in g.member_names() {
                    if !proxies.contains_key(&*m.to_string()) {
                        proxies.insert(
                            m.to_string(),
                            json!({ "type": "Static", "name": m.to_string(), "all": [] }),
                        );
                    }
                }
            }
            reply(&mut stream, 200, "OK", &json!({ "proxies": proxies })).await;
        }
        ("GET", ["proxies", name]) => {
            if let Some(g) = router.get_group(name) {
                reply(
                    &mut stream,
                    200,
                    "OK",
                    &json!({
                        "type": g.ty().as_str(),
                        "now": g.selected_name(),
                        "all": g.member_names().iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                    }),
                )
                .await;
            } else {
                reply(&mut stream, 404, "Not Found", &json!({"message": "not found"})).await;
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
                    reply(&mut stream, 404, "Not Found", &json!({"message": "not found"})).await
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
                            reply(
                                &mut stream,
                                200,
                                "OK",
                                &json!({"delay": ms, "url": url}),
                            )
                            .await
                        }
                        Err(_) => {
                            reply(
                                &mut stream,
                                408,
                                "Timeout",
                                &json!({"message": "测速失败"}),
                            )
                            .await
                        }
                    }
                }
                None => {
                    reply(&mut stream, 404, "Not Found", &json!({"message": "not found"})).await
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
        ("GET", ["configs"]) => {
            reply(
                &mut stream,
                200,
                "OK",
                &json!({"mode": format!("{:?}", router.mode())}),
            )
            .await;
        }
        _ => {
            reply(&mut stream, 404, "Not Found", &json!({"message": "not found"})).await;
        }
    }
    Ok(())
}

fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        if k == key {
            Some(url_decode(v))
        } else {
            None
        }
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

        // rules
        let resp = http_get("127.0.0.1:19091", "/rules", Some("s3cret")).await;
        assert!(resp.1.contains("MATCH"));

        // connections
        let resp = http_get("127.0.0.1:19091", "/connections", Some("s3cret")).await;
        assert!(resp.1.contains("connections"));

        // 切换 selector（DIRECT→DIRECT 幂等）
        let resp = http_put(
            "127.0.0.1:19091",
            "/proxies/PROXY",
            Some("s3cret"),
            r#"{"name":"DIRECT"}"#,
        )
        .await;
        assert!(resp.0 == 204, "{resp:?}");
        let _ = app;
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

    async fn http_put(
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

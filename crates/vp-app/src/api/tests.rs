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

    // 验证订阅端点 /sub (通用订阅与 Clash 订阅)
    let resp = http_get(&ctl_addr, "/sub?token=s3cret", None).await;
    assert_eq!(resp.0, 200);

    let resp_clash = http_get(&ctl_addr, "/sub?token=s3cret&format=clash", None).await;
    assert_eq!(resp_clash.0, 200);
    assert!(resp_clash.1.contains("proxies:"));

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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

async fn http_put_raw(addr: &str, path: &str, secret: Option<&str>, body: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let auth = secret
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let req = format!("DELETE {path} HTTP/1.1\r\nHost: {addr}\r\n{auth}Connection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    parse_http(&buf)
}

async fn http_get(addr: &str, path: &str, secret: Option<&str>) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

async fn http_post(addr: &str, path: &str, secret: Option<&str>, body: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let auth = secret
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    parse_http(&buf)
}

#[tokio::test]
async fn test_user_management_and_metrics_api() {
    async fn free_port() -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    }
    let ctl_port = free_port().await;
    let ctl_addr = format!("127.0.0.1:{ctl_port}");

    let cfg = format!(
        r#"
external-controller: {ctl_addr}
secret: "test_sec"
proxies: []
rules: ['MATCH,DIRECT']
"#
    );
    let app = App::start(&cfg, vp_config::Format::Yaml, &std::env::temp_dir(), true)
        .await
        .unwrap();

    // 1. 测试 Prometheus 指标导出
    let resp = http_get(&ctl_addr, "/metrics", Some("test_sec")).await;
    assert_eq!(resp.0, 200);
    assert!(resp.1.contains("vpcore_build_info"));
    assert!(resp.1.contains("vpcore_traffic_upload_bytes_total"));
    assert!(resp.1.contains("vpcore_bufpool_active_buffers"));

    // 2. 初始用户列表为空
    let resp = http_get(&ctl_addr, "/api/v1/users", Some("test_sec")).await;
    assert_eq!(resp.0, 200);
    assert!(resp.1.contains(r#""users":[]"#) || resp.1.contains(r#""users": []"#));

    // 3. 动态添加用户
    let new_user_json = r#"{
        "name": "alice_api",
        "secret": "my_secret_key",
        "quota_bytes": 5000000000,
        "rate_limit_up": 1048576,
        "rate_limit_down": 2097152
    }"#;
    let resp = http_post(&ctl_addr, "/api/v1/users", Some("test_sec"), new_user_json).await;
    assert_eq!(resp.0, 200);
    assert!(resp.1.contains("alice_api"));

    // 4. 获取用户列表
    let resp = http_get(&ctl_addr, "/api/v1/users", Some("test_sec")).await;
    assert_eq!(resp.0, 200);
    assert!(resp.1.contains("alice_api"));

    // 5. 获取单个用户
    let resp = http_get(&ctl_addr, "/api/v1/users/alice_api", Some("test_sec")).await;
    assert_eq!(resp.0, 200);
    assert!(resp.1.contains("alice_api"));

    // 6. 指标中包含了 alice_api
    let resp = http_get(&ctl_addr, "/metrics", Some("test_sec")).await;
    assert_eq!(resp.0, 200);
    assert!(resp.1.contains(r#"user="alice_api""#));

    // 7. 重置流量
    let resp = http_post(
        &ctl_addr,
        "/api/v1/users/alice_api/reset",
        Some("test_sec"),
        "",
    )
    .await;
    assert_eq!(resp.0, 200);

    // 8. 删除用户
    let resp = http_del(&ctl_addr, "/api/v1/users/alice_api", Some("test_sec")).await;
    assert_eq!(resp.0, 200);
    assert!(resp.1.contains("removed"));

    // 9. 再次查询为 404
    let resp = http_get(&ctl_addr, "/api/v1/users/alice_api", Some("test_sec")).await;
    assert_eq!(resp.0, 404);

    let _ = app;
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

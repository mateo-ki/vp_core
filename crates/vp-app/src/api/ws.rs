use serde_json::json;
use tokio::io::AsyncWriteExt;

use super::ApiState;

pub(crate) async fn upgrade_to_ws(
    mut stream: tokio::net::TcpStream,
    ws_key: Option<&str>,
) -> Option<vp_transport::WsStream<tokio::net::TcpStream>> {
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
pub(crate) fn current_memory_inuse(st: &ApiState) -> u64 {
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
pub(crate) async fn serve_traffic_ws(
    stream: tokio::net::TcpStream,
    ws_key: Option<&str>,
    st: &ApiState,
) {
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
pub(crate) async fn serve_memory_ws(
    stream: tokio::net::TcpStream,
    ws_key: Option<&str>,
    st: &ApiState,
) {
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
pub(crate) async fn serve_logs_ws(
    stream: tokio::net::TcpStream,
    ws_key: Option<&str>,
    st: &ApiState,
) {
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

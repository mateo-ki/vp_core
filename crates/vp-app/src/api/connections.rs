use serde_json::json;

use super::{ApiState, reply};

pub(crate) async fn handle_connections_list(stream: &mut tokio::net::TcpStream, st: &ApiState) {
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
        stream,
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

pub(crate) async fn handle_connection_get(
    stream: &mut tokio::net::TcpStream,
    st: &ApiState,
    id: &str,
) {
    let hit = st
        .conns
        .list()
        .into_iter()
        .find(|c| c.meta.id.to_string() == *id);
    match hit {
        Some(c) => reply(stream, 200, "OK", &json!({"connection": c})).await,
        None => reply(stream, 404, "Not Found", &json!({"message": "not found"})).await,
    }
}

pub(crate) async fn handle_connection_delete(
    stream: &mut tokio::net::TcpStream,
    st: &ApiState,
    id: &str,
) {
    let ok = st.conns.kill(id.parse().unwrap_or(0));
    reply(
        stream,
        if ok { 204 } else { 404 },
        if ok { "No Content" } else { "Not Found" },
        &json!({}),
    )
    .await;
}

pub(crate) async fn handle_connections_close_all(
    stream: &mut tokio::net::TcpStream,
    st: &ApiState,
) {
    let n = st.conns.close_all();
    reply(stream, 204, "No Content", &json!({"closed": n})).await;
}

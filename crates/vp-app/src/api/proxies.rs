use serde_json::json;

use super::{query_param, reply};

pub(crate) async fn handle_proxies_list(
    stream: &mut tokio::net::TcpStream,
    router: &vp_router::Router,
) {
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
            let entry = proxies
                .entry(m.to_string())
                .or_insert_with(|| json!({ "type": "Static", "name": m.to_string(), "all": [] }));
            if let Some(obj) = entry.as_object_mut() {
                obj.insert("alive".into(), json!(alive));
                if let Some(ms) = delay {
                    obj.insert("history".into(), json!([{"time": "now", "delay": ms}]));
                }
            }
        }
    }
    reply(stream, 200, "OK", &json!({ "proxies": proxies })).await;
}

pub(crate) async fn handle_proxy_get(
    stream: &mut tokio::net::TcpStream,
    router: &vp_router::Router,
    name: &str,
) {
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
        reply(stream, 200, "OK", &item).await;
    } else if let Some(ob) = router.outbound(name) {
        let mut item = json!({
            "name": name,
            "type": ob.name(),
            "udp": ob.support_udp(),
            "history": [],
        });
        // 查找是否有策略组保留了该节点的历史延迟与存活状态
        for g in router.groups().values() {
            if let Some((_, delay, alive)) = g.member_states().iter().find(|(n, _, _)| &**n == name)
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
        reply(stream, 200, "OK", &item).await;
    } else {
        reply(stream, 404, "Not Found", &json!({"message": "not found"})).await;
    }
}

pub(crate) async fn handle_proxy_put(
    stream: &mut tokio::net::TcpStream,
    router: &vp_router::Router,
    name: &str,
    body_bytes: &[u8],
) {
    let g = router.get_group(name);
    match g {
        Some(g) => {
            let body: serde_json::Value = serde_json::from_slice(body_bytes).unwrap_or(json!({}));
            let target = body["name"].as_str().unwrap_or_default().to_string();
            if g.set_selected(&target) {
                reply(stream, 204, "No Content", &json!({})).await;
            } else {
                reply(
                    stream,
                    400,
                    "Bad Request",
                    &json!({"message": format!("选择 {target:?} 失败")}),
                )
                .await;
            }
        }
        None => {
            reply(stream, 404, "Not Found", &json!({"message": "not found"})).await;
        }
    }
}

pub(crate) async fn handle_proxy_delete(
    stream: &mut tokio::net::TcpStream,
    router: &vp_router::Router,
    name: &str,
) {
    if let Some(g) = router.get_group(name) {
        g.unfix_selected();
        reply(stream, 204, "No Content", &json!({})).await;
    } else {
        reply(stream, 404, "Not Found", &json!({"message": "not found"})).await;
    }
}

pub(crate) async fn handle_group_delay(
    stream: &mut tokio::net::TcpStream,
    router: &vp_router::Router,
    name: &str,
    query: &str,
) {
    let timeout_ms: u64 = query_param(query, "timeout")
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
        reply(stream, 200, "OK", &serde_json::Value::Object(results)).await;
    } else {
        reply(stream, 404, "Not Found", &json!({"message": "not found"})).await;
    }
}

pub(crate) async fn handle_proxy_delay(
    stream: &mut tokio::net::TcpStream,
    router: &vp_router::Router,
    name: &str,
    query: &str,
) {
    let url =
        query_param(query, "url").unwrap_or_else(|| "http://www.gstatic.com/generate_204".into());
    if let Some(g) = router.get_group(name) {
        let member = query_param(query, "member");
        let ms = match member {
            Some(m) => g.url_test_member(&m).await,
            None => g.url_test_member(&g.selected_name()).await,
        };
        match ms {
            Ok(ms) => reply(stream, 200, "OK", &json!({"delay": ms, "url": url})).await,
            Err(_) => reply(stream, 408, "Timeout", &json!({"message": "测速失败"})).await,
        }
    } else if router.outbound(name).is_some() {
        match router.url_test_node(name, &url).await {
            Ok(ms) => reply(stream, 200, "OK", &json!({"delay": ms, "url": url})).await,
            Err(_) => reply(stream, 408, "Timeout", &json!({"message": "测速失败"})).await,
        }
    } else {
        reply(stream, 404, "Not Found", &json!({"message": "not found"})).await
    }
}

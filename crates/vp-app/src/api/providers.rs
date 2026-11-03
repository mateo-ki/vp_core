use serde_json::json;

use super::{ApiState, configs::reload_into, reply};

pub(crate) async fn handle_proxy_providers_list(stream: &mut tokio::net::TcpStream, st: &ApiState) {
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
                    .unwrap_or_else(|| meta.base_dir.join(".cache").join(format!("{name}.yaml")));
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
    reply(stream, 200, "OK", &json!({ "providers": providers_map })).await;
}

pub(crate) async fn handle_proxy_provider_get(
    stream: &mut tokio::net::TcpStream,
    st: &ApiState,
    name: &str,
) {
    let meta = st.config_meta.read().unwrap().clone();
    let mut found = None;
    if let Some(meta) = meta {
        if let Ok(cfg) = vp_config::parse(&meta.text, meta.fmt) {
            if let Some(p) = cfg.proxy_providers.get(name) {
                let mut proxy_list = Vec::new();
                let cache_path = p
                    .path
                    .as_ref()
                    .map(|p| meta.base_dir.join(p))
                    .unwrap_or_else(|| meta.base_dir.join(".cache").join(format!("{name}.yaml")));
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
        Some(val) => reply(stream, 200, "OK", &val).await,
        None => {
            reply(
                stream,
                404,
                "Not Found",
                &json!({"message": "provider not found"}),
            )
            .await
        }
    }
}

pub(crate) async fn handle_proxy_provider_put(
    stream: &mut tokio::net::TcpStream,
    st: &ApiState,
    name: &str,
) {
    let cur = st.config_meta.read().unwrap().clone();
    match cur {
        Some(meta) => {
            // 若该 proxy-provider 配置了远端 URL，先主动拉取最新订阅并更新本地缓存文件
            if let Ok(cfg) = vp_config::parse(&meta.text, meta.fmt) {
                if let Some(p) = cfg.proxy_providers.get(name) {
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
                reply(stream, 204, "No Content", &json!({})).await;
            } else {
                reply(
                    stream,
                    500,
                    "Internal Server Error",
                    &json!({"message": format!("刷新 {name} 失败")}),
                )
                .await;
            }
        }
        None => {
            reply(
                stream,
                404,
                "Not Found",
                &json!({"message": "no config loaded"}),
            )
            .await
        }
    }
}

pub(crate) async fn handle_rule_providers_list(stream: &mut tokio::net::TcpStream, st: &ApiState) {
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
    reply(stream, 200, "OK", &json!({ "providers": providers_map })).await;
}

pub(crate) async fn handle_rule_provider_get(
    stream: &mut tokio::net::TcpStream,
    st: &ApiState,
    name: &str,
) {
    let meta = st.config_meta.read().unwrap().clone();
    let mut found = None;
    if let Some(meta) = meta {
        if let Ok(cfg) = vp_config::parse(&meta.text, meta.fmt) {
            if let Some(r) = cfg.rule_providers.get(name) {
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
        Some(val) => reply(stream, 200, "OK", &val).await,
        None => {
            reply(
                stream,
                404,
                "Not Found",
                &json!({"message": "rule provider not found"}),
            )
            .await
        }
    }
}

pub(crate) async fn handle_rule_provider_put(
    stream: &mut tokio::net::TcpStream,
    st: &ApiState,
    name: &str,
) {
    let cur = st.config_meta.read().unwrap().clone();
    match cur {
        Some(meta) => {
            if let Ok(cfg) = vp_config::parse(&meta.text, meta.fmt) {
                if let Some(r) = cfg.rule_providers.get(name) {
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
                reply(stream, 204, "No Content", &json!({})).await;
            } else {
                reply(
                    stream,
                    500,
                    "Internal Server Error",
                    &json!({"message": format!("刷新规则集 {name} 失败")}),
                )
                .await;
            }
        }
        None => {
            reply(
                stream,
                404,
                "Not Found",
                &json!({"message": "no config loaded"}),
            )
            .await
        }
    }
}

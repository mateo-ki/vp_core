use serde_json::json;

use super::{ApiState, query_param, reply};

/// 热重载：重建 Router 并替换（失败保留旧配置）；配置 tun 段有开关差量时
/// 同步动态启停 TUN 入站（免重启热切换）。
pub(crate) async fn reload_into(
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

pub(crate) async fn handle_configs_get(
    stream: &mut tokio::net::TcpStream,
    st: &ApiState,
    router: &vp_router::Router,
) {
    let tun_st = st.tun_status.read().unwrap().clone();
    let dns_st = st.dns_status.read().unwrap().clone();
    reply(
        stream,
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

pub(crate) async fn handle_configs_patch(
    stream: &mut tokio::net::TcpStream,
    st: &ApiState,
    body_bytes: &[u8],
) {
    // 免停热切分流模式：PATCH /configs {"mode": "rule"|"global"|"direct"}
    let mut patched = false;
    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(body_bytes) {
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
        reply(stream, 204, "No Content", &json!({})).await;
    } else {
        reply(
            stream,
            400,
            "Bad Request",
            &json!({"message": "无效的配置 PATCH 请求体或不支持的模式"}),
        )
        .await;
    }
}

pub(crate) async fn handle_configs_put(
    stream: &mut tokio::net::TcpStream,
    st: &ApiState,
    query: &str,
    body_bytes: &[u8],
) {
    // 热重载：PUT /configs?path=... 或 JSON body {"path": "..."} 或重新读取当前配置
    let mut target_path = query_param(query, "path");
    if target_path.is_none() && !body_bytes.is_empty() {
        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(body_bytes) {
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
        reply(stream, 204, "No Content", &json!({})).await;
    } else {
        reply(
            stream,
            500,
            "Internal Server Error",
            &json!({"message": "重载失败（保留旧配置）"}),
        )
        .await;
    }
}

pub(crate) async fn handle_rules_get(
    stream: &mut tokio::net::TcpStream,
    router: &vp_router::Router,
) {
    let mut out = Vec::new();
    for r in router.rules().rules() {
        let parts: Vec<&str> = r.raw.split(',').collect();
        out.push(json!({
            "type": parts.first().copied().unwrap_or(""),
            "payload": parts.get(1).copied().unwrap_or(""),
            "proxy": r.target,
        }));
    }
    reply(stream, 200, "OK", &json!({ "rules": out })).await;
}

pub(crate) async fn handle_dns_flush(stream: &mut tokio::net::TcpStream, st: &ApiState) {
    st.dns.flush_cache();
    reply(stream, 200, "OK", &json!({"message": "dns cache flushed"})).await;
}

pub(crate) async fn handle_fakeip_flush(stream: &mut tokio::net::TcpStream, st: &ApiState) {
    vp_dns::flush_global_fake_ip_pool();
    st.dns.flush_cache();
    reply(stream, 204, "No Content", &json!({})).await;
}

pub(crate) async fn handle_ui(stream: &mut tokio::net::TcpStream) {
    reply(
        stream,
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

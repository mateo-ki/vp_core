use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::json;

use vp_common::DstAddr;
use vp_core::{Router, Session};

use super::{Req, query_param, reply};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExplainParams {
    pub url: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub network: Option<String>,
    pub inbound: Option<String>,
    pub inbound_port: Option<u16>,
    pub inbound_user: Option<String>,
    pub process: Option<String>,
    pub src_ip: Option<String>,
}

pub(crate) async fn handle_routes_explain(
    stream: &mut tokio::net::TcpStream,
    router: &Arc<vp_router::Router>,
    req: &Req,
) {
    let mut params = ExplainParams::default();

    if req.method.eq_ignore_ascii_case("POST") && !req.body.is_empty() {
        if let Ok(p) = serde_json::from_slice::<ExplainParams>(&req.body) {
            params = p;
        }
    }

    // Query 参数优先级高于 POST body（可覆盖）
    if let Some(u) = query_param(&req.query, "url") {
        params.url = Some(u);
    }
    if let Some(h) = query_param(&req.query, "host") {
        params.host = Some(h);
    }
    if let Some(p) = query_param(&req.query, "port").and_then(|s| s.parse::<u16>().ok()) {
        params.port = Some(p);
    }
    if let Some(n) = query_param(&req.query, "network") {
        params.network = Some(n);
    }
    if let Some(i) = query_param(&req.query, "inbound") {
        params.inbound = Some(i);
    }
    if let Some(ip) = query_param(&req.query, "inbound_port").and_then(|s| s.parse::<u16>().ok()) {
        params.inbound_port = Some(ip);
    }
    if let Some(u) = query_param(&req.query, "inbound_user") {
        params.inbound_user = Some(u);
    }
    if let Some(p) = query_param(&req.query, "process") {
        params.process = Some(p);
    }
    if let Some(s) = query_param(&req.query, "src_ip") {
        params.src_ip = Some(s);
    }

    let dst = match resolve_dst_addr(&params) {
        Some(dst) => dst,
        None => {
            reply(
                stream,
                400,
                "Bad Request",
                &json!({
                    "error": "missing or invalid destination: provide 'url' (e.g. https://google.com) or 'host' (e.g. google.com)"
                }),
            )
            .await;
            return;
        }
    };

    let network = match params
        .network
        .as_deref()
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("udp") => vp_core::Network::Udp,
        _ => vp_core::Network::Tcp,
    };

    let inbound = params.inbound.unwrap_or_else(|| "mixed".to_string());

    let src = params
        .src_ip
        .and_then(|s| s.parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, 0));

    let mut sess = match network {
        vp_core::Network::Tcp => Session::new_tcp(inbound.into(), src, dst),
        vp_core::Network::Udp => Session::new_udp(inbound.into(), src, dst),
    };
    sess.process = params.process.map(|p| p.into());
    sess.inbound_port = params.inbound_port;
    sess.inbound_user = params.inbound_user.map(|u| u.into());

    let trace = router.explain(&sess).await;

    reply(
        stream,
        200,
        "OK",
        &serde_json::to_value(&trace).unwrap_or_default(),
    )
    .await;
}

pub fn resolve_dst_addr(params: &ExplainParams) -> Option<DstAddr> {
    if let Some(target) = params.url.as_ref().or(params.host.as_ref()) {
        parse_target(target, params.port)
    } else {
        None
    }
}

pub fn parse_target(target: &str, override_port: Option<u16>) -> Option<DstAddr> {
    let s = target.trim();
    if s.is_empty() {
        return None;
    }

    // 尝试识别带有 scheme 的 URL，如 https://github.com/path
    let (host_part, default_port) = if let Some(rest) = s.strip_prefix("https://") {
        (rest, 443)
    } else if let Some(rest) = s.strip_prefix("http://") {
        (rest, 80)
    } else if let Some((_, rest)) = s.split_once("://") {
        (rest, 443)
    } else {
        (s, override_port.unwrap_or(443))
    };

    // 去除 path 部分（如有）
    let host_port = host_part.split('/').next().unwrap_or(host_part);

    // 如果指定了 override_port 且目标不含端口号，优先使用
    if let Ok(dst) = DstAddr::parse(host_port) {
        if let Some(p) = override_port {
            Some(DstAddr::new(format!("{}", dst.host), p))
        } else {
            Some(dst)
        }
    } else {
        let p = override_port.unwrap_or(default_port);
        Some(DstAddr::new(host_port, p))
    }
}

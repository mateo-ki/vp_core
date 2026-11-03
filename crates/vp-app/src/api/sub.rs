use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

use super::{ApiState, Req, query_param, reply_subscription};

pub(crate) async fn handle_sub(
    stream: &mut tokio::net::TcpStream,
    st: &ApiState,
    req: &Req,
    segs: &[&str],
) {
    let is_clash = segs.get(1) == Some(&"clash")
        || query_param(&req.query, "format")
            .map(|f| f.eq_ignore_ascii_case("clash"))
            .unwrap_or(false)
        || req
            .user_agent
            .as_ref()
            .map(|ua| {
                let ua_lower = ua.to_ascii_lowercase();
                ua_lower.contains("clash")
                    || ua_lower.contains("meta")
                    || ua_lower.contains("stash")
                    || ua_lower.contains("verge")
                    || ua_lower.contains("mihomo")
            })
            .unwrap_or(false);

    let (base_dir, cfg_text) = {
        let meta_guard = st.config_meta.read().unwrap();
        if let Some(ref meta) = *meta_guard {
            (meta.base_dir.clone(), meta.text.clone())
        } else {
            (std::path::PathBuf::from("."), String::new())
        }
    };

    if is_clash {
        let clash_content = if let Ok(c) = std::fs::read_to_string(base_dir.join("sub-clash.yaml"))
        {
            c
        } else if let Ok(c) = std::fs::read_to_string(base_dir.join("clash.yaml")) {
            c
        } else {
            generate_clash_sub_from_text(&cfg_text, req.host.as_deref())
        };
        reply_subscription(
            stream,
            200,
            "OK",
            &clash_content,
            "text/yaml; charset=utf-8",
            "vpcore-clash.yaml",
        )
        .await;
    } else {
        let sub_content = if let Ok(c) = std::fs::read_to_string(base_dir.join("sub.txt")) {
            c.trim().to_string()
        } else {
            generate_base64_sub_from_text(&cfg_text, req.host.as_deref())
        };
        reply_subscription(
            stream,
            200,
            "OK",
            &sub_content,
            "text/plain; charset=utf-8",
            "vpcore-sub.txt",
        )
        .await;
    }
}

pub(crate) fn generate_base64_sub_from_text(cfg_text: &str, host_header: Option<&str>) -> String {
    let clean_host = host_header
        .and_then(|h| h.split(':').next())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && *s != "0.0.0.0" && *s != "127.0.0.1")
        .unwrap_or("127.0.0.1");

    let Ok(cfg) = vp_config::parse(cfg_text, vp_config::Format::Yaml) else {
        return String::new();
    };

    let mut links = Vec::new();
    for l in &cfg.listeners {
        match l.kind.as_str() {
            "mux" | "reality" => {
                let uuid = l
                    .users
                    .first()
                    .map(|s| s.as_str())
                    .unwrap_or("00000000-0000-0000-0000-000000000000");
                let reality = l.reality.as_ref();
                let sid = reality
                    .and_then(|r| r.short_ids.first().map(|s| s.as_str()))
                    .unwrap_or("");
                let sni = reality
                    .and_then(|r| r.server_names.first().map(|s| s.as_str()))
                    .unwrap_or("www.amazon.com");
                links.push(format!(
                    "vless://{uuid}@{clean_host}:{}?security=reality&encryption=none&pbk=&sid={sid}&sni={sni}&fp=chrome&type=tcp#vpcore-reality",
                    l.port
                ));
            }
            "hysteria2" => {
                let pass = l.users.first().map(|s| s.as_str()).unwrap_or("");
                links.push(format!(
                    "hysteria2://{pass}@{clean_host}:{}/?insecure=1&sni=hy2.vpcore.internal#vpcore-hy2",
                    l.port
                ));
            }
            "ss" => {
                let cipher = l.cipher.as_deref().unwrap_or("2022-blake3-aes-128-gcm");
                let key = l.users.first().map(|s| s.as_str()).unwrap_or("");
                let userinfo = BASE64_STANDARD.encode(format!("{cipher}:{key}"));
                links.push(format!("ss://{userinfo}@{clean_host}:{}#vpcore-ss", l.port));
            }
            "trojan" => {
                let pass = l.users.first().map(|s| s.as_str()).unwrap_or("");
                links.push(format!(
                    "trojan://{pass}@{clean_host}:{}?security=tls&sni={clean_host}#vpcore-trojan",
                    l.port
                ));
            }
            "vless" => {
                let uuid = l.users.first().map(|s| s.as_str()).unwrap_or("");
                links.push(format!(
                    "vless://{uuid}@{clean_host}:{}?security=tls&sni={clean_host}#vpcore-vless",
                    l.port
                ));
            }
            _ => {}
        }
    }
    let joined = links.join("\n");
    BASE64_STANDARD.encode(joined.as_bytes())
}

pub(crate) fn generate_clash_sub_from_text(cfg_text: &str, host_header: Option<&str>) -> String {
    let clean_host = host_header
        .and_then(|h| h.split(':').next())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && *s != "0.0.0.0" && *s != "127.0.0.1")
        .unwrap_or("127.0.0.1");

    let Ok(cfg) = vp_config::parse(cfg_text, vp_config::Format::Yaml) else {
        return String::new();
    };

    let mut proxies_yaml = String::new();
    let mut names = Vec::new();

    for l in &cfg.listeners {
        match l.kind.as_str() {
            "mux" | "reality" => {
                let uuid = l
                    .users
                    .first()
                    .map(|s| s.as_str())
                    .unwrap_or("00000000-0000-0000-0000-000000000000");
                let reality = l.reality.as_ref();
                let sid = reality
                    .and_then(|r| r.short_ids.first().map(|s| s.as_str()))
                    .unwrap_or("");
                let sni = reality
                    .and_then(|r| r.server_names.first().map(|s| s.as_str()))
                    .unwrap_or("www.amazon.com");
                names.push("vpcore-reality".to_string());
                proxies_yaml.push_str(&format!(
                    "  - name: \"vpcore-reality\"\n    type: vless\n    server: \"{clean_host}\"\n    port: {}\n    uuid: \"{uuid}\"\n    cipher: auto\n    tls: true\n    udp: true\n    servername: \"{sni}\"\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: \"\"\n      short-id: \"{sid}\"\n",
                    l.port
                ));
            }
            "hysteria2" => {
                let pass = l.users.first().map(|s| s.as_str()).unwrap_or("");
                names.push("vpcore-hy2".to_string());
                proxies_yaml.push_str(&format!(
                    "  - name: \"vpcore-hy2\"\n    type: hysteria2\n    server: \"{clean_host}\"\n    port: {}\n    password: \"{pass}\"\n    sni: hy2.vpcore.internal\n    skip-cert-verify: true\n",
                    l.port
                ));
            }
            "ss" => {
                let cipher = l.cipher.as_deref().unwrap_or("2022-blake3-aes-128-gcm");
                let key = l.users.first().map(|s| s.as_str()).unwrap_or("");
                names.push("vpcore-ss".to_string());
                proxies_yaml.push_str(&format!(
                    "  - name: \"vpcore-ss\"\n    type: ss\n    server: \"{clean_host}\"\n    port: {}\n    cipher: {cipher}\n    password: \"{key}\"\n    udp: true\n",
                    l.port
                ));
            }
            "trojan" => {
                let pass = l.users.first().map(|s| s.as_str()).unwrap_or("");
                names.push("vpcore-trojan".to_string());
                proxies_yaml.push_str(&format!(
                    "  - name: \"vpcore-trojan\"\n    type: trojan\n    server: \"{clean_host}\"\n    port: {}\n    password: \"{pass}\"\n    udp: true\n    sni: \"{clean_host}\"\n    skip-cert-verify: true\n",
                    l.port
                ));
            }
            "vless" => {
                let uuid = l.users.first().map(|s| s.as_str()).unwrap_or("");
                names.push("vpcore-vless".to_string());
                proxies_yaml.push_str(&format!(
                    "  - name: \"vpcore-vless\"\n    type: vless\n    server: \"{clean_host}\"\n    port: {}\n    uuid: \"{uuid}\"\n    cipher: auto\n    tls: true\n    udp: true\n",
                    l.port
                ));
            }
            _ => {}
        }
    }

    let mut out =
        String::from("port: 7890\nsocks-port: 7891\nmode: rule\nlog-level: info\n\nproxies:\n");
    out.push_str(&proxies_yaml);
    out.push_str(
        "\nproxy-groups:\n  - name: PROXY\n    type: select\n    proxies:\n      - AUTO\n",
    );
    for n in &names {
        out.push_str(&format!("      - \"{n}\"\n"));
    }
    out.push_str("  - name: AUTO\n    type: url-test\n    url: http://www.gstatic.com/generate_204\n    interval: 300\n    proxies:\n");
    for n in &names {
        out.push_str(&format!("      - \"{n}\"\n"));
    }
    out.push_str("\nrules:\n  - MATCH,PROXY\n");
    out
}

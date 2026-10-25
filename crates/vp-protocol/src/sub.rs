//! 订阅与分享链接解析：vless:// / vmess:// / trojan:// / ss:// URI → 节点配置。
//!
//! 输出为 Clash 兼容 YAML 片段（proxies），供 `vpcore sub` 生成完整配置。

use std::collections::HashMap;

use vp_common::{Error, Result};

/// 解析后的节点（Clash YAML 片段序列化形式）
pub struct SubNode {
    pub fields: Vec<(String, String)>,
}

impl SubNode {
    pub fn name(&self) -> &str {
        self.fields
            .iter()
            .find(|(k, _)| k == "name")
            .map(|(_, v)| v.trim_matches('"'))
            .unwrap_or("")
    }

    pub fn to_yaml(&self) -> String {
        // 普通字段（跳过 __ws_* 内部标记）
        let lines: Vec<String> = self
            .fields
            .iter()
            .filter(|(k, _)| !k.starts_with("__"))
            .map(|(k, v)| format!("{k}: {v}"))
            .collect();
        let mut out = String::from("  - ");
        out.push_str(&lines.join("\n    "));
        // plugin-opts 块（shadow-tls，若存在）
        if let Some((_, host)) = self.fields.iter().find(|(k, _)| k == "__stls_host") {
            let password = self
                .fields
                .iter()
                .find(|(k, _)| k == "__stls_password")
                .map(|(_, v)| v.as_str())
                .unwrap_or("\"\"");
            let port = self
                .fields
                .iter()
                .find(|(k, _)| k == "__stls_port")
                .map(|(_, v)| v.trim_matches('"'))
                .unwrap_or("");
            let port_line = if port.is_empty() {
                String::new()
            } else {
                format!("
      port: {port}")
            };
            out.push_str(&format!(
                "
    plugin-opts:
      host: {host}
      password: {password}{{port_line}}
      version: 3"
            ));
        }
        // ws-opts 块（若存在）
        if let Some((_, path)) = self.fields.iter().find(|(k, _)| k == "__ws_path") {
            let host = self
                .fields
                .iter()
                .find(|(k, _)| k == "__ws_host")
                .map(|(_, v)| v.as_str())
                .unwrap_or("\"\"");
            out.push_str(&format!(
                "\n    ws-opts:\n      path: {path}\n      headers:\n        Host: {host}"
            ));
        }
        out.push('\n');
        out
    }
}

fn q(s: &str) -> String {
    format!("\"{}\"", s.replace('"', ""))
}

/// 解析任意分享链接
pub fn parse_uri(line: &str) -> Result<SubNode> {
    let line = line.trim();
    if let Some(rest) = line.strip_prefix("vless://") {
        parse_vless(rest)
    } else if let Some(rest) = line.strip_prefix("vmess://") {
        parse_vmess(rest)
    } else if let Some(rest) = line.strip_prefix("trojan://") {
        parse_trojan(rest)
    } else if let Some(rest) = line.strip_prefix("ss://") {
        parse_ss(rest)
    } else {
        Err(Error::Config(format!("无法识别的分享链接: {}", &line[..line.len().min(32)])))
    }
}

fn split_main(rest: &str) -> Result<(String, String, String, HashMap<String, String>, String)> {
    // userinfo@host:port?params#name
    let (body, name) = match rest.split_once('#') {
        Some((b, n)) => (b, urldecode(n)),
        None => (rest, String::new()),
    };
    let (main, qs) = match body.split_once('?') {
        Some((m, q)) => (m, q),
        None => (body, ""),
    };
    let params: HashMap<String, String> = qs
        .split('&')
        .filter(|kv| !kv.is_empty())
        .filter_map(|kv| {
            kv.split_once('=')
                .map(|(k, v)| (k.to_string(), urldecode(v)))
        })
        .collect();
    let (userinfo, hostport) = main.rsplit_once('@').ok_or(Error::Config("缺少 @".into()))?;
    let (host, port) = hostport.rsplit_once(':').ok_or(Error::Config("缺少端口".into()))?;
    Ok((userinfo.to_string(), host.to_string(), port.to_string(), params, name))
}

fn parse_vless(rest: &str) -> Result<SubNode> {
    let (uuid, host, port, p, name) = split_main(rest)?;
    let network = p.get("type").cloned().unwrap_or_else(|| "tcp".into());
    let tls = p.get("security").map(|s| s != "none").unwrap_or(false);
    let mut f = vec![
        ("name".into(), q(&name)),
        ("type".into(), "vless".into()),
        ("server".into(), host),
        ("port".into(), port),
        ("uuid".into(), uuid),
        ("tls".into(), tls.to_string()),
    ];
    if let Some(sni) = p.get("sni").or_else(|| p.get("host")) {
        f.push(("servername".into(), sni.clone()));
    }
    if p.get("allowInsecure").map(|v| v == "1").unwrap_or(false) {
        f.push(("skip-cert-verify".into(), "true".into()));
    }
    f.push(("network".into(), network.clone()));
    if network == "ws" {
        f.push(("ws-opts".into(), "{...}".into())); // 占位，由下方特化输出
        return finish_ws(f, &p);
    }
    if network == "grpc" {
        let svc = p.get("serviceName").cloned().unwrap_or_default();
        f.pop();
        f.push(("grpc-opts".into(), format!("{{grpc-service-name: {svc}}}")));
    }
    Ok(SubNode { fields: f })
}

fn finish_ws(mut f: Vec<(String, String)>, p: &HashMap<String, String>) -> Result<SubNode> {
    // 把 ws-opts 占位替换成完整段（在 to_yaml 前处理）
    let path = p.get("path").cloned().unwrap_or_else(|| "/".into());
    let host = p.get("host").cloned().unwrap_or_default();
    // 移除占位，附加结构标记字段
    f.retain(|(k, _)| k != "ws-opts");
    // 用特殊字段承载（序列化时展开）
    f.push(("__ws_path".into(), q(&path)));
    f.push(("__ws_host".into(), q(&host)));
    Ok(SubNode { fields: f })
}

fn parse_vmess(rest: &str) -> Result<SubNode> {
    // vmess://base64(json)
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(rest.trim())
        .or_else(|_| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(rest.trim())
        })
        .map_err(|_| Error::Config("vmess base64 解码失败".into()))?;
    let j: serde_json::Value = serde_json::from_slice(&decoded)
        .map_err(|e| Error::Config(format!("vmess json: {e}")))?;
    let get = |k: &str| j[k].as_str().unwrap_or("").to_string();
    let host = get("add");
    let port = j["port"].as_u64().unwrap_or_else(|| get("port").parse().unwrap_or(443));
    let mut f = vec![
        ("name".into(), q(&get("ps"))),
        ("type".into(), "vmess".into()),
        ("server".into(), host),
        ("port".into(), port.to_string()),
        ("uuid".into(), get("id")),
        ("alterId".into(), j["aid"].as_u64().unwrap_or(0).to_string()),
        ("cipher".into(), get("scy").is_empty().then(|| "auto".into()).unwrap_or_else(|| get("scy"))),
        ("tls".into(), get("tls").eq_ignore_ascii_case("tls").to_string()),
    ];
    let net = get("net");
    if !get("sni").is_empty() {
        f.push(("servername".into(), get("sni")));
    } else if !get("host").is_empty() && get("tls") == "tls" {
        f.push(("servername".into(), get("host")));
    }
    f.push(("network".into(), net.clone()));
    if net == "ws" {
        f.push(("__ws_path".into(), q(&get("path"))));
        f.push(("__ws_host".into(), q(&get("host"))));
    } else if net == "grpc" {
        f.push(("grpc-opts".into(), format!("{{grpc-service-name: {}}}", get("path"))));
    }
    Ok(SubNode { fields: f })
}

fn parse_trojan(rest: &str) -> Result<SubNode> {
    let (password, host, port, p, name) = split_main(rest)?;
    let network = p.get("type").cloned().unwrap_or_else(|| "tcp".into());
    let mut f = vec![
        ("name".into(), q(&name)),
        ("type".into(), "trojan".into()),
        ("server".into(), host),
        ("port".into(), port),
        ("password".into(), q(&password)),
    ];
    if let Some(sni) = p.get("sni").or_else(|| p.get("peer")) {
        f.push(("sni".into(), sni.clone()));
    }
    if p.get("allowInsecure").map(|v| v == "1").unwrap_or(false) {
        f.push(("skip-cert-verify".into(), "true".into()));
    }
    f.push(("network".into(), network.clone()));
    if network == "ws" {
        f.push(("__ws_path".into(), q(&p.get("path").cloned().unwrap_or_else(|| "/".into()))));
        f.push(("__ws_host".into(), q(&p.get("host").cloned().unwrap_or_default())));
    }
    Ok(SubNode { fields: f })
}

fn parse_ss(rest: &str) -> Result<SubNode> {
    // ss://base64(method:pass)@host:port#name 或 SIP002
    // 兼容直接调用（可能仍带 ss:// 前缀）
    let rest = rest.strip_prefix("ss://").unwrap_or(rest);
    let (body, name) = match rest.split_once('#') {
        Some((b, n)) => (b, urldecode(n)),
        None => (rest, String::new()),
    };
    let (main, qs) = body.split_once('?').unwrap_or((body, ""));
    let (encoded, hostport) = main.rsplit_once('@').ok_or(Error::Config("ss 缺少 @".into()))?;
    // SIP002: plugin=shadow-tls;mode=v3;host=xx;password=yy（urlencoded）
    let mut stls: Option<Vec<(String, String)>> = None;
    for kv in qs.split('&') {
        let Some((k, v)) = kv.split_once('=') else { continue };
        if urldecode(k) != "plugin" {
            continue;
        }
        let p = urldecode(v);
        let mut parts = p.split(';');
        let name = parts.next().unwrap_or_default().to_string();
        let opts: Vec<(String, String)> = parts
            .filter_map(|o| o.split_once('=').map(|(a, b)| (a.to_string(), b.to_string())))
            .collect();
        if name.contains("shadow-tls") {
            stls = Some(opts);
        }
    }
    use base64::Engine;
    let userinfo = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded))
        .map_err(|_| Error::Config("ss userinfo base64".into()))?;
    let userinfo = String::from_utf8_lossy(&userinfo).to_string();
    let (method, password) = userinfo
        .split_once(':')
        .ok_or(Error::Config("ss userinfo 格式".into()))?;
    let (host, port) = hostport.rsplit_once(':').ok_or(Error::Config("ss 缺端口".into()))?;
    let mut fields = vec![
        ("name".into(), q(&name)),
        ("type".into(), "ss".into()),
        ("server".into(), host.to_string()),
        ("port".into(), port.to_string()),
        ("cipher".into(), method.to_string()),
        ("password".into(), q(password)),
    ];
    if let Some(opts) = stls {
        let get = |k: &str| {
            opts.iter()
                .find(|(a, _)| a == k)
                .map(|(_, b)| b.clone())
                .unwrap_or_default()
        };
        fields.push(("plugin".into(), "shadow-tls".into()));
        fields.push(("__stls_host".into(), q(&get("host"))));
        fields.push(("__stls_password".into(), q(&get("password"))));
        fields.push(("__stls_port".into(), q(&get("port"))));
    }
    Ok(SubNode { fields })
}

fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() + 1 => {
                if i + 2 < bytes.len() {
                    if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                        out.push(b);
                        i += 3;
                        continue;
                    }
                }
                out.push(b'%');
                i += 1;
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

/// 订阅内容 → 节点列表（自动识别 base64 包装）
pub fn parse_subscription(text: &str) -> Vec<SubNode> {
    let body = text.trim();
    // 尝试 base64 解包
    let lines: Vec<String> = if body.contains("://") {
        body.lines().map(|l| l.trim().to_string()).collect()
    } else {
        use base64::Engine;
        let cleaned: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&cleaned)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&cleaned))
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .unwrap_or_default();
        decoded.lines().map(|l| l.trim().to_string()).collect()
    };
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for l in lines.into_iter().filter(|l| l.contains("://")) {
        match parse_uri(&l) {
            Ok(n) => {
                // 只保留本内核支持的传输（tcp/ws/grpc）
                let net_ok = n.fields.iter().any(|(k, v)| k == "network" && matches!(v.trim_matches('"'), "tcp" | "ws" | "grpc"));
                if net_ok {
                    out.push(n);
                } else {
                    skipped += 1;
                }
            }
            Err(_) => skipped += 1,
        }
    }
    if skipped > 0 {
        eprintln!("订阅：跳过 {skipped} 个不支持的节点/传输");
    }
    out
}

/// 生成完整可运行配置
pub fn build_config(nodes: &[SubNode], port: u16) -> String {
    let mut out = String::new();
    out.push_str(&format!("mixed-port: {port}\nmode: rule\nlog-level: info\n\nproxies:\n"));
    for n in nodes {
        // ws-opts 展开已在 SubNode::to_yaml 内完成
        out.push_str(&n.to_yaml());
    }
    let names: Vec<String> = nodes.iter().map(|n| n.name().to_string()).collect();
    out.push_str("\nproxy-groups:\n");
    out.push_str("  - name: PROXY\n    type: select\n    proxies: [自动选择");
    for n in &names {
        out.push_str(&format!(", \"{}\"", n));
    }
    out.push_str("]\n");
    out.push_str("  - name: 自动选择\n    type: url-test\n    url: http://www.gstatic.com/generate_204\n    interval: 300\n    proxies: [");
    out.push_str(&names.iter().map(|n| format!("\"{n}\"")).collect::<Vec<_>>().join(", "));
    out.push_str("]\n");
    out.push_str("\nrules:\n  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve\n  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve\n  - MATCH,PROXY\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vless_uri() {
        let n = parse_uri("vless://uuid-123@1.2.3.4:443?security=tls&sni=ex.com&type=ws&path=%2Fabc%3Fed%3D2048&host=ex.com#%E9%A6%99%E6%B8%AF-01").unwrap();
        assert_eq!(n.name(), "香港-01");
        let y = n.to_yaml();
        assert!(y.contains("type: vless"));
        assert!(y.contains("tls: true"));
    }

    #[test]
    fn trojan_and_ss() {
        let n = parse_uri("trojan://pw123@h.com:443?sni=h.com#t1").unwrap();
        assert_eq!(n.name(), "t1");
        assert!(n.to_yaml().contains("password: \"pw123\""));
        let s = parse_ss("ss://YWVzLTI1Ni1nY206cGFzcw@a.com:8388#s1").unwrap();
        assert!(s.to_yaml().contains("cipher: aes-256-gcm"));
    }

    #[test]
    fn ss_shadowtls_plugin() {
        // SIP002: plugin 参数 urlencoded，分号分隔
        let uri = "ss://YWVzLTI1Ni1nY206cGFzcw@a.com:8388?plugin=shadow-tls%3Bmode%3Dv3%3Bhost%3Dwww.apple.com%3Bpassword%3Dstls-pw#s1";
        let n = parse_uri(uri).unwrap();
        let y = n.to_yaml();
        assert!(y.contains("plugin: shadow-tls"), "{y}");
        assert!(y.contains("plugin-opts:"));
        assert!(y.contains("host: \"www.apple.com\""));
        assert!(y.contains("password: \"stls-pw\""));
        assert!(y.contains("version: 3"));
        // 无 plugin 的 ss 不应生成 plugin 段
        let plain = parse_ss("ss://YWVzLTI1Ni1nY206cGFzcw@a.com:8388#s2").unwrap();
        assert!(!plain.to_yaml().contains("plugin"));
    }

    #[test]
    fn vmess_uri() {
        use base64::Engine;
        let j = r#"{"v":"2","ps":"vm","add":"h.com","port":"443","id":"u1","aid":"0","scy":"auto","net":"ws","host":"h.com","path":"/w","tls":"tls","sni":"h.com"}"#;
        let enc = base64::engine::general_purpose::STANDARD.encode(j);
        let n = parse_uri(&format!("vmess://{enc}")).unwrap();
        assert_eq!(n.name(), "vm");
        assert!(n.to_yaml().contains("uuid: u1"));
    }

    #[test]
    fn subscription_base64() {
        use base64::Engine;
        let raw = "trojan://pw@h.com:443#n1\nvless://u@h2.com:443#n2\n";
        let enc = base64::engine::general_purpose::STANDARD.encode(raw);
        let nodes = parse_subscription(&enc);
        assert_eq!(nodes.len(), 2);
    }

    #[test]
    fn build_config_yaml() {
        let nodes = parse_subscription("trojan://pw@h.com:443#n1");
        let cfg = build_config(&nodes, 7890);
        assert!(cfg.contains("mixed-port: 7890"));
        assert!(cfg.contains("MATCH,PROXY"));
    }

    #[test]
    fn two_nodes_layout() {
        let sub = "trojan://pw@h.com:443?sni=h.com&type=ws&path=/t#t1
vless://u@h2.com:443?security=tls&sni=h2.com&type=ws&path=/v&host=h2.com#v1";
        let nodes = parse_subscription(sub);
        assert_eq!(nodes.len(), 2);
        let cfg = build_config(&nodes, 7890);
        // 每个节点首行必须 2 空格缩进
        for line in cfg.lines() {
            if line.contains("- name:") {
                assert!(line.starts_with("  - name:"), "坏行: {line:?}");
            }
        }
        // 无 __ 残留
        assert!(!cfg.contains("__ws"));
        // 验证可被 serde_yaml 解析
        let v: serde_yaml::Value = serde_yaml::from_str(&cfg).unwrap();
        assert!(v.get("proxies").is_some());
    }
}

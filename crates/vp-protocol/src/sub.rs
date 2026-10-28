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
                format!(
                    "
      port: {port}"
                )
            };
            out.push_str(&format!(
                "
    plugin-opts:
      host: {host}
      password: {password}{port_line}
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
        // reality-opts 块（若存在）
        if let Some((_, pbk)) = self.fields.iter().find(|(k, _)| k == "__reality_pbk") {
            out.push_str(&format!("\n    reality-opts:\n      public-key: {pbk}"));
            if let Some((_, sid)) = self.fields.iter().find(|(k, _)| k == "__reality_sid") {
                if !sid.is_empty() {
                    out.push_str(&format!("\n      short-id: {sid}"));
                }
            }
            if let Some((_, spx)) = self.fields.iter().find(|(k, _)| k == "__reality_spx") {
                if !spx.is_empty() {
                    out.push_str(&format!("\n      spider-x: {spx}"));
                }
            }
        }
        out.push('\n');
        out
    }
}

fn q(s: &str) -> String {
    serde_json::to_string(s).expect("string serialization is infallible")
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
    } else if let Some(rest) = line.strip_prefix("anytls://") {
        parse_anytls(rest)
    } else if let Some(rest) = line.strip_prefix("ssh://") {
        parse_ssh(rest)
    } else if let Some(rest) = line.strip_prefix("brook://") {
        parse_brook(rest)
    } else if let Some(rest) = line.strip_prefix("mieru://") {
        parse_mieru(rest)
    } else if let Some(rest) = line.strip_prefix("snell://") {
        parse_snell(rest)
    } else if let Some(rest) = line.strip_prefix("ssr://") {
        parse_ssr(rest)
    } else if let Some(rest) = line.strip_prefix("naive+https://") {
        parse_naive(rest, true)
    } else if let Some(rest) = line.strip_prefix("naive+http://") {
        parse_naive(rest, false)
    } else if let Some(rest) = line.strip_prefix("naive://") {
        parse_naive(rest, true)
    } else {
        Err(Error::Config("无法识别的分享链接格式".into()))
    }
}

type UriParts = (String, String, String, HashMap<String, String>, String);

fn split_main(rest: &str) -> Result<UriParts> {
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
    let (userinfo, hostport) = main
        .rsplit_once('@')
        .ok_or(Error::Config("缺少 @".into()))?;
    let (host, port) = hostport
        .rsplit_once(':')
        .ok_or(Error::Config("缺少端口".into()))?;
    Ok((
        userinfo.to_string(),
        host.to_string(),
        port.to_string(),
        params,
        name,
    ))
}

fn parse_vless(rest: &str) -> Result<SubNode> {
    let (uuid, host, port, p, name) = split_main(rest)?;
    let network = p.get("type").cloned().unwrap_or_else(|| "tcp".into());
    let is_reality = p.get("security").map(|s| s == "reality").unwrap_or(false)
        || p.contains_key("pbk")
        || p.contains_key("publicKey");
    let tls = is_reality || p.get("security").map(|s| s != "none").unwrap_or(false);
    let mut f = vec![
        ("name".into(), q(&name)),
        ("type".into(), "vless".into()),
        ("server".into(), host),
        ("port".into(), port),
        ("uuid".into(), uuid),
        ("tls".into(), tls.to_string()),
    ];
    if let Some(flow) = p.get("flow") {
        if !flow.is_empty() {
            f.push(("flow".into(), flow.clone()));
        }
    }
    if let Some(sni) = p.get("sni").or_else(|| p.get("host")) {
        f.push(("servername".into(), sni.clone()));
    }
    if p.get("allowInsecure").map(|v| v == "1").unwrap_or(false) {
        f.push(("skip-cert-verify".into(), "true".into()));
    }
    if is_reality {
        if let Some(pbk) = p.get("pbk").or_else(|| p.get("publicKey")) {
            f.push(("__reality_pbk".into(), q(pbk)));
        }
        if let Some(sid) = p.get("sid").or_else(|| p.get("shortId")) {
            f.push(("__reality_sid".into(), q(sid)));
        }
        if let Some(spx) = p.get("spx").or_else(|| p.get("spiderX")) {
            f.push(("__reality_spx".into(), q(spx)));
        }
        let fp = p
            .get("fp")
            .or_else(|| p.get("fingerprint"))
            .cloned()
            .unwrap_or_else(|| "chrome".into());
        f.push(("client-fingerprint".into(), fp));
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
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(rest.trim()))
        .map_err(|_| Error::Config("vmess base64 解码失败".into()))?;
    let j: serde_json::Value =
        serde_json::from_slice(&decoded).map_err(|e| Error::Config(format!("vmess json: {e}")))?;
    let get = |k: &str| j[k].as_str().unwrap_or("").to_string();
    let host = get("add");
    let port = j["port"]
        .as_u64()
        .unwrap_or_else(|| get("port").parse().unwrap_or(443));
    let mut f = vec![
        ("name".into(), q(&get("ps"))),
        ("type".into(), "vmess".into()),
        ("server".into(), host),
        ("port".into(), port.to_string()),
        ("uuid".into(), get("id")),
        ("alterId".into(), j["aid"].as_u64().unwrap_or(0).to_string()),
        (
            "cipher".into(),
            if get("scy").is_empty() {
                "auto".into()
            } else {
                get("scy")
            },
        ),
        (
            "tls".into(),
            get("tls").eq_ignore_ascii_case("tls").to_string(),
        ),
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
        f.push((
            "grpc-opts".into(),
            format!("{{grpc-service-name: {}}}", get("path")),
        ));
    }
    Ok(SubNode { fields: f })
}

fn parse_trojan(rest: &str) -> Result<SubNode> {
    let (password, host, port, p, name) = split_main(rest)?;
    let network = p.get("type").cloned().unwrap_or_else(|| "tcp".into());
    let is_reality = p.get("security").map(|s| s == "reality").unwrap_or(false)
        || p.contains_key("pbk")
        || p.contains_key("publicKey");
    let tls = is_reality || p.get("security").map(|s| s != "none").unwrap_or(true);
    let mut f = vec![
        ("name".into(), q(&name)),
        ("type".into(), "trojan".into()),
        ("server".into(), host),
        ("port".into(), port),
        ("password".into(), q(&password)),
        ("tls".into(), tls.to_string()),
    ];
    if let Some(sni) = p.get("sni").or_else(|| p.get("peer")) {
        f.push(("sni".into(), sni.clone()));
    }
    if p.get("allowInsecure").map(|v| v == "1").unwrap_or(false) {
        f.push(("skip-cert-verify".into(), "true".into()));
    }
    if is_reality {
        if let Some(pbk) = p.get("pbk").or_else(|| p.get("publicKey")) {
            f.push(("__reality_pbk".into(), q(pbk)));
        }
        if let Some(sid) = p.get("sid").or_else(|| p.get("shortId")) {
            f.push(("__reality_sid".into(), q(sid)));
        }
        if let Some(spx) = p.get("spx").or_else(|| p.get("spiderX")) {
            f.push(("__reality_spx".into(), q(spx)));
        }
        let fp = p
            .get("fp")
            .or_else(|| p.get("fingerprint"))
            .cloned()
            .unwrap_or_else(|| "chrome".into());
        f.push(("client-fingerprint".into(), fp));
    }
    f.push(("network".into(), network.clone()));
    if network == "ws" {
        f.push((
            "__ws_path".into(),
            q(&p.get("path").cloned().unwrap_or_else(|| "/".into())),
        ));
        f.push((
            "__ws_host".into(),
            q(&p.get("host").cloned().unwrap_or_default()),
        ));
    }
    Ok(SubNode { fields: f })
}

fn parse_ssh(rest: &str) -> Result<SubNode> {
    // ssh://user[:pass]@host:port#name
    let (userinfo, host, port, _p, name) = split_main(rest)?;
    let (username, password) = match userinfo.split_once(':') {
        Some((u, p)) => (u.to_string(), Some(p.to_string())),
        None => (userinfo, None),
    };
    let mut f = vec![
        ("name".into(), q(&name)),
        ("type".into(), "ssh".into()),
        ("server".into(), host),
        ("port".into(), port),
        ("username".into(), q(&username)),
    ];
    if let Some(pw) = password {
        f.push(("password".into(), q(&pw)));
    }
    Ok(SubNode { fields: f })
}

fn parse_anytls(rest: &str) -> Result<SubNode> {
    // anytls://password@host:port?sni=x&insecure=1&udp=1&fp=chrome#name
    let (password, host, port, p, name) = split_main(rest)?;
    let mut f = vec![
        ("name".into(), q(&name)),
        ("type".into(), "anytls".into()),
        ("server".into(), host),
        ("port".into(), port),
        ("password".into(), q(&password)),
    ];
    if let Some(sni) = p.get("sni").or_else(|| p.get("peer")) {
        f.push(("sni".into(), sni.clone()));
    }
    let insecure = p
        .get("insecure")
        .or_else(|| p.get("allowInsecure"))
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if insecure {
        f.push(("skip-cert-verify".into(), "true".into()));
    }
    if p.get("udp")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        f.push(("udp".into(), "true".into()));
    }
    if let Some(fp) = p.get("fp").or_else(|| p.get("client-fingerprint")) {
        f.push(("client-fingerprint".into(), q(fp)));
    }
    Ok(SubNode { fields: f })
}

fn parse_brook(rest: &str) -> Result<SubNode> {
    // 两种形式：
    // 1. 官方 BrookLink：brook://server?server=host:port&password=xxx&udpovertcp=true
    // 2. 常见订阅转换：brook://password@host:port?udp=1#name
    let has_at = rest.split(['?', '#']).next().unwrap_or(rest).contains('@');
    if !has_at {
        // 官方形式
        let (body, name) = match rest.split_once('#') {
            Some((b, n)) => (b, urldecode(n)),
            None => (rest, String::new()),
        };
        let (_kind, qs) = body.split_once('?').unwrap_or((body, ""));
        let p: HashMap<String, String> = qs
            .split('&')
            .filter_map(|kv| {
                kv.split_once('=')
                    .map(|(k, v)| (k.to_string(), urldecode(v)))
            })
            .collect();
        let server = p
            .get("server")
            .ok_or(Error::Config("brook 链接缺少 server 参数".into()))?;
        let password = p
            .get("password")
            .ok_or(Error::Config("brook 链接缺少 password 参数".into()))?;
        let (host, port) = server
            .rsplit_once(':')
            .ok_or(Error::Config("brook server 缺少端口".into()))?;
        let udp = p
            .get("udpovertcp")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let mut f = vec![
            ("name".into(), q(&name)),
            ("type".into(), "brook".into()),
            ("server".into(), host.to_string()),
            ("port".into(), port.to_string()),
            ("password".into(), q(password)),
        ];
        if udp {
            f.push(("udp".into(), "true".into()));
        }
        return Ok(SubNode { fields: f });
    }
    // password@host:port 形式
    let (password, host, port, p, name) = split_main(rest)?;
    let udp = p
        .get("udp")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let mut f = vec![
        ("name".into(), q(&name)),
        ("type".into(), "brook".into()),
        ("server".into(), host),
        ("port".into(), port),
        ("password".into(), q(&password)),
    ];
    if udp {
        f.push(("udp".into(), "true".into()));
    }
    Ok(SubNode { fields: f })
}

fn parse_mieru(rest: &str) -> Result<SubNode> {
    // mieru://username:password@host:port?transport=tcp#name
    let (userinfo, host, port, p, name) = split_main(rest)?;
    let (username, password) = userinfo
        .split_once(':')
        .ok_or(Error::Config("mieru 链接缺少 username:password".into()))?;
    let transport = p.get("transport").cloned().unwrap_or_else(|| "tcp".into());
    if transport != "tcp" {
        return Err(Error::Config("mieru 仅支持 tcp 传输".into()));
    }
    Ok(SubNode {
        fields: vec![
            ("name".into(), q(&name)),
            ("type".into(), "mieru".into()),
            ("server".into(), host),
            ("port".into(), port),
            ("username".into(), q(&urldecode(username))),
            ("password".into(), q(&urldecode(password))),
        ],
    })
}

fn parse_snell(rest: &str) -> Result<SubNode> {
    // snell://psk@host:port?version=4&obfs=http&host=bing.com&udp=1#name
    let (psk, host, port, p, name) = split_main(rest)?;
    let mut f = vec![
        ("name".into(), q(&name)),
        ("type".into(), "snell".into()),
        ("server".into(), host),
        ("port".into(), port),
        ("psk".into(), q(&psk)),
    ];
    let version = p
        .get("version")
        .or_else(|| p.get("v"))
        .cloned()
        .unwrap_or_else(|| "4".into());
    f.push(("version".into(), version));
    if let Some(obfs) = p.get("obfs").or_else(|| p.get("mode")) {
        f.push(("obfs".into(), q(obfs)));
    }
    if let Some(h) = p.get("host").or_else(|| p.get("obfs-host")) {
        f.push(("host".into(), q(h)));
    }
    if p.get("udp")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        f.push(("udp".into(), "true".into()));
    }
    Ok(SubNode { fields: f })
}

fn decode_base64_flexible(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let clean = s.trim().replace('-', "+").replace('_', "/");
    let pad = match clean.len() % 4 {
        2 => "==",
        3 => "=",
        _ => "",
    };
    let with_pad = format!("{clean}{pad}");
    base64::engine::general_purpose::STANDARD
        .decode(&with_pad)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim()))
        .ok()
}

fn parse_ssr(rest: &str) -> Result<SubNode> {
    // ssr://base64(host:port:protocol:method:obfs:base64pass/?obfsparam=...&protoparam=...&remarks=...&group=...)
    let decoded_bytes = decode_base64_flexible(rest)
        .ok_or_else(|| Error::Config("ssr 链接 Base64 解码失败".into()))?;
    let decoded = String::from_utf8(decoded_bytes)
        .map_err(|e| Error::Config(format!("ssr 链接非 UTF-8: {e}")))?;

    let (main_part, query_part) = match decoded.split_once("/?") {
        Some((m, q)) => (m, Some(q)),
        None => (decoded.as_str(), None),
    };

    let parts: Vec<&str> = main_part.split(':').collect();
    if parts.len() < 6 {
        return Err(Error::Config("ssr 链接格式错误：字段不足 6 项".into()));
    }

    let base64pass = parts[parts.len() - 1];
    let obfs = parts[parts.len() - 2];
    let method = parts[parts.len() - 3];
    let protocol = parts[parts.len() - 4];
    let port = parts[parts.len() - 5];
    let host = parts[..parts.len() - 5].join(":");

    let password = decode_base64_flexible(base64pass)
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| base64pass.to_string());

    let mut params = HashMap::new();
    if let Some(q) = query_part {
        for pair in q.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                params.insert(k.to_ascii_lowercase(), v);
            }
        }
    }

    let name = params
        .get("remarks")
        .and_then(|r| decode_base64_flexible(r))
        .and_then(|b| String::from_utf8(b).ok())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("ssr-{}:{}", host, port));

    let obfs_param = params
        .get("obfsparam")
        .and_then(|r| decode_base64_flexible(r))
        .and_then(|b| String::from_utf8(b).ok())
        .filter(|s| !s.is_empty());

    let proto_param = params
        .get("protoparam")
        .and_then(|r| decode_base64_flexible(r))
        .and_then(|b| String::from_utf8(b).ok())
        .filter(|s| !s.is_empty());

    let mut f = vec![
        ("name".into(), q(&name)),
        ("type".into(), "ssr".into()),
        ("server".into(), host),
        ("port".into(), port.to_string()),
        ("password".into(), q(&password)),
        ("cipher".into(), method.to_string()),
        ("protocol".into(), protocol.to_string()),
        ("obfs".into(), obfs.to_string()),
    ];

    if let Some(op) = obfs_param {
        f.push(("obfs-param".into(), q(&op)));
    }
    if let Some(pp) = proto_param {
        f.push(("protocol-param".into(), q(&pp)));
    }
    if params.contains_key("udpport") || params.get("uot").map(|v| *v == "1").unwrap_or(false) {
        f.push(("udp".into(), "true".into()));
    }

    Ok(SubNode { fields: f })
}

fn parse_naive(rest: &str, default_tls: bool) -> Result<SubNode> {
    let (userinfo, host, port, p, name) = split_main(rest)?;
    let (username, password) = match userinfo.split_once(':') {
        Some((u, p)) => (u.to_string(), p.to_string()),
        None => (userinfo, String::new()),
    };
    let tls = p
        .get("tls")
        .map(|v| v != "0" && v != "false")
        .unwrap_or(default_tls);
    let sni = p
        .get("sni")
        .or_else(|| p.get("peer"))
        .or_else(|| p.get("servername"))
        .cloned();
    let insecure = p
        .get("insecure")
        .map(|v| v == "1" || v == "true")
        .or_else(|| p.get("allowInsecure").map(|v| v == "1" || v == "true"))
        .unwrap_or(false);
    let fp = p.get("fp").or_else(|| p.get("fingerprint")).cloned();
    let udp = p
        .get("udp")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);

    let mut fields = vec![
        ("name".into(), q(&name)),
        ("type".into(), "naive".into()),
        ("server".into(), host),
        ("port".into(), port),
        ("username".into(), q(&username)),
        ("password".into(), q(&password)),
    ];
    if !tls {
        fields.push(("tls".into(), "false".into()));
    }
    if let Some(s) = sni {
        fields.push(("sni".into(), q(&s)));
    }
    if insecure {
        fields.push(("skip-cert-verify".into(), "true".into()));
    }
    if let Some(f) = fp {
        fields.push(("client-fingerprint".into(), q(&f)));
    }
    if udp {
        fields.push(("udp".into(), "true".into()));
    }
    Ok(SubNode { fields })
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
    let (encoded, hostport) = main
        .rsplit_once('@')
        .ok_or(Error::Config("ss 缺少 @".into()))?;
    // SIP002: plugin=shadow-tls;mode=v3;host=xx;password=yy（urlencoded）
    let mut stls: Option<Vec<(String, String)>> = None;
    for kv in qs.split('&') {
        let Some((k, v)) = kv.split_once('=') else {
            continue;
        };
        if urldecode(k) != "plugin" {
            continue;
        }
        let p = urldecode(v);
        let mut parts = p.split(';');
        let name = parts.next().unwrap_or_default().to_string();
        let opts: Vec<(String, String)> = parts
            .filter_map(|o| {
                o.split_once('=')
                    .map(|(a, b)| (a.to_string(), b.to_string()))
            })
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
    let (host, port) = hostport
        .rsplit_once(':')
        .ok_or(Error::Config("ss 缺端口".into()))?;
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
                // 只保留本内核支持的传输（tcp/ws/grpc）；无 network 字段的协议（ss/trojan/anytls）直接接受
                let net_ok = match n.fields.iter().find(|(k, _)| k == "network") {
                    None => true,
                    Some((_, v)) => matches!(v.trim_matches('"'), "tcp" | "ws" | "grpc"),
                };
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
    out.push_str(&format!(
        "mixed-port: {port}\nmode: rule\nlog-level: info\n\nproxies:\n"
    ));
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
    out.push_str(
        &names
            .iter()
            .map(|n| format!("\"{n}\""))
            .collect::<Vec<_>>()
            .join(", "),
    );
    out.push_str("]\n");
    out.push_str("\nrules:\n  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve\n  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve\n  - MATCH,PROXY\n");
    out
}

/// 解析 proxy-provider 载荷（支持 Clash YAML proxies 段，或 Base64 / URI 列表）
pub fn parse_provider_proxies(
    text: &str,
    filter: Option<&str>,
) -> std::result::Result<Vec<vp_config::ProxyCfg>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(Vec::new());
    }

    // 1. 尝试直接作为 YAML 反序列化
    let mut proxies: Vec<vp_config::ProxyCfg> = if let Ok(doc) =
        serde_yaml::from_str::<std::collections::HashMap<String, Vec<vp_config::ProxyCfg>>>(text)
    {
        doc.get("proxies").cloned().unwrap_or_default()
    } else if let Ok(list) = serde_yaml::from_str::<Vec<vp_config::ProxyCfg>>(text) {
        list
    } else {
        // 2. 尝试作为订阅节点链接（Base64 或 raw URI 列表）解析
        let nodes = parse_subscription(text);
        if nodes.is_empty() {
            return Err("无法解析为 YAML 节点列表或订阅链接".into());
        }
        let mut y = String::from("proxies:\n");
        for n in &nodes {
            y.push_str(&n.to_yaml());
        }
        let doc: std::collections::HashMap<String, Vec<vp_config::ProxyCfg>> =
            serde_yaml::from_str(&y).map_err(|e| format!("节点转换为配置失败: {e}"))?;
        doc.get("proxies").cloned().unwrap_or_default()
    };

    // 3. 正则过滤 (filter)
    if let Some(f) = filter {
        let trimmed = f.trim();
        if !trimmed.is_empty() {
            let re =
                regex::Regex::new(trimmed).map_err(|e| format!("无效的 filter 正则表达式: {e}"))?;
            proxies.retain(|p| re.is_match(&p.name));
        }
    }

    Ok(proxies)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anytls_uri() {
        let n = parse_uri("anytls://pw123@a.com:8388?sni=a.com&insecure=1&udp=1&fp=chrome#at1")
            .unwrap();
        assert_eq!(n.name(), "at1");
        let y = n.to_yaml();
        assert!(y.contains("type: anytls"), "{y}");
        assert!(y.contains("password: \"pw123\""));
        assert!(y.contains("sni: a.com"));
        assert!(y.contains("skip-cert-verify: true"));
        assert!(y.contains("udp: true"));
        assert!(y.contains("client-fingerprint: \"chrome\""));
        // 订阅打包不被 network 过滤丢弃
        let nodes = parse_subscription("anytls://pw@a.com:443#n1");
        assert_eq!(nodes.len(), 1);
    }

    #[test]
    fn brook_uri() {
        // 常见形式：brook://password@host:port?udp=1#name
        let n = parse_uri("brook://pw123@b.com:9999?udp=1#bk1").unwrap();
        assert_eq!(n.name(), "bk1");
        let y = n.to_yaml();
        assert!(y.contains("type: brook"), "{y}");
        assert!(y.contains("password: \"pw123\""));
        assert!(y.contains("udp: true"));
        // 官方 BrookLink 形式：brook://server?server=host:port&password=xxx
        let n =
            parse_uri("brook://server?server=b.com%3A9999&password=pw456&udpovertcp=true").unwrap();
        let y = n.to_yaml();
        assert!(y.contains("server: b.com"), "{y}");
        assert!(y.contains("port: 9999"), "{y}");
        assert!(y.contains("password: \"pw456\""), "{y}");
        assert!(y.contains("udp: true"), "{y}");
        // 订阅打包
        let nodes = parse_subscription("brook://pw@b.com:443#n1");
        assert_eq!(nodes.len(), 1);
    }

    #[test]
    fn mieru_encoded_credentials() {
        let n = parse_uri("mieru://alice:p%40ss%3A%22word@m.com:8964#encoded").unwrap();
        let yaml = format!("proxies:\n{}", n.to_yaml());
        let value: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(
            value["proxies"][0]["password"].as_str(),
            Some("p@ss:\"word")
        );
        assert!(parse_uri("未知链接未知链接未知链接未知链接未知链接").is_err());
    }

    #[test]
    fn mieru_uri() {
        let n = parse_uri("mieru://alice:pw123@m.com:8964?transport=tcp#mu1").unwrap();
        assert_eq!(n.name(), "mu1");
        let y = n.to_yaml();
        assert!(y.contains("type: mieru"), "{y}");
        assert!(y.contains("username: \"alice\""), "{y}");
        assert!(y.contains(&format!("password: {}", q("pw123"))), "{y}");
        assert!(parse_uri("mieru://alice:pw@m.com:1?transport=udp#x").is_err());
        // 订阅打包
        let nodes = parse_subscription("mieru://alice:pw@m.com:443#n1");
        assert_eq!(nodes.len(), 1);
    }

    #[test]
    fn snell_uri() {
        let n = parse_uri("snell://psk123@s.com:8388?version=4&obfs=http&host=bing.com&udp=1#sn1")
            .unwrap();
        assert_eq!(n.name(), "sn1");
        let y = n.to_yaml();
        assert!(y.contains("type: snell"), "{y}");
        assert!(y.contains("psk: \"psk123\""), "{y}");
        assert!(y.contains("version: 4"), "{y}");
        assert!(y.contains("obfs: \"http\""), "{y}");
        assert!(y.contains("host: \"bing.com\""), "{y}");
        assert!(y.contains("udp: true"), "{y}");

        let nodes = parse_subscription("snell://psk@s.com:443#n1");
        assert_eq!(nodes.len(), 1);
    }

    #[test]
    fn ssr_uri() {
        let uri = "ssr://MTI3LjAuMC4xOjg4ODg6YXV0aF9hZXMxMjhfbWQ1OmFlcy0xMjgtY2ZiOmh0dHBfc2ltcGxlOmNHRnpjM2R2Y21ReE1qTT0vP29iZnNwYXJhbT1kM2QzTG1KcGJtY3VZMjl0JnJlbWFya3M9VTFOU0xVNXZaR1U9";
        let n = parse_uri(uri).unwrap();
        assert_eq!(n.name(), "SSR-Node");
        let y = n.to_yaml();
        assert!(y.contains("type: ssr"), "{y}");
        assert!(y.contains("server: 127.0.0.1"), "{y}");
        assert!(y.contains("port: 8888"), "{y}");
        assert!(y.contains("password: \"password123\""), "{y}");
        assert!(y.contains("cipher: aes-128-cfb"), "{y}");
        assert!(y.contains("protocol: auth_aes128_md5"), "{y}");
        assert!(y.contains("obfs: http_simple"), "{y}");
        assert!(y.contains("obfs-param: \"www.bing.com\""), "{y}");

        let nodes = parse_subscription(uri);
        assert_eq!(nodes.len(), 1);
    }

    #[test]
    fn naive_uri() {
        let n = parse_uri(
            "naive+https://bob:nvpw123@n.com:443?sni=n.com&insecure=1&udp=1&fp=chrome#nv1",
        )
        .unwrap();
        assert_eq!(n.name(), "nv1");
        let y = n.to_yaml();
        assert!(y.contains("type: naive"), "{y}");
        assert!(y.contains("username: \"bob\""), "{y}");
        assert!(y.contains("password: \"nvpw123\""), "{y}");
        assert!(y.contains("sni: \"n.com\""), "{y}");
        assert!(y.contains("skip-cert-verify: true"), "{y}");
        assert!(y.contains("udp: true"), "{y}");
        assert!(y.contains("client-fingerprint: \"chrome\""), "{y}");

        // naive+http://
        let n2 = parse_uri("naive+http://user:pass@127.0.0.1:8080#nv2").unwrap();
        assert_eq!(n2.name(), "nv2");
        let y2 = n2.to_yaml();
        assert!(y2.contains("tls: false"), "{y2}");

        // 订阅打包
        let nodes = parse_subscription("naive+https://u:p@n.com:443#n1");
        assert_eq!(nodes.len(), 1);
    }

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
    fn vless_reality_uri() {
        let uri = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?security=reality&sni=www.apple.com&fp=chrome&pbk=1111222233334444555566667777888899990000111&sid=0123456789abcdef&spx=%2F#reality-node";
        let n = parse_uri(uri).unwrap();
        assert_eq!(n.name(), "reality-node");
        let y = n.to_yaml();
        assert!(y.contains("type: vless"), "{y}");
        assert!(y.contains("tls: true"), "{y}");
        assert!(y.contains("servername: www.apple.com"), "{y}");
        assert!(y.contains("client-fingerprint: chrome"), "{y}");
        assert!(y.contains("reality-opts:"), "{y}");
        assert!(
            y.contains("public-key: \"1111222233334444555566667777888899990000111\""),
            "{y}"
        );
        assert!(y.contains("short-id: \"0123456789abcdef\""), "{y}");
        assert!(y.contains("spider-x: \"/\""), "{y}");

        // 反序列化为 ProxyCfg 确认格式完全兼容
        let doc = format!("proxies:\n{y}");
        let mut map: std::collections::HashMap<String, Vec<vp_config::ProxyCfg>> =
            serde_yaml::from_str(&doc).unwrap();
        let cfg = map.remove("proxies").unwrap().pop().unwrap();
        match cfg.kind {
            vp_config::ProxyKind::Vless(v) => {
                let ro = v.reality_opts.unwrap();
                assert_eq!(ro.public_key, "1111222233334444555566667777888899990000111");
                assert_eq!(ro.short_id.as_deref(), Some("0123456789abcdef"));
                assert_eq!(ro.spider_x.as_deref(), Some("/"));
            }
            _ => panic!("Expected VLESS kind"),
        }
    }

    #[test]
    fn trojan_reality_uri() {
        let uri = "trojan://password123@1.2.3.4:443?security=reality&sni=www.apple.com&fp=chrome&pbk=aabbccdd11223344&sid=1234#tr-reality";
        let n = parse_uri(uri).unwrap();
        assert_eq!(n.name(), "tr-reality");
        let y = n.to_yaml();
        assert!(y.contains("type: trojan"), "{y}");
        assert!(y.contains("tls: true"), "{y}");
        assert!(y.contains("reality-opts:"), "{y}");
        assert!(y.contains("public-key: \"aabbccdd11223344\""), "{y}");
        assert!(y.contains("short-id: \"1234\""), "{y}");

        let doc = format!("proxies:\n{y}");
        let mut map: std::collections::HashMap<String, Vec<vp_config::ProxyCfg>> =
            serde_yaml::from_str(&doc).unwrap();
        let cfg = map.remove("proxies").unwrap().pop().unwrap();
        match cfg.kind {
            vp_config::ProxyKind::Trojan(t) => {
                let ro = t.reality_opts.unwrap();
                assert_eq!(ro.public_key, "aabbccdd11223344");
                assert_eq!(ro.short_id.as_deref(), Some("1234"));
            }
            _ => panic!("Expected Trojan kind"),
        }
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

    #[test]
    fn proxy_provider_payload_parsing() {
        // 1. Clash YAML 格式 + filter 过滤
        let yaml = r#"
proxies:
  - name: "HK-01"
    type: ss
    server: 1.1.1.1
    port: 8388
    cipher: aes-128-gcm
    password: pw1
  - name: "US-01"
    type: ss
    server: 2.2.2.2
    port: 8388
    cipher: aes-128-gcm
    password: pw2
"#;
        let all = parse_provider_proxies(yaml, None).unwrap();
        assert_eq!(all.len(), 2);

        let filtered = parse_provider_proxies(yaml, Some("^HK")).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "HK-01");

        // 2. Base64 订阅链接格式
        use base64::Engine;
        let raw = "trojan://pw@h.com:443#JP-01\ntrojan://pw@h2.com:443#SG-01\n";
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        let from_b64 = parse_provider_proxies(&b64, Some("SG")).unwrap();
        assert_eq!(from_b64.len(), 1);
        assert_eq!(from_b64[0].name, "SG-01");
    }
}

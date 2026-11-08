//! vp-config：配置加载与校验。
//!
//! 同一套 Clash 兼容 schema，两种前端：
//! - YAML（`.yaml` / `.yml`）
//! - JSON / JSON5（`.json`，容忍注释）

pub mod convert;
pub mod ir;
pub mod model;
pub mod validate;

pub use model::*;

use vp_common::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Yaml,
    Json,
    Dsl,
}

impl Format {
    pub fn from_path(path: &str) -> Format {
        let lower = path.to_ascii_lowercase();
        if lower.ends_with(".yaml") || lower.ends_with(".yml") {
            Format::Yaml
        } else if lower.ends_with(".vp") {
            Format::Dsl
        } else {
            Format::Json
        }
    }
}

/// 解析配置文本。格式由参数指定。
pub fn parse(text: &str, fmt: Format) -> Result<Config> {
    let mut json_value: serde_json::Value = match fmt {
        Format::Yaml => {
            let v: serde_yaml::Value = serde_yaml::from_str(text)
                .map_err(|e| Error::Config(format!("YAML 解析失败: {e}")))?;
            convert::yaml_to_json(v).map_err(Error::Config)?
        }
        Format::Json => {
            json5::from_str(text).map_err(|e| Error::Config(format!("JSON 解析失败: {e}")))?
        }
        Format::Dsl => {
            return Err(Error::Config(
                ".vp DSL 脚本请使用 vp_dsl::parse 解析为统一 VP IR".into(),
            ));
        }
    };
    sanitize_proxy_aliases(&mut json_value);
    coerce_numeric_strings(&mut json_value);
    use serde::de::IntoDeserializer;
    let deserializer = json_value.into_deserializer();
    let cfg: Config = serde_path_to_error::deserialize(deserializer)
        .map_err(|e| Error::Config(format!("配置结构错误: {}", e)))?;
    Ok(cfg)
}

/// 归一化代理节点中的同义别名字段（如 servername 与 sni、skip-cert-verify 与 allowInsecure 等），
/// 杜绝因同时存在多个别名键导致 serde 反序列化时报 duplicate field 错误。
fn sanitize_proxy_aliases(val: &mut serde_json::Value) {
    if let Some(proxies) = val.get_mut("proxies").and_then(|p| p.as_array_mut()) {
        for p in proxies {
            if let Some(obj) = p.as_object_mut() {
                // 1. server_name / servername / sni / server-name 全部移除，取首个有效值
                let s1 = obj.remove("server_name");
                let s2 = obj.remove("servername");
                let s3 = obj.remove("server-name");
                let s4 = obj.remove("sni");
                if let Some(s) = s1.or(s2).or(s3).or(s4) {
                    obj.insert("server_name".into(), s);
                }

                // 2. skip-cert-verify / skip_cert_verify / allowInsecure / allow_insecure / insecure
                let k1 = obj.remove("skip_cert_verify");
                let k2 = obj.remove("skip-cert-verify");
                let k3 = obj.remove("allowInsecure");
                let k4 = obj.remove("allow_insecure");
                let k5 = obj.remove("insecure");
                if let Some(s) = k1.or(k2).or(k3).or(k4).or(k5) {
                    obj.insert("skip_cert_verify".into(), s);
                }

                // 3. client-fingerprint / client_fingerprint / fp
                let f1 = obj.remove("client_fingerprint");
                let f2 = obj.remove("client-fingerprint");
                let f3 = obj.remove("fp");
                if let Some(f) = f1.or(f2).or(f3) {
                    obj.insert("client_fingerprint".into(), f);
                }

                // 4. alter_id / alterId
                let a1 = obj.remove("alter_id");
                let a2 = obj.remove("alterId");
                if let Some(a) = a1.or(a2) {
                    obj.insert("alter_id".into(), a);
                }

                // 5. ports / mport (如 Hysteria2 端口跳跃范围)
                let p1 = obj.remove("ports");
                let p2 = obj.remove("mport");
                if let Some(p) = p1.or(p2) {
                    obj.insert("ports".into(), p);
                }

                // 6. up / up-mbps / up_mbps
                let u1 = obj.remove("up");
                let u2 = obj.remove("up-mbps");
                let u3 = obj.remove("up_mbps");
                if let Some(u) = u1.or(u2).or(u3) {
                    obj.insert("up".into(), u);
                }

                // 7. down / down-mbps / down_mbps
                let d1 = obj.remove("down");
                let d2 = obj.remove("down-mbps");
                let d3 = obj.remove("down_mbps");
                if let Some(d) = d1.or(d2).or(d3) {
                    obj.insert("down".into(), d);
                }

                // 8. obfs / obfs-type / obfs_type
                let o1 = obj.remove("obfs");
                let o2 = obj.remove("obfs-type");
                let o3 = obj.remove("obfs_type");
                if let Some(s) = o1.or(o2).or(o3) {
                    obj.insert("obfs".into(), s);
                }

                // 9. auth-str / auth_str（hysteria1，真实订阅两键并存即 serde duplicate）
                let au1 = obj.remove("auth-str");
                let au2 = obj.remove("auth_str");
                if let Some(s) = au1.or(au2) {
                    obj.insert("auth_str".into(), s);
                }

                // 10. udp-relay-mode / udp_relay_mode（tuic，真实订阅两键并存）
                let ur1 = obj.remove("udp-relay-mode");
                let ur2 = obj.remove("udp_relay_mode");
                if let Some(s) = ur1.or(ur2) {
                    obj.insert("udp_relay_mode".into(), s);
                }

                // 11. V2Ray 原生/分享链接平铺字段 → Clash 结构化字段
                //     （2969 个 vmess 用 id/aid/net/scy，7845 个 vless 用 pbk/sid/security）
                normalize_v2ray_flat_fields(obj);

                // 11b. 数据侧损坏清洗：密码为字面量 "None"（导出器 str(None) 泄漏）
                if obj.get("password").and_then(|v| v.as_str()) == Some("None") {
                    obj.remove("password");
                }

                // 12a. 删除全部 null 标量键（V2Ray JSON 常写 scy: null / sni: null；
                //      null 与缺省对 Option 等价，对非 Option 字段则消除 null 类型错误）
                strip_null_scalars(obj);

                // 12b. tls: "auto" → 按端口推断（mihomo 语义：443 才自动启用 TLS）
                if obj.get("tls").and_then(|v| v.as_str()) == Some("auto") {
                    let port = obj.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
                    obj.insert("tls".into(), serde_json::Value::Bool(port == 443));
                }
            }
        }
    }
}

/// V2Ray 原生 JSON / 分享链接展开风格字段 → Clash 结构化字段。
/// 仅在目标键不存在时填充（绝不覆盖已有结构化配置）；unknown 键 serde 会
/// 自行忽略，这里只搬有语义的。真实订阅里 vmess 57%、vless 74% 是这种形态。
fn normalize_v2ray_flat_fields(obj: &mut serde_json::Map<String, serde_json::Value>) {
    let ptype = obj
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();

    // id → uuid（vmess/vless 通用；仅当无 uuid）
    if !obj.contains_key("uuid") {
        if let Some(id) = obj.remove("id") {
            obj.insert("uuid".into(), id);
        }
    }
    // aid → alter_id（仅当无 alterId/alter_id）
    if !obj.contains_key("alterId") && !obj.contains_key("alter_id") {
        if let Some(a) = obj.remove("aid") {
            obj.insert("alter_id".into(), a);
        }
    }
    // net → network（仅当无 network）
    let flat_net = obj.remove("net");
    let has_network = obj.get("network").is_some();
    if let Some(n) = flat_net {
        if !has_network {
            obj.insert("network".into(), n);
        }
    }

    // ws 平铺 path/host → ws-opts（net/network == ws 且无 ws-opts 时）
    let net_val = obj
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if net_val == "ws" && !obj.contains_key("ws-opts") && !obj.contains_key("ws_opts") {
        let path = obj.remove("path").map(flat_to_string);
        let host = obj.remove("host").map(flat_to_string);
        if path.is_some() || host.is_some() {
            let mut ws = serde_json::Map::new();
            if let Some(p) = path {
                ws.insert("path".into(), p);
            }
            if let Some(h) = host {
                let mut headers = serde_json::Map::new();
                headers.insert("Host".into(), h);
                ws.insert("headers".into(), serde_json::Value::Object(headers));
            }
            obj.insert("ws-opts".into(), serde_json::Value::Object(ws));
        }
    }

    if ptype == "vmess" {
        // scy/security/cipher 三键归一（cipher 的 alias 是 security，两键并存即
        // serde duplicate；真实订阅 981 个节点 security 与 cipher 并存）
        let scy = obj.remove("scy");
        let security = obj.remove("security");
        if !obj.contains_key("cipher") {
            if let Some(c) = scy.or(security) {
                obj.insert("cipher".into(), c);
            }
        }
    }

    if ptype == "vless" {
        // security: "reality" → 强制开 TLS（reality 必然 TLS）
        if obj.get("security").and_then(|v| v.as_str()) == Some("reality") {
            obj.insert("tls".into(), serde_json::Value::Bool(true));
        }
        // pbk/sid → reality-opts（仅当无 reality-opts）
        if !obj.contains_key("reality-opts") && !obj.contains_key("reality_opts") {
            let pbk = obj.remove("pbk");
            let sid = obj.remove("sid");
            if pbk.is_some() || sid.is_some() {
                let mut r = serde_json::Map::new();
                if let Some(p) = pbk {
                    r.insert("public-key".into(), p);
                }
                if let Some(s) = sid {
                    r.insert("short-id".into(), s);
                }
                obj.insert("reality-opts".into(), serde_json::Value::Object(r));
            }
        }
        // serviceName → grpc-opts.grpc-service-name（仅当无 grpc-opts 且网络确为
        // grpc；真实订阅里大量 ws 节点带 serviceName 残留（订阅器导出垃圾字段），
        // 不分网络类型归并会把 ws 节点污染出假 grpc 配置）
        if !obj.contains_key("grpc-opts") && !obj.contains_key("grpc_opts") {
            let is_grpc = obj
                .get("network")
                .and_then(|v| v.as_str())
                .map(|n| n.eq_ignore_ascii_case("grpc") || n.eq_ignore_ascii_case("gun"))
                .unwrap_or(false);
            if is_grpc {
                if let Some(sn) = obj.remove("serviceName") {
                    let mut g = serde_json::Map::new();
                    g.insert("grpc-service-name".into(), sn);
                    obj.insert("grpc-opts".into(), serde_json::Value::Object(g));
                }
            }
        }
    }
}

/// 递归删除对象中值为 null 的键（V2Ray 原生 JSON 大量 null 占位字段）
fn strip_null_scalars(obj: &mut serde_json::Map<String, serde_json::Value>) {
    let null_keys: Vec<String> = obj
        .iter()
        .filter(|(_, v)| v.is_null())
        .map(|(k, _)| k.clone())
        .collect();
    for k in null_keys {
        obj.remove(&k);
    }
    for (_, v) in obj.iter_mut() {
        if let serde_json::Value::Object(inner) = v {
            strip_null_scalars(inner);
        }
    }
}

/// V2Ray 平铺字段宽容归一：host/path 在 V2Ray JSON 里常为数组，取首个字符串值
fn flat_to_string(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Array(items) => items
            .into_iter()
            .find_map(|it| match it {
                serde_json::Value::String(s) => Some(serde_json::Value::String(s)),
                _ => None,
            })
            .unwrap_or(serde_json::Value::String(String::new())),
        other => other,
    }
}

/// mihomo 解析配置是弱类型的：字符串字段写成纯数字也照样接受，机场导出的配置里很常见
/// （`username: 416479`、`password: 123456`、纯数字节点名）。serde 是强类型，遇到就整份
/// 配置报错，所以这里先把"语义上是字符串、却常被写成数字"的字段转成字符串。
/// 端口、带宽等真正的数字字段不在名单里，保持原样。
fn coerce_numeric_strings(val: &mut serde_json::Value) {
    use serde_json::Value;
    fn stringify(obj: &mut serde_json::Map<String, Value>, keys: &[&str]) {
        for key in keys {
            match obj.get_mut(*key) {
                Some(v @ Value::Number(_)) => *v = Value::String(v.to_string()),
                Some(Value::Array(items)) => {
                    for it in items.iter_mut().filter(|it| it.is_number()) {
                        *it = Value::String(it.to_string());
                    }
                }
                _ => {}
            }
        }
    }
    if let Some(proxies) = val.get_mut("proxies").and_then(|p| p.as_array_mut()) {
        for obj in proxies.iter_mut().filter_map(|p| p.as_object_mut()) {
            stringify(
                obj,
                &[
                    "name",
                    "username",
                    "password",
                    "psk",
                    "auth",
                    "auth-str",
                    "auth_str",
                    "obfs-password",
                    "obfs_password",
                ],
            );
            for key in ["reality-opts", "reality_opts"] {
                if let Some(r) = obj.get_mut(key).and_then(|r| r.as_object_mut()) {
                    stringify(r, &["short-id", "short_id", "shortId", "sid"]);
                }
            }
        }
    }
    for key in ["proxy-groups", "proxy_groups"] {
        if let Some(groups) = val.get_mut(key).and_then(|g| g.as_array_mut()) {
            for obj in groups.iter_mut().filter_map(|g| g.as_object_mut()) {
                stringify(obj, &["name", "proxies", "use", "fallback"]);
            }
        }
    }
}

/// 从文件加载（扩展名决定格式）
pub async fn load(path: &std::path::Path) -> Result<Config> {
    let text = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| Error::Config(format!("读取 {} 失败: {e}", path.display())))?;
    parse(&text, Format::from_path(&path.to_string_lossy()))
}

/// 解析 + 校验，一步到位
pub fn parse_and_validate(text: &str, fmt: Format) -> std::result::Result<Config, Vec<String>> {
    let cfg = parse(text, fmt).map_err(|e| vec![e.to_string()])?;
    match validate::validate(&cfg) {
        Ok(()) => Ok(cfg),
        Err(errs) => Err(errs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_over_tcp_mihomo_spelling() {
        let cfg = parse(
            "proxies:\n  - { name: a, type: ss, server: s, port: 1, cipher: aes-128-gcm, password: x, udp-over-tcp: true, udp-over-tcp-version: 2 }\n  - { name: b, type: ss, server: s, port: 1, cipher: aes-128-gcm, password: x }\n",
            Format::Yaml,
        )
        .unwrap();
        assert!(
            cfg.proxies[0].udp_over_tcp,
            "mihomo 写法 udp-over-tcp 不能被静默忽略"
        );
        assert_eq!(cfg.proxies[0].udp_over_tcp_version, Some(2));
        assert!(!cfg.proxies[1].udp_over_tcp);
        assert_eq!(cfg.proxies[1].udp_over_tcp_version, None);
    }

    #[test]
    fn numeric_string_fields_accepted_like_mihomo() {
        let cfg = parse(
            r#"
proxies:
  - { name: 1, type: http, server: a.com, port: 995, username: 416479, password: 123456, tls: true }
  - { name: "r", type: vless, server: b.com, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811,
      tls: true, reality-opts: { public-key: "k", short-id: 12345678 } }
proxy-groups:
  - { name: 2, type: select, proxies: [1, r] }
rules:
  - MATCH,2
"#,
            Format::Yaml,
        )
        .expect("纯数字的字符串字段应当被接受");
        assert_eq!(cfg.proxies[0].name, "1");
        match &cfg.proxies[0].kind {
            ProxyKind::Http(h) => {
                assert_eq!(h.username.as_deref(), Some("416479"));
                assert_eq!(h.password.as_deref(), Some("123456"));
            }
            other => panic!("应解析为 http，实际 {other:?}"),
        }
        match &cfg.proxies[1].kind {
            ProxyKind::Vless(v) => assert_eq!(
                v.reality_opts.as_ref().unwrap().short_id.as_deref(),
                Some("12345678")
            ),
            other => panic!("应解析为 vless，实际 {other:?}"),
        }
        assert_eq!(cfg.proxy_groups[0].name, "2");
        assert_eq!(cfg.proxy_groups[0].proxies, vec!["1", "r"]);
    }

    const SAMPLE_YAML: &str = r#"
mixed-port: 7890
allow-lan: true
mode: rule
log-level: debug
external-controller: 127.0.0.1:9090
secret: "abc"
dns:
  enable: true
  nameserver:
    - 223.5.5.5
    - https://doh.pub/dns-query
proxies:
  - name: "ss1"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: passw0rd
    udp: true
  - name: "vm1"
    type: vmess
    server: v.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: auto
    tls: true
    servername: v.example.com
    client-fingerprint: chrome
    network: ws
    ws-opts:
      path: /path
      headers:
        Host: v.example.com
  - name: "vl1"
    type: vless
    server: v2.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    flow: xtls-rprx-vision
    tls: true
    servername: www.apple.com
    client-fingerprint: chrome
    reality-opts:
      public-key: "1111222233334444555566667777888899990000111"
      short-id: "0123456789abcdef"
      spider-x: "/"
    network: tcp
  - name: "tr1"
    type: trojan
    server: t.example.com
    port: 443
    password: pw123
    sni: t.example.com
    skip-cert-verify: true
  - name: "at1"
    type: anytls
    server: a.example.com
    port: 443
    password: pw456
    sni: a.example.com
    client-fingerprint: chrome
    udp: true
  - name: "ssh1"
    type: ssh
    server: s.example.com
    port: 22
    username: root
    password: pw789
  - name: "bk1"
    type: brook
    server: b.example.com
    port: 9999
    password: bkpw
    udp: true
  - name: "mu1"
    type: mieru
    server: m.example.com
    port: 8964
    username: alice
    password: mupw
  - name: "sn1"
    type: snell
    server: sn.example.com
    port: 1234
    psk: secretpsk
    version: 4
    obfs-opts:
      mode: http
      host: www.bing.com
    udp: true
  - name: "nv1"
    type: naive
    server: n.example.com
    port: 443
    username: bob
    password: nvpw
    sni: n.example.com
    client-fingerprint: chrome
    udp: true
  - name: "sk1"
    type: socks5
    server: 127.0.0.1
    port: 1080
  - name: "ht1"
    type: http
    server: 127.0.0.1
    port: 8080
    username: u
    password: p
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - AUTO
      - ss1
  - name: AUTO
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    proxies:
      - vm1
      - vl1
      - tr1
rules:
  - DOMAIN-SUFFIX,google.com,PROXY
  - DOMAIN-KEYWORD,github,PROXY
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
sub-rules:
  sub1:
    - MATCH,DIRECT
"#;

    #[test]
    fn parse_yaml_full() {
        let cfg = parse(SAMPLE_YAML, Format::Yaml).unwrap();
        assert_eq!(cfg.mixed_port, Some(7890));
        assert!(cfg.allow_lan);
        assert_eq!(cfg.mode, Mode::Rule);
        assert_eq!(cfg.proxies.len(), 12);
        assert_eq!(cfg.proxy_groups.len(), 2);
        assert_eq!(cfg.rules.len(), 5);
        assert!(validate::validate(&cfg).is_ok());

        let snell = cfg.proxies.iter().find(|p| p.name == "sn1").unwrap();
        match &snell.kind {
            ProxyKind::Snell(s) => {
                assert_eq!(s.server, "sn.example.com");
                assert_eq!(s.port, 1234);
                assert_eq!(s.psk, "secretpsk");
                assert_eq!(s.version, 4);
                assert_eq!(s.obfs_opts.as_ref().unwrap().mode.as_deref(), Some("http"));
                assert_eq!(
                    s.obfs_opts.as_ref().unwrap().host.as_deref(),
                    Some("www.bing.com")
                );
                assert!(s.udp);
            }
            other => panic!("unexpected {other:?}"),
        }

        match &cfg.proxies[1].kind {
            ProxyKind::Vmess(v) => {
                assert_eq!(v.uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
                assert_eq!(v.alter_id, 0);
                assert!(v.tls);
                assert_eq!(v.network.as_deref(), Some("ws"));
                assert_eq!(v.client_fingerprint.as_deref(), Some("chrome"));
                assert_eq!(v.ws_opts.as_ref().unwrap().path.as_deref(), Some("/path"));
                assert_eq!(
                    v.ws_opts.as_ref().unwrap().headers.as_ref().unwrap()["Host"],
                    "v.example.com"
                );
            }
            other => panic!("unexpected {other:?}"),
        }
        match &cfg.proxies[3].kind {
            ProxyKind::Trojan(t) => {
                assert_eq!(t.password, "pw123");
                assert_eq!(t.server_name.as_deref(), Some("t.example.com"));
                assert!(t.skip_cert_verify);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(cfg.proxy_groups[1].kind, GroupKind::UrlTest));
        match &cfg.proxies[5].kind {
            ProxyKind::Ssh(sh) => {
                assert_eq!(sh.username, "root");
                assert_eq!(sh.password.as_deref(), Some("pw789"));
            }
            other => panic!("unexpected {other:?}"),
        }
        match &cfg.proxies[6].kind {
            ProxyKind::Brook(b) => {
                assert_eq!(b.password, "bkpw");
                assert!(b.udp);
            }
            other => panic!("unexpected {other:?}"),
        }
        match &cfg.proxies[7].kind {
            ProxyKind::Mieru(m) => {
                assert_eq!(m.username, "alice");
                assert_eq!(m.password, "mupw");
            }
            other => panic!("unexpected {other:?}"),
        }
        match &cfg.proxies[4].kind {
            ProxyKind::Anytls(a) => {
                assert_eq!(a.password, "pw456");
                assert_eq!(a.server_name.as_deref(), Some("a.example.com"));
                assert_eq!(a.client_fingerprint.as_deref(), Some("chrome"));
                assert!(a.udp);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn json_frontend_same_schema() {
        // 同构 JSON（含注释），字段语义一致
        let json = r#"
{
  // 双格式支持
  "mixed-port": 7891,
  "proxies": [
    {"name": "a", "type": "ss", "server": "1.1.1.1", "port": 8388,
     "cipher": "chacha20-ietf-poly1305", "password": "p"}
  ],
  "proxy-groups": [{"name": "G", "type": "select", "proxies": ["a"]}],
  "rules": ["MATCH,G"]
}
"#;
        let cfg = parse(json, Format::Json).unwrap();
        assert_eq!(cfg.mixed_port, Some(7891));
        assert_eq!(cfg.proxies.len(), 1);
        assert!(validate::validate(&cfg).is_ok());
    }

    #[test]
    fn yaml_aliases_kebab_snake() {
        let y = "port: 1080\nsocks-port: 1081\nredir-port: 1082\nrules: ['MATCH,DIRECT']\n";
        let cfg = parse(y, Format::Yaml).unwrap();
        assert_eq!(cfg.port, Some(1080));
        assert_eq!(cfg.socks_port, Some(1081));
        assert_eq!(cfg.redir_port, Some(1082));
    }

    #[test]
    fn error_has_field_path() {
        // 缺 password
        let y =
            "proxies:\n  - name: a\n    type: ss\n    server: x\n    port: 1\n    cipher: aes\n";
        let err = parse(y, Format::Yaml).unwrap_err();
        assert!(err.to_string().contains("password"), "{err}");
    }

    #[test]
    fn test_duplicate_alias_keys_in_proxy_handled_gracefully() {
        let yaml = r#"
mixed-port: 7890
proxies:
  - name: "dup_vless"
    type: vless
    server: 1.1.1.1
    port: 443
    uuid: "d9d939c9-1a6b-47d1-80d0-4bf008fee7ff"
    tls: true
    server_name: "test.com"
    servername: "test.com"
    sni: "test.com"
    skip-cert-verify: true
    skip_cert_verify: true
"#;
        let cfg = parse(yaml, Format::Yaml)
            .expect("同义别名字段并存时应当优雅去重，不能报 duplicate field");
        assert_eq!(cfg.proxies.len(), 1);
        match &cfg.proxies[0].kind {
            ProxyKind::Vless(v) => {
                assert_eq!(v.server_name.as_deref(), Some("test.com"));
                assert!(v.skip_cert_verify);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn test_hysteria2_and_tuic_sni_alias_retained() {
        let yaml = r#"
mixed-port: 7890
proxies:
  - name: "hy2-node"
    type: hysteria2
    server: 52.1.2.3
    port: 443
    password: "secretpassword"
    sni: "www.bing.com"
  - name: "tuic-node"
    type: tuic
    server: 52.1.2.4
    port: 443
    uuid: "d9d939c9-1a6b-47d1-80d0-4bf008fee7ff"
    password: "tuicpassword"
    servername: "www.microsoft.com"
"#;
        let cfg = parse(yaml, Format::Yaml).expect("hy2 与 tuic 别名解析应当成功");
        assert_eq!(cfg.proxies.len(), 2);
        match &cfg.proxies[0].kind {
            ProxyKind::Hysteria2(h) => {
                assert_eq!(
                    h.sni.as_deref(),
                    Some("www.bing.com"),
                    "Hysteria2 sni 字段必须正确保留，不可被别名清洗阶段清除"
                );
            }
            other => panic!("unexpected {other:?}"),
        }
        match &cfg.proxies[1].kind {
            ProxyKind::Tuic(t) => {
                assert_eq!(
                    t.sni.as_deref(),
                    Some("www.microsoft.com"),
                    "Tuic servername 字段必须正确解析为 sni"
                );
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn test_hysteria2_ports_and_mport_duplicate_alias() {
        let json = r#"
{
  "mixed-port": 7890,
  "proxies": [
    {
      "name": "hy2-ports",
      "type": "hysteria2",
      "server": "203.0.113.10",
      "port": 20000,
      "password": "pwd",
      "mport": "20000-50000",
      "ports": "20000-50000",
      "up": "100 Mbps",
      "up-mbps": 100,
      "down": "200 Mbps",
      "down-mbps": 200
    }
  ]
}
"#;
        let cfg = parse(json, Format::Json).expect("mport 与 ports 共存应被正确去重");
        assert_eq!(cfg.proxies.len(), 1);
        match &cfg.proxies[0].kind {
            ProxyKind::Hysteria2(h) => {
                assert_eq!(h.ports.as_deref(), Some("20000-50000"));
                assert_eq!(h.up, Some(100));
                assert_eq!(h.down, Some(200));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn defaults() {
        let cfg = parse("rules: ['MATCH,DIRECT']\n", Format::Yaml).unwrap();
        assert!(!cfg.allow_lan);
        assert_eq!(cfg.bind_address, "*");
        assert_eq!(cfg.log_level, "info");
        assert_eq!(cfg.mode, Mode::Rule);
        assert!(!cfg.dns.enable);
    }

    #[test]
    fn parse_production_configs() {
        // 验证根目录 config.yaml
        if let Ok(content) = std::fs::read_to_string("../../config.yaml") {
            let cfg = parse(&content, Format::Yaml).expect("根目录 config.yaml 语法解析失败");
            validate::validate(&cfg).expect("根目录 config.yaml 业务规则校验失败");
            assert!(cfg.tuning.is_some());
            let t = cfg.tuning.as_ref().unwrap();
            assert_eq!(t.socket_buffer_size, Some(524288));
            assert!(t.tcp_nodelay);
        }

        // 验证 example/config.yaml
        if let Ok(content) = std::fs::read_to_string("../../example/config.yaml") {
            let cfg = parse(&content, Format::Yaml).expect("example/config.yaml 语法解析失败");
            validate::validate(&cfg).expect("example/config.yaml 业务规则校验失败");
            assert!(cfg.tuning.is_some());
        }
    }

    #[test]
    fn test_structured_cel_rules_in_yaml() {
        let yaml = r#"
proxies:
  - name: "node-1"
    type: socks5
    server: 127.0.0.1
    port: 1080
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - node-1
rules:
  - DOMAIN-SUFFIX,example.com,DIRECT
  - expr: 'process.name == "git" && dst.port == 22'
    target: "PROXY"
  - expression: 'host.endsWith(".google.com") && dst.port in [80, 443]'
    proxy: "PROXY"
    no-resolve: true
  - MATCH,PROXY
"#;
        let cfg = parse(yaml, Format::Yaml).expect("CEL 表达式 YAML 映射解析应当成功");
        assert_eq!(cfg.rules.len(), 4);
        assert_eq!(cfg.rules[0], "DOMAIN-SUFFIX,example.com,DIRECT");
        assert_eq!(
            cfg.rules[1],
            "EXPR,(process.name == \"git\" && dst.port == 22),PROXY"
        );
        assert_eq!(
            cfg.rules[2],
            "EXPR,(host.endsWith(\".google.com\") && dst.port in [80, 443]),PROXY,no-resolve"
        );
        assert_eq!(cfg.rules[3], "MATCH,PROXY");
    }
}

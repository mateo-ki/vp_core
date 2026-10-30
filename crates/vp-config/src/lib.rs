//! vp-config：配置加载与校验。
//!
//! 同一套 Clash 兼容 schema，两种前端：
//! - YAML（`.yaml` / `.yml`）
//! - JSON / JSON5（`.json`，容忍注释）

pub mod convert;
pub mod model;
pub mod validate;

pub use model::*;

use vp_common::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Yaml,
    Json,
}

impl Format {
    pub fn from_path(path: &str) -> Format {
        let lower = path.to_ascii_lowercase();
        if lower.ends_with(".yaml") || lower.ends_with(".yml") {
            Format::Yaml
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
    };
    sanitize_proxy_aliases(&mut json_value);
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
}

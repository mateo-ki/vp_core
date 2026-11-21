//! vp-dsl：全量配置与 CEL 路由流向 DSL 编译引擎。
//!
//! 支持单文件全量声明式定义入站 (inbound)、出站节点 (node)、
//! 策略组 (group)、DNS (dns)、系统服务 (services) 与 CEL 路由块 (route)，
//! 并一站式编译生成强类型纯净中间表示 `VpIr`。

pub mod ast;
pub mod lowering;
pub mod parser;
pub mod serializer;
pub mod token;

pub use ast::*;
pub use serializer::{format_dsl, ir_to_dsl};
pub use token::Lexer;

use vp_ir::VpIr;

/// 解析 `.vp` 全量 DSL 脚本文本，直接编译输出统一中间表示 `VpIr`。
pub fn parse(input: &str) -> Result<VpIr, String> {
    let mut lexer = token::Lexer::new(input);
    let tokens = lexer.tokenize()?;
    let mut parser = parser::Parser::new(input, tokens);
    let blocks = parser.parse_all()?;
    lowering::lower_to_ir(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_vp_dsl_compilation() {
        let script = r#"
// 入站
inbound mixed {
    listen: "127.0.0.1:7890"
}

inbound tun {
    address: "198.18.0.1"
    netmask: "255.255.0.0"
    auto_route: true
}

// 出站节点
node "hk-01" vless {
    server: "hk.example.com"
    port: 443
    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811"
    flow: "xtls-rprx-vision"
    tls: reality {
        sni: "www.amazon.com"
        public_key: "1111222233334444555566667777888899990000111"
        short_id: "0123456789abcdef"
    }
}

node "us-01" ss {
    server: "us.example.com"
    port: 8388
    cipher: "aes-128-gcm"
    password: "secretpassword"
    udp: true
}

// 策略组
group "AUTO" url_test {
    members: ["hk-01", "us-01"]
    interval: 300s
    tolerance: 50ms
    filter: "(?i)hk"
    fallback: "DIRECT"
}

group "PROXY" select {
    members: ["AUTO", "hk-01", "us-01", "DIRECT"]
}

// DNS 引擎
dns {
    nameservers: ["https://doh.pub/dns-query", "223.5.5.5"]
    fake_ip: "198.18.0.0/15"
}

// Google CEL 路由流向块
route {
    process.name == "git" && dst.port == 22 => "PROXY"
    net == "tcp" && dst.port in [80, 443] && host.endsWith(".google.com") => "AUTO"
    dst.ip in "10.0.0.0/8" || src.ip in "192.168.1.0/24" => "DIRECT"
    geoip == "CN" => "DIRECT"
    _ => "PROXY"
}
"#;

        let ir = parse(script).expect(".vp 脚本编译应当成功");
        assert_eq!(ir.inbounds.len(), 1); // mixed
        assert!(ir.tun.is_some());
        assert_eq!(ir.tun.as_ref().unwrap().address, "198.18.0.1");

        // outbounds: DIRECT, REJECT, hk-01, us-01
        assert_eq!(ir.outbounds.len(), 4);
        let hk = ir.outbounds.iter().find(|o| o.name == "hk-01").unwrap();
        match &hk.kind {
            vp_ir::OutboundKind::Vless { server, flow, .. } => {
                assert_eq!(server, "hk.example.com");
                assert_eq!(flow.as_deref(), Some("xtls-rprx-vision"));
            }
            other => panic!("expected vless, got {other:?}"),
        }
        assert!(hk.transport.reality.is_some());
        let reality = hk.transport.reality.as_ref().unwrap();
        assert_eq!(
            reality.public_key,
            "1111222233334444555566667777888899990000111"
        );

        // groups
        assert_eq!(ir.groups.len(), 2);
        let auto = ir.groups.iter().find(|g| g.name == "AUTO").unwrap();
        assert_eq!(auto.interval, 300);
        assert_eq!(auto.tolerance, 50);
        assert_eq!(auto.fallback.as_deref(), Some("DIRECT"));

        // routes
        assert_eq!(ir.routes.len(), 5);
        match &ir.routes[0].payload {
            vp_ir::RulePayload::Cel(expr) => {
                assert_eq!(expr, "process.name == \"git\" && dst.port == 22");
            }
            other => panic!("expected cel, got {other:?}"),
        }
        assert_eq!(ir.routes[0].target, "PROXY");

        assert!(matches!(ir.routes[4].payload, vp_ir::RulePayload::MatchAll));
        assert_eq!(ir.routes[4].target, "PROXY");
    }

    #[test]
    fn test_invalid_cel_syntax_rejected_at_parse_time() {
        let bad_script = r#"
route {
    host.invalid_cel_syntax( &&& => "PROXY"
}
"#;
        let res = parse(bad_script);
        assert!(res.is_err());
    }

    #[test]
    fn test_sub_rules_and_server_inbound() {
        let script = r#"
inbound server "ss-server" shadowsocks {
    listen: "0.0.0.0:8388"
    cipher: "aes-128-gcm"
    password: "mypassword"
}

sub_rule "custom_flow" {
    host.endsWith(".apple.com") => "DIRECT"
    _ => "PROXY"
}
"#;
        let ir = parse(script).expect("解析 sub_rule 与 server 入站");
        assert_eq!(ir.inbounds.len(), 1);
        match &ir.inbounds[0] {
            vp_ir::InboundSpec::Server(s) => {
                assert_eq!(s.name, "ss-server");
                assert_eq!(s.kind, "shadowsocks");
                assert_eq!(s.cipher.as_deref(), Some("aes-128-gcm"));
                assert_eq!(s.users[0].secret, "mypassword");
            }
            other => panic!("expected server inbound, got {other:?}"),
        }
        assert!(ir.sub_rules.contains_key("custom_flow"));
        let sub = &ir.sub_rules["custom_flow"];
        assert_eq!(sub.len(), 2);
        assert_eq!(sub[0].target, "DIRECT");
        assert_eq!(sub[1].target, "PROXY");
    }

    #[test]
    fn test_ir_to_dsl_and_format_roundtrip() {
        let original_dsl = r#"
inbound mixed {
    listen: "127.0.0.1:7890"
}

node "hk-01" vless {
    server: "hk.example.com"
    port: 443
    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811"
    flow: "xtls-rprx-vision"
    tls: reality {
        sni: "www.amazon.com"
        public_key: "abc123"
        short_id: "1234"
    }
}

group "AUTO" url_test {
    members: ["hk-01"]
    interval: 300s
    tolerance: 50ms
    filter: "hk"
    fallback: "DIRECT"
}

dns {
    nameservers: ["https://doh.pub/dns-query", "223.5.5.5"]
    fake_ip: "198.18.0.0/15"
}

services {
    mode: "rule"
    log_level: "info"
}

route {
    process.name == "git" => "AUTO"
    host.endsWith(".google.com") => "AUTO"
    geoip == "CN" => "DIRECT"
    _ => "AUTO"
}
"#;
        let ir = parse(original_dsl).expect("首次解析 DSL 成功");
        let generated_dsl = ir_to_dsl(&ir);
        assert!(generated_dsl.contains("inbound mixed {"));
        assert!(generated_dsl.contains("node \"hk-01\" vless {"));
        assert!(generated_dsl.contains("tls: reality {"));
        assert!(generated_dsl.contains("group \"AUTO\" url_test {"));
        assert!(generated_dsl.contains("dns {"));
        assert!(generated_dsl.contains("host.endsWith(\".google.com\") => \"AUTO\""));

        // 二次往返解析：确认生成的 DSL 代码可被 100% 成功解析且等价
        let roundtrip_ir = parse(&generated_dsl).expect("往返解析生成的 DSL 成功");
        assert_eq!(roundtrip_ir.inbounds.len(), ir.inbounds.len());
        assert_eq!(roundtrip_ir.outbounds.len(), ir.outbounds.len());
        assert_eq!(roundtrip_ir.groups.len(), ir.groups.len());
        assert_eq!(roundtrip_ir.routes.len(), ir.routes.len());

        // 测试 format_dsl
        let formatted = format_dsl(original_dsl).expect("format_dsl 应当成功");
        assert_eq!(formatted, generated_dsl);
    }

    #[test]
    fn test_masque_node_dsl_roundtrip() {
        let script = r#"
node "warp-masque" masque {
    server: "162.159.199.2"
    port: 443
    private_key: "priv_key_example"
    public_key: "pub_key_example"
    ip: "172.16.0.2"
    ipv6: "2606:4700:110::1"
    uri: "https://cloudflareaccess.com"
    sni: "consumer-masque.cloudflareclient.com"
    mtu: 1280
    udp: true
    remote_dns_resolve: true
    dns: ["1.1.1.1", "2606:4700:4700::1111"]
    skip_cert_verify: true
}
"#;
        let ir = parse(script).expect("解析 masque 节点成功");
        let node = ir
            .outbounds
            .iter()
            .find(|o| o.name == "warp-masque")
            .unwrap();
        match &node.kind {
            vp_ir::OutboundKind::Masque {
                server,
                port,
                private_key,
                public_key,
                ip,
                ipv6,
                uri,
                sni,
                mtu,
                udp,
                remote_dns_resolve,
                dns,
                skip_cert_verify,
                ..
            } => {
                assert_eq!(server, "162.159.199.2");
                assert_eq!(*port, 443);
                assert_eq!(private_key, "priv_key_example");
                assert_eq!(public_key.as_deref(), Some("pub_key_example"));
                assert_eq!(ip.as_deref(), Some("172.16.0.2"));
                assert_eq!(ipv6.as_deref(), Some("2606:4700:110::1"));
                assert_eq!(uri.as_deref(), Some("https://cloudflareaccess.com"));
                assert_eq!(sni.as_deref(), Some("consumer-masque.cloudflareclient.com"));
                assert_eq!(*mtu, Some(1280));
                assert!(*udp);
                assert!(*remote_dns_resolve);
                assert_eq!(dns.len(), 2);
                assert!(*skip_cert_verify);
            }
            other => panic!("expected masque, got {other:?}"),
        }

        let dsl = ir_to_dsl(&ir);
        assert!(dsl.contains("node \"warp-masque\" masque {"));
        assert!(dsl.contains("server: \"162.159.199.2\""));
        assert!(dsl.contains("private_key: \"priv_key_example\""));
        assert!(dsl.contains("public_key: \"pub_key_example\""));
        assert!(dsl.contains("dns: [\"1.1.1.1\", \"2606:4700:4700::1111\"]"));

        let roundtrip_ir = parse(&dsl).expect("往返解析 masque 成功");
        assert_eq!(roundtrip_ir.outbounds.len(), ir.outbounds.len());
    }

    /// XHTTP 节点：DSL xhttp 子对象 → IR → 序列化 → 再解析 往返无损
    #[test]
    fn test_xhttp_node_dsl_roundtrip() {
        let script = r#"
node "cdn-xhttp" vless {
    server: "104.16.0.1"
    port: 443
    uuid: "11111111-2222-3333-4444-555555555555"
    flow: "xtls-rprx-vision"
    sni: "cdn.example.com"
    tls: true
    udp: true
    xhttp: {
        path: "/xhttp-upload"
        mode: "stream-up"
        headers: { Host: "cdn.example.com" }
    }
}
"#;
        let ir = parse(script).expect("解析 xhttp 节点成功");
        let node = ir.outbounds.iter().find(|o| o.name == "cdn-xhttp").unwrap();
        let x = node
            .transport
            .xhttp
            .as_ref()
            .expect("xhttp spec 应当被 lower");
        assert_eq!(x.path, "/xhttp-upload");
        assert_eq!(x.mode.as_deref(), Some("stream-up"));
        assert_eq!(
            x.headers.get("Host").map(String::as_str),
            Some("cdn.example.com")
        );
        assert_eq!(node.transport.network.as_deref(), Some("xhttp"));
        assert!(node.transport.tls);

        // 序列化 → 重新解析 → 字段一致
        let dsl = ir_to_dsl(&ir);
        assert!(dsl.contains("xhttp: {"));
        assert!(dsl.contains("path: \"/xhttp-upload\""));
        assert!(dsl.contains("mode: \"stream-up\""));
        let rt_ir = parse(&dsl).expect("往返 DSL 解析成功");
        let rt_node = rt_ir
            .outbounds
            .iter()
            .find(|o| o.name == "cdn-xhttp")
            .unwrap();
        let rt_x = rt_node.transport.xhttp.as_ref().expect("往返 xhttp spec");
        assert_eq!(rt_x.path, "/xhttp-upload");
        assert_eq!(rt_x.mode.as_deref(), Some("stream-up"));
        assert_eq!(
            rt_x.headers.get("Host").map(String::as_str),
            Some("cdn.example.com")
        );
        assert_eq!(rt_node.transport.network.as_deref(), Some("xhttp"));
    }

    /// shadow_tls 子对象与 network 标识的 DSL 往返回归：
    /// serializer 输出的 `shadow_tls: {..}` 与 `network: ".."` 必须可被 lowering 还原
    /// （历史上 lowering 缺失这两个解析臂，往返即丢数据）
    #[test]
    fn test_shadowtls_and_network_dsl_roundtrip() {
        let script = r#"
node "st-test" trojan {
    server: "1.2.3.4"
    port: 443
    password: "pw"
    shadow_tls: {
        password: "stls-pw"
        sni: "www.apple.com"
    }
}

node "hu-node" vless {
    server: "5.6.7.8"
    port: 443
    uuid: "11111111-2222-3333-4444-555555555555"
    tls: true
    network: "httpupgrade"
    ws: {
        path: "/hu"
        headers: { Host: "cdn.com" }
    }
}
"#;
        let ir = parse(script).expect("解析成功");

        // shadow_tls 子对象应被 lowering 捕获
        let st = ir.outbounds.iter().find(|o| o.name == "st-test").unwrap();
        let spec = st
            .transport
            .shadow_tls
            .as_ref()
            .expect("shadow_tls 应被 lower");
        assert_eq!(spec.password, "stls-pw");
        assert_eq!(spec.sni, "www.apple.com");

        // network 显式标识应被 lowering 捕获（httpupgrade 场景）
        let hu = ir.outbounds.iter().find(|o| o.name == "hu-node").unwrap();
        assert_eq!(hu.transport.network.as_deref(), Some("httpupgrade"));

        // 序列化 → 再解析：两字段均不丢失
        let dsl = ir_to_dsl(&ir);
        let rt = parse(&dsl).expect("往返解析成功");
        let rt_st = rt.outbounds.iter().find(|o| o.name == "st-test").unwrap();
        let spec2 = rt_st
            .transport
            .shadow_tls
            .as_ref()
            .expect("往返 shadow_tls 不得丢失");
        assert_eq!(spec2.password, "stls-pw");
        assert_eq!(spec2.sni, "www.apple.com");
        let rt_hu = rt.outbounds.iter().find(|o| o.name == "hu-node").unwrap();
        assert_eq!(
            rt_hu.transport.network.as_deref(),
            Some("httpupgrade"),
            "往返 network 不得丢失"
        );
    }

    /// 穷举回归：全部 23 种 OutboundKind + 全部传输层块 + 元字段（smux/uot/拨号链）
    /// IR → DSL → IR 逐节点全等。任何 serializer/lowering 缺字段都会在此炸出。
    #[test]
    fn test_exhaustive_ir_roundtrip_all_protocols() {
        use std::collections::HashMap;
        use vp_ir::outbound::*;

        let mut headers = HashMap::new();
        headers.insert("X-Foo".to_string(), "bar".to_string());

        let plain = TransportSpec::default();
        let tr = |t: TransportSpec| t;

        let full_tls = TransportSpec {
            tls: true,
            sni: Some("sni.example.com".into()),
            alpn: vec!["h2".into(), "http/1.1".into()],
            insecure: true,
            client_fingerprint: Some("chrome".into()),
            ..TransportSpec::default()
        };

        let mut ws = full_tls.clone();
        ws.network = Some("ws".into());
        ws.ws = Some(WsSpec {
            path: "/ws-path".into(),
            headers: headers.clone(),
            max_early_data: Some(2048),
            v2ray_http_upgrade: true,
        });

        let mut grpc = full_tls.clone();
        grpc.network = Some("grpc".into());
        grpc.grpc = Some(GrpcSpec {
            service_name: "grpc-svc".into(),
        });

        let mut httpt = full_tls.clone();
        httpt.network = Some("http".into());
        let mut h_headers: HashMap<String, Vec<String>> = HashMap::new();
        h_headers.insert("X-A".to_string(), vec!["a1".to_string()]);
        httpt.http = Some(HttpSpec {
            method: Some("GET".into()),
            path: vec!["/p1".into(), "/p2".into()],
            headers: h_headers,
        });

        let mut xhttp = full_tls.clone();
        xhttp.network = Some("xhttp".into());
        xhttp.xhttp = Some(XhttpSpec {
            path: "/xh".into(),
            host: Some("xh.example.com".into()),
            mode: Some("stream-up".into()),
            headers: headers.clone(),
        });

        let reality = TransportSpec {
            network: Some("tcp".into()),
            // 规范形：reality 块隐含 tls（lowering 解析 reality 时置 tls=true，语义保留）
            tls: true,
            reality: Some(RealitySpec {
                public_key: "pbk-0123456789abcdef".into(),
                short_id: Some("0123456789abcdef".into()),
                spider_x: Some("https://www.bing.com".into()),
            }),
            client_fingerprint: Some("chrome".into()),
            ..TransportSpec::default()
        };

        let mut ech = full_tls.clone();
        ech.ech = Some(EchSpec {
            enable: true,
            config: Some("AER+HQ".into()),
            query_server_name: Some("q.example.com".into()),
            doh: Some("https://1.1.1.1/dns-query".into()),
        });

        let mut stls = full_tls.clone();
        stls.shadow_tls = Some(ShadowTlsSpec {
            password: "stls-pw".into(),
            sni: "www.apple.com".into(),
            version: 3,
        });

        let node = |name: &str, kind: OutboundKind, t: TransportSpec| OutboundSpec {
            name: name.into(),
            kind,
            transport: t,
            dialer_proxy: None,
            routing_mark: None,
            bind_interface: None,
            udp_over_tcp: None,
            smux: None,
        };

        let outbounds = vec![
            node(
                "n-ss",
                OutboundKind::Ss {
                    server: "1.1.1.1".into(),
                    port: 8388,
                    cipher: "aes-256-gcm".into(),
                    password: "ss-pw".into(),
                    udp: true,
                },
                tr(plain.clone()),
            ),
            node(
                "n-ssr",
                OutboundKind::Ssr {
                    server: "1.1.1.1".into(),
                    port: 8389,
                    password: "ssr-pw".into(),
                    cipher: "rc4-md5".into(),
                    protocol: "auth_sha1_v4".into(),
                    obfs: "http_simple".into(),
                    obfs_param: Some("obfstest".into()),
                    protocol_param: Some("protest".into()),
                    udp: false,
                },
                tr(plain.clone()),
            ),
            node(
                "n-vmess",
                OutboundKind::Vmess {
                    server: "2.2.2.2".into(),
                    port: 10086,
                    uuid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
                    alter_id: 8,
                    security: Some("aes-128-gcm".into()),
                    udp: true,
                },
                tr(ws.clone()),
            ),
            node(
                "n-vless-tls",
                OutboundKind::Vless {
                    server: "3.3.3.3".into(),
                    port: 443,
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    flow: Some("xtls-rprx-vision".into()),
                    packet_encoding: Some("packetaddr".into()),
                    udp: true,
                },
                tr(full_tls.clone()),
            ),
            node(
                "n-vless-ws",
                OutboundKind::Vless {
                    server: "3.3.3.3".into(),
                    port: 443,
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    flow: None,
                    packet_encoding: None,
                    udp: false,
                },
                tr(ws.clone()),
            ),
            node(
                "n-vless-grpc",
                OutboundKind::Vless {
                    server: "3.3.3.3".into(),
                    port: 443,
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    flow: None,
                    packet_encoding: None,
                    udp: false,
                },
                tr(grpc.clone()),
            ),
            node(
                "n-vless-http",
                OutboundKind::Vless {
                    server: "3.3.3.3".into(),
                    port: 443,
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    flow: None,
                    packet_encoding: None,
                    udp: false,
                },
                tr(httpt.clone()),
            ),
            node(
                "n-vless-xhttp",
                OutboundKind::Vless {
                    server: "3.3.3.3".into(),
                    port: 443,
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    flow: None,
                    packet_encoding: None,
                    udp: false,
                },
                tr(xhttp.clone()),
            ),
            node(
                "n-vless-reality",
                OutboundKind::Vless {
                    server: "3.3.3.3".into(),
                    port: 443,
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    flow: Some("xtls-rprx-vision".into()),
                    packet_encoding: None,
                    udp: true,
                },
                tr(reality.clone()),
            ),
            node(
                "n-vless-ech",
                OutboundKind::Vless {
                    server: "3.3.3.3".into(),
                    port: 443,
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    flow: None,
                    packet_encoding: None,
                    udp: false,
                },
                tr(ech.clone()),
            ),
            node(
                "n-vless-stls",
                OutboundKind::Vless {
                    server: "3.3.3.3".into(),
                    port: 443,
                    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
                    flow: None,
                    packet_encoding: None,
                    udp: false,
                },
                tr(stls.clone()),
            ),
            node(
                "n-trojan",
                OutboundKind::Trojan {
                    server: "4.4.4.4".into(),
                    port: 443,
                    password: "trojan-pw".into(),
                    network: Some("grpc".into()),
                    udp: true,
                },
                tr(grpc.clone()),
            ),
            node(
                "n-hy1",
                OutboundKind::Hysteria {
                    server: "5.5.5.5".into(),
                    port: 443,
                    auth: Some("hy1-auth".into()),
                    up_mbps: Some(50),
                    down_mbps: Some(200),
                    obfs: Some("salamander".into()),
                    obfs_password: Some("obfs-pw".into()),
                    sni: Some("hy.example.com".into()),
                    alpn: vec!["h3".into()],
                    insecure: true,
                },
                {
                    // DSL 往返规范形：hysteria 系 sni/alpn/insecure 存 kind，
                    // lowering 从顶层属性回填 kind 同时镜像进 transport（语义等价）
                    let mut t = plain.clone();
                    t.sni = Some("hy.example.com".into());
                    t.alpn = vec!["h3".into()];
                    t.insecure = true;
                    t
                },
            ),
            node(
                "n-hy2",
                OutboundKind::Hysteria2 {
                    server: "5.5.5.5".into(),
                    port: 8443,
                    ports: Some("20000-30000".into()),
                    password: Some("hy2-pw".into()),
                    up_mbps: Some(100),
                    down_mbps: Some(500),
                    obfs: Some("salamander".into()),
                    obfs_password: Some("obfs-pw".into()),
                    sni: Some("hy2.example.com".into()),
                    insecure: true,
                },
                {
                    let mut t = plain.clone();
                    t.sni = Some("hy2.example.com".into());
                    t.insecure = true;
                    t
                },
            ),
            node(
                "n-tuic",
                OutboundKind::Tuic {
                    server: "6.6.6.6".into(),
                    port: 8443,
                    uuid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
                    password: "tuic-pw".into(),
                    congestion_controller: Some("bbr".into()),
                    udp_relay_mode: Some("native".into()),
                    zero_rtt_handshake: true,
                    heartbeat: Some("10s".into()),
                    sni: Some("tuic.example.com".into()),
                    insecure: true,
                },
                {
                    let mut t = plain.clone();
                    t.sni = Some("tuic.example.com".into());
                    t.insecure = true;
                    t
                },
            ),
            node(
                "n-juicity",
                OutboundKind::Juicity {
                    server: "7.7.7.7".into(),
                    port: 8443,
                    uuid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
                    password: "juicity-pw".into(),
                    congestion_controller: Some("bbr".into()),
                    sni: Some("ju.example.com".into()),
                    insecure: false,
                    pinned_cert_chain: Some("aabbccdd".into()),
                },
                {
                    let mut t = plain.clone();
                    t.sni = Some("ju.example.com".into());
                    t
                },
            ),
            node(
                "n-openvpn",
                OutboundKind::OpenVpn {
                    server: "8.8.8.8".into(),
                    port: 1194,
                    proto: Some("tcp".into()),
                    username: Some("ovpn-user".into()),
                    password: Some("ovpn-pass".into()),
                    ca: "-----BEGIN CERT-----".into(),
                    cert: Some("-----BEGIN CERT2-----".into()),
                    key: Some("-----BEGIN KEY-----".into()),
                    cipher: Some("AES-256-GCM".into()),
                    insecure: true,
                    udp: false,
                },
                {
                    // DSL 规范形：kind.insecure 由顶层属性回填，transport 镜像 true
                    let mut t = plain.clone();
                    t.insecure = true;
                    t
                },
            ),
            node(
                "n-wg",
                OutboundKind::Wireguard {
                    server: "9.9.9.9".into(),
                    port: 51820,
                    ip: "172.16.0.2".into(),
                    ipv6: Some("fd00::2".into()),
                    private_key: "wg-priv".into(),
                    public_key: "wg-pub".into(),
                    preshared_key: Some("wg-psk".into()),
                    mtu: Some(1420),
                    reserved: Some([1, 2, 3]),
                    workers: Some(4),
                    udp: true,
                },
                tr(plain.clone()),
            ),
            node(
                "n-tailscale",
                OutboundKind::Tailscale {
                    server: "10.10.10.10".into(),
                    port: 443,
                    authkey: Some("ts-key".into()),
                    control_url: Some("https://control.tailscale.com".into()),
                    hostname: Some("ts-host".into()),
                    state_dir: Some("/tmp/ts".into()),
                    exit_node: Some("ts-exit".into()),
                    exit_node_allow_lan: true,
                },
                tr(plain.clone()),
            ),
            node(
                "n-masque",
                OutboundKind::Masque {
                    server: "162.159.192.1".into(),
                    port: 443,
                    private_key: "MHcCAQEEI".into(),
                    public_key: Some("MFkwEwYH".into()),
                    ip: Some("172.16.0.2".into()),
                    ipv6: Some("2606:4700::1".into()),
                    uri: Some("https://warp.example.com".into()),
                    sni: Some("warp.example.com".into()),
                    mtu: Some(1280),
                    udp: true,
                    remote_dns_resolve: true,
                    dns: vec!["1.1.1.1".into()],
                    skip_cert_verify: false,
                    network: None,
                },
                {
                    // DSL 规范形：kind.sni 序列化为顶层属性，transport 镜像
                    let mut t = plain.clone();
                    t.sni = Some("warp.example.com".into());
                    t
                },
            ),
            node(
                "n-snell",
                OutboundKind::Snell {
                    server: "11.11.11.11".into(),
                    port: 6160,
                    psk: "snell-psk".into(),
                    version: 4,
                    obfs_opts: Some(SnellObfsSpec {
                        mode: Some("http".into()),
                        host: Some("obfs.example.com".into()),
                        path: Some("/obfs".into()),
                    }),
                    udp: true,
                },
                tr(plain.clone()),
            ),
            node(
                "n-anytls",
                OutboundKind::Anytls {
                    server: "12.12.12.12".into(),
                    port: 8443,
                    password: "anytls-pw".into(),
                    // DSL 规范形：kind.sni 与 transport.sni 同源镜像（YAML→IR 两侧一致）
                    sni: Some("sni.example.com".into()),
                    client_fingerprint: Some("chrome".into()),
                    udp: true,
                },
                tr(full_tls.clone()),
            ),
            node(
                "n-ssh",
                OutboundKind::Ssh {
                    server: "13.13.13.13".into(),
                    port: 22,
                    username: "ssh-user".into(),
                    password: Some("ssh-pass".into()),
                    private_key: Some("/tmp/id_ed25519".into()),
                    private_key_passphrase: Some("key-pass".into()),
                    host_key: Some("sha256-abc".into()),
                },
                tr(plain.clone()),
            ),
            node(
                "n-brook",
                OutboundKind::Brook {
                    server: "14.14.14.14".into(),
                    port: 9999,
                    password: "brook-pw".into(),
                    protocol: Some("ws".into()),
                    udp: true,
                },
                tr(plain.clone()),
            ),
            node(
                "n-mieru",
                OutboundKind::Mieru {
                    server: "15.15.15.15".into(),
                    port: 8443,
                    username: "mieru-u".into(),
                    password: "mieru-p".into(),
                    transport: Some("TCP".into()),
                    multiplexing: Some("MULTIPLEX".into()),
                },
                tr(plain.clone()),
            ),
            node(
                "n-naive",
                OutboundKind::Naive {
                    server: "16.16.16.16".into(),
                    port: 443,
                    username: "naive-u".into(),
                    password: "naive-p".into(),
                    // DSL 规范形：kind.sni := transport.sni（lowering 回填）
                    sni: Some("sni.example.com".into()),
                    client_fingerprint: Some("chrome".into()),
                    udp: true,
                },
                tr(full_tls.clone()),
            ),
            node(
                "n-socks5",
                OutboundKind::Socks5 {
                    server: "17.17.17.17".into(),
                    port: 1080,
                    username: Some("sk-u".into()),
                    password: Some("sk-p".into()),
                    tls: true,
                    sni: Some("sk.example.com".into()),
                    insecure: true,
                    udp: true,
                },
                {
                    // DSL 规范形：kind.tls/sni/insecure 由 transport 镜像（序列化去重设计）
                    let mut t = plain.clone();
                    t.tls = true;
                    t.sni = Some("sk.example.com".into());
                    t.insecure = true;
                    t
                },
            ),
            node(
                "n-http",
                OutboundKind::Http {
                    server: "18.18.18.18".into(),
                    port: 8080,
                    username: Some("http-u".into()),
                    password: Some("http-p".into()),
                    tls: true,
                    sni: Some("http.example.com".into()),
                    insecure: false,
                    headers: headers.clone(),
                },
                {
                    // DSL 规范形：kind.tls/sni 由 transport 镜像
                    let mut t = plain.clone();
                    t.tls = true;
                    t.sni = Some("http.example.com".into());
                    t
                },
            ),
        ];

        let ir = VpIr {
            outbounds,
            ..Default::default()
        };

        let dsl = ir_to_dsl(&ir);
        let rt = parse(&dsl).expect("穷举往返：DSL 解析成功");
        for n in &ir.outbounds {
            let got = rt
                .outbounds
                .iter()
                .find(|o| o.name == n.name)
                .unwrap_or_else(|| panic!("穷举往返：节点 {} 丢失", n.name));
            assert_eq!(
                got, n,
                "穷举往返：节点 {} 字段不一致\n--- DSL ---\n{dsl}",
                n.name
            );
        }
        assert_eq!(
            rt.outbounds.len(),
            ir.outbounds.len() + 2, // DIRECT/REJECT 兜底节点
            "往返不得引入或丢失节点"
        );
    }

    /// 元字段穷举：smux / udp_over_tcp（此前 DSL 侧完全不支持，YAML→DSL 转换会静默丢弃）
    #[test]
    fn test_exhaustive_ir_roundtrip_meta_fields() {
        use vp_ir::outbound::*;

        // 注：security None 与 Some("auto") 语义等价，lowering 统一规范化为 Some("auto")，
        // 穷举输入按规范形构造（None 的规范化属预期行为，非数据丢失）
        let vmess = OutboundKind::Vmess {
            server: "2.2.2.2".into(),
            port: 10086,
            uuid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
            alter_id: 0,
            security: Some("auto".into()),
            udp: true,
        };
        let ob = OutboundSpec {
            name: "n-meta".into(),
            kind: vmess,
            transport: TransportSpec::default(),
            dialer_proxy: Some("upstream-group".into()),
            routing_mark: Some(7777),
            bind_interface: Some("eth5".into()),
            udp_over_tcp: Some(UotVersion::V2),
            smux: Some(SmuxSpec {
                enabled: true,
                protocol: Some("h2mux".into()),
                max_connections: Some(4),
                min_streams: Some(2),
                max_streams: Some(8),
                padding: true,
            }),
        };
        let ir = VpIr {
            outbounds: vec![ob],
            ..Default::default()
        };

        let dsl = ir_to_dsl(&ir);
        assert!(dsl.contains("udp_over_tcp: 2"), "uot V2 应序列化为 2");
        assert!(dsl.contains("smux: {"), "smux 应序列化");
        assert!(dsl.contains("dialer_proxy: \"upstream-group\""));

        let rt = parse(&dsl).expect("元字段往返解析成功");
        let got = rt.outbounds.iter().find(|o| o.name == "n-meta").unwrap();
        assert_eq!(&ir.outbounds[0], got, "元字段往返不一致\n{dsl}");
    }
}

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
}

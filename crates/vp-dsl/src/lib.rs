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
}

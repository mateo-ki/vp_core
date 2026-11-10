//! 真实订阅库 57 个 MASQUE (Cloudflare WARP) 节点全面反序列化、IR 转换与 DSL 往返测试

use std::fs;
use std::path::Path;

#[test]
fn test_all_57_real_masque_nodes_compatibility() {
    let test_file = Path::new("target/masque_nodes_test.json");
    if !test_file.exists() {
        return;
    }

    let json_str = fs::read_to_string(test_file).expect("读取真实 MASQUE 节点文件");
    let cfg = vp_config::parse(&json_str, vp_config::Format::Json)
        .expect("vp_config 应当 100% 成功解析全部 57 个真实 MASQUE 节点");

    assert_eq!(cfg.proxies.len(), 57, "应当成功解析 57 个节点");

    for (i, p) in cfg.proxies.iter().enumerate() {
        assert_eq!(
            p.kind.type_name(),
            "masque",
            "节点 {} [{}] 协议类型应当为 masque",
            i,
            p.name
        );
        match &p.kind {
            vp_config::ProxyKind::Masque(m) => {
                assert!(!m.server.is_empty(), "节点 {} server 不能为空", p.name);
                assert!(m.port > 0, "节点 {} port 必须大于 0", p.name);
                assert!(
                    !m.private_key.is_empty(),
                    "节点 {} private_key 不能为空",
                    p.name
                );
                assert!(
                    m.public_key.is_some(),
                    "节点 {} public_key 不能为空",
                    p.name
                );
                assert!(m.ip.is_some(), "节点 {} ip 不能为空", p.name);
            }
            _ => panic!("预期 ProxyKind::Masque"),
        }
    }

    // 转换为统一中间表示 VpIr
    let ir = cfg.into_ir().expect("MASQUE 节点转 VpIr 成功");
    // 过滤掉内置 DIRECT / REJECT
    let custom_outbounds: Vec<_> = ir
        .outbounds
        .iter()
        .filter(|o| matches!(o.kind, vp_ir::OutboundKind::Masque { .. }))
        .collect();
    assert_eq!(custom_outbounds.len(), 57);

    // 格式化输出为 .vp DSL
    let dsl = vp_dsl::ir_to_dsl(&ir);
    assert!(dsl.contains("node \""));
    assert!(dsl.contains("masque {"));

    // 往返编译验证：从生成的 DSL 重新解析为 VpIr
    let ir_from_dsl = vp_dsl::parse(&dsl).expect("生成的 MASQUE DSL 必须可重新编译为 VpIr");
    let roundtrip_masque_count = ir_from_dsl
        .outbounds
        .iter()
        .filter(|o| matches!(o.kind, vp_ir::OutboundKind::Masque { .. }))
        .count();
    assert_eq!(
        roundtrip_masque_count, 57,
        "DSL 往返后的 MASQUE 节点数必须保持为 57 个"
    );
}

#[test]
fn test_embedded_sample_masque_node_ci() {
    let json_str = r#"{
  "proxies": [
    {
      "name": "WARP-199.2-443",
      "type": "masque",
      "server": "162.159.199.2",
      "port": 443,
      "private-key": "MHcCAQEEIBsdMrQ/Ai+aaQdjsexdBeTAbcZOKQthvFEy+urepiGzoAoGCCqGSM49AwEHoUQDQgAE7dGjdy1OZlfH9yaBWRHGG9Esle5yXI43Bia9X+5pSNKsLaRk9qg5AB8a3kgkwTv/+rSJWg+EcrJW79BqyGLlIQ==",
      "public-key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==",
      "ip": "172.16.0.2",
      "ipv6": "2606:4700:110:8c52:2be5:d2e:405:dc11",
      "mtu": 1280,
      "udp": true,
      "remote-dns-resolve": true,
      "dns": [
        "1.1.1.1",
        "2606:4700:4700::1111"
      ]
    }
  ]
}"#;

    let cfg = vp_config::parse(json_str, vp_config::Format::Json)
        .expect("解析标准样例 MASQUE 节点应当成功");
    assert_eq!(cfg.proxies.len(), 1);
    let p = &cfg.proxies[0];
    assert_eq!(p.kind.type_name(), "masque");

    let ir = cfg.into_ir().expect("转 IR 应当成功");
    let ob = ir
        .outbounds
        .iter()
        .find(|o| o.name == "WARP-199.2-443")
        .unwrap();
    assert!(matches!(ob.kind, vp_ir::OutboundKind::Masque { .. }));

    let dsl = vp_dsl::ir_to_dsl(&ir);
    assert!(dsl.contains("node \"WARP-199.2-443\" masque {"));
    assert!(dsl.contains("server: \"162.159.199.2\""));
    assert!(dsl.contains("private_key: \"MHcCAQEEIBsdMrQ/Ai+aaQdjsexdBeTAbcZOKQthvFEy+urepiGzoAoGCCqGSM49AwEHoUQDQgAE7dGjdy1OZlfH9yaBWRHGG9Esle5yXI43Bia9X+5pSNKsLaRk9qg5AB8a3kgkwTv/+rSJWg+EcrJW79BqyGLlIQ==\""));

    let roundtrip_ir = vp_dsl::parse(&dsl).expect("往返 DSL 解析应当成功");
    let rt_ob = roundtrip_ir
        .outbounds
        .iter()
        .find(|o| o.name == "WARP-199.2-443")
        .unwrap();
    assert!(matches!(rt_ob.kind, vp_ir::OutboundKind::Masque { .. }));
}

//! 手动工具（#[ignore]）：把拉取到的新鲜订阅 YAML 的 proxies 数组规范导出为 JSON，
//! 供外部全协议实测驱动挑选新鲜候选节点。
//! 运行：cargo test -p vp-config --test fresh_dump -- --ignored --nocapture
//!
//! 输入/输出目录经环境变量 `VPCORE_FRESH_DIR` 注入（默认当前目录），不写入源码。

use std::collections::BTreeMap;

fn fresh_dir() -> String {
    std::env::var("VPCORE_FRESH_DIR").unwrap_or_else(|_| ".".into())
}

#[test]
#[ignore = "手动工具：依赖 VPCORE_FRESH_DIR 下的 fresh_subs.json"]
fn dump_fresh_subscription_proxies() {
    let dir = fresh_dir();
    let raw = std::fs::read_to_string(format!("{dir}/fresh_subs.json"))
        .expect("fresh_subs.json (位于 VPCORE_FRESH_DIR)");
    let subs: BTreeMap<String, String> = serde_json::from_str(&raw).expect("json map");
    let mut out = BTreeMap::new();
    for (name, yaml) in subs {
        let val: serde_yaml::Value = match serde_yaml::from_str(&yaml) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{name}: yaml error: {e}");
                continue;
            }
        };
        let proxies = val.get("proxies").and_then(|p| p.as_sequence()).cloned();
        let Some(proxies) = proxies else {
            eprintln!("{name}: 无 proxies 段");
            continue;
        };
        eprintln!("{name}: {} proxies", proxies.len());
        out.insert(name, proxies);
    }
    std::fs::write(
        format!("{dir}/fresh_proxies.json"),
        serde_json::to_string_pretty(&out).expect("json"),
    )
    .expect("write");
}

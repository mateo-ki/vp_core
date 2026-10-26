//! 配置校验：端口、命名唯一性、组引用、组环。

use std::collections::{HashMap, HashSet};

use crate::model::{Config, is_builtin};

pub fn validate(cfg: &Config) -> Result<(), Vec<String>> {
    let mut errs = Vec::new();

    // 1. 监听端口冲突
    let port_slots: [(Option<u16>, &str); 5] = [
        (cfg.mixed_port, "mixed-port"),
        (cfg.port, "port"),
        (cfg.socks_port, "socks-port"),
        (cfg.redir_port, "redir-port"),
        (cfg.tproxy_port, "tproxy-port"),
    ];
    let mut ports: Vec<(u16, &str)> = Vec::new();
    for (p, tag) in port_slots {
        if let Some(p) = p {
            if let Some((_, prev)) = ports.iter().find(|(x, _)| *x == p) {
                errs.push(format!("端口 {p} 同时被 {prev} 与 {tag} 使用"));
            }
            ports.push((p, tag));
        }
    }

    // 2. 节点命名
    let mut names: HashSet<&str> = HashSet::new();
    for (i, p) in cfg.proxies.iter().enumerate() {
        if p.name.is_empty() {
            errs.push(format!("proxies[{i}].name 为空"));
        } else if !names.insert(&p.name) {
            errs.push(format!("proxies[{i}].name {:?} 重复", p.name));
        }
    }

    // 3. 组命名
    let mut group_names: HashSet<&str> = HashSet::new();
    for (i, g) in cfg.proxy_groups.iter().enumerate() {
        if g.name.is_empty() {
            errs.push(format!("proxy-groups[{i}].name 为空"));
        } else if !group_names.insert(g.name.as_str()) {
            errs.push(format!("proxy-groups[{i}].name {:?} 重复", g.name));
        } else if names.contains(g.name.as_str()) {
            errs.push(format!("组名 {:?} 与节点名冲突", g.name));
        }
    }
    // 引用检查（两遍：允许前向引用）
    for g in &cfg.proxy_groups {
        if g.proxies.is_empty() && g.r#use.is_empty() {
            errs.push(format!("组 {:?} proxies 与 use 均为空", g.name));
        }
        for r in &g.proxies {
            if !names.contains(r.as_str()) && !group_names.contains(r.as_str()) && !is_builtin(r) {
                errs.push(format!("组 {:?} 引用了不存在的出站 {:?}", g.name, r));
            }
        }
        for u in &g.r#use {
            if !cfg.proxy_providers.contains_key(u) {
                errs.push(format!(
                    "组 {:?} 引用了未定义的 proxy-provider {:?}",
                    g.name, u
                ));
            }
        }
    }

    // 4. 组环检测（DFS 三色标记）
    let group_map: HashMap<&str, &Vec<String>> = cfg
        .proxy_groups
        .iter()
        .map(|g| (g.name.as_str(), &g.proxies))
        .collect();
    let mut state: HashMap<&str, u8> = HashMap::new(); // 0=未访问 1=栈上 2=完成
    fn dfs<'a>(
        name: &'a str,
        groups: &HashMap<&'a str, &'a Vec<String>>,
        state: &mut HashMap<&'a str, u8>,
        path: &mut Vec<&'a str>,
    ) -> bool {
        let s = state.entry(name).or_insert(0);
        if *s == 1 {
            return true; // 环
        }
        if *s == 2 {
            return false;
        }
        *s = 1;
        path.push(name);
        if let Some(members) = groups.get(name) {
            for m in members.iter() {
                if groups.contains_key(m.as_str()) && dfs(m, groups, state, path) {
                    return true;
                }
            }
        }
        path.pop();
        state.insert(name, 2);
        false
    }
    for g in &cfg.proxy_groups {
        let mut path = Vec::new();
        if dfs(g.name.as_str(), &group_map, &mut state, &mut path) {
            errs.push(format!("组存在环引用: {}", path.join(" -> ")));
            state.clear(); // 后续组重新检测，避免污染
        }
    }

    // 5. SUB-RULE 目标存在性
    for (i, rule) in cfg.rules.iter().enumerate() {
        if let Some(rest) = rule.strip_prefix("SUB-RULE,") {
            // SUB-RULE,(逻辑规则),子规则名
            if let Some(pos) = rest.rfind(',') {
                let sub = rest[pos + 1..].trim();
                if !cfg.sub_rules.contains_key(sub) {
                    errs.push(format!("rules[{i}]: SUB-RULE 引用的子规则 {sub:?} 不存在"));
                }
            } else {
                errs.push(format!("rules[{i}]: SUB-RULE 格式非法: {rule:?}"));
            }
        }
    }
    for (name, rules) in &cfg.sub_rules {
        if rules.is_empty() {
            errs.push(format!("sub-rules[{name:?}] 规则为空"));
        }
    }

    // 6. DNS nameserver 形式
    if cfg.dns.enable {
        for ns in cfg.dns.nameserver.iter().chain(cfg.dns.fallback.iter()) {
            let ok = ns.starts_with("https://")
                || ns.starts_with("tls://")
                || ns.starts_with("udp://")
                || ns.starts_with("tcp://")
                || ns.parse::<std::net::IpAddr>().is_ok()
                || ns.contains("://"); // 其它 scheme 留给运行时报错
            if !ok {
                errs.push(format!("dns.nameserver 项 {ns:?} 无法识别"));
            }
        }
    }

    if errs.is_empty() { Ok(()) } else { Err(errs) }
}

#[cfg(test)]
mod tests {
    use crate::Config;

    fn cfg_from_yaml(y: &str) -> Config {
        crate::parse(y, crate::Format::Yaml).unwrap()
    }

    #[test]
    fn group_cycle_detected() {
        let cfg = cfg_from_yaml(
            "proxies:\n  - name: a\n    type: socks5\n    server: 1.2.3.4\n    port: 1\nproxy-groups:\n  - name: G1\n    type: select\n    proxies: [G2]\n  - name: G2\n    type: select\n    proxies: [G1]\nrules:\n  - MATCH,DIRECT\n",
        );
        let errs = super::validate(&cfg).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("环")));
    }

    #[test]
    fn unknown_ref_detected() {
        let cfg = cfg_from_yaml(
            "proxy-groups:\n  - name: G\n    type: select\n    proxies: [不存在]\nrules:\n  - MATCH,DIRECT\n",
        );
        let errs = super::validate(&cfg).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("不存在")));
    }

    #[test]
    fn port_conflict_detected() {
        let cfg = cfg_from_yaml("mixed-port: 7890\nport: 7890\nrules:\n  - MATCH,DIRECT\n");
        let errs = super::validate(&cfg).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("7890")));
    }

    #[test]
    fn valid_config_passes() {
        let cfg = cfg_from_yaml(
            "mixed-port: 7890\nproxies:\n  - name: p1\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: aes-128-gcm\n    password: x\nproxy-groups:\n  - name: PROXY\n    type: select\n    proxies: [p1, DIRECT]\nrules:\n  - DOMAIN-SUFFIX,example.com,PROXY\n  - MATCH,DIRECT\n",
        );
        assert!(super::validate(&cfg).is_ok());
    }
}

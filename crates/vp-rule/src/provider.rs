//! RULE-SET 加载：mihomo 生态文本/ YAML 两种 format，domain / ipcidr / classical 三种 behavior。

use crate::domain::DomainTrie;
use crate::ipset::IpIntervalSetBuilder;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behavior {
    Domain,
    IpCidr,
    Classical,
}

impl Behavior {
    pub fn parse(s: &str) -> Result<Behavior, String> {
        match s {
            "domain" => Ok(Behavior::Domain),
            "ipcidr" => Ok(Behavior::IpCidr),
            "classical" => Ok(Behavior::Classical),
            other => Err(format!("未知 behavior: {other:?}")),
        }
    }
}

/// 解析后的 provider 载荷
pub enum ProviderPayload {
    Domain(Box<DomainSet>),
    Ip(Box<crate::ipset::IpIntervalSet>),
    /// classical：一组 (类型, 参数) 简化匹配；目标字段忽略（由 RULE-SET 行决定）
    Classical(Box<ClassicalSet>),
}

pub struct DomainSet {
    pub trie: DomainTrie,
    pub keywords: Vec<Box<str>>,
}

impl DomainSet {
    pub fn matches(&self, domain: &str) -> bool {
        if self.trie.is_match(domain) {
            return true;
        }
        let lower = domain.to_ascii_lowercase();
        self.keywords.iter().any(|k| lower.contains(&**k))
    }
}

pub struct ClassicalSet {
    pub domains: DomainSet,
    pub ips: crate::ipset::IpIntervalSet,
    pub ports: Vec<(u16, u16)>,
}

impl ClassicalSet {
    pub fn matches(
        &self,
        host: Option<&str>,
        dst_ip: Option<std::net::IpAddr>,
        dst_port: u16,
    ) -> bool {
        if let Some(h) = host {
            if self.domains.matches(h) {
                return true;
            }
        }
        if let Some(ip) = dst_ip {
            if self.ips.contains(ip) {
                return true;
            }
        }
        self.ports
            .iter()
            .any(|&(lo, hi)| dst_port >= lo && dst_port <= hi)
    }
}

/// 从文本行加载（自动识别 yaml payload / 纯 .list）
pub fn load_payload(text: &str, behavior: Behavior) -> Result<ProviderPayload, String> {
    let lines = extract_lines(text)?;
    match behavior {
        Behavior::Domain => {
            let mut trie = DomainTrie::new();
            let mut keywords = Vec::new();
            for line in lines {
                insert_domain_line(&mut trie, &mut keywords, &line)?;
            }
            Ok(ProviderPayload::Domain(Box::new(DomainSet {
                trie,
                keywords,
            })))
        }
        Behavior::IpCidr => {
            let mut b = IpIntervalSetBuilder::new();
            for line in lines {
                let cidr = line.split(',').next().unwrap_or("").trim();
                b.insert_cidr(cidr)?;
            }
            Ok(ProviderPayload::Ip(Box::new(b.build())))
        }
        Behavior::Classical => {
            let mut domains = DomainSet {
                trie: DomainTrie::new(),
                keywords: Vec::new(),
            };
            let mut ips = IpIntervalSetBuilder::new();
            let mut ports = Vec::new();
            for line in lines {
                let mut parts = line.splitn(3, ',');
                let ty = parts.next().unwrap_or("").trim();
                let payload = parts.next().unwrap_or("").trim();
                match ty {
                    "DOMAIN" => domains.trie.insert_exact(payload),
                    "DOMAIN-SUFFIX" => domains.trie.insert_suffix_all(payload),
                    "DOMAIN-KEYWORD" => keywords_push(&mut domains, payload),
                    "IP-CIDR" | "IP-CIDR6" => ips.insert_cidr(payload)?,
                    "DST-PORT" => ports.push(parse_port_range(payload)?),
                    _ => {} // SRC-*/PROCESS 等暂不进 provider
                }
            }
            Ok(ProviderPayload::Classical(Box::new(ClassicalSet {
                domains,
                ips: ips.build(),
                ports,
            })))
        }
    }
}

fn keywords_push(set: &mut DomainSet, kw: &str) {
    set.keywords.push(kw.to_ascii_lowercase().into());
}

/// mihomo 域名行语法：+.x / .x / x / keyword:x / regexp:x
pub fn insert_domain_line(
    trie: &mut DomainTrie,
    keywords: &mut Vec<Box<str>>,
    line: &str,
) -> Result<(), String> {
    let l = line.trim();
    if l.is_empty() {
        return Ok(());
    }
    if let Some(rest) = l.strip_prefix("+.") {
        trie.insert_suffix_all(rest);
    } else if let Some(rest) = l.strip_prefix('.') {
        trie.insert_suffix_all(rest);
    } else if let Some(rest) = l.strip_prefix("domain:") {
        trie.insert_exact(rest);
    } else if let Some(rest) = l.strip_prefix("keyword:") {
        keywords.push(rest.to_ascii_lowercase().into());
    } else if let Some(_rest) = l.strip_prefix("regexp:") {
        // M1 不在 provider 中支持正则行（极少数见），忽略
    } else {
        // 裸域名视为后缀匹配（mihomo 语义）
        trie.insert_suffix_all(l);
    }
    Ok(())
}

fn extract_lines(text: &str) -> Result<Vec<String>, String> {
    // YAML provider: 形如 "payload:\n  - '+.google.com'"
    let trimmed = text.trim_start();
    if trimmed.starts_with("payload:") {
        let v: serde_yaml::Value = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
        let arr = v
            .get("payload")
            .and_then(|p| p.as_sequence())
            .ok_or("payload 不是列表")?;
        return Ok(arr
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect());
    }
    Ok(text
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect())
}

pub fn parse_port_range(s: &str) -> Result<(u16, u16), String> {
    if let Some((a, b)) = s.split_once('-') {
        let a: u16 = a.trim().parse().map_err(|_| format!("非法端口 {s:?}"))?;
        let b: u16 = b.trim().parse().map_err(|_| format!("非法端口 {s:?}"))?;
        Ok((a.min(b), a.max(b)))
    } else {
        let p: u16 = s.parse().map_err(|_| format!("非法端口 {s:?}"))?;
        Ok((p, p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_list_syntax() {
        let text = "+.google.com\n.facebook.net\n# comment\nkeyword:taobao\ndomain:exact.com\n";
        let p = load_payload(text, Behavior::Domain).unwrap();
        match &p {
            ProviderPayload::Domain(d) => {
                assert!(d.matches("www.google.com"));
                assert!(d.matches("google.com"));
                assert!(d.matches("x.facebook.net"));
                assert!(!d.matches("facebook.net.evil.com"));
                assert!(d.matches("m.taobao.com")); // keyword
                assert!(d.matches("exact.com"));
                assert!(!d.matches("sub.exact.com"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn yaml_payload_format() {
        let yaml = "payload:\n  - '+.google.com'\n  - '.github.com'\n";
        let p = load_payload(yaml, Behavior::Domain).unwrap();
        match &p {
            ProviderPayload::Domain(d) => {
                assert!(d.matches("a.google.com"));
                assert!(d.matches("api.github.com"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn ipcidr_and_classical() {
        let p = load_payload("10.0.0.0/8\n192.168.0.0/16\n", Behavior::IpCidr).unwrap();
        match &p {
            ProviderPayload::Ip(s) => {
                assert!(s.contains("10.1.2.3".parse().unwrap()));
                assert!(!s.contains("11.0.0.1".parse().unwrap()));
            }
            _ => panic!(),
        }
        let c = load_payload(
            "DOMAIN-SUFFIX,github.com\nIP-CIDR,8.8.8.0/24\nDST-PORT,8443\n",
            Behavior::Classical,
        )
        .unwrap();
        match &c {
            ProviderPayload::Classical(s) => {
                assert!(s.matches(Some("www.github.com"), None, 80));
                assert!(s.matches(None, Some("8.8.8.8".parse().unwrap()), 80));
                assert!(s.matches(None, None, 8443));
                assert!(!s.matches(Some("x.com"), None, 80));
            }
            _ => panic!(),
        }
    }
}

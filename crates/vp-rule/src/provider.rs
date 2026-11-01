//! RULE-SET 加载：mihomo 生态文本/ YAML 两种 format，domain / ipcidr / classical 三种 behavior。

use crate::domain::DomainTrie;
use crate::ipset::IpIntervalSetBuilder;
use crate::{CompileEnv, MatchCtx, Matcher};

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
    /// classical：支持全部顶层规则类型（RULE-SET / SUB-RULE / MATCH 除外，对齐 mihomo）
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

/// 高频类型（DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR）并入共享集合，
/// 保证十万级规则集的内存与匹配速度；其余类型由规则引擎逐行编译进 `rest`。
pub struct ClassicalSet {
    pub domains: DomainSet,
    pub ips: crate::ipset::IpIntervalSet,
    pub rest: Vec<Matcher>,
    /// 是否有未带 no-resolve 的目标 IP 类规则（决定路由器是否惰性解析 DNS）
    needs_ip: bool,
}

impl ClassicalSet {
    pub fn matches(&self, ctx: &MatchCtx) -> bool {
        // ponytail: rest 逐条线性扫描（与顶层规则同代价）；若出现数千条 DOMAIN-REGEX /
        // SRC-IP-CIDR 的大列表，再按类型合并成 RegexSet / 区间集
        ctx.host.is_some_and(|h| self.domains.matches(h))
            || ctx.dst_ip.is_some_and(|ip| self.ips.contains(ip))
            || self.rest.iter().any(|m| m.r#match(ctx))
    }

    pub fn needs_dst_ip(&self) -> bool {
        self.needs_ip
    }
}

/// 解析规则集文本。`env` 为 None 时只做文本层校验（vp-app 拉取后校验内容用）：
/// classical 中需要规则引擎编译的行会被略过、也不告警，正式编译时才处理。
pub fn load_payload(
    text: &str,
    behavior: Behavior,
    env: Option<&CompileEnv>,
) -> Result<ProviderPayload, String> {
    let lines = extract_lines(text)?;
    match behavior {
        Behavior::Domain => {
            let mut trie = DomainTrie::new();
            let mut keywords = Vec::new();
            for line in lines {
                insert_domain_line(&mut trie, &mut keywords, &line);
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
            let mut rest = Vec::new();
            let mut needs_ip = false;
            // 同 mihomo：单行无法解析只告警跳过，不让整个规则集失效
            let skip = |line: &str, e: &str| {
                if env.is_some() {
                    tracing::warn!("classical 规则集跳过无法解析的行 {line:?}: {e}");
                }
            };
            for line in lines {
                let mut parts = line.split(',').map(str::trim);
                let ty = parts.next().unwrap_or("").to_ascii_uppercase();
                let payload = parts.next().unwrap_or("");
                match ty.as_str() {
                    "" => {}
                    // 空 payload 的域名行会让整个集合变成全匹配（空关键字 / 根后缀），必须拒收
                    "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" if payload.is_empty() => {
                        skip(&line, "缺少 payload")
                    }
                    "DOMAIN" => domains.trie.insert_exact(payload),
                    "DOMAIN-SUFFIX" => domains.trie.insert_suffix_all(payload),
                    "DOMAIN-KEYWORD" => keywords_push(&mut domains, payload),
                    "IP-CIDR" | "IP-CIDR6" => match ips.insert_cidr(payload) {
                        Ok(()) => needs_ip |= !parts.any(|p| p.eq_ignore_ascii_case("no-resolve")),
                        // 拉取校验（env = None）保持严格：宁可保留旧缓存，也不用可能截断的新内容
                        Err(e) if env.is_none() => return Err(format!("{line:?}: {e}")),
                        Err(e) => skip(&line, &e),
                    },
                    _ => {
                        let Some(env) = env else { continue };
                        match crate::compile_classical_line(&line, env) {
                            Ok(Some((m, no_resolve))) => {
                                needs_ip |= !no_resolve && m.needs_dst_ip();
                                rest.push(m);
                            }
                            Ok(None) => {}
                            Err(e) => skip(&line, &e),
                        }
                    }
                }
            }
            Ok(ProviderPayload::Classical(Box::new(ClassicalSet {
                domains,
                ips: ips.build(),
                rest,
                needs_ip,
            })))
        }
    }
}

fn keywords_push(set: &mut DomainSet, kw: &str) {
    set.keywords.push(kw.to_ascii_lowercase().into());
}

/// domain 行：mihomo 通配语法（`+.x` / `.x` / `*` / 裸域名精确，见 DomainTrie::insert_wildcard），
/// 另兼容 `domain:`（精确）与 `keyword:`（包含）前缀；`regexp:` 不支持，告警跳过。
pub fn insert_domain_line(trie: &mut DomainTrie, keywords: &mut Vec<Box<str>>, line: &str) {
    let l = line.trim();
    if l.is_empty() {
        return;
    }
    if let Some(rest) = l.strip_prefix("domain:") {
        trie.insert_exact(rest);
    } else if let Some(rest) = l.strip_prefix("keyword:") {
        let kw = rest.trim();
        if kw.is_empty() {
            // 空关键字包含于任何域名，会让整个集合变成全匹配
            tracing::warn!("domain 规则集跳过空关键字行: {l:?}");
        } else {
            keywords.push(kw.to_ascii_lowercase().into());
        }
    } else if l.starts_with("regexp:") {
        tracing::warn!("domain 规则集不支持正则行，已跳过: {l:?}");
    } else if !trie.insert_wildcard(l) {
        tracing::warn!("domain 规则集跳过缺少域名的行: {l:?}");
    }
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
        let p = load_payload(text, Behavior::Domain, None).unwrap();
        match &p {
            ProviderPayload::Domain(d) => {
                assert!(d.matches("www.google.com"));
                assert!(d.matches("google.com"));
                assert!(d.matches("x.facebook.net"));
                assert!(!d.matches("facebook.net")); // ".x" 仅子域
                assert!(!d.matches("facebook.net.evil.com"));
                assert!(d.matches("m.taobao.com")); // keyword
                assert!(d.matches("exact.com"));
                assert!(!d.matches("sub.exact.com"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn domain_semantics_match_mihomo() {
        let text = "example.com\n*.qq.com\nregexp:^ad\\.\n+.\n.\n";
        let p = load_payload(text, Behavior::Domain, None).unwrap();
        let ProviderPayload::Domain(d) = &p else {
            panic!()
        };
        // 裸域名 = 精确匹配（此前误作后缀，会把子域一并命中）
        assert!(d.matches("example.com") && !d.matches("www.example.com"));
        // `*` 恰好一级
        assert!(d.matches("a.qq.com"));
        assert!(!d.matches("qq.com") && !d.matches("a.b.qq.com"));
        // regexp: 行跳过而不是被当成域名
        assert!(!d.matches("ad.foo.com"));
        // "+." / "." 这类缺域名的行被拒收，不会把集合变成全匹配
        assert!(!d.matches("unrelated.org"));
    }

    #[test]
    fn yaml_payload_format() {
        let yaml = "payload:\n  - '+.google.com'\n  - '.github.com'\n";
        let p = load_payload(yaml, Behavior::Domain, None).unwrap();
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
        let p = load_payload("10.0.0.0/8\n192.168.0.0/16\n", Behavior::IpCidr, None).unwrap();
        match &p {
            ProviderPayload::Ip(s) => {
                assert!(s.contains("10.1.2.3".parse().unwrap()));
                assert!(!s.contains("11.0.0.1".parse().unwrap()));
            }
            _ => panic!(),
        }
        // 文本层校验（env = None）：高频类型照常入集合，其余类型不编译
        let c = load_payload(
            "DOMAIN-SUFFIX,github.com\nIP-CIDR,8.8.8.0/24\nPROCESS-NAME,x.exe\n",
            Behavior::Classical,
            None,
        )
        .unwrap();
        match &c {
            ProviderPayload::Classical(s) => {
                fn ctx(host: Option<&str>, ip: Option<std::net::IpAddr>) -> MatchCtx<'_> {
                    MatchCtx {
                        host,
                        dst_ip: ip,
                        src_ip: None,
                        dst_port: 80,
                        src_port: 0,
                        network: crate::Net::Tcp,
                        process: None,
                        inbound: "",
                        inbound_port: None,
                        inbound_user: None,
                    }
                }
                assert!(s.matches(&ctx(Some("www.github.com"), None)));
                assert!(s.matches(&ctx(None, Some("8.8.8.8".parse().unwrap()))));
                assert!(!s.matches(&ctx(Some("x.com"), None)));
                assert!(s.needs_dst_ip());
                assert!(s.rest.is_empty(), "env 为 None 时不编译其余类型");
            }
            _ => panic!(),
        }
        // 拉取校验对坏 IP-CIDR 行保持严格（截断的下载不能覆盖旧缓存）；正式编译时跳过（见 lib.rs 测试）
        assert!(
            load_payload(
                "IP-CIDR,8.8.8.0/24\nIP-CIDR,1.2.3",
                Behavior::Classical,
                None
            )
            .is_err()
        );
    }

    #[test]
    fn domain_empty_keyword_rejected() {
        let p = load_payload(
            "keyword:\nkeyword:   \nkeyword:ads\n",
            Behavior::Domain,
            None,
        )
        .unwrap();
        let ProviderPayload::Domain(d) = &p else {
            panic!()
        };
        assert!(d.matches("ads.example.com"));
        assert!(!d.matches("example.com"), "空关键字不能让集合全匹配");
    }
}

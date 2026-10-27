//! vp-rule：规则引擎。
//!
//! 规则行解析（括号感知分割）→ 编译期构造匹配器 → 热路径零分配匹配。

pub mod domain;
#[cfg(feature = "geoip")]
pub mod geoip;
pub mod geosite;
pub mod ipset;
pub mod process;
pub mod provider;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use crate::domain::DomainTrie;
use crate::ipset::IpIntervalSet;

// ---------------------------------------------------------------------------
// 匹配上下文
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Net {
    Tcp,
    Udp,
}

/// 匹配输入（由 Session 派生）
#[derive(Debug, Clone)]
pub struct MatchCtx<'a> {
    pub host: Option<&'a str>,
    /// 目标 IP（已解析，或目标本身就是 IP）
    pub dst_ip: Option<IpAddr>,
    pub src_ip: Option<IpAddr>,
    pub dst_port: u16,
    pub src_port: u16,
    pub network: Net,
    pub process: Option<&'a str>,
    pub inbound: &'a str,
    pub inbound_port: Option<u16>,
    pub inbound_user: Option<&'a str>,
}

// ---------------------------------------------------------------------------
// 匹配器
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicOp {
    And,
    Or,
    Not,
}

#[derive(Clone)]
pub enum Matcher {
    MatchAll,
    /// 永不匹配（用于缺少 geoip/geosite 数据库或不支持类别时的优雅降级，防止进程崩溃）
    NeverMatch,
    /// 精确域名
    Domain(Arc<DomainTrie>),
    /// 后缀域名
    DomainSuffix(Arc<DomainTrie>),
    DomainKeyword(Arc<str>),
    DomainRegex(Arc<regex::Regex>),
    IpCidr {
        set: Arc<IpIntervalSet>,
        src: bool,
    },
    GeoSite(Arc<geosite::CompiledSite>),
    #[cfg(feature = "geoip")]
    GeoIp(Arc<geoip::GeoIpMatcher>),
    Port {
        src: bool,
        ranges: Arc<Vec<(u16, u16)>>,
    },
    ProcessName(Arc<str>),
    ProcessPath(Arc<str>),
    Inbound(Arc<str>),
    InPort(Arc<Vec<(u16, u16)>>),
    InUser(Arc<str>),
    Network(Net),
    Logic {
        op: LogicOp,
        subs: Arc<Vec<Matcher>>,
    },
    /// 子规则集命中（SUB-RULE 的条件部分由 Logic 包装）
    SubRules(Arc<Vec<CompiledRule>>),
    RuleSetDomain(Arc<provider::DomainSet>),
    RuleSetIp(Arc<IpIntervalSet>),
    RuleSetClassical(Arc<provider::ClassicalSet>),
}

impl Matcher {
    fn r#match(&self, ctx: &MatchCtx) -> bool {
        match self {
            Matcher::MatchAll => true,
            Matcher::NeverMatch => false,
            Matcher::Domain(t) => ctx.host.is_some_and(|h| t.is_exact_match(h)),
            Matcher::DomainSuffix(t) => ctx.host.is_some_and(|h| t.is_match(h)),
            Matcher::DomainKeyword(k) => ctx
                .host
                .is_some_and(|h| h.to_ascii_lowercase().contains(&**k)),
            Matcher::DomainRegex(re) => ctx.host.is_some_and(|h| re.is_match(h)),
            Matcher::IpCidr { set, src } => match (*src, ctx.src_ip, ctx.dst_ip) {
                (true, Some(ip), _) | (false, _, Some(ip)) => set.contains(ip),
                _ => false,
            },
            Matcher::GeoSite(s) => ctx.host.is_some_and(|h| s.matches(h)),
            #[cfg(feature = "geoip")]
            Matcher::GeoIp(g) => ctx.dst_ip.is_some_and(|ip| g.matches(ip)),
            Matcher::Port { src, ranges } => {
                let p = if *src { ctx.src_port } else { ctx.dst_port };
                ranges.iter().any(|&(lo, hi)| p >= lo && p <= hi)
            }
            Matcher::ProcessName(n) => ctx.process.is_some_and(|p| p.eq_ignore_ascii_case(n)),
            Matcher::ProcessPath(p) => ctx.process.is_some_and(|x| x.eq_ignore_ascii_case(p)),
            Matcher::Inbound(n) => ctx.inbound == &**n,
            Matcher::InPort(ranges) => ctx
                .inbound_port
                .is_some_and(|p| ranges.iter().any(|&(lo, hi)| p >= lo && p <= hi)),
            Matcher::InUser(u) => ctx
                .inbound_user
                .is_some_and(|user| user.eq_ignore_ascii_case(u)),
            Matcher::Network(n) => ctx.network == *n,
            Matcher::Logic { op, subs } => match op {
                LogicOp::And => subs.iter().all(|m| m.r#match(ctx)),
                LogicOp::Or => subs.iter().any(|m| m.r#match(ctx)),
                LogicOp::Not => subs.iter().all(|m| !m.r#match(ctx)),
            },
            Matcher::SubRules(list) => list.iter().any(|r| r.matcher.r#match(ctx)),
            Matcher::RuleSetDomain(d) => ctx.host.is_some_and(|h| d.matches(h)),
            Matcher::RuleSetIp(s) => ctx.dst_ip.is_some_and(|ip| s.contains(ip)),
            Matcher::RuleSetClassical(c) => c.matches(ctx.host, ctx.dst_ip, ctx.dst_port),
        }
    }

    /// SUB-RULE 传导：返回子规则集中命中的 (target, raw)
    fn match_sub<'m>(&'m self, ctx: &MatchCtx) -> Option<(&'m str, &'m str)> {
        match self {
            Matcher::SubRules(list) => {
                for r in list.iter() {
                    if r.matcher.r#match(ctx) {
                        return Some(
                            r.matcher
                                .match_sub(ctx)
                                .unwrap_or((r.target.as_ref(), r.raw.as_ref())),
                        );
                    }
                }
                None
            }
            Matcher::Logic { subs, .. } => subs.iter().find_map(|m| m.match_sub(ctx)),
            _ => None,
        }
    }

    /// 是否依赖目标 IP（决定路由器是否需要先解析 DNS）
    pub fn needs_dst_ip(&self) -> bool {
        match self {
            Matcher::IpCidr { src: true, .. } => false,
            Matcher::IpCidr { src: false, .. } => true,
            #[cfg(feature = "geoip")]
            Matcher::GeoIp(_) => true,
            Matcher::RuleSetIp(_) => true,
            Matcher::RuleSetClassical(c) => !c.ips.is_empty(),
            Matcher::Logic { subs, .. } => subs.iter().any(|m| m.needs_dst_ip()),
            Matcher::SubRules(list) => list.iter().any(|r| r.matcher.needs_dst_ip()),
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// 引擎
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct CompiledRule {
    pub raw: Arc<str>,
    pub target: Arc<str>,
    pub matcher: Matcher,
    pub no_resolve: bool,
}

impl CompiledRule {
    pub fn r#match(&self, ctx: &MatchCtx) -> bool {
        self.matcher.r#match(ctx)
    }

    pub fn match_target<'a>(&'a self, ctx: &MatchCtx) -> Option<(&'a str, &'a str)> {
        if !self.matcher.r#match(ctx) {
            return None;
        }
        if let Some((target, rule)) = self.matcher.match_sub(ctx) {
            Some((target, rule))
        } else {
            Some((&self.target, &self.raw))
        }
    }

    pub fn needs_dst_ip(&self) -> bool {
        if self.no_resolve {
            false
        } else {
            self.matcher.needs_dst_ip()
        }
    }
}

pub struct MatchResult<'a> {
    pub target: &'a str,
    pub rule: &'a str,
}

#[derive(Default)]
pub struct RuleEngine {
    rules: Vec<CompiledRule>,
    needs_ip: bool,
}

impl RuleEngine {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn needs_dst_ip(&self) -> bool {
        self.needs_ip
    }

    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// 顺序匹配，返回首个命中（SUB-RULE 传导子规则命中的目标）
    pub fn r#match<'a>(&'a self, ctx: &MatchCtx) -> Option<MatchResult<'a>> {
        for r in &self.rules {
            if r.matcher.r#match(ctx) {
                if let Some((target, rule)) = r.matcher.match_sub(ctx) {
                    return Some(MatchResult { target, rule });
                }
                return Some(MatchResult {
                    target: &r.target,
                    rule: &r.raw,
                });
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// 编译
// ---------------------------------------------------------------------------

/// 规则目标（策略名）合法性由外部注入：节点名 + 组名 + 内置名
pub type KnownTargets<'a> = dyn Fn(&str) -> bool + Send + Sync + 'a;

pub struct CompileEnv<'a> {
    pub is_known_target: &'a KnownTargets<'a>,
    pub geosite: &'a Option<geosite::GeoSiteDb>,
    #[cfg(feature = "geoip")]
    pub geoip: &'a Option<geoip::GeoIpDb>,
    /// rule provider：name → (behavior, 文本内容)
    pub providers: &'a HashMap<String, (provider::Behavior, String)>,
    /// 子规则定义
    pub sub_rules: &'a HashMap<String, Vec<String>>,
}

pub fn compile(rules: &[String], env: &CompileEnv<'_>) -> Result<RuleEngine, Vec<String>> {
    let mut errs = Vec::new();
    let mut compiled = Vec::with_capacity(rules.len());
    for (i, raw) in rules.iter().enumerate() {
        match compile_one(raw, env, 0) {
            Ok(cr) => compiled.push(cr),
            Err(e) => errs.push(format!("rules[{i}]: {e}")),
        }
    }
    if errs.is_empty() {
        let needs_ip = compiled.iter().any(|r| r.needs_dst_ip());
        Ok(RuleEngine {
            rules: compiled,
            needs_ip,
        })
    } else {
        Err(errs)
    }
}

fn check_target(target: &str, env: &CompileEnv, raw: &str) -> Result<Arc<str>, String> {
    if target.is_empty() {
        return Err(format!("规则缺少目标: {raw:?}"));
    }
    if !(env.is_known_target)(target) {
        return Err(format!("规则目标 {target:?} 不存在"));
    }
    Ok(target.into())
}

fn compile_one(raw: &str, env: &CompileEnv, depth: usize) -> Result<CompiledRule, String> {
    if depth > 8 {
        return Err("规则嵌套过深".into());
    }
    let parts = split_top_level(raw);
    if parts.is_empty() {
        return Err("空规则".into());
    }
    let ty = parts[0].trim().to_ascii_uppercase();
    if ty == "MATCH" {
        let target = parts.get(1).map(|s| s.trim()).unwrap_or("");
        let target = check_target(target, env, raw)?;
        return Ok(CompiledRule {
            raw: raw.into(),
            target,
            matcher: Matcher::MatchAll,
            no_resolve: false,
        });
    }
    if ty == "SUB-RULE" {
        if parts.len() != 3 {
            return Err(format!("SUB-RULE 需要 (条件) 与子规则名: {raw:?}"));
        }
        let cond = parts[1]
            .trim()
            .strip_prefix('(')
            .and_then(|s| s.strip_suffix(')'))
            .ok_or_else(|| format!("SUB-RULE 条件需要括号包裹: {raw:?}"))?;
        let sub_name = parts[2].trim();
        let sub_rules = env
            .sub_rules
            .get(sub_name)
            .ok_or_else(|| format!("子规则 {sub_name:?} 不存在"))?;
        let mut sub_compiled = Vec::with_capacity(sub_rules.len());
        for sr in sub_rules {
            sub_compiled.push(compile_one(sr, env, depth + 1)?);
        }
        let cond_matcher = compile_logic_str(cond, env, depth + 1)?;
        return Ok(CompiledRule {
            raw: raw.into(),
            target: sub_name.into(),
            matcher: Matcher::Logic {
                op: LogicOp::And,
                subs: Arc::new(vec![
                    cond_matcher,
                    Matcher::SubRules(Arc::new(sub_compiled)),
                ]),
            },
            no_resolve: false,
        });
    }
    if matches!(ty.as_str(), "AND" | "OR" | "NOT") {
        if parts.len() != 3 {
            return Err(format!("{ty} 需要规则组与目标: {raw:?}"));
        }
        let inner = parts[1]
            .trim()
            .strip_prefix('(')
            .and_then(|s| s.strip_suffix(')'))
            .ok_or_else(|| format!("{ty} 规则组需要括号包裹: {raw:?}"))?;
        let target = check_target(parts[2].trim(), env, raw)?;
        let op = match ty.as_str() {
            "AND" => LogicOp::And,
            "OR" => LogicOp::Or,
            _ => LogicOp::Not,
        };
        let subs: Vec<Matcher> = split_rules_group(inner)
            .drain(..)
            .map(|s| {
                let s = s
                    .trim()
                    .strip_prefix('(')
                    .and_then(|x| x.strip_suffix(')'))
                    .unwrap_or_else(|| s.trim());
                parse_plain_rule(s, env, depth + 1, raw)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if subs.is_empty() {
            return Err(format!("{ty} 规则组为空: {raw:?}"));
        }
        return Ok(CompiledRule {
            raw: raw.into(),
            target,
            matcher: Matcher::Logic {
                op,
                subs: Arc::new(subs),
            },
            no_resolve: false,
        });
    }

    // 普通规则：TYPE,payload,target[,params]
    if parts.len() < 3 {
        return Err(format!("规则格式应为 TYPE,payload,target: {raw:?}"));
    }
    let payload = parts[1].trim();
    let target = check_target(parts[2].trim(), env, raw)?;
    let no_resolve = parts
        .iter()
        .skip(3)
        .any(|p| p.trim().eq_ignore_ascii_case("no-resolve"));
    let matcher = parse_plain_rule(&format!("{ty},{payload}"), env, depth, raw)?;
    Ok(CompiledRule {
        raw: raw.into(),
        target,
        matcher,
        no_resolve,
    })
}

/// 解析 "TYPE,payload"（不带目标）
fn parse_plain_rule(
    s: &str,
    env: &CompileEnv,
    _depth: usize,
    full: &str,
) -> Result<Matcher, String> {
    let parts = split_top_level(s);
    if parts.len() != 2 {
        return Err(format!("规则条件应为 TYPE,payload: {full:?}"));
    }
    let ty = parts[0].trim().to_ascii_uppercase();
    let payload = parts[1].trim();
    match ty.as_str() {
        "DOMAIN" => {
            let mut t = DomainTrie::new();
            t.insert_exact(payload);
            Ok(Matcher::Domain(Arc::new(t)))
        }
        "DOMAIN-SUFFIX" => {
            let mut t = DomainTrie::new();
            t.insert_suffix_all(payload);
            Ok(Matcher::DomainSuffix(Arc::new(t)))
        }
        "DOMAIN-KEYWORD" => Ok(Matcher::DomainKeyword(payload.to_ascii_lowercase().into())),
        "DOMAIN-REGEX" => {
            let re = regex::Regex::new(&format!("(?i){payload}"))
                .map_err(|e| format!("非法正则 {payload:?}: {e}"))?;
            Ok(Matcher::DomainRegex(Arc::new(re)))
        }
        "IP-CIDR" | "IP-CIDR6" => {
            let mut b = ipset::IpIntervalSetBuilder::new();
            for cidr in payload.split(',') {
                b.insert_cidr(cidr.trim())
                    .map_err(|e| format!("{e}: {full:?}"))?;
            }
            Ok(Matcher::IpCidr {
                set: Arc::new(b.build()),
                src: false,
            })
        }
        "SRC-IP-CIDR" => {
            let mut b = ipset::IpIntervalSetBuilder::new();
            for cidr in payload.split(',') {
                b.insert_cidr(cidr.trim())
                    .map_err(|e| format!("{e}: {full:?}"))?;
            }
            Ok(Matcher::IpCidr {
                set: Arc::new(b.build()),
                src: true,
            })
        }
        "GEOIP" => {
            #[cfg(feature = "geoip")]
            {
                let db = match env.geoip.as_ref() {
                    Some(db) => db,
                    None => {
                        tracing::warn!("未加载 GeoIP 数据库，GEOIP 规则将被跳过: {full:?}");
                        return Ok(Matcher::NeverMatch);
                    }
                };
                let m = match db.matcher(payload.to_ascii_lowercase()) {
                    Some(m) => m,
                    None => {
                        tracing::warn!("GeoIP 类别非法或未找到，规则将被跳过: {payload:?}");
                        return Ok(Matcher::NeverMatch);
                    }
                };
                Ok(Matcher::GeoIp(Arc::new(m)))
            }
            #[cfg(not(feature = "geoip"))]
            {
                let _ = (payload, env);
                tracing::warn!("此构建未启用 geoip 支持，规则将被跳过: {full:?}");
                Ok(Matcher::NeverMatch)
            }
        }
        "GEOSITE" => {
            let db = match env.geosite.as_ref() {
                Some(db) => db,
                None => {
                    tracing::warn!("未加载 GeoSite 数据库，GEOSITE 规则将被跳过: {full:?}");
                    return Ok(Matcher::NeverMatch);
                }
            };
            let tag = payload.to_ascii_lowercase();
            let site = match db.compile(&tag) {
                Some(s) => s,
                None => {
                    tracing::warn!("GEOSITE 中没有类别 {payload:?}，规则将被跳过");
                    return Ok(Matcher::NeverMatch);
                }
            };
            Ok(Matcher::GeoSite(site))
        }
        "DST-PORT" | "SRC-PORT" => {
            let mut ranges = Vec::new();
            for p in payload.split('/') {
                ranges.push(provider::parse_port_range(p.trim())?);
            }
            Ok(Matcher::Port {
                src: ty == "SRC-PORT",
                ranges: Arc::new(ranges),
            })
        }
        "PROCESS-PATH" => Ok(Matcher::ProcessPath(payload.into())),
        "PROCESS-NAME" => Ok(Matcher::ProcessName(payload.into())),
        "IN-NAME" | "IN-TAG" | "IN-TYPE" => Ok(Matcher::Inbound(payload.into())),
        "IN-USER" => Ok(Matcher::InUser(payload.into())),
        "IN-PORT" => {
            let mut ranges = Vec::new();
            for p in payload.split('/') {
                ranges.push(provider::parse_port_range(p.trim())?);
            }
            Ok(Matcher::InPort(Arc::new(ranges)))
        }
        "NETWORK" => {
            let n = match payload.to_ascii_uppercase().as_str() {
                "TCP" => Net::Tcp,
                "UDP" => Net::Udp,
                _ => return Err(format!("NETWORK 仅支持 TCP/UDP: {full:?}")),
            };
            Ok(Matcher::Network(n))
        }
        "RULE-SET" => {
            let (behavior, text) = env
                .providers
                .get(payload)
                .ok_or_else(|| format!("RULE-SET {payload:?} 未在 rule-providers 中定义"))?;
            let loaded = provider::load_payload(text, *behavior)
                .map_err(|e| format!("RULE-SET {payload:?} 加载失败: {e}"))?;
            Ok(match loaded {
                provider::ProviderPayload::Domain(d) => Matcher::RuleSetDomain(Arc::from(d)),
                provider::ProviderPayload::Ip(s) => Matcher::RuleSetIp(Arc::from(s)),
                provider::ProviderPayload::Classical(c) => Matcher::RuleSetClassical(Arc::from(c)),
            })
        }
        other => Err(format!("未知规则类型 {other:?}")),
    }
}

/// 逻辑条件字符串：AND,((A),(B)) 可嵌套；叶子为 TYPE,payload
fn compile_logic_str(s: &str, env: &CompileEnv, depth: usize) -> Result<Matcher, String> {
    let parts = split_top_level(s);
    if parts.is_empty() {
        return Err("空逻辑条件".into());
    }
    let ty = parts[0].trim().to_ascii_uppercase();
    if matches!(ty.as_str(), "AND" | "OR" | "NOT") && parts.len() == 2 {
        let inner = parts[1]
            .trim()
            .strip_prefix('(')
            .and_then(|x| x.strip_suffix(')'))
            .ok_or_else(|| format!("逻辑条件需要括号包裹: {s:?}"))?;
        let op = match ty.as_str() {
            "AND" => LogicOp::And,
            "OR" => LogicOp::Or,
            _ => LogicOp::Not,
        };
        let subs = split_rules_group(inner)
            .drain(..)
            .map(|x| {
                let x = x
                    .trim()
                    .strip_prefix('(')
                    .and_then(|y| y.strip_suffix(')'))
                    .unwrap_or_else(|| x.trim());
                compile_logic_str(x, env, depth + 1)
                    .or_else(|_| parse_plain_rule(x, env, depth + 1, s))
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(Matcher::Logic {
            op,
            subs: Arc::new(subs),
        });
    }
    parse_plain_rule(s, env, depth, s)
}

/// 顶层逗号分割（括号感知）
pub fn split_top_level(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut cur = String::new();
    for ch in s.chars() {
        match ch {
            '(' => {
                depth += 1;
                cur.push(ch);
            }
            ')' => {
                depth = depth.saturating_sub(1);
                cur.push(ch);
            }
            ',' if depth == 0 => out.push(std::mem::take(&mut cur)),
            _ => cur.push(ch),
        }
    }
    out.push(cur);
    out.retain(|p| !p.trim().is_empty());
    out
}

/// 分割 "(A),(B),(C)"（去掉最外层括号）
fn split_rules_group(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut cur = String::new();
    for ch in s.chars() {
        match ch {
            '(' => {
                depth += 1;
                if depth > 1 {
                    cur.push(ch);
                }
            }
            ')' => {
                depth = depth.saturating_sub(1);
                if depth >= 1 {
                    cur.push(ch);
                }
            }
            ',' if depth == 0 => out.push(std::mem::take(&mut cur)),
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_env() -> CompileEnv<'static> {
        static SUB: std::sync::OnceLock<HashMap<String, Vec<String>>> = std::sync::OnceLock::new();
        static GEOSITE: Option<geosite::GeoSiteDb> = None;
        #[cfg(feature = "geoip")]
        static GEOIP: Option<geoip::GeoIpDb> = None;
        static PROVIDERS: std::sync::OnceLock<HashMap<String, (provider::Behavior, String)>> =
            std::sync::OnceLock::new();
        let sub = SUB.get_or_init(|| {
            let mut m = HashMap::new();
            m.insert("sub1".to_string(), vec!["MATCH,DIRECT".to_string()]);
            m
        });
        CompileEnv {
            is_known_target: &|t| matches!(t, "DIRECT" | "REJECT" | "PROXY" | "AUTO"),
            geosite: &GEOSITE,
            #[cfg(feature = "geoip")]
            geoip: &GEOIP,
            providers: PROVIDERS.get_or_init(HashMap::new),
            sub_rules: sub,
        }
    }

    fn engine(rules: &[&str]) -> RuleEngine {
        let owned: Vec<String> = rules.iter().map(|s| s.to_string()).collect();
        compile(&owned, &test_env()).unwrap()
    }

    fn ctx<'a>(host: Option<&'a str>, ip: Option<IpAddr>) -> MatchCtx<'a> {
        MatchCtx {
            host,
            dst_ip: ip,
            src_ip: Some("127.0.0.1".parse().unwrap()),
            dst_port: 443,
            src_port: 50000,
            network: Net::Tcp,
            process: Some("chrome.exe"),
            inbound: "mixed-1",
            inbound_port: Some(7890),
            inbound_user: Some("alice"),
        }
    }

    #[test]
    fn basic_domain_rules() {
        let e = engine(&[
            "DOMAIN,example.com,DIRECT",
            "DOMAIN-SUFFIX,google.com,PROXY",
            "DOMAIN-KEYWORD,github,PROXY",
            "MATCH,REJECT",
        ]);
        assert_eq!(
            e.r#match(&ctx(Some("example.com"), None)).unwrap().target,
            "DIRECT"
        );
        assert_eq!(
            e.r#match(&ctx(Some("www.google.com"), None))
                .unwrap()
                .target,
            "PROXY"
        );
        assert_eq!(
            e.r#match(&ctx(Some("api.github.x.com"), None))
                .unwrap()
                .target,
            "PROXY"
        );
        assert_eq!(
            e.r#match(&ctx(None, Some("1.1.1.1".parse().unwrap())))
                .unwrap()
                .target,
            "REJECT"
        );
        assert_eq!(
            e.r#match(&ctx(Some("sub.example.com"), None))
                .unwrap()
                .target,
            "REJECT"
        );
    }

    #[test]
    fn ip_and_port_rules() {
        let e = engine(&[
            "IP-CIDR,10.0.0.0/8,DIRECT",
            "DST-PORT,8443,PROXY",
            "SRC-PORT,50000-50100,AUTO",
            "MATCH,DIRECT",
        ]);
        assert!(e.needs_dst_ip());
        assert_eq!(
            e.r#match(&ctx(Some("x"), Some("10.1.1.1".parse().unwrap())))
                .unwrap()
                .target,
            "DIRECT"
        );
        // 域名未解析时 IP 规则跳过，落到 SRC-PORT
        assert_eq!(e.r#match(&ctx(Some("x"), None)).unwrap().target, "AUTO");
    }

    #[test]
    fn logic_rules() {
        let e = engine(&[
            "AND,((DOMAIN-SUFFIX,cn),(DST-PORT,443)),PROXY",
            "OR,((DOMAIN-SUFFIX,a.com),(DOMAIN-SUFFIX,b.com)),AUTO",
            "NOT,((DOMAIN-SUFFIX,gov.cn)),PROXY",
            "MATCH,DIRECT",
        ]);
        assert_eq!(e.r#match(&ctx(Some("x.cn"), None)).unwrap().target, "PROXY");
        assert_eq!(
            e.r#match(&ctx(Some("y.b.com"), None)).unwrap().target,
            "AUTO"
        );
        // 注意 x.gov.cn 也满足 DOMAIN-SUFFIX,cn，但端口为 80 时不满足 AND 的 443 条件
        let mut p80 = ctx(Some("x.gov.cn"), None);
        p80.dst_port = 80;
        assert_eq!(e.r#match(&p80).unwrap().target, "DIRECT");
        assert_eq!(
            e.r#match(&ctx(Some("ok.com"), None)).unwrap().target,
            "PROXY"
        );
    }

    #[test]
    fn sub_rule() {
        let e = engine(&["SUB-RULE,(DOMAIN-SUFFIX,sub.com),sub1", "MATCH,REJECT"]);
        assert_eq!(
            e.r#match(&ctx(Some("a.sub.com"), None)).unwrap().target,
            "DIRECT"
        );
        assert_eq!(
            e.r#match(&ctx(Some("other.com"), None)).unwrap().target,
            "REJECT"
        );
    }

    #[test]
    fn unknown_target_rejected() {
        let owned = vec!["MATCH,不存在".to_string()];
        match compile(&owned, &test_env()) {
            Err(errs) => assert!(errs.iter().any(|e| e.contains("不存在"))),
            Ok(_) => panic!("应当报错"),
        }
    }

    #[test]
    fn split_paren_aware() {
        assert_eq!(
            split_top_level("SUB-RULE,(AND,((A,1),(B,2))),name"),
            vec!["SUB-RULE", "(AND,((A,1),(B,2)))", "name"]
        );
    }

    #[test]
    fn rule_set_provider() {
        let mut providers = HashMap::new();
        providers.insert(
            "myset".to_string(),
            (
                provider::Behavior::Domain,
                "+.gg.com\ndomain:only.com\n".to_string(),
            ),
        );
        let env = CompileEnv {
            is_known_target: &|t| matches!(t, "DIRECT" | "PROXY"),
            geosite: &None,
            #[cfg(feature = "geoip")]
            geoip: &None,
            providers: &providers,
            sub_rules: &HashMap::new(),
        };
        let rules = vec![
            "RULE-SET,myset,PROXY".to_string(),
            "MATCH,DIRECT".to_string(),
        ];
        let eng = compile(&rules, &env).unwrap();
        assert_eq!(
            eng.r#match(&ctx(Some("a.gg.com"), None)).unwrap().target,
            "PROXY"
        );
        assert_eq!(
            eng.r#match(&ctx(Some("only.com"), None)).unwrap().target,
            "PROXY"
        );
        assert_eq!(
            eng.r#match(&ctx(Some("only.com.x"), None)).unwrap().target,
            "DIRECT"
        );
    }

    #[test]
    fn process_and_network() {
        let e = engine(&[
            "PROCESS-NAME,chrome.exe,DIRECT",
            "NETWORK,UDP,PROXY",
            "MATCH,REJECT",
        ]);
        assert_eq!(
            e.r#match(&ctx(Some("a.com"), None)).unwrap().target,
            "DIRECT"
        );
        let mut u = ctx(Some("a.com"), None);
        u.process = None;
        u.network = Net::Udp;
        assert_eq!(e.r#match(&u).unwrap().target, "PROXY");
    }

    #[test]
    fn inbound_features_rules() {
        let e = engine(&[
            "IN-PORT,7890,PROXY",
            "IN-USER,alice,DIRECT",
            "IN-NAME,mixed-1,PROXY",
            "MATCH,REJECT",
        ]);
        let mut c = ctx(Some("a.com"), None);
        c.inbound_port = Some(7890);
        assert_eq!(e.r#match(&c).unwrap().target, "PROXY");

        c.inbound_port = Some(8080);
        c.inbound_user = Some("alice");
        assert_eq!(e.r#match(&c).unwrap().target, "DIRECT");

        c.inbound_user = Some("bob");
        c.inbound = "mixed-1";
        assert_eq!(e.r#match(&c).unwrap().target, "PROXY");

        c.inbound = "other";
        assert_eq!(e.r#match(&c).unwrap().target, "REJECT");
    }

    #[test]
    fn geoip_and_geosite_graceful_degradation() {
        // 在未加载 geoip/geosite 数据库的情况下，规则不应报错崩溃，而应优雅降级跳过
        let e = engine(&[
            "GEOIP,CN,DIRECT,no-resolve",
            "GEOIP,GOOGLE,PROXY",
            "GEOSITE,category-ads-all,REJECT",
            "MATCH,PROXY",
        ]);
        // 访问任意 IP 或域名，跳过未加载的规则，命中兜底规则
        assert_eq!(
            e.r#match(&ctx(Some("google.com"), Some("8.8.8.8".parse().unwrap())))
                .unwrap()
                .target,
            "PROXY"
        );
    }
}

//! vp-rule：规则引擎。
//!
//! 规则行解析（括号感知分割）→ 编译期构造匹配器 → 热路径零分配匹配。

#[cfg(feature = "geoip")]
pub mod asn;
pub mod consts;
pub mod domain;
pub mod dsl;
#[cfg(feature = "geoip")]
pub mod geoip;
pub mod geosite;
pub mod ipset;
pub mod mrs;
pub mod process;
pub mod provider;
pub mod srs;

#[cfg(feature = "geoip")]
pub use asn::{AsnDb, AsnMatcher};
#[cfg(feature = "geoip")]
pub use geoip::{GeoIpDb, GeoIpMatcher};

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

/// 匹配热路径跨规则共享缓存：多条同类规则复用一次昂贵查询/一次转换。
/// 单连接单线程使用，OnceLock 语义天然幂等。
#[derive(Debug, Default)]
pub struct MatchCtxCache {
    /// GEOIP mmdb 记录（按 IP 去重）：N 条 GEOIP 规则共享一次 mmdb 树遍历
    pub geo_record: std::sync::OnceLock<(IpAddr, Option<Box<crate::geoip::MmdbRecord>>)>,
    /// IP-ASN 原始 ASN 查询结果
    pub asn_result: std::sync::OnceLock<(IpAddr, Option<u32>)>,
    /// 小写化 host：N 条 DOMAIN-KEYWORD 共享一次转换
    pub host_lower: std::sync::OnceLock<Box<str>>,
}

impl Clone for MatchCtxCache {
    /// OnceLock 不可克隆：ctx 克隆（..base 展开构造新连接）时重置缓存，
    /// 新连接重新惰性填充
    fn clone(&self) -> Self {
        Self::default()
    }
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
    /// 跨规则共享查询缓存
    pub cache: MatchCtxCache,
}

impl MatchCtx<'_> {
    /// host 的小写形式：惰性转换一次（多条 DOMAIN-KEYWORD 规则共享，消除
    /// 每规则一次的堆分配）；重复调用同一 host 直接命中缓存
    fn lower_host(&self, host: &str) -> &str {
        self.cache
            .host_lower
            .get_or_init(|| host.to_ascii_lowercase().into_boxed_str())
            .as_ref()
    }
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
    #[cfg(feature = "geoip")]
    IpAsn {
        matcher: Arc<asn::AsnMatcher>,
        src: bool,
    },
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
    /// Google CEL 声明式表达式（短路求值与开销感知优化）
    Expr(Arc<dsl::CompiledExpr>),
}

impl Matcher {
    fn r#match(&self, ctx: &MatchCtx) -> bool {
        match self {
            Matcher::MatchAll => true,
            Matcher::NeverMatch => false,
            Matcher::Domain(t) => ctx.host.is_some_and(|h| t.is_exact_match(h)),
            Matcher::DomainSuffix(t) => ctx.host.is_some_and(|h| t.is_match(h)),
            Matcher::DomainKeyword(k) => ctx.host.is_some_and(|h| ctx.lower_host(h).contains(&**k)),
            Matcher::DomainRegex(re) => ctx.host.is_some_and(|h| re.is_match(h)),
            Matcher::IpCidr { set, src } => match (*src, ctx.src_ip, ctx.dst_ip) {
                (true, Some(ip), _) | (false, _, Some(ip)) => set.contains(ip),
                _ => false,
            },
            Matcher::GeoSite(s) => ctx.host.is_some_and(|h| s.matches(h)),
            #[cfg(feature = "geoip")]
            Matcher::GeoIp(g) => ctx
                .dst_ip
                .is_some_and(|ip| g.matches_cached(ip, &ctx.cache.geo_record)),
            #[cfg(feature = "geoip")]
            Matcher::IpAsn { matcher, src } => match (*src, ctx.src_ip, ctx.dst_ip) {
                (true, Some(ip), _) | (false, _, Some(ip)) => {
                    matcher.matches_cached(ip, &ctx.cache.asn_result)
                }
                _ => false,
            },
            Matcher::Port { src, ranges } => {
                let p = if *src { ctx.src_port } else { ctx.dst_port };
                ranges.iter().any(|&(lo, hi)| p >= lo && p <= hi)
            }
            Matcher::ProcessName(n) => ctx.process.is_some_and(|p| {
                if p.eq_ignore_ascii_case(n) {
                    return true;
                }
                let base = p.rsplit(['/', '\\']).next().unwrap_or(p);
                base.eq_ignore_ascii_case(n)
                    || base
                        .strip_suffix(".exe")
                        .is_some_and(|s| s.eq_ignore_ascii_case(n))
            }),
            Matcher::ProcessPath(pat) => ctx.process.is_some_and(|p| {
                if p.eq_ignore_ascii_case(pat) {
                    return true;
                }
                let pat_base = pat.rsplit(['/', '\\']).next().unwrap_or(pat);
                let p_base = p.rsplit(['/', '\\']).next().unwrap_or(p);
                !pat_base.is_empty() && p_base.eq_ignore_ascii_case(pat_base)
            }),
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
            Matcher::RuleSetClassical(c) => c.matches(ctx),
            Matcher::Expr(e) => e.eval(ctx),
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
            #[cfg(feature = "geoip")]
            Matcher::IpAsn { src: false, .. } => true,
            Matcher::RuleSetIp(_) => true,
            Matcher::RuleSetClassical(c) => c.needs_dst_ip(),
            Matcher::Logic { subs, .. } => subs.iter().any(|m| m.needs_dst_ip()),
            Matcher::SubRules(list) => list.iter().any(|r| r.matcher.needs_dst_ip()),
            Matcher::Expr(e) => e.needs_dst_ip(),
            _ => false,
        }
    }

    pub fn needs_process(&self) -> bool {
        match self {
            Matcher::ProcessName(_) | Matcher::ProcessPath(_) => true,
            Matcher::Logic { subs, .. } => subs.iter().any(|m| m.needs_process()),
            Matcher::SubRules(list) => list.iter().any(|r| r.matcher.needs_process()),
            Matcher::Expr(e) => e.needs_process(),
            _ => false,
        }
    }

    /// 是否依赖每连接动态特征（进程 / 源地址 / 源端口 / 入站标识）。
    /// 规则集完全不依赖时，路由决策对 (协议, 目标, 端口) 是幂等确定的，可安全缓存。
    pub fn uses_session_state(&self) -> bool {
        matcher_uses_session(self)
    }

    /// 是否含降级占位（NeverMatch：缺数据库 / 未知类型 / 嵌套过深）
    fn is_degraded(&self) -> bool {
        match self {
            Matcher::NeverMatch => true,
            Matcher::Logic { subs, .. } => subs.iter().any(Matcher::is_degraded),
            _ => false,
        }
    }
}

/// 组装逻辑规则。NOT 之下若含降级占位，取反会把"永不匹配"变成"全匹配"，
/// 因此整条 NOT 一并降级为 NeverMatch（降级原因解析器已告警）。
fn logic(op: LogicOp, subs: Vec<Matcher>) -> Matcher {
    if op == LogicOp::Not && subs.iter().any(Matcher::is_degraded) {
        return Matcher::NeverMatch;
    }
    Matcher::Logic {
        op,
        subs: Arc::new(subs),
    }
}

/// 递归判定单条 Matcher 是否依赖连接动态特征
fn matcher_uses_session(m: &Matcher) -> bool {
    match m {
        Matcher::ProcessName(_) | Matcher::ProcessPath(_) => true,
        Matcher::Inbound(_) | Matcher::InPort(_) | Matcher::InUser(_) => true,
        Matcher::IpCidr { src: true, .. } => true,
        Matcher::IpAsn { src: true, .. } => true,
        Matcher::Port { src: true, .. } => true,
        // 经典规则集内容不可静态判定（可能含 SRC 类条目），保守视为依赖
        Matcher::RuleSetClassical(_) => true,
        Matcher::Logic { subs, .. } => subs.iter().any(matcher_uses_session),
        Matcher::SubRules(list) => list.iter().any(|r| matcher_uses_session(&r.matcher)),
        _ => false,
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

#[derive(Default, Clone)]
pub struct RuleEngine {
    rules: Vec<CompiledRule>,
    needs_ip: bool,
    needs_process: bool,
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

    pub fn needs_process(&self) -> bool {
        self.needs_process
    }

    /// 规则集整体是否依赖连接动态特征（决定路由决策缓存能否启用）：
    /// 结构化 Matcher 静态判定；CEL 表达式按原文保守子串扫描（src/process/inbound）
    pub fn uses_session_state(&self) -> bool {
        self.rules.iter().any(|r| match &r.matcher {
            Matcher::Expr(_) => {
                let t = r.raw.as_ref();
                t.contains("src") || t.contains("process") || t.contains("inbound")
            }
            m => matcher_uses_session(m),
        })
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
    #[cfg(feature = "geoip")]
    pub asn: &'a Option<asn::AsnDb>,
    /// rule provider：name → (behavior, 载荷字节数据或文本)
    pub providers: &'a HashMap<String, (provider::Behavior, Vec<u8>)>,
    /// 子规则定义
    pub sub_rules: &'a HashMap<String, Vec<String>>,
}

pub fn compile(rules: &[String], env: &CompileEnv<'_>) -> Result<RuleEngine, Vec<String>> {
    let mut errs = Vec::new();
    let mut compiled = Vec::with_capacity(rules.len().min(1024));
    let mut cur_domain: Option<PendingDomainBatch> = None;
    let mut cur_ip: Option<PendingIpBatch> = None;

    let flush_domain = |cur: &mut Option<PendingDomainBatch>, out: &mut Vec<CompiledRule>| {
        if let Some(batch) = cur.take() {
            let raw = if batch.count > 1 {
                format!("DOMAIN-SET({} 条合并)", batch.count).into()
            } else {
                batch.raw_first
            };
            out.push(CompiledRule {
                raw,
                target: batch.target,
                matcher: Matcher::DomainSuffix(Arc::new(batch.trie)),
                no_resolve: batch.no_resolve,
            });
        }
    };

    let flush_ip = |cur: &mut Option<PendingIpBatch>, out: &mut Vec<CompiledRule>| {
        if let Some(batch) = cur.take() {
            let raw = if batch.count > 1 {
                format!("IP-CIDR-SET({} 条合并)", batch.count).into()
            } else {
                batch.raw_first
            };
            out.push(CompiledRule {
                raw,
                target: batch.target,
                matcher: Matcher::IpCidr {
                    set: Arc::new(batch.builder.build()),
                    src: batch.src,
                },
                no_resolve: batch.no_resolve,
            });
        }
    };

    for (i, raw) in rules.iter().enumerate() {
        // 快速无分配路径：针对 99% 的常见直白规则 (DOMAIN / DOMAIN-SUFFIX / IP-CIDR)
        if !raw.contains('(') {
            let mut parts = raw.split(',').map(str::trim).filter(|p| !p.is_empty());
            if let (Some(ty), Some(payload), Some(target)) =
                (parts.next(), parts.next(), parts.next())
            {
                let is_domain = ty.eq_ignore_ascii_case("DOMAIN");
                let is_suffix = ty.eq_ignore_ascii_case("DOMAIN-SUFFIX");
                let is_ip_cidr =
                    ty.eq_ignore_ascii_case("IP-CIDR") || ty.eq_ignore_ascii_case("IP-CIDR6");
                let is_src_ip = ty.eq_ignore_ascii_case("SRC-IP-CIDR");

                if is_domain || is_suffix {
                    flush_ip(&mut cur_ip, &mut compiled);
                    let no_resolve = parts.any(|p| p.eq_ignore_ascii_case("no-resolve"));
                    match check_target(target, env, raw) {
                        Ok(target_arc) => {
                            if let Some(cur) = &mut cur_domain {
                                if cur.target == target_arc && cur.no_resolve == no_resolve {
                                    if is_domain {
                                        cur.trie.insert_exact(payload);
                                    } else {
                                        cur.trie.insert_suffix_all(payload);
                                    }
                                    cur.count += 1;
                                    continue;
                                }
                            }
                            flush_domain(&mut cur_domain, &mut compiled);
                            let mut trie = DomainTrie::new();
                            if is_domain {
                                trie.insert_exact(payload);
                            } else {
                                trie.insert_suffix_all(payload);
                            }
                            cur_domain = Some(PendingDomainBatch {
                                target: target_arc,
                                no_resolve,
                                trie,
                                count: 1,
                                raw_first: raw.as_str().into(),
                            });
                            continue;
                        }
                        Err(e) => {
                            errs.push(format!("rules[{i}]: {e}"));
                            continue;
                        }
                    }
                } else if is_ip_cidr || is_src_ip {
                    flush_domain(&mut cur_domain, &mut compiled);
                    let no_resolve = parts.any(|p| p.eq_ignore_ascii_case("no-resolve"));
                    match check_target(target, env, raw) {
                        Ok(target_arc) => {
                            if let Some(cur) = &mut cur_ip {
                                if cur.target == target_arc
                                    && cur.no_resolve == no_resolve
                                    && cur.src == is_src_ip
                                {
                                    for cidr in payload.split(',') {
                                        let _ = cur.builder.insert_cidr(cidr.trim());
                                    }
                                    cur.count += 1;
                                    continue;
                                }
                            }
                            flush_ip(&mut cur_ip, &mut compiled);
                            let mut builder = ipset::IpIntervalSetBuilder::new();
                            for cidr in payload.split(',') {
                                let _ = builder.insert_cidr(cidr.trim());
                            }
                            cur_ip = Some(PendingIpBatch {
                                target: target_arc,
                                no_resolve,
                                src: is_src_ip,
                                builder,
                                count: 1,
                                raw_first: raw.as_str().into(),
                            });
                            continue;
                        }
                        Err(e) => {
                            errs.push(format!("rules[{i}]: {e}"));
                            continue;
                        }
                    }
                }
            }
        }

        // 遇到非 DOMAIN/IP 规则或复杂逻辑规则，先 flush 当前批次
        flush_domain(&mut cur_domain, &mut compiled);
        flush_ip(&mut cur_ip, &mut compiled);
        match compile_one(raw, env, 0) {
            Ok(cr) => compiled.push(cr),
            Err(e) => errs.push(format!("rules[{i}]: {e}")),
        }
    }
    flush_domain(&mut cur_domain, &mut compiled);
    flush_ip(&mut cur_ip, &mut compiled);

    if errs.is_empty() {
        let needs_ip = compiled.iter().any(|r| r.needs_dst_ip());
        let needs_process = compiled.iter().any(|r| r.matcher.needs_process());
        Ok(RuleEngine {
            rules: compiled,
            needs_ip,
            needs_process,
        })
    } else {
        Err(errs)
    }
}

struct PendingDomainBatch {
    target: Arc<str>,
    no_resolve: bool,
    trie: DomainTrie,
    count: usize,
    raw_first: Arc<str>,
}

struct PendingIpBatch {
    target: Arc<str>,
    no_resolve: bool,
    src: bool,
    builder: ipset::IpIntervalSetBuilder,
    count: usize,
    raw_first: Arc<str>,
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
    if ty == "EXPR" || ty == "CEL" {
        if parts.len() < 3 {
            return Err(format!("EXPR 规则需要表达式与目标: {raw:?}"));
        }
        let expr_str = parts[1].trim();
        let expr_clean = expr_str
            .strip_prefix('(')
            .and_then(|s| s.strip_suffix(')'))
            .unwrap_or(expr_str);
        let target = check_target(parts[2].trim(), env, raw)?;
        let no_resolve = parts
            .iter()
            .skip(3)
            .any(|p| p.trim().eq_ignore_ascii_case("no-resolve"));
        let compiled = dsl::compile_expr(expr_clean, env)
            .map_err(|e| format!("CEL 表达式解析失败 ({expr_clean}): {e}"))?;
        return Ok(CompiledRule {
            raw: raw.into(),
            target,
            matcher: Matcher::Expr(Arc::new(compiled)),
            no_resolve,
        });
    }
    if matches!(ty.as_str(), "AND" | "OR" | "NOT") {
        if parts.len() != 3 {
            return Err(format!("{ty} 需要规则组与目标: {raw:?}"));
        }
        let target = check_target(parts[2].trim(), env, raw)?;
        // 条件与 SUB-RULE 条件、classical 逻辑行共用 compile_logic_str（支持嵌套逻辑）
        let cond = format!("{ty},{}", parts[1].trim());
        return Ok(CompiledRule {
            raw: raw.into(),
            target,
            matcher: compile_logic_str(&cond, env, depth + 1)?,
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
    let matcher = parse_matcher(&ty, payload, env, depth, raw)?;
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
    depth: usize,
    full: &str,
) -> Result<Matcher, String> {
    let parts = split_top_level(s);
    if parts.len() != 2 {
        return Err(format!("规则条件应为 TYPE,payload: {full:?}"));
    }
    let ty = parts[0].trim().to_ascii_uppercase();
    let payload = parts[1].trim();
    parse_matcher(&ty, payload, env, depth, full)
}

/// classical 规则集的一行（无目标，可带 no-resolve 等参数），与顶层规则共用解析器。
/// 返回 `(匹配器, no_resolve)`；None 表示解析器已告警降级（未知类型 / 缺数据库）。
fn compile_classical_line(line: &str, env: &CompileEnv) -> Result<Option<(Matcher, bool)>, String> {
    let parts = split_top_level(line);
    let ty = parts
        .first()
        .map(|s| s.trim().to_ascii_uppercase())
        .unwrap_or_default();
    // 对齐 mihomo：classical 内不支持 MATCH / RULE-SET / SUB-RULE
    if matches!(ty.as_str(), "MATCH" | "RULE-SET" | "SUB-RULE") {
        return Err(format!("classical 规则集内不支持 {ty}"));
    }
    // 逻辑规则里嵌套的 RULE-SET 同样禁止：providers 置空，防止规则集互相引用无限递归
    let no_providers = HashMap::new();
    let env = &CompileEnv {
        providers: &no_providers,
        ..*env
    };
    let (matcher, no_resolve) = if matches!(ty.as_str(), "AND" | "OR" | "NOT") {
        (compile_logic_str(line, env, 1)?, false)
    } else {
        // DOMAIN-REGEX 的正则可能含逗号：同 mihomo，类型之后的全部内容都是 payload
        let payload = if ty == "DOMAIN-REGEX" {
            line.split_once(',').map(|(_, p)| p)
        } else {
            parts.get(1).map(String::as_str)
        }
        .map(str::trim)
        .filter(|p| !p.is_empty()) // 空正则会匹配一切，与缺 payload 同样拒收
        .ok_or_else(|| format!("规则格式应为 TYPE,payload: {line:?}"))?;
        let no_resolve = parts
            .iter()
            .skip(2)
            .any(|p| p.trim().eq_ignore_ascii_case("no-resolve"));
        (parse_matcher(&ty, payload, env, 1, line)?, no_resolve)
    };
    Ok((!matches!(matcher, Matcher::NeverMatch)).then_some((matcher, no_resolve)))
}

fn parse_matcher(
    ty: &str,
    payload: &str,
    env: &CompileEnv,
    _depth: usize,
    full: &str,
) -> Result<Matcher, String> {
    match ty {
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
        "IP-ASN" | "SRC-IP-ASN" => {
            #[cfg(feature = "geoip")]
            {
                let db = match env.asn.as_ref() {
                    Some(db) => db,
                    None => {
                        tracing::warn!(
                            "未加载 ASN 数据库 (ASN.mmdb / GeoLite2-ASN.mmdb)，规则将被跳过: {full:?}"
                        );
                        return Ok(Matcher::NeverMatch);
                    }
                };
                let Some(matcher) = db.matcher(payload) else {
                    tracing::warn!("IP-ASN payload 非法（应为 ASN 号）: {full:?}");
                    return Ok(Matcher::NeverMatch);
                };
                Ok(Matcher::IpAsn {
                    matcher: Arc::new(matcher),
                    src: ty == "SRC-IP-ASN",
                })
            }
            #[cfg(not(feature = "geoip"))]
            {
                let _ = (ty, payload, env);
                tracing::warn!("此构建未启用 geoip 支持，规则将被跳过: {full:?}");
                Ok(Matcher::NeverMatch)
            }
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
            let (behavior, bytes) = env
                .providers
                .get(payload)
                .ok_or_else(|| format!("RULE-SET {payload:?} 未在 rule-providers 中定义"))?;
            let loaded = provider::load_payload_bytes(bytes, *behavior, Some(env))
                .map_err(|e| format!("RULE-SET {payload:?} 加载失败: {e}"))?;
            Ok(match loaded {
                provider::ProviderPayload::Domain(d) => Matcher::RuleSetDomain(Arc::from(d)),
                provider::ProviderPayload::Ip(s) => Matcher::RuleSetIp(Arc::from(s)),
                provider::ProviderPayload::Classical(c) => Matcher::RuleSetClassical(Arc::from(c)),
            })
        }
        "EXPR" | "CEL" => {
            let expr_clean = payload
                .strip_prefix('(')
                .and_then(|s| s.strip_suffix(')'))
                .unwrap_or(payload);
            let compiled = dsl::compile_expr(expr_clean, env)
                .map_err(|e| format!("CEL 表达式解析失败 ({expr_clean}): {e}"))?;
            Ok(Matcher::Expr(Arc::new(compiled)))
        }
        other => {
            // 未知规则类型（如暂不支持的 IP-ASN 变体 / 拼写差异）：
            // 警告后跳过而非拒绝启动，保证 mihomo 等来源的配置可平滑运行
            tracing::warn!("未知规则类型 {other:?}，规则将被跳过: {full:?}");
            Ok(Matcher::NeverMatch)
        }
    }
}

/// 逻辑条件字符串：AND,((A),(B)) 可嵌套；叶子为 TYPE,payload
fn compile_logic_str(s: &str, env: &CompileEnv, depth: usize) -> Result<Matcher, String> {
    // classical 规则集的行来自远端：限制嵌套深度，防止构造的深层括号递归打爆栈
    if depth > 8 {
        return Err("规则嵌套过深".into());
    }
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
                // 子项本身是逻辑表达式时保留它的真实错误（嵌套过深 / 叶子非法）；
                // 退回 parse_plain_rule 会把 AND/NOT 当成"未知规则类型"，日志指错原因
                let head = x.split(',').next().unwrap_or("").trim();
                if ["AND", "OR", "NOT"]
                    .iter()
                    .any(|op| head.eq_ignore_ascii_case(op))
                {
                    compile_logic_str(x, env, depth + 1)
                } else {
                    parse_plain_rule(x, env, depth + 1, s)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        // 空组：AND / NOT 对空集合恒为真，会变成全匹配
        if subs.is_empty() {
            return Err(format!("{ty} 规则组为空: {s:?}"));
        }
        return Ok(logic(op, subs));
    }
    parse_plain_rule(s, env, depth, s)
}

/// 顶层逗号分割（括号、中括号与引号感知）
pub fn split_top_level(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut in_quote = None;
    let mut escaped = false;
    let mut cur = String::new();

    for ch in s.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            cur.push(ch);
            continue;
        }
        if let Some(q) = in_quote {
            if ch == q {
                in_quote = None;
            }
            cur.push(ch);
            continue;
        }
        match ch {
            '"' | '\'' => {
                in_quote = Some(ch);
                cur.push(ch);
            }
            '(' => {
                paren_depth += 1;
                cur.push(ch);
            }
            ')' => {
                paren_depth = paren_depth.saturating_sub(1);
                cur.push(ch);
            }
            '[' => {
                bracket_depth += 1;
                cur.push(ch);
            }
            ']' => {
                bracket_depth = bracket_depth.saturating_sub(1);
                cur.push(ch);
            }
            ',' if paren_depth == 0 && bracket_depth == 0 => {
                out.push(std::mem::take(&mut cur));
            }
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
        #[cfg(feature = "geoip")]
        static ASN: Option<asn::AsnDb> = None;
        static PROVIDERS: std::sync::OnceLock<HashMap<String, (provider::Behavior, Vec<u8>)>> =
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
            #[cfg(feature = "geoip")]
            asn: &ASN,
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
            cache: Default::default(),
        }
    }

    // ------------------------- 规模化回归 -------------------------

    /// 数万条混合规则：编译 + 匹配语义保序 + 性能冒烟。
    /// 覆盖：相邻同 target 批量合并、跨 target 交替、IP/域名混排、keyword、MATCH 兜底。
    #[test]
    fn scale_mixed_rules_20k() {
        let mut rules: Vec<String> = Vec::with_capacity(20_013);
        // 1.2 万条 DOMAIN-SUFFIX 交替 target（PROXY/DIRECT 各 6000，制造多次批量切换）
        for i in 0..12_000 {
            let t = if i % 2 == 0 { "PROXY" } else { "DIRECT" };
            rules.push(format!("DOMAIN-SUFFIX,s{i}.example.com,{t}"));
        }
        // 6000 条 IP-CIDR（交替 DIRECT/REJECT）
        for i in 0..6_000 {
            let t = if i % 2 == 0 { "DIRECT" } else { "REJECT" };
            rules.push(format!("IP-CIDR,10.{i}.0.0/16,{t}"));
        }
        // 2000 条 DOMAIN 精确
        for i in 0..2_000 {
            rules.push(format!("DOMAIN,exact{i}.example.org,PROXY"));
        }
        // 100 条 DOMAIN-KEYWORD
        for i in 0..100 {
            rules.push(format!("DOMAIN-KEYWORD,keyword{i},REJECT"));
        }
        // 12 条 GEOIP（真实机场常见量；无数据库环境下降级为 NeverMatch 不拦截）
        for code in [
            "CN", "US", "JP", "HK", "SG", "TW", "KR", "DE", "FR", "RU", "IN", "LAN",
        ] {
            rules.push(format!("GEOIP,{code},DIRECT"));
        }
        rules.push("MATCH,PROXY".into());

        let t0 = std::time::Instant::now();
        let owned: Vec<String> = rules;
        let e = compile(&owned, &test_env()).unwrap();
        let compile_ms = t0.elapsed().as_millis();
        println!("20k 规则编译: {compile_ms}ms, 编译后条目: {}", e.len());
        assert!(compile_ms < 10_000, "编译耗时异常: {compile_ms}ms");

        // 语义保序：各目标命中正确（域名段 PROXY/DIRECT 交替、keyword 段 REJECT）
        let hit = |h: &str| e.r#match(&ctx(Some(h), None)).unwrap().target.to_string();
        assert_eq!(hit("s0.example.com"), "PROXY");
        assert_eq!(hit("s1.example.com"), "DIRECT");
        assert_eq!(hit("s11999.example.com"), "DIRECT");
        assert_eq!(hit("exact1999.example.org"), "PROXY");
        assert_eq!(hit("x.keyword5.yz"), "REJECT");
        assert_eq!(hit("nomatch.anything.io"), "PROXY");
        // IP 目标命中 CIDR（域名规则不应拦截）
        let hip = |ip: &str| {
            e.r#match(&ctx(None, Some(ip.parse().unwrap())))
                .unwrap()
                .target
                .to_string()
        };
        assert_eq!(hip("10.0.1.2"), "DIRECT");
        assert_eq!(hip("10.1.1.2"), "REJECT");
        assert_eq!(hip("10.59.0.0"), "REJECT");
        assert_eq!(hip("8.8.8.8"), "PROXY");

        // 匹配性能冒烟：1 万次首连级匹配（每次独立 ctx = 缓存 miss 场景），
        // 分段计时定位热点段
        let t1 = std::time::Instant::now();
        for i in 0..2_000 {
            let h = format!("perf{i}.example.com");
            let _ = e.r#match(&ctx(Some(&h), None));
        }
        let full_ms = t1.elapsed().as_millis();
        println!("2 千次全量扫描(未命中): {full_ms}ms");

        // 分段：仅前 12k 域名段（DOMAIN-SUFFIX 交替，每条独立 trie）
        let mut rules_dom: Vec<String> = (0..12_000)
            .map(|i| {
                let t = if i % 2 == 0 { "PROXY" } else { "DIRECT" };
                format!("DOMAIN-SUFFIX,s{i}.example.com,{t}")
            })
            .collect();
        rules_dom.push("MATCH,PROXY".into());
        let e_dom = compile(&rules_dom, &test_env()).unwrap();
        let t2 = std::time::Instant::now();
        for i in 0..2_000 {
            let h = format!("perf{i}.example.com");
            let _ = e_dom.r#match(&ctx(Some(&h), None));
        }
        let dom_ms = t2.elapsed().as_millis();
        println!("2 千次仅 12k 域名段: {dom_ms}ms");

        // 分段：仅 6k IP 段（IP 目标）
        let mut rules_ip: Vec<String> = (0..6_000)
            .map(|i| {
                let t = if i % 2 == 0 { "DIRECT" } else { "REJECT" };
                format!("IP-CIDR,10.{i}.0.0/16,{t}")
            })
            .collect();
        rules_ip.push("MATCH,PROXY".into());
        let e_ip = compile(&rules_ip, &test_env()).unwrap();
        let t3 = std::time::Instant::now();
        for i in 0..2_000u32 {
            let ip = format!("192.168.{}.{}", i % 250 + 1, i / 250 + 1);
            let _ = e_ip.r#match(&ctx(None, Some(ip.parse().unwrap())));
        }
        let ip_ms = t3.elapsed().as_millis();
        println!("2 千次仅 6k IP 段(未命中): {ip_ms}ms");

        // 分段：域名命中第一条（最优情形）
        let t4 = std::time::Instant::now();
        for _ in 0..2_000 {
            let _ = e_dom.r#match(&ctx(Some("s0.example.com"), None));
        }
        let hit_ms = t4.elapsed().as_millis();
        println!("2 千次首条命中: {hit_ms}ms");

        // 微基准：单条 trie 直查 1.2 万次（等价一次线性扫描的 trie 工作量，
        // 绕过主循环）——把"主循环开销"与"trie 查询开销"分离
        let trie = e_dom
            .rules()
            .iter()
            .find_map(|r| match &r.matcher {
                Matcher::DomainSuffix(t) => Some(t.clone()),
                _ => None,
            })
            .unwrap();
        let t5 = std::time::Instant::now();
        for i in 0..12_000 {
            let h = format!("perf{i}.example.com");
            std::hint::black_box(trie.is_match(&h));
        }
        let trie_ms = t5.elapsed().as_millis();
        println!("1.2 万次单 trie 直查: {trie_ms}ms");

        // 微基准：主循环空转（全部规则快速不命中：host=None 走 1.2 万条 Domain 分支）
        let t6 = std::time::Instant::now();
        for _ in 0..2_000 {
            let _ = e_dom.r#match(&ctx(None, None));
        }
        let dispatch_ms = t6.elapsed().as_millis();
        println!("2 千次主循环 host=None: {dispatch_ms}ms");

        // 最坏形态基线：交替 target 使批量合并完全失效（真实订阅为连续同
        // target，合并后仅几十条批量规则、首连 <2µs——此处是有意的压力形态）。
        // FNV 哈希器 + Cow 小写化后约 6.6ms/次；上界 20s 只防数量级退化。
        let match_ms = full_ms;
        assert!(match_ms < 20_000, "全量扫描性能异常: {match_ms}ms");
        assert!(trie_ms < 100, "单 trie 直查异常: {trie_ms}ms");
        assert!(dispatch_ms < 500, "主循环空转异常: {dispatch_ms}ms");
    }

    /// 规则引擎并发匹配：8 线程 × 5000 次（&self 共享引用），结果一致且无 panic。
    /// MatchCtxCache 为 per-ctx 独立缓存，引擎本体不可变共享。
    #[test]
    fn concurrent_match_thread_safety() {
        let e = engine(&[
            "DOMAIN-SUFFIX,google.com,PROXY",
            "DOMAIN-KEYWORD,ads,REJECT",
            "IP-CIDR,10.0.0.0/8,DIRECT",
            "MATCH,AUTO",
        ]);
        let handles: Vec<_> = (0..8)
            .map(|t| {
                let e = e.clone();
                std::thread::spawn(move || {
                    for i in 0..5_000u32 {
                        let h = format!("{}.google.com", i);
                        let r = e.r#match(&ctx(Some(&h), None)).unwrap().target.to_string();
                        assert_eq!(r, "PROXY", "线程 {t} 第 {i} 轮结果漂移");
                        let r2 = e
                            .r#match(&ctx(Some("ads.example.net"), None))
                            .unwrap()
                            .target
                            .to_string();
                        assert_eq!(r2, "REJECT");
                        let r3 = e
                            .r#match(&ctx(None, Some("10.1.2.3".parse().unwrap())))
                            .unwrap()
                            .target
                            .to_string();
                        assert_eq!(r3, "DIRECT");
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    }

    /// DOMAIN-KEYWORD：host 大写时经惰性缓存转换后仍匹配（多规则共享一次转换），
    /// 且第二次查询命中缓存路径结果一致
    #[test]
    fn domain_keyword_case_insensitive_shared_cache() {
        let e = engine(&["DOMAIN-KEYWORD,google,PROXY"]);
        let c = ctx(Some("WWW.GOOGLE.COM"), None);
        assert!(c.cache.host_lower.get().is_none(), "首查前缓存应为空");
        assert!(e.r#match(&c).is_some());
        assert!(c.cache.host_lower.get().is_some(), "首查后缓存应已填充");
        assert!(e.r#match(&c).is_some(), "缓存路径下仍应匹配");
        let miss = ctx(Some("baidu.com"), None);
        assert!(e.r#match(&miss).is_none());
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
    fn test_adjacent_domain_rules_merging() {
        let e = engine(&[
            "DOMAIN,example.com,PROXY",
            "DOMAIN-SUFFIX,google.com,PROXY",
            "DOMAIN-SUFFIX,youtube.com,PROXY",
            "DOMAIN,twitter.com,PROXY",
            "MATCH,DIRECT",
        ]);
        // 4 条连续 domain 规则合并为 1 条 DOMAIN-SET 规则，总共 2 条规则！
        assert_eq!(e.len(), 2);
        assert_eq!(
            e.r#match(&ctx(Some("example.com"), None)).unwrap().target,
            "PROXY"
        );
        assert_eq!(
            e.r#match(&ctx(Some("mail.google.com"), None))
                .unwrap()
                .target,
            "PROXY"
        );
        assert_eq!(
            e.r#match(&ctx(Some("www.youtube.com"), None))
                .unwrap()
                .target,
            "PROXY"
        );
        assert_eq!(
            e.r#match(&ctx(Some("twitter.com"), None)).unwrap().target,
            "PROXY"
        );
        assert_eq!(
            e.r#match(&ctx(Some("sub.twitter.com"), None))
                .unwrap()
                .target,
            "DIRECT"
        );
        assert_eq!(
            e.r#match(&ctx(Some("baidu.com"), None)).unwrap().target,
            "DIRECT"
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
    fn top_level_nested_logic() {
        // 此前顶层 AND/OR/NOT 的子项不支持嵌套逻辑：OR 被当成未知类型，整条规则静默失效
        let e = engine(&[
            "AND,((NETWORK,UDP),(OR,((DST-PORT,443),(DST-PORT,80)))),REJECT",
            "MATCH,DIRECT",
        ]);
        let mut c = ctx(Some("x.com"), None); // 默认 TCP / 443
        assert_eq!(e.r#match(&c).unwrap().target, "DIRECT");
        c.network = Net::Udp;
        assert_eq!(e.r#match(&c).unwrap().target, "REJECT");
        c.dst_port = 53;
        assert_eq!(e.r#match(&c).unwrap().target, "DIRECT");
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
                "+.gg.com\ndomain:only.com\n".as_bytes().to_vec(),
            ),
        );
        let env = CompileEnv {
            is_known_target: &|t| matches!(t, "DIRECT" | "PROXY"),
            geosite: &None,
            #[cfg(feature = "geoip")]
            geoip: &None,
            #[cfg(feature = "geoip")]
            asn: &None,
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
    fn classical_rule_set_compiles_all_rule_types() {
        let classical = [
            "DOMAIN-SUFFIX,github.com",
            "PROCESS-NAME,telegram.exe",
            "SRC-IP-CIDR,192.168.1.201/32",
            "DST-PORT,8000-8100/9443",
            "AND,((NETWORK,UDP),(DOMAIN-KEYWORD,quic))",
            r"DOMAIN-REGEX,^api[0-9]{1,3}\.example\.com$",
            "IP-CIDR,8.8.8.0/24,no-resolve",
            // 以下各行均应告警跳过，而不是让整个规则集失败
            "GEOIP,CN",
            "MATCH",
            "RULE-SET,cls",
            "AND,((RULE-SET,cls),(NETWORK,TCP))",
            "IP-CIDR,not-a-cidr",
            "UNKNOWN-TYPE,x",
            // 空 payload 不能把整个集合变成全匹配（下方 a.com → DIRECT 的断言兜底验证）
            "DOMAIN-KEYWORD,",
            "DOMAIN-SUFFIX",
            "DOMAIN-REGEX,",
            // NOT 包住降级的子规则（缺 GeoIP 库 / 嵌套逻辑解析失败）不能取反成全匹配
            "NOT,((GEOIP,CN))",
            "NOT,((AND,((NETWORK,ICMP),(DOMAIN,a.com))))",
            // 空规则组：AND / NOT 对空集合恒真，同样不能变成全匹配
            "AND,()",
            "NOT,(())",
        ]
        .join("\n");
        let mut providers = HashMap::new();
        providers.insert(
            "cls".to_string(),
            (provider::Behavior::Classical, classical.into_bytes()),
        );
        providers.insert(
            "cls-ip".to_string(),
            (
                provider::Behavior::Classical,
                "IP-CIDR,1.0.0.0/8\n".as_bytes().to_vec(),
            ),
        );
        let env = CompileEnv {
            is_known_target: &|t| matches!(t, "DIRECT" | "PROXY"),
            geosite: &None,
            #[cfg(feature = "geoip")]
            geoip: &None,
            #[cfg(feature = "geoip")]
            asn: &None,
            providers: &providers,
            sub_rules: &HashMap::new(),
        };
        let eng = compile(
            &["RULE-SET,cls,PROXY".to_string(), "MATCH,DIRECT".to_string()],
            &env,
        )
        .unwrap();
        let hit = |c: &MatchCtx| eng.r#match(c).unwrap().target.to_string();

        assert_eq!(hit(&ctx(Some("x.github.com"), None)), "PROXY");
        assert_eq!(hit(&ctx(Some("a.com"), None)), "DIRECT");

        let mut c = ctx(Some("a.com"), None);
        c.process = Some(r"C:\Apps\Telegram.exe");
        assert_eq!(hit(&c), "PROXY", "PROCESS-NAME");

        let mut c = ctx(Some("a.com"), None);
        c.src_ip = Some("192.168.1.201".parse().unwrap());
        assert_eq!(hit(&c), "PROXY", "SRC-IP-CIDR");

        for (port, want) in [(9443, "PROXY"), (8050, "PROXY"), (8101, "DIRECT")] {
            let mut c = ctx(Some("a.com"), None);
            c.dst_port = port;
            assert_eq!(hit(&c), want, "DST-PORT 多段 {port}");
        }

        let mut c = ctx(Some("quic.a.com"), None);
        c.network = Net::Udp;
        assert_eq!(hit(&c), "PROXY", "AND 逻辑规则");
        c.network = Net::Tcp;
        assert_eq!(hit(&c), "DIRECT");

        assert_eq!(
            hit(&ctx(Some("api12.example.com"), None)),
            "PROXY",
            "正则含逗号"
        );
        assert_eq!(hit(&ctx(None, Some("8.8.8.8".parse().unwrap()))), "PROXY");
        // 唯一的目标 IP 行带 no-resolve：不应触发 DNS 解析
        assert!(!eng.needs_dst_ip());

        let eng_ip = compile(&["RULE-SET,cls-ip,PROXY".to_string()], &env).unwrap();
        assert!(eng_ip.needs_dst_ip());
    }

    #[test]
    fn deeply_nested_logic_rejected_instead_of_overflowing() {
        // 远端规则集可以构造任意深度的嵌套：超过上限应报出真实原因，而不是递归到栈溢出
        let n = 20_000;
        let line = format!("{}DOMAIN,a.com{}", "NOT,((".repeat(n), "))".repeat(n));
        let err = compile_logic_str(&line, &test_env(), 0)
            .err()
            .expect("超深嵌套应当报错");
        assert!(err.contains("嵌套过深"), "{err}");
        // 上限之内的正常嵌套照常工作
        let ok = compile_logic_str("NOT,((NOT,((DOMAIN,a.com))))", &test_env(), 0).unwrap();
        assert!(ok.r#match(&ctx(Some("a.com"), None)));
        assert!(!ok.r#match(&ctx(Some("b.com"), None)));
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
            // NOT 包住降级规则：必须同样跳过，而不是取反成全匹配把流量全部 REJECT
            "NOT,((GEOIP,CN)),REJECT",
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

    #[test]
    fn test_expr_cel_rules_end_to_end() {
        let e = engine(&[
            "EXPR,(process.name == 'git' && dst.port == 22),PROXY",
            "EXPR,(net == 'tcp' && dst.port in [80, 443] && host.endsWith('.google.com')),PROXY",
            "EXPR,(dst.ip in '10.0.0.0/8' || src.ip in '192.168.1.0/24'),DIRECT,no-resolve",
            "MATCH,REJECT",
        ]);

        // 1. git 22 端口 -> PROXY
        let mut c_git = ctx(Some("github.com"), None);
        c_git.process = Some("C:\\Program Files\\Git\\bin\\git.exe");
        c_git.dst_port = 22;
        assert_eq!(e.r#match(&c_git).unwrap().target, "PROXY");

        // 2. git 但非 22 端口 -> 不匹配第 1 条，转后序
        c_git.dst_port = 8080;
        assert_eq!(e.r#match(&c_git).unwrap().target, "REJECT");

        // 3. google 443 -> PROXY
        let c_google = ctx(Some("mail.google.com"), None);
        assert_eq!(e.r#match(&c_google).unwrap().target, "PROXY");

        // 4. 内网 IP -> DIRECT
        let c_internal = ctx(None, Some("10.1.2.3".parse().unwrap()));
        assert_eq!(e.r#match(&c_internal).unwrap().target, "DIRECT");
    }
}

//! vp-router：规则路由决策 + 策略组装配。

pub mod consts;
pub mod group;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tracing::debug;

pub use consts::*;
use vp_common::Result;
use vp_config::Mode;
use vp_core::{
    DestinationTrace, DnsTrace, GroupMemberTrace, GroupStepTrace, LeafOutboundTrace, Outbound,
    Resolution, RouteTrace, Router as RouterTrait, RuleHit, RuleHitDetail, RuleMatchTrace, Session,
    SessionTrace,
};
use vp_dns::Resolver;
use vp_rule::{MatchCtx, Net, RuleEngine};

pub use group::{Group, GroupSpec, GroupType, LbStrategy, group_spec};

pub struct RouterSpec {
    /// 具名出站（含 DIRECT/REJECT 内置与所有协议节点）
    pub outbounds: HashMap<String, Arc<dyn Outbound>>,
    pub groups: Vec<GroupSpec>,
    /// 链式代理配置表（target -> dialer）
    pub dialers: HashMap<String, String>,
    pub rules: RuleEngine,
    pub mode: Mode,
    pub dns: Arc<Resolver>,
    pub ipv6: bool,
    /// 是否启动后台自动定时健康检查任务（纯测速模式或无入站时不启动，避免任务惊群与重复探测）
    pub start_health_checks: bool,
}

pub struct Router {
    outbounds: HashMap<String, Arc<dyn Outbound>>,
    groups: HashMap<String, Arc<Group>>,
    rules: RuleEngine,
    mode: Mode,
    dns: Arc<Resolver>,
    ipv6: bool,
    global_outbound: Arc<dyn Outbound>,
    /// 确定性路由决策缓存：(network, host, port) -> (出站, 规则命中)。
    /// 仅当规则集不依赖连接动态特征（进程/源地址/入站标识）时启用，
    /// 日常浏览的 98%+ 连接 O(1) 直出，免除逐条线性规则扫描
    route_cache: Mutex<RouteCacheMap>,
    route_cache_enabled: bool,
    /// 健康检查等后台任务句柄：热替换时 abort，防止旧 Router 任务滞留
    background_tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// 缓存命中的决策值：(出站, 规则命中)
type CachedHit = (Arc<dyn Outbound>, Option<(String, String)>);

/// 路由决策缓存条目
type CachedRoute = (Arc<dyn Outbound>, Option<(String, String)>, Instant);

/// 路由决策缓存表：(network, host, port) -> 缓存条目
type RouteCacheMap = HashMap<(u8, vp_common::Host, u16), CachedRoute>;

/// 路由决策缓存容量与存活期（热重载自然失效：缓存在 Router 内，随旧 Router 一起丢弃）
const ROUTE_CACHE_CAP: usize = 1024;
const ROUTE_CACHE_TTL: Duration = Duration::from_secs(60);

/// 构造路由缓存：仅规则模式下且规则集不依赖连接动态特征时启用
fn new_route_cache(rules: &RuleEngine, mode: &Mode) -> (Mutex<RouteCacheMap>, bool) {
    let enabled = matches!(mode, Mode::Rule) && !rules.uses_session_state();
    (Mutex::new(HashMap::new()), enabled)
}

impl Router {
    /// 装配：解析组成员引用并构建组对象（要求配置校验已通过）
    pub fn build(spec: RouterSpec) -> Result<Arc<Router>> {
        let mut resolved: HashMap<String, Arc<dyn Outbound>> = spec.outbounds;
        let mut groups: HashMap<String, Arc<Group>> = HashMap::new();

        // 组与链式代理可能嵌套引用：按轮次解析直到收敛
        let mut round = spec.groups;
        let mut deferred: Vec<GroupSpec> = Vec::new();
        let mut dialers = spec.dialers;
        let mut progress = true;
        while progress {
            progress = false;

            // 1. 尝试解析其 dialer 已就绪的节点
            let mut resolved_dialers = Vec::new();
            for (target, dialer_name) in &dialers {
                if let Some(dialer) = resolved.get(dialer_name).cloned() {
                    if let Some(node) = resolved.get(target).cloned() {
                        let chained = Arc::new(vp_core::ChainedOutbound::new(node, dialer));
                        resolved.insert(target.clone(), chained);
                        resolved_dialers.push(target.clone());
                        progress = true;
                    }
                }
            }
            for t in resolved_dialers {
                dialers.remove(&t);
            }

            // 2. 尝试解析成员已就绪的策略组
            deferred.clear();
            for gs in round.drain(..) {
                let mut members: Vec<Arc<dyn Outbound>> = Vec::with_capacity(gs.members.len());
                let mut ok = true;
                for m in &gs.members {
                    if let Some(o) = resolved.get(m) {
                        members.push(o.clone());
                    } else if let Some(g) = groups.get(m) {
                        members.push(g.clone());
                    } else {
                        ok = false;
                        break;
                    }
                }
                let mut fallback_outbound: Option<Arc<dyn Outbound>> = None;
                if let Some(ref fb_name) = gs.fallback {
                    if let Some(o) = resolved.get(fb_name) {
                        fallback_outbound = Some(o.clone());
                    } else if let Some(g) = groups.get(fb_name) {
                        fallback_outbound = Some(g.clone() as Arc<dyn Outbound>);
                    } else {
                        ok = false;
                    }
                }
                if ok {
                    let g = Group::new(gs.clone(), members, fallback_outbound);
                    groups.insert(gs.name.clone(), g.clone());
                    resolved.insert(gs.name.clone(), g);
                    progress = true;
                } else {
                    deferred.push(gs);
                }
            }
            round = std::mem::take(&mut deferred);
            if !progress && (!round.is_empty() || !dialers.is_empty()) {
                return Err(vp_common::Error::Config(format!(
                    "组或 dialer-proxy 引用无法解析（可能成环或目标不存在）: groups={:?}, dialers={:?}",
                    round.iter().map(|g| &g.name).collect::<Vec<_>>(),
                    dialers
                )));
            }
        }

        // 全局模式缺省出站：第一个组，否则第一个非内置节点，否则 DIRECT
        let global_outbound: Arc<dyn Outbound> = groups
            .values()
            .next()
            .map(|g| g.clone() as Arc<dyn Outbound>)
            .or_else(|| {
                resolved
                    .values()
                    .find(|o| o.name() != "DIRECT" && o.name() != "REJECT")
                    .cloned()
            })
            .or_else(|| resolved.get("DIRECT").cloned())
            .ok_or(vp_common::Error::Config("无可用出站".into()))?;

        // 健康检查句柄在构造 Router 前收集：热替换旧 Router 时统一 abort，
        // 否则旧组任务持有 Arc<Group> 永久滞留（热更新泄漏）。
        // 仅在明确启用后台健康检查时启动，避免测速模式与构造阶段并发惊群重复探活。
        let mut background_tasks = Vec::new();
        if spec.start_health_checks {
            for (idx, g) in groups.values().enumerate() {
                if let Some(h) = g.start_health_checks(idx) {
                    background_tasks.push(h);
                }
            }
        }
        let route_cache = new_route_cache(&spec.rules, &spec.mode);
        let router = Arc::new(Router {
            outbounds: resolved,
            groups,
            route_cache: route_cache.0,
            route_cache_enabled: route_cache.1,
            rules: spec.rules,
            mode: spec.mode,
            dns: spec.dns,
            ipv6: spec.ipv6,
            global_outbound,
            background_tasks,
        });
        Ok(router)
    }

    /// 终止本 Router 的全部后台任务（热替换旧 Router 时调用；
    /// 已建立的连接不受影响 —— 它们持有的是出站/组对象，探测只是旁路）。
    pub fn abort_background_tasks(&self) {
        for h in &self.background_tasks {
            h.abort();
        }
    }

    pub fn groups(&self) -> &HashMap<String, Arc<Group>> {
        &self.groups
    }

    pub fn get_group(&self, name: &str) -> Option<Arc<Group>> {
        self.groups.get(name).cloned()
    }

    pub fn outbound(&self, name: &str) -> Option<Arc<dyn Outbound>> {
        self.outbounds.get(name).cloned()
    }

    pub fn outbounds(&self) -> &HashMap<String, Arc<dyn Outbound>> {
        &self.outbounds
    }

    /// 对指定节点（或策略组）执行延迟测试，并将结果同步回填到包含该节点的所有策略组
    pub async fn url_test_node(&self, name: &str, url: &str) -> Result<u32> {
        let ob = self
            .outbounds
            .get(name)
            .cloned()
            .ok_or_else(|| vp_common::Error::Other(format!("节点 {name:?} 不存在")))?;
        let res = group::url_test_outbound(&ob, url).await;
        let ms_opt = res.as_ref().ok().copied();
        for g in self.groups.values() {
            g.record_member_probe_result(name, ms_opt);
        }
        res
    }

    pub fn dns(&self) -> &Arc<Resolver> {
        &self.dns
    }

    pub fn needs_process(&self) -> bool {
        self.rules.needs_process()
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn rules(&self) -> &RuleEngine {
        &self.rules
    }

    /// 仅替换规则引擎（复用现有 groups 与出站表，保持延迟历史与已选手工状态）。
    /// 组对象虽复用，但任务按"Router 一代"归属：本代重启健康检查，
    /// 旧代任务在 swap 时被 abort（重叠窗口极短，探测有全局信号量兜底）。
    pub fn clone_with_rules(&self, rules: RuleEngine) -> Arc<Router> {
        let mut background_tasks = Vec::new();
        for (idx, g) in self.groups.values().enumerate() {
            if let Some(h) = g.start_health_checks(idx) {
                background_tasks.push(h);
            }
        }
        let route_cache = new_route_cache(&rules, &self.mode);
        Arc::new(Router {
            outbounds: self.outbounds.clone(),
            groups: self.groups.clone(),
            route_cache: route_cache.0,
            route_cache_enabled: route_cache.1,
            rules,
            mode: self.mode,
            dns: self.dns.clone(),
            ipv6: self.ipv6,
            global_outbound: self.global_outbound.clone(),
            background_tasks,
        })
    }

    /// 仅替换分流模式（规则 / 全局 / 直连）。
    /// 复用现有 groups、outbounds 与 rules，保持延迟历史与手工节点选择。
    pub fn clone_with_mode(&self, mode: Mode) -> Arc<Router> {
        let mut background_tasks = Vec::new();
        for (idx, g) in self.groups.values().enumerate() {
            if let Some(h) = g.start_health_checks(idx) {
                background_tasks.push(h);
            }
        }
        let route_cache = new_route_cache(&self.rules, &mode);
        Arc::new(Router {
            outbounds: self.outbounds.clone(),
            groups: self.groups.clone(),
            route_cache: route_cache.0,
            route_cache_enabled: route_cache.1,
            rules: self.rules.clone(),
            mode,
            dns: self.dns.clone(),
            ipv6: self.ipv6,
            global_outbound: self.global_outbound.clone(),
            background_tasks,
        })
    }

    /// 穿透组得到叶子节点名（API 展示 via）
    fn resolve_via(&self, outbound: &Arc<dyn Outbound>, sess: &Session) -> Arc<str> {
        let mut name: Arc<str> = outbound.name().into();
        let mut cur = outbound.clone();
        let mut depth = 0;
        while let Some(g) = self.groups.get(cur.name()) {
            if depth > 8 {
                break;
            }
            cur = g.pick_for(sess);
            name = cur.name().into();
            depth += 1;
        }
        name
    }

    /// 确定性路由缓存查询（过期即未命中，由后续连接的写入路径顺带清理）
    fn route_cache_lookup(&self, key: &(u8, vp_common::Host, u16)) -> Option<CachedHit> {
        let m = self.route_cache.lock().unwrap();
        let (ob, rule, at) = m.get(key)?;
        if at.elapsed() < ROUTE_CACHE_TTL {
            Some((ob.clone(), rule.clone()))
        } else {
            None
        }
    }

    /// 确定性路由缓存写入（容量触顶先清过期，仍满则整表清空；TTL 仅 60s，代价可控）
    fn route_cache_store(
        &self,
        key: (u8, vp_common::Host, u16),
        outbound: Arc<dyn Outbound>,
        rule: Option<(String, String)>,
    ) {
        let mut m = self.route_cache.lock().unwrap();
        if m.len() >= ROUTE_CACHE_CAP {
            let now = Instant::now();
            m.retain(|_, (_, _, at)| now.duration_since(*at) < ROUTE_CACHE_TTL);
            if m.len() >= ROUTE_CACHE_CAP {
                m.clear();
            }
        }
        m.insert(key, (outbound, rule, Instant::now()));
    }

    /// 寻找默认的兜底代理策略出站（优先 PROXY 组，否则首个代理组，否则首个非内置出站）
    pub fn fallback_proxy_outbound(&self) -> Option<Arc<dyn Outbound>> {
        if let Some(ob) = self.outbounds.get(GROUP_PROXY) {
            return Some(ob.clone());
        }
        for g in self.groups.values() {
            if g.name().as_ref() != OUTBOUND_DIRECT && g.name().as_ref() != OUTBOUND_REJECT {
                return Some(g.clone() as Arc<dyn Outbound>);
            }
        }
        for ob in self.outbounds.values() {
            if ob.name() != OUTBOUND_DIRECT && ob.name() != OUTBOUND_REJECT {
                return Some(ob.clone());
            }
        }
        None
    }
}

impl Drop for Router {
    fn drop(&mut self) {
        self.abort_background_tasks();
    }
}

#[async_trait]
impl RouterTrait for Router {
    async fn pick(&self, sess: &Session) -> Resolution {
        let (outbound, rule) = match self.mode {
            Mode::Direct => (
                self.outbounds
                    .get(OUTBOUND_DIRECT)
                    .cloned()
                    .unwrap_or(self.global_outbound.clone()),
                None,
            ),
            Mode::Global => (self.global_outbound.clone(), None),
            Mode::Rule => {
                if let Some(host_str) = sess.dst.host.as_domain() {
                    if vp_core::adaptive::is_blocked(host_str) {
                        if let Some(fallback) = self.fallback_proxy_outbound() {
                            let via = self.resolve_via(&fallback, sess);
                            tracing::debug!(
                                "Router::pick: 目标 {} 命中自适应临时阻断缓存，直接切至代理 {}",
                                host_str,
                                fallback.name()
                            );
                            return Resolution {
                                outbound: fallback,
                                via,
                                rule: Some(RuleHit {
                                    rule: RULE_ADAPTIVE_LRU.into(),
                                    target: GROUP_PROXY.into(),
                                }),
                            };
                        }
                    }
                }

                let dst_ip = match &sess.dst.host {
                    vp_common::Host::Ip(ip) => Some(*ip),
                    vp_common::Host::Domain(_) => None,
                };
                let cache_key = (
                    match sess.network {
                        vp_core::Network::Tcp => 0u8,
                        vp_core::Network::Udp => 1,
                    },
                    sess.dst.host.clone(),
                    sess.dst.port,
                );
                // 确定性路由缓存：规则集不依赖连接动态特征时，同 (协议, 目标, 端口)
                // 60s 内 O(1) 直出，免除数千条规则的线性扫描与惰性 DNS
                if self.route_cache_enabled {
                    if let Some((outbound, rule)) = self.route_cache_lookup(&cache_key) {
                        debug!("Router::pick 命中确定性路由缓存: {}", sess.dst);
                        let via = self.resolve_via(&outbound, sess);
                        return Resolution {
                            outbound,
                            via,
                            rule: rule.map(|(target, rule)| RuleHit { rule, target }),
                        };
                    }
                }
                let mut ctx = MatchCtx {
                    host: sess.dst.host.as_domain(),
                    dst_ip,
                    src_ip: sess.src.map(|s| s.ip()),
                    dst_port: sess.dst.port,
                    src_port: sess.src.map(|s| s.port()).unwrap_or(0),
                    network: match sess.network {
                        vp_core::Network::Tcp => Net::Tcp,
                        vp_core::Network::Udp => Net::Udp,
                    },
                    process: sess.process.as_deref(),
                    inbound: &sess.inbound,
                    inbound_port: sess.inbound_port,
                    inbound_user: sess.inbound_user.as_deref(),
                    cache: Default::default(),
                };

                let mut matched = None;
                for r in self.rules.rules() {
                    // 仅当当前规则需要目标 IP，且尚未解析时，才惰性触发 DNS 解析（避免前置域名规则被阻塞）
                    if ctx.dst_ip.is_none() && r.needs_dst_ip() {
                        if let Ok(ips) = self.dns.resolve(&sess.dst.host, self.ipv6).await {
                            if let Some(first) = ips.first() {
                                ctx.dst_ip = Some(*first);
                            }
                        }
                    }

                    if let Some((target, rule)) = r.match_target(&ctx) {
                        tracing::debug!("Router::pick matched: target={target}, rule={rule}");
                        matched = Some((target.to_string(), rule.to_string()));
                        break;
                    }
                }

                match matched {
                    Some((target, rule_str)) => {
                        let hit = RuleHit {
                            rule: rule_str.clone(),
                            target: target.clone(),
                        };
                        let ob = match self.outbounds.get(&target).cloned() {
                            Some(ob) => ob,
                            None => {
                                // 目标不存在时禁止静默回退：无可用节点直接报错，避免"配错目标却走了 DIRECT"这类排障黑洞
                                tracing::error!(
                                    "规则命中目标 {target} 不存在（规则: {rule_str}），连接中止"
                                );
                                return Resolution {
                                    outbound: self
                                        .outbounds
                                        .get("REJECT")
                                        .cloned()
                                        .unwrap_or(self.global_outbound.clone()),
                                    via: "REJECT".into(),
                                    rule: Some(hit),
                                };
                            }
                        };
                        if self.route_cache_enabled {
                            self.route_cache_store(cache_key, ob.clone(), Some((target, rule_str)));
                        }
                        (ob, Some(hit))
                    }
                    None => {
                        debug!("无规则命中，回落 DIRECT: {}", sess.dst);
                        if self.route_cache_enabled {
                            self.route_cache_store(cache_key, self.global_outbound.clone(), None);
                        }
                        (self.global_outbound.clone(), None)
                    }
                }
            }
        };
        let via = self.resolve_via(&outbound, sess);
        Resolution {
            outbound,
            via,
            rule,
        }
    }

    async fn explain(&self, sess: &Session) -> RouteTrace {
        let t_start = std::time::Instant::now();
        let destination = DestinationTrace {
            original: format!("{}", sess.dst),
            host: match &sess.dst.host {
                vp_common::Host::Domain(d) => d.clone(),
                vp_common::Host::Ip(ip) => ip.to_string(),
            },
            is_domain: sess.dst.host.as_domain().is_some(),
            port: sess.dst.port,
        };

        let session = SessionTrace {
            network: match sess.network {
                vp_core::Network::Tcp => "tcp",
                vp_core::Network::Udp => "udp",
            }
            .to_string(),
            inbound: sess.inbound.to_string(),
            inbound_port: sess.inbound_port,
            inbound_user: sess.inbound_user.as_deref().map(|s| s.to_string()),
            process: sess.process.as_deref().map(|s| s.to_string()),
            src_ip: sess.src.map(|s| s.ip().to_string()),
        };

        let mode_str = match self.mode {
            Mode::Direct => "direct",
            Mode::Global => "global",
            Mode::Rule => "rule",
        }
        .to_string();

        let mut dns_trace: Option<DnsTrace> = None;
        let mut adaptive_blocked = false;
        let mut rule_match = RuleMatchTrace {
            matched: None,
            evaluated_count: 0,
            total_rules: self.rules.rules().len(),
            elapsed_us: 0,
        };

        let outbound = match self.mode {
            Mode::Direct => self
                .outbounds
                .get(OUTBOUND_DIRECT)
                .cloned()
                .unwrap_or(self.global_outbound.clone()),
            Mode::Global => self.global_outbound.clone(),
            Mode::Rule => {
                let mut found_outbound = None;
                if let Some(host_str) = sess.dst.host.as_domain() {
                    if vp_core::adaptive::is_blocked(host_str) {
                        adaptive_blocked = true;
                        if let Some(fallback) = self.fallback_proxy_outbound() {
                            rule_match.matched = Some(RuleHitDetail {
                                index: 0,
                                rule_type: "ADAPTIVE-LRU".into(),
                                payload: host_str.to_string(),
                                target: GROUP_PROXY.into(),
                                raw: RULE_ADAPTIVE_LRU.into(),
                                no_resolve: false,
                            });
                            found_outbound = Some(fallback);
                        }
                    }
                }

                if found_outbound.is_none() {
                    let dst_ip = match &sess.dst.host {
                        vp_common::Host::Ip(ip) => Some(*ip),
                        vp_common::Host::Domain(_) => None,
                    };

                    let mut ctx = MatchCtx {
                        host: sess.dst.host.as_domain(),
                        dst_ip,
                        src_ip: sess.src.map(|s| s.ip()),
                        dst_port: sess.dst.port,
                        src_port: sess.src.map(|s| s.port()).unwrap_or(0),
                        network: match sess.network {
                            vp_core::Network::Tcp => Net::Tcp,
                            vp_core::Network::Udp => Net::Udp,
                        },
                        process: sess.process.as_deref(),
                        inbound: &sess.inbound,
                        inbound_port: sess.inbound_port,
                        inbound_user: sess.inbound_user.as_deref(),
                        cache: Default::default(),
                    };

                    let mut evaluated = 0;
                    let mut matched_info = None;

                    let t_rules = std::time::Instant::now();
                    for (idx, r) in self.rules.rules().iter().enumerate() {
                        evaluated += 1;
                        if ctx.dst_ip.is_none() && r.needs_dst_ip() {
                            let t0 = std::time::Instant::now();
                            let dns_res = self.dns.resolve(&sess.dst.host, self.ipv6).await;
                            let duration_ms = t0.elapsed().as_millis() as u64;
                            match dns_res {
                                Ok(ips) => {
                                    if let Some(first) = ips.first() {
                                        ctx.dst_ip = Some(*first);
                                    }
                                    dns_trace = Some(DnsTrace {
                                        triggered: true,
                                        trigger_rule: Some(r.raw.to_string()),
                                        resolved_ips: ips.iter().map(|ip| ip.to_string()).collect(),
                                        duration_ms,
                                        error: None,
                                    });
                                }
                                Err(e) => {
                                    dns_trace = Some(DnsTrace {
                                        triggered: true,
                                        trigger_rule: Some(r.raw.to_string()),
                                        resolved_ips: Vec::new(),
                                        duration_ms,
                                        error: Some(e.to_string()),
                                    });
                                }
                            }
                        }

                        if let Some((target, rule_str)) = r.match_target(&ctx) {
                            let (rule_type, payload) =
                                if let Some((t, p)) = rule_str.split_once(',') {
                                    (t.to_string(), p.to_string())
                                } else {
                                    (rule_str.to_string(), String::new())
                                };
                            matched_info = Some((
                                target.to_string(),
                                RuleHitDetail {
                                    index: idx + 1,
                                    rule_type,
                                    payload,
                                    target: target.to_string(),
                                    raw: rule_str.to_string(),
                                    no_resolve: r.no_resolve,
                                },
                            ));
                            break;
                        }
                    }

                    rule_match.evaluated_count = evaluated;
                    rule_match.elapsed_us = t_rules.elapsed().as_micros() as u64;

                    match matched_info {
                        Some((target, hit_detail)) => {
                            rule_match.matched = Some(hit_detail);
                            let ob = match self.outbounds.get(&target).cloned() {
                                Some(ob) => ob,
                                None => self
                                    .outbounds
                                    .get("REJECT")
                                    .cloned()
                                    .unwrap_or(self.global_outbound.clone()),
                            };
                            found_outbound = Some(ob);
                        }
                        None => {
                            found_outbound = Some(self.global_outbound.clone());
                        }
                    }
                }
                found_outbound.unwrap_or(self.global_outbound.clone())
            }
        };

        // 穿透策略组并记录每一级
        let mut group_chain = Vec::new();
        let mut cur = outbound.clone();
        let mut depth = 0;
        let mut decision_parts = Vec::new();

        if let Some(ref m) = rule_match.matched {
            decision_parts.push(format!("[Rule {}: {}] -> {}", m.index, m.raw, m.target));
        } else {
            decision_parts.push(format!("[Mode: {}] -> {}", mode_str, outbound.name()));
        }

        while let Some(g) = self.groups.get(cur.name()) {
            if depth > 8 {
                break;
            }
            depth += 1;

            let picked_tcp = g.pick(sess);
            let picked_udp = g.pick_udp(sess);
            let (picked, udp_adjusted) = match sess.network {
                vp_core::Network::Udp if picked_tcp.name() != picked_udp.name() => {
                    (picked_udp, true)
                }
                vp_core::Network::Udp => (picked_udp, false),
                vp_core::Network::Tcp => (picked_tcp, false),
            };

            let states = g.member_states();
            let mut member_traces = Vec::with_capacity(states.len());
            let mut picked_delay = None;

            for (m_name, delay, alive) in states {
                let support_udp = self
                    .outbounds
                    .get(&*m_name)
                    .map_or(true, |o| o.support_udp());
                if &*m_name == picked.name() {
                    picked_delay = delay;
                }
                member_traces.push(GroupMemberTrace {
                    name: m_name.to_string(),
                    delay_ms: delay,
                    alive,
                    support_udp,
                });
            }

            let group_type_str = format!("{:?}", g.ty()).to_lowercase();
            let reason = match g.ty() {
                GroupType::Select => format!("手动选中 (当前节点: {})", picked.name()),
                GroupType::UrlTest => {
                    if let Some(d) = picked_delay {
                        format!("最低延迟优先 ({}ms)", d)
                    } else {
                        "测速选优".into()
                    }
                }
                GroupType::Fallback => "故障转移优先存活节点".into(),
                GroupType::LoadBalance => "负载均衡调度".into(),
                GroupType::Relay => "链式中继下一跳".into(),
            };

            let reason_summary = if udp_adjusted {
                format!("{reason} [UDP自动降级切换]")
            } else {
                reason.clone()
            };

            decision_parts.push(format!(
                "{}({}) -> {}",
                g.name(),
                group_type_str,
                picked.name()
            ));

            group_chain.push(GroupStepTrace {
                group_name: g.name().to_string(),
                group_type: group_type_str,
                picked_member: picked.name().to_string(),
                reason: reason_summary,
                members: member_traces,
                udp_adjusted,
            });

            cur = picked;
        }

        let leaf_name = cur.name().to_string();
        let leaf_remote = cur.remote_addr().map(|(h, p)| format!("{h}:{p}"));
        let final_outbound = LeafOutboundTrace {
            name: leaf_name.clone(),
            outbound_type: if self.groups.contains_key(&leaf_name) {
                "group".into()
            } else if leaf_name == "DIRECT" || leaf_name == "REJECT" {
                "builtin".into()
            } else {
                "proxy".into()
            },
            support_udp: cur.support_udp(),
            remote_addr: leaf_remote,
            dialer_proxy: None,
        };

        let elapsed_us = t_start.elapsed().as_micros() as u64;

        RouteTrace {
            mode: mode_str,
            destination,
            session,
            dns: dns_trace,
            adaptive_blocked,
            rule_match,
            group_chain,
            final_outbound,
            decision_chain: decision_parts.join(" > "),
            elapsed_us,
        }
    }

    fn needs_process(&self) -> bool {
        self.rules.needs_process()
    }

    fn fallback_proxy_outbound(&self) -> Option<Arc<dyn Outbound>> {
        Router::fallback_proxy_outbound(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use vp_common::DstAddr;

    struct CountingOutbound {
        name: String,
        connects: AtomicUsize,
    }

    #[async_trait]
    impl Outbound for CountingOutbound {
        fn name(&self) -> &str {
            &self.name
        }
        async fn connect_stream(
            &self,
            _sess: &Session,
            _dst: &DstAddr,
        ) -> Result<Box<dyn vp_core::ProxyStream>> {
            self.connects.fetch_add(1, Ordering::Relaxed);
            let (a, _b) = tokio::io::duplex(4096);
            Ok(Box::new(a))
        }
    }

    fn dst(host: &str) -> DstAddr {
        DstAddr::new(host, 443)
    }

    fn sess(host: &str) -> Session {
        Session::new_tcp("test".into(), None, dst(host))
    }

    async fn build_router(mode: Mode) -> Arc<Router> {
        let direct: Arc<dyn Outbound> = Arc::new(CountingOutbound {
            name: "DIRECT".into(),
            connects: AtomicUsize::new(0),
        });
        let proxy: Arc<dyn Outbound> = Arc::new(CountingOutbound {
            name: "P1".into(),
            connects: AtomicUsize::new(0),
        });
        let reject: Arc<dyn Outbound> = Arc::new(CountingOutbound {
            name: "REJECT".into(),
            connects: AtomicUsize::new(0),
        });
        let mut outbounds: HashMap<String, Arc<dyn Outbound>> = HashMap::new();
        outbounds.insert("DIRECT".to_string(), direct.clone());
        outbounds.insert("REJECT".to_string(), reject);
        outbounds.insert("P1".to_string(), proxy.clone());

        let rules_text = vec![
            "DOMAIN-SUFFIX,google.com,P1".to_string(),
            "IP-CIDR,127.0.0.0/8,DIRECT".to_string(),
            "MATCH,DIRECT".to_string(),
        ];
        let env = vp_rule::CompileEnv {
            is_known_target: &|t| matches!(t, "DIRECT" | "REJECT" | "P1" | "G"),
            geosite: &None,
            #[cfg(feature = "geoip")]
            geoip: &None,
            #[cfg(feature = "geoip")]
            asn: &None,
            providers: &HashMap::new(),
            sub_rules: &HashMap::new(),
        };
        let rules = vp_rule::compile(&rules_text, &env).unwrap();

        Router::build(RouterSpec {
            outbounds,
            groups: vec![GroupSpec::new("G", GroupType::Select, vec!["P1".into()])],
            dialers: HashMap::new(),
            rules,
            mode,
            dns: Arc::new(Resolver::system()),
            ipv6: false,
            start_health_checks: false,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn rule_mode_routes_by_domain() {
        let r = build_router(Mode::Rule).await;
        let res = r.pick(&sess("www.google.com")).await;
        assert_eq!(&*res.via, "P1");
        assert!(res.rule.is_some());

        let res = r.pick(&sess("localhost")).await; // 解析为 127.0.0.1 命中 IP-CIDR
        assert_eq!(&*res.via, "DIRECT");
    }

    #[tokio::test]
    async fn global_and_direct_mode() {
        let g = build_router(Mode::Global).await;
        let res = g.pick(&sess("anything.com")).await;
        assert_eq!(&*res.via, "P1");

        let d = build_router(Mode::Direct).await;
        let res = d.pick(&sess("anything.com")).await;
        assert_eq!(&*res.via, "DIRECT");
    }

    #[tokio::test]
    async fn dialer_proxy_chaining_resolved() {
        let direct = Arc::new(CountingOutbound {
            name: "DIRECT".into(),
            connects: AtomicUsize::new(0),
        });
        let proxy1 = Arc::new(CountingOutbound {
            name: "P1".into(),
            connects: AtomicUsize::new(0),
        });
        let proxy2 = Arc::new(CountingOutbound {
            name: "P2".into(),
            connects: AtomicUsize::new(0),
        });

        let mut outbounds = HashMap::new();
        outbounds.insert("DIRECT".into(), direct as Arc<dyn Outbound>);
        outbounds.insert("P1".into(), proxy1 as Arc<dyn Outbound>);
        outbounds.insert("P2".into(), proxy2 as Arc<dyn Outbound>);

        let mut dialers = HashMap::new();
        dialers.insert("P2".into(), "P1".into()); // P2 经由 P1 跳板

        let rules = vp_rule::compile(
            &["MATCH,P2".to_string()],
            &vp_rule::CompileEnv {
                is_known_target: &|_| true,
                geosite: &None,
                #[cfg(feature = "geoip")]
                geoip: &None,
                #[cfg(feature = "geoip")]
                asn: &None,
                providers: &HashMap::new(),
                sub_rules: &HashMap::new(),
            },
        )
        .unwrap();

        let r = Router::build(RouterSpec {
            outbounds,
            groups: vec![],
            dialers,
            rules,
            mode: Mode::Rule,
            dns: Arc::new(Resolver::system()),
            ipv6: false,
            start_health_checks: false,
        })
        .unwrap();

        let res = r.pick(&sess("target.com")).await;
        assert_eq!(&*res.via, "P2");
    }

    #[tokio::test]
    async fn selector_via_group() {
        let r = build_router(Mode::Global).await;
        assert!(r.groups.contains_key("G"));
        let g = r.get_group("G").unwrap();
        assert_eq!(g.selected_name().as_ref(), "P1");
        assert!(g.set_selected("P1"));
    }

    #[tokio::test]
    async fn test_explain_full_diagnostic_trace() {
        let r = build_router(Mode::Rule).await;
        let trace = r.explain(&sess("www.google.com")).await;

        assert_eq!(trace.mode, "rule");
        assert_eq!(trace.destination.host, "www.google.com");
        assert!(trace.destination.is_domain);
        assert_eq!(trace.destination.port, 443);
        assert!(trace.rule_match.matched.is_some());

        let matched = trace.rule_match.matched.unwrap();
        assert_eq!(matched.target, "P1");
        assert_eq!(matched.rule_type, "DOMAIN-SUFFIX");
        assert_eq!(trace.final_outbound.name, "P1");
        assert!(trace.decision_chain.contains("-> P1"));
    }
}

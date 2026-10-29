//! vp-router：规则路由决策 + 策略组装配。

pub mod group;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tracing::debug;

use vp_common::Result;
use vp_config::Mode;
use vp_core::{Outbound, Resolution, Router as RouterTrait, RuleHit, Session};
use vp_dns::Resolver;
use vp_rule::{MatchCtx, Net, RuleEngine};

pub use group::{Group, GroupSpec, GroupType, LbStrategy};

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
}

pub struct Router {
    outbounds: HashMap<String, Arc<dyn Outbound>>,
    groups: HashMap<String, Arc<Group>>,
    rules: RuleEngine,
    mode: Mode,
    dns: Arc<Resolver>,
    ipv6: bool,
    global_outbound: Arc<dyn Outbound>,
    /// 健康检查等后台任务句柄：热替换时 abort，防止旧 Router 任务滞留
    background_tasks: Vec<tokio::task::JoinHandle<()>>,
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
                if ok {
                    let g = Group::new(
                        GroupSpec {
                            name: gs.name.clone(),
                            ty: gs.ty,
                            members: gs.members.clone(),
                            test_url: gs.test_url.clone(),
                            interval: gs.interval,
                            tolerance: gs.tolerance,
                            lazy: gs.lazy,
                            lb_strategy: gs.lb_strategy,
                        },
                        members,
                    );
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
        let mut background_tasks = Vec::new();
        for (idx, g) in groups.values().enumerate() {
            if let Some(h) = g.start_health_checks(idx) {
                background_tasks.push(h);
            }
        }
        let router = Arc::new(Router {
            outbounds: resolved,
            groups,
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

    pub fn dns(&self) -> &Arc<Resolver> {
        &self.dns
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
        Arc::new(Router {
            outbounds: self.outbounds.clone(),
            groups: self.groups.clone(),
            rules,
            mode: self.mode,
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
            cur = g.pick(sess);
            name = cur.name().into();
            depth += 1;
        }
        name
    }
}

#[async_trait]
impl RouterTrait for Router {
    async fn pick(&self, sess: &Session) -> Resolution {
        let (outbound, rule) = match self.mode {
            Mode::Direct => (
                self.outbounds
                    .get("DIRECT")
                    .cloned()
                    .unwrap_or(self.global_outbound.clone()),
                None,
            ),
            Mode::Global => (self.global_outbound.clone(), None),
            Mode::Rule => {
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
                        (ob, Some(hit))
                    }
                    None => {
                        debug!("无规则命中，回落 DIRECT: {}", sess.dst);
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
            groups: vec![GroupSpec {
                name: "G".into(),
                ty: GroupType::Select,
                members: vec!["P1".into()],
                test_url: None,
                interval: 300,
                tolerance: 0,
                lazy: true,
                lb_strategy: LbStrategy::RoundRobin,
            }],
            dialers: HashMap::new(),
            rules,
            mode,
            dns: Arc::new(Resolver::system()),
            ipv6: false,
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
}

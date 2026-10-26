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
}

impl Router {
    /// 装配：解析组成员引用并构建组对象（要求配置校验已通过）
    pub fn build(spec: RouterSpec) -> Result<Arc<Router>> {
        let mut resolved: HashMap<String, Arc<dyn Outbound>> = spec.outbounds;
        let mut groups: HashMap<String, Arc<Group>> = HashMap::new();

        // 组可能嵌套引用组：按轮次解析直到收敛
        let mut round = spec.groups;
        let mut deferred: Vec<GroupSpec> = Vec::new();
        let mut progress = true;
        while progress {
            progress = false;
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
            if !progress && !round.is_empty() {
                return Err(vp_common::Error::Config(format!(
                    "组引用无法解析（可能成环）: {:?}",
                    round.iter().map(|g| &g.name).collect::<Vec<_>>()
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

        let router = Arc::new(Router {
            outbounds: resolved,
            groups,
            rules: spec.rules,
            mode: spec.mode,
            dns: spec.dns,
            ipv6: spec.ipv6,
            global_outbound,
        });

        for g in router.groups.values() {
            g.start_health_checks();
        }
        Ok(router)
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

    /// 仅替换规则引擎（复用现有 groups 与出站表，保持延迟历史与已选手工状态）
    pub fn clone_with_rules(&self, rules: RuleEngine) -> Arc<Router> {
        Arc::new(Router {
            outbounds: self.outbounds.clone(),
            groups: self.groups.clone(),
            rules,
            mode: self.mode,
            dns: self.dns.clone(),
            ipv6: self.ipv6,
            global_outbound: self.global_outbound.clone(),
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

    /// 构造匹配上下文（IP 规则在时解析 DNS）
    async fn match_context<'a>(&'a self, sess: &'a Session) -> MatchCtx<'a> {
        let mut dst_ip = match &sess.dst.host {
            vp_common::Host::Ip(ip) => Some(*ip),
            vp_common::Host::Domain(_) => None,
        };
        if dst_ip.is_none() && self.rules.needs_dst_ip() {
            if let Ok(ips) = self.dns.resolve(&sess.dst.host, self.ipv6).await {
                if let Some(first) = ips.first() {
                    dst_ip = Some(*first);
                }
            }
        }
        MatchCtx {
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
        }
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
                let ctx = self.match_context(sess).await;
                match self.rules.r#match(&ctx) {
                    Some(m) => {
                        let hit = RuleHit {
                            rule: m.rule.to_string(),
                            target: m.target.to_string(),
                        };
                        let ob = self
                            .outbounds
                            .get(m.target)
                            .cloned()
                            .unwrap_or_else(|| self.global_outbound.clone());
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
    async fn selector_via_group() {
        let r = build_router(Mode::Global).await;
        assert!(r.groups.contains_key("G"));
        let g = r.get_group("G").unwrap();
        assert_eq!(g.selected_name().as_ref(), "P1");
        assert!(g.set_selected("P1"));
    }
}

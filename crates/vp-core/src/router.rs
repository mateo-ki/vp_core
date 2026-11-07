//! 路由器抽象：入站协议握手完成后，由路由器决定出站。

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::outbound::Outbound;
use crate::session::Session;

/// 命中规则信息（API 展示用）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleHit {
    /// 规则原文，如 "DOMAIN-SUFFIX,google.com,PROXY"
    pub rule: String,
    /// 规则目标，如 "PROXY"
    pub target: String,
}

#[derive(Clone)]
pub struct Resolution {
    pub outbound: Arc<dyn Outbound>,
    /// 最终使用的节点/组名（穿透组之后）
    pub via: Arc<str>,
    pub rule: Option<RuleHit>,
}

/// 路由链路完整诊断追踪（CLI explain 与 API 展示用）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteTrace {
    /// 分流模式 (rule / global / direct)
    pub mode: String,
    pub destination: DestinationTrace,
    pub session: SessionTrace,
    pub dns: Option<DnsTrace>,
    pub adaptive_blocked: bool,
    pub rule_match: RuleMatchTrace,
    pub group_chain: Vec<GroupStepTrace>,
    pub final_outbound: LeafOutboundTrace,
    /// 决策链摘要展示，如 "PROXY (url-test) > HK-01 (42ms)"
    pub decision_chain: String,
    /// 诊断全过程总耗时（微秒）
    #[serde(default)]
    pub elapsed_us: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DestinationTrace {
    pub original: String,
    pub host: String,
    pub is_domain: bool,
    pub port: u16,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionTrace {
    pub network: String,
    pub inbound: String,
    pub inbound_port: Option<u16>,
    pub inbound_user: Option<String>,
    pub process: Option<String>,
    pub src_ip: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsTrace {
    pub triggered: bool,
    pub trigger_rule: Option<String>,
    pub resolved_ips: Vec<String>,
    pub duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleMatchTrace {
    pub matched: Option<RuleHitDetail>,
    pub evaluated_count: usize,
    pub total_rules: usize,
    /// 规则匹配耗时（微秒）
    #[serde(default)]
    pub elapsed_us: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleHitDetail {
    pub index: usize,
    pub rule_type: String,
    pub payload: String,
    pub target: String,
    pub raw: String,
    pub no_resolve: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GroupStepTrace {
    pub group_name: String,
    pub group_type: String,
    pub picked_member: String,
    pub reason: String,
    pub members: Vec<GroupMemberTrace>,
    pub udp_adjusted: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GroupMemberTrace {
    pub name: String,
    pub delay_ms: Option<u32>,
    pub alive: bool,
    pub support_udp: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LeafOutboundTrace {
    pub name: String,
    pub outbound_type: String,
    pub support_udp: bool,
    pub remote_addr: Option<String>,
    pub dialer_proxy: Option<String>,
}

#[async_trait]
pub trait Router: Send + Sync {
    /// 规则匹配 + 策略组决策，返回出站。
    /// 内部可能触发 DNS 解析（IP 类规则 + 域名目标时）。
    async fn pick(&self, sess: &Session) -> Resolution;

    /// 诊断追踪：模拟分流决策并捕获全链路决策详情
    async fn explain(&self, _sess: &Session) -> RouteTrace {
        RouteTrace::default()
    }

    /// 路由规则是否需要匹配进程名/路径（未配置时可跳过系统级进程扫描，避免高并发测速下产生无谓系统调用）
    fn needs_process(&self) -> bool {
        false
    }

    /// 寻找默认的兜底代理出站（直连失败时透明自适应重试用）
    fn fallback_proxy_outbound(&self) -> Option<Arc<dyn Outbound>> {
        None
    }
}

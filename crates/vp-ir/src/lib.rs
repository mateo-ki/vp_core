//! VP_Core 统一中间表示层 (Unified Intermediate Representation)。
//!
//! 承载解耦后的规范化配置数据模型。
//! 所有配置前端（Clash YAML, JSON/JSON5, 订阅 URI, 全量 DSL）均降维为 VpIr，
//! 再交由运行时装配层 (vp-app) 构建内存网络栈。

pub mod dns;
pub mod group;
pub mod inbound;
pub mod outbound;
pub mod route;
pub mod security;
pub mod services;
pub mod tun;

pub use dns::*;
pub use group::*;
pub use inbound::*;
pub use outbound::*;
pub use route::*;
pub use security::*;
pub use services::*;
pub use tun::*;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct VpIr {
    pub inbounds: Vec<InboundSpec>,
    pub outbounds: Vec<OutboundSpec>,
    pub groups: Vec<GroupSpec>,
    pub routes: Vec<RouteRuleSpec>,
    pub sub_rules: HashMap<String, Vec<RouteRuleSpec>>,
    pub rule_providers: HashMap<String, RuleProviderSpec>,
    pub proxy_providers: HashMap<String, ProxyProviderSpec>,
    pub dns: DnsSpec,
    pub tun: Option<TunSpec>,
    pub services: ServiceSpec,
    pub security: SecuritySpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleProviderSpec {
    pub name: String,
    pub behavior: String, // "domain", "ipcidr", "classical"
    pub format: String,   // "yaml", "text", "mrs", "srs"
    pub url: Option<String>,
    pub path: Option<String>,
    pub interval: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyProviderSpec {
    pub name: String,
    pub url: Option<String>,
    pub path: Option<String>,
    pub interval: u64,
    pub filter: Option<String>,
}

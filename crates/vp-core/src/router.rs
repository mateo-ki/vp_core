//! 路由器抽象：入站协议握手完成后，由路由器决定出站。

use async_trait::async_trait;
use std::sync::Arc;

use crate::outbound::Outbound;
use crate::session::Session;

/// 命中规则信息（API 展示用）
#[derive(Debug, Clone)]
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

#[async_trait]
pub trait Router: Send + Sync {
    /// 规则匹配 + 策略组决策，返回出站。
    /// 内部可能触发 DNS 解析（IP 类规则 + 域名目标时）。
    async fn pick(&self, sess: &Session) -> Resolution;
}

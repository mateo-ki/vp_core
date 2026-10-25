//! 入站监听器抽象。

use async_trait::async_trait;
use std::sync::Arc;
use vp_common::{Result, Stats};

use crate::conn_table::ConnTable;
use crate::router::Router;

/// 入站启动所需的上下文
pub struct InboundCtx {
    pub router: Arc<dyn Router>,
    pub stats: Arc<Stats>,
    pub conns: Arc<ConnTable>,
}

#[async_trait]
pub trait Inbound: Send + Sync {
    fn tag(&self) -> &str;

    /// 启动监听（内部自行 spawn 任务）。返回绑定的本地端口。
    async fn start(self: Arc<Self>, ctx: InboundCtx) -> Result<u16>;
}

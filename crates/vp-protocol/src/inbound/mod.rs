//! 入站：mixed（socks5+http 同端口自动识别）、socks5、http。

pub mod dispatch;
mod http_in;
mod mixed;
pub mod mux_in;
mod socks5_in;
pub mod udp_nat;

pub use dispatch::dispatch_stream;
pub use http_in::HttpInbound;
pub use mixed::MixedInbound;
pub use mux_in::{TlsMuxInbound, TlsMuxOptions};
pub use socks5_in::Socks5Inbound;
pub use udp_nat::UdpNat;

use std::sync::Arc;
use vp_common::Result;
use vp_core::Inbound;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundKind {
    Mixed,
    Socks5,
    Http,
    Redir,
    Tproxy,
}

/// 构建入站监听器
pub fn build_inbound(kind: InboundKind, bind: String, port: u16, tag: &str) -> Arc<dyn Inbound> {
    build_inbound_with_gate(kind, bind, port, tag, None)
}

/// 支持安全门禁的入站监听器构建
pub fn build_inbound_with_gate(
    kind: InboundKind,
    bind: String,
    port: u16,
    tag: &str,
    gate: Option<Arc<vp_core::InboundGate>>,
) -> Arc<dyn Inbound> {
    match kind {
        InboundKind::Mixed => Arc::new(MixedInbound::with_gate(bind, port, tag, gate)),
        InboundKind::Socks5 => Arc::new(Socks5Inbound::with_gate(bind, port, tag, gate)),
        InboundKind::Http => Arc::new(HttpInbound::with_gate(bind, port, tag, gate)),
        InboundKind::Redir => Arc::new(crate::redir::RedirInbound::new(&bind, port, tag)),
        InboundKind::Tproxy => Arc::new(crate::tproxy::TproxyInbound::new(&bind, port, tag)),
    }
}

/// 预留：入站通用构造结果
pub type InboundResult = Result<()>;

//! 入站：mixed（socks5+http 同端口自动识别）、socks5、http。

mod dispatch;
mod http_in;
mod mixed;
mod socks5_in;
pub mod udp_nat;

pub use dispatch::dispatch_stream;
pub use http_in::HttpInbound;
pub use mixed::MixedInbound;
pub use udp_nat::UdpNat;
pub use socks5_in::Socks5Inbound;

use std::sync::Arc;
use vp_common::Result;
use vp_core::Inbound;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundKind {
    Mixed,
    Socks5,
    Http,
}

/// 构建入站监听器
pub fn build_inbound(kind: InboundKind, bind: String, port: u16, tag: &str) -> Arc<dyn Inbound> {
    match kind {
        InboundKind::Mixed => Arc::new(MixedInbound::new(bind, port, tag)),
        InboundKind::Socks5 => Arc::new(Socks5Inbound::new(bind, port, tag)),
        InboundKind::Http => Arc::new(HttpInbound::new(bind, port, tag)),
    }
}

/// 预留：入站通用构造结果
pub type InboundResult = Result<()>;

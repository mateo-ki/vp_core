//! VP_Core 核心抽象层。
//!
//! 依赖方向的最底层：定义流/出站/入站/路由器/转发引擎，
//! 不依赖任何具体协议与配置实现。

pub mod conn_table;
pub mod inbound;
pub mod outbound;
pub mod router;
pub mod session;
pub mod stream;
pub mod tunnel;

pub use conn_table::{ConnMeta, ConnSnapshot, ConnTable};
pub use inbound::{Inbound, InboundCtx};
pub use outbound::Outbound;
pub use router::{Resolution, Router, RuleHit};
pub use session::{Network, Session};
pub use stream::{PacketConn, ProxyStream, UdpPacket};
pub use tunnel::{relay, RelayHook};

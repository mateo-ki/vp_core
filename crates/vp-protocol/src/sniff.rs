//! 协议嗅探层（Sniffing）：在建立出站连接前无损窥探首包数据，
//! 提取 TLS SNI 或 HTTP Host 域名，以精准激活域名分流规则。

pub use vp_core::sniff::*;

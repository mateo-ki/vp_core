use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InboundSpec {
    Mixed { listen: SocketAddr },
    Http { listen: SocketAddr },
    Socks5 { listen: SocketAddr },
    Redir { listen: SocketAddr },
    Tproxy { listen: SocketAddr },
    Server(Box<ServerInboundSpec>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInboundSpec {
    pub name: String,
    pub kind: String,
    pub listen: SocketAddr,
    pub cipher: Option<String>,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub users: Vec<ServerUserSpec>,
    pub fallback: Option<String>,
    pub shadow_tls: Option<crate::outbound::ShadowTlsSpec>,
    pub reality: Option<crate::outbound::RealitySpec>,
    pub sni_routes: HashMap<String, String>,
    pub obfs: Option<String>,
    pub obfs_password: Option<String>,
    pub ports: Option<String>,
    pub allow_geoip: Vec<String>,
    pub block_geoip: Vec<String>,
    pub allow_asn: Vec<u32>,
    pub block_asn: Vec<u32>,
    pub knock: Option<crate::security::KnockSpec>,
    pub rrl: Option<crate::security::RrlSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerUserSpec {
    pub username: String,
    pub secret: String,
    pub quota_bytes: Option<u64>,
    pub rate_limit_bps: Option<u64>,
}

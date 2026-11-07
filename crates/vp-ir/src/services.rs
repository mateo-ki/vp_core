use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ServiceSpec {
    pub external_controller: Option<String>,
    pub secret: Option<String>,
    pub mode: RoutingMode,
    pub log_level: String,
    pub routing_mark: Option<u32>,
    pub interface_name: Option<String>,
    pub tuning: TuningSpec,
    pub resource_limits: ResourceLimitsSpec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum RoutingMode {
    #[default]
    Rule,
    Global,
    Direct,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TuningSpec {
    pub socket_buffer_size: Option<usize>,
    pub tcp_nodelay: bool,
    pub tcp_keepalive_secs: Option<u64>,
    pub tcp_bbr: bool,
    pub tcp_fast_open: bool,
    pub reuse_port: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ResourceLimitsSpec {
    pub max_connections: Option<u32>,
    pub max_connections_per_inbound: Option<u32>,
}

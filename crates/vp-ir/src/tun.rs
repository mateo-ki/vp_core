use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TunSpec {
    pub enable: bool,
    pub device: Option<String>,
    pub address: String,
    pub netmask: String,
    pub mtu: u16,
    pub auto_route: bool,
    pub auto_route_mode: Option<String>,
    pub auto_detect_interface: bool,
    pub route_address: Vec<String>,
    pub route_exclude_address: Vec<String>,
    pub dns_hijack: Vec<String>,
    pub strict: bool,
}

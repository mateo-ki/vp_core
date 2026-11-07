use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DnsSpec {
    pub enable: bool,
    pub listen: Option<String>,
    pub ipv6: bool,
    pub default_nameserver: Vec<String>,
    pub nameserver: Vec<String>,
    pub fallback: Vec<String>,
    pub fallback_filter: Option<FallbackFilterSpec>,
    pub nameserver_policy: HashMap<String, String>,
    pub hosts: HashMap<String, Vec<IpAddr>>,
    pub fake_ip: Option<FakeIpSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FallbackFilterSpec {
    pub geoip: bool,
    pub geoip_code: String,
    pub geosite: Vec<String>,
    pub ipcidr: Vec<String>,
    pub domain: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FakeIpSpec {
    pub enabled: bool,
    pub ip_range: String,
    pub filters: Vec<String>,
    pub persist: bool,
}

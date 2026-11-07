use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupType {
    Select,
    UrlTest,
    Fallback,
    LoadBalance,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum LbStrategy {
    #[default]
    RoundRobin,
    ConsistentHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupSpec {
    pub name: String,
    pub ty: GroupType,
    pub members: Vec<String>,
    pub providers: Vec<String>,
    pub test_url: Option<String>,
    pub interval: u64,
    pub tolerance: u32,
    pub lazy: bool,
    pub lb_strategy: LbStrategy,
    pub filter: Option<String>,
    pub exclude_filter: Option<String>,
    pub fallback: Option<String>,
    pub disable_udp: bool,
}

impl GroupSpec {
    pub fn new(name: impl Into<String>, ty: GroupType, members: Vec<String>) -> Self {
        Self {
            name: name.into(),
            ty,
            members,
            providers: Vec::new(),
            test_url: None,
            interval: 300,
            tolerance: 0,
            lazy: true,
            lb_strategy: LbStrategy::RoundRobin,
            filter: None,
            exclude_filter: None,
            fallback: None,
            disable_udp: false,
        }
    }
}

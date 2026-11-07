use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SecuritySpec {
    pub allow_geoip: Vec<String>,
    pub block_geoip: Vec<String>,
    pub allow_asn: Vec<u32>,
    pub block_asn: Vec<u32>,
    pub knock: Option<KnockSpec>,
    pub rrl: Option<RrlSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct KnockSpec {
    pub port: u16,
    pub secret: String,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RrlSpec {
    pub max_qps: u32,
    pub burst: u32,
    pub slip: u32,
}

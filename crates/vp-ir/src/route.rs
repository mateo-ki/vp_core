use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteRuleSpec {
    pub payload: RulePayload,
    pub target: String,
    pub no_resolve: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RulePayload {
    /// Google CEL 声明式表达式字符串
    Cel(String),
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainRegex(String),
    IpCidr {
        cidr: String,
        src: bool,
    },
    GeoSite(String),
    GeoIp(String),
    IpAsn {
        asn: u32,
        src: bool,
    },
    Port {
        ranges: Vec<(u16, u16)>,
        src: bool,
    },
    ProcessName(String),
    ProcessPath(String),
    Inbound(String),
    InPort(Vec<(u16, u16)>),
    InUser(String),
    Network(String),
    RuleSet(String),
    SubRule(String),
    MatchAll,
}

//! vp-rule 模块常量定义。

// ---------------------------------------------------------------------------
// 预编译规则集二进制魔数与格式
// ---------------------------------------------------------------------------

/// Zstandard 压缩魔数
pub const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Mihomo MRS 二进制规则集魔数 `MRS\x01`
pub const MRS_MAGIC: [u8; 4] = *b"MRS\x01";

/// sing-box SRS 二进制规则集魔数 `SRS`
pub const SRS_MAGIC: [u8; 3] = *b"SRS";

/// sing-box SRS 规则集支持的最小与最大版本号
pub const SRS_VERSION_MIN: u8 = 1;
pub const SRS_VERSION_MAX: u8 = 5;

// ---------------------------------------------------------------------------
// sing-box SRS Tagged Items 规则项标识
// ---------------------------------------------------------------------------

pub const RULE_ITEM_QUERY_TYPE: u8 = 0;
pub const RULE_ITEM_NETWORK: u8 = 1;
pub const RULE_ITEM_DOMAIN: u8 = 2;
pub const RULE_ITEM_DOMAIN_KEYWORD: u8 = 3;
pub const RULE_ITEM_DOMAIN_REGEX: u8 = 4;
pub const RULE_ITEM_SOURCE_IP_CIDR: u8 = 5;
pub const RULE_ITEM_IP_CIDR: u8 = 6;
pub const RULE_ITEM_SOURCE_PORT: u8 = 7;
pub const RULE_ITEM_SOURCE_PORT_RANGE: u8 = 8;
pub const RULE_ITEM_PORT: u8 = 9;
pub const RULE_ITEM_PORT_RANGE: u8 = 10;
pub const RULE_ITEM_PROCESS_NAME: u8 = 11;
pub const RULE_ITEM_PROCESS_PATH: u8 = 12;
pub const RULE_ITEM_FINAL: u8 = 0xFF;

// ---------------------------------------------------------------------------
// 规则保留目标与动作常量
// ---------------------------------------------------------------------------

pub const TARGET_DIRECT: &str = "DIRECT";
pub const TARGET_REJECT: &str = "REJECT";
pub const TARGET_PROXY: &str = "PROXY";

// ---------------------------------------------------------------------------
// 规则匹配器类型关键字
// ---------------------------------------------------------------------------

pub const RULE_DOMAIN: &str = "DOMAIN";
pub const RULE_DOMAIN_SUFFIX: &str = "DOMAIN-SUFFIX";
pub const RULE_DOMAIN_KEYWORD: &str = "DOMAIN-KEYWORD";
pub const RULE_DOMAIN_REGEX: &str = "DOMAIN-REGEX";
pub const RULE_IP_CIDR: &str = "IP-CIDR";
pub const RULE_IP_CIDR6: &str = "IP-CIDR6";
pub const RULE_GEOIP: &str = "GEOIP";
pub const RULE_GEOSITE: &str = "GEOSITE";
pub const RULE_PROCESS_NAME: &str = "PROCESS-NAME";
pub const RULE_PORT: &str = "DST-PORT";
pub const RULE_SRC_PORT: &str = "SRC-PORT";
pub const RULE_INBOUND_PORT: &str = "INBOUND-PORT";
pub const RULE_MATCH: &str = "MATCH";
pub const RULE_RULE_SET: &str = "RULE-SET";

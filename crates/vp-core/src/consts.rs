//! vp-core 核心模块常量定义。

// ---------------------------------------------------------------------------
// 核心保留出站与策略组名称
// ---------------------------------------------------------------------------

pub const OUTBOUND_DIRECT: &str = "DIRECT";
pub const OUTBOUND_REJECT: &str = "REJECT";
pub const OUTBOUND_PROXY: &str = "PROXY";
pub const OUTBOUND_PASS: &str = "PASS";

// ---------------------------------------------------------------------------
// 规则匹配与分流命中描述
// ---------------------------------------------------------------------------

pub const RULE_MATCH: &str = "MATCH";
pub const RULE_ADAPTIVE_LRU: &str = "Adaptive(LRU)";

// ---------------------------------------------------------------------------
// MEOW 风格自适应抗阻断重试参数
// ---------------------------------------------------------------------------

/// 默认自适应阻断域名缓存的存活期（TTL）：15 分钟
pub const DEFAULT_ADAPTIVE_TTL_SECS: u64 = 15 * 60;

/// 自适应阻断缓存最大条目数，防止无限制内存膨胀
pub const DEFAULT_ADAPTIVE_MAX_CAPACITY: usize = 5000;

/// 直连快速拨号超时阈值（毫秒）：2.5 秒未完成握手视为潜在阻断
pub const DEFAULT_DIRECT_TIMEOUT_MS: u64 = 2500;

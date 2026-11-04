//! vp-protocol 模块常量定义。

// ---------------------------------------------------------------------------
// 基础出站名称
// ---------------------------------------------------------------------------

pub const OUTBOUND_DIRECT: &str = "DIRECT";
pub const OUTBOUND_REJECT: &str = "REJECT";
pub const OUTBOUND_PROXY: &str = "PROXY";

// ---------------------------------------------------------------------------
// 自适应启发式直连重试参数
// ---------------------------------------------------------------------------

/// 直连建链超时检测阈值（毫秒）：2.5s
pub const DIRECT_CONNECT_TIMEOUT_MS: u64 = 2500;

// ---------------------------------------------------------------------------
// Smux / 多路复用 (Multiplex) 核心常量
// ---------------------------------------------------------------------------

pub const SMUX_VERSION: u8 = 1;
pub const CMD_SYN: u8 = 0;
pub const CMD_FIN: u8 = 1;
pub const CMD_PSH: u8 = 2;
pub const CMD_NOP: u8 = 3;

/// 物理长连接锚点虚拟地址，解耦物理连接与单次业务目标
pub const DEFAULT_MUX_ANCHOR: &str = "v1.mux.cool:0";

/// Mux 链路心跳保活检测间隔（秒）
pub const MUX_PING_INTERVAL_SECS: u64 = 15;

/// Mux 链路最大空闲超时（秒）
pub const MUX_IDLE_TIMEOUT_SECS: u64 = 60;

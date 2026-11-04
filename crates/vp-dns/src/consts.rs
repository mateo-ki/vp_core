//! vp-dns 模块常量定义。

// ---------------------------------------------------------------------------
// Fake-IP 核心常量
// ---------------------------------------------------------------------------

/// 默认 fake-ip 网段（198.18.0.0/15，RFC 2544 benchmark 保留段）
pub const DEFAULT_FAKEIP_RANGE: &str = "198.18.0.0/15";

/// Fake-IP 二进制事务快照文件魔数 `FKIP\x01`
pub const FAKEIP_MAGIC: [u8; 4] = *b"FKI\x01";

/// 快照文件头部定长字节数 (Magic: 4B + Base: 4B + Size: 4B + Next: 4B + Count: 4B + Checksum: 4B)
pub const FAKEIP_HEADER_SIZE: usize = 24;

/// 默认持久化快照文件名
pub const DEFAULT_FAKEIP_DB_FILE: &str = "fakeip.db";

/// 异步防抖刷盘默认间隔（秒）
pub const DEFAULT_PERSIST_DEBOUNCE_SECS: u64 = 1;

/// Fake-IP 地址池满时的淘汰比例除数（如 10 代表淘汰最老 10%）
pub const FAKEIP_EVICTION_DIVISOR: usize = 10;

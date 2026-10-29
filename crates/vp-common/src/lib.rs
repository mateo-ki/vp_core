//! VP_Core 公共基础库。

pub mod addr;
pub mod bufpool;
pub mod error;
pub mod stats;

pub use addr::{DstAddr, Host};
pub use bufpool::get_buf;
pub use error::{Error, Result};
pub use stats::{ConnBudget, ConnPermit, ResourceLimits, Stats, StatsSnapshot};

/// 生成密码学随机字节
pub fn rand_bytes(buf: &mut [u8]) {
    use rand::RngCore;
    rand::rng().fill_bytes(buf);
}

/// 当前 Unix 毫秒
pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

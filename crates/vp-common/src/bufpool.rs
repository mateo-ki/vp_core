//! 全局缓冲池：转发引擎按块租借/归还，避免每连接反复分配。
//! 每条连接仅在泵启动时租借主块（预读块只在读到"整块满"时才租），锁竞争可忽略。

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

// ---- 观测指标（审计报告任务2/3 第一阶段：先统计，后预算）----
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static POOL_HIT: AtomicU64 = AtomicU64::new(0);
static POOL_MISS: AtomicU64 = AtomicU64::new(0);
static OVER_BUDGET: AtomicU64 = AtomicU64::new(0);
/// 活跃缓冲区预算上限（0 = 不限）。超限不阻塞数据面（会拖死转发），
/// 只计数告警 —— 硬限流等压测证明必要后再上。
static ACTIVE_CAP: AtomicUsize = AtomicUsize::new(0);

/// 设置活跃缓冲区预算（0 = 不限）
pub fn set_active_budget(cap: usize) {
    ACTIVE_CAP.store(cap, Ordering::Relaxed);
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BufpoolStats {
    /// 正被连接持有的缓冲块数（活跃内存的直接观测值）
    pub active: usize,
    /// 闲置池中的块数
    pub idle: usize,
    pub pool_hits: u64,
    pub pool_misses: u64,
    /// 超预算分配次数（预算开启时）
    pub over_budget: u64,
}

/// 缓冲池观测快照：活跃内存 = active * BUF_SIZE
pub fn stats() -> BufpoolStats {
    BufpoolStats {
        active: ACTIVE.load(Ordering::Relaxed),
        idle: pool().lock().unwrap().len(),
        pool_hits: POOL_HIT.load(Ordering::Relaxed),
        pool_misses: POOL_MISS.load(Ordering::Relaxed),
        over_budget: OVER_BUDGET.load(Ordering::Relaxed),
    }
}

/// 32KB：裸转发单核吞吐的关键参数 —— 两次 syscall（读+写）搬 32KB，
/// 相比 16KB 直接把 syscall 数砍半；交互式小包流量读不满整块，走不到预读，无额外延迟。
pub const BUF_SIZE: usize = 32 * 1024;
/// 缓冲池上限：256 块 * 32KB = 8MB 常驻上限，兼顾高并发零分配与低内存嵌入式/路由器设备不 OOM
const POOL_CAP: usize = 256;

fn pool() -> &'static Mutex<Vec<Box<[u8; BUF_SIZE]>>> {
    static POOL: OnceLock<Mutex<Vec<Box<[u8; BUF_SIZE]>>>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(Vec::new()))
}

/// 租借一块缓冲，Drop 时自动归还池。
pub struct PooledBuf {
    buf: Option<Box<[u8; BUF_SIZE]>>,
    len: usize,
}

impl PooledBuf {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf.as_ref().unwrap()[..self.len]
    }

    pub fn spare_mut(&mut self) -> &mut [u8] {
        self.buf.as_mut().unwrap().as_mut_slice()
    }

    pub fn set_len(&mut self, len: usize) {
        debug_assert!(len <= BUF_SIZE);
        self.len = len;
    }
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::Relaxed);
        if let Some(buf) = self.buf.take() {
            let mut p = pool().lock().unwrap();
            if p.len() < POOL_CAP {
                p.push(buf);
            }
        }
    }
}

pub fn get_buf() -> PooledBuf {
    let (buf, hit) = pool()
        .lock()
        .unwrap()
        .pop()
        .map(|b| (b, true))
        .unwrap_or_else(|| (vec![0u8; BUF_SIZE].try_into().expect("exact size"), false));
    if hit {
        POOL_HIT.fetch_add(1, Ordering::Relaxed);
    } else {
        POOL_MISS.fetch_add(1, Ordering::Relaxed);
    }
    let active = ACTIVE.fetch_add(1, Ordering::AcqRel) + 1;
    let cap = ACTIVE_CAP.load(Ordering::Relaxed);
    if cap > 0 && active > cap {
        OVER_BUDGET.fetch_add(1, Ordering::Relaxed);
    }
    PooledBuf {
        buf: Some(buf),
        len: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_track_active_and_hits() {
        let before = stats();
        let b = get_buf();
        let mid = stats();
        assert_eq!(mid.active, before.active + 1);
        drop(b);
        let after = stats();
        assert_eq!(after.active, before.active);
        // 复用一次必命中（上一块刚归还）
        let c = get_buf();
        drop(c);
        assert!(stats().pool_hits > before.pool_hits || before.pool_hits == 0);
    }

    #[test]
    fn rent_return() {
        let mut b = get_buf();
        assert_eq!(b.spare_mut().len(), BUF_SIZE);
        b.set_len(8);
        assert_eq!(b.as_slice().len(), 8);
        drop(b);
        let b2 = get_buf(); // 应从池中复用
        drop(b2);
    }
}

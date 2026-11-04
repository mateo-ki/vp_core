//! 自适应阻断学习与临时代理缓存 (借鉴 MEOW 启发式重试)。
//!
//! 在 DIRECT 直连模式下，当目标遭遇 TCP RST、连接拒绝或拨号快速超时时，
//! 自动将该域名/主机记入内存带 TTL 的 LRU 阻断缓存，并透明重试兜底代理。
//! 后续请求在路由分流阶段前置短路，直接命中代理，无需再次等待直连重试。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::consts::{DEFAULT_ADAPTIVE_MAX_CAPACITY, DEFAULT_ADAPTIVE_TTL_SECS};

static GLOBAL_TTL: AtomicU64 = AtomicU64::new(DEFAULT_ADAPTIVE_TTL_SECS);

#[derive(Default)]
struct CacheInner {
    /// 域名 -> 过期时间戳 (秒)
    entries: HashMap<String, u64>,
}

static ADAPTIVE_CACHE: OnceLock<RwLock<CacheInner>> = OnceLock::new();

fn cache() -> &'static RwLock<CacheInner> {
    ADAPTIVE_CACHE.get_or_init(|| RwLock::new(CacheInner::default()))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// 设置临时阻断缓存的 TTL（秒）
pub fn set_ttl_secs(ttl: u64) {
    GLOBAL_TTL.store(ttl, Ordering::Relaxed);
}

/// 记录目标主机被直连阻断（写入临时 LRU 代理表）
pub fn record_block(host: &str) {
    let key = host.trim().to_ascii_lowercase();
    if key.is_empty() {
        return;
    }

    let now = now_secs();
    let ttl = GLOBAL_TTL.load(Ordering::Relaxed);
    let expire_at = now + ttl;

    let mut inner = cache().write().unwrap();

    // 容量上限保护：若超额，先清理已过期的条目
    if inner.entries.len() >= DEFAULT_ADAPTIVE_MAX_CAPACITY {
        inner.entries.retain(|_, exp| *exp > now);
        if inner.entries.len() >= DEFAULT_ADAPTIVE_MAX_CAPACITY {
            // 若仍满，随机淘汰最先遍历到的 10%
            let to_remove: Vec<String> = inner
                .entries
                .keys()
                .take(DEFAULT_ADAPTIVE_MAX_CAPACITY / 10)
                .cloned()
                .collect();
            for k in to_remove {
                inner.entries.remove(&k);
            }
        }
    }

    inner.entries.insert(key, expire_at);
}

/// 检查目标主机是否此前被直连阻断过且仍在临时代理期内
pub fn is_blocked(host: &str) -> bool {
    let key = host.trim().to_ascii_lowercase();
    if key.is_empty() {
        return false;
    }

    let now = now_secs();
    let inner = cache().read().unwrap();
    if let Some(&expire_at) = inner.entries.get(&key) {
        if expire_at > now {
            return true;
        }
    }

    // 若当前是子域名，检查父域是否已在阻断表中（例如 sub.google.com -> google.com）
    let mut parts = key.split('.');
    while parts.next().is_some() {
        let parent = parts.clone().collect::<Vec<_>>().join(".");
        if !parent.is_empty() {
            if let Some(&expire_at) = inner.entries.get(&parent) {
                if expire_at > now {
                    return true;
                }
            }
        }
    }

    false
}

/// 获取当前受阻临时代理的域名总数
pub fn len() -> usize {
    let now = now_secs();
    let inner = cache().read().unwrap();
    inner.entries.values().filter(|&&exp| exp > now).count()
}

/// 清空临时代理缓存
pub fn clear() {
    let mut inner = cache().write().unwrap();
    inner.entries.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adaptive_cache_flow() {
        clear();
        set_ttl_secs(DEFAULT_ADAPTIVE_TTL_SECS);
        assert!(!is_blocked("test-blocked.com"));
        record_block("test-blocked.com");
        assert!(is_blocked("test-blocked.com"));
        assert!(is_blocked("sub.test-blocked.com")); // 子域名继承
        assert!(!is_blocked("other.com"));

        // 过期测试
        set_ttl_secs(1);
        record_block("quick-expire.com");
        assert!(is_blocked("quick-expire.com"));
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(!is_blocked("quick-expire.com"));
        set_ttl_secs(DEFAULT_ADAPTIVE_TTL_SECS);
    }
}

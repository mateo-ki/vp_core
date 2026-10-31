//! Fake-IP 池：域名 ↔ 保留网段 IP 的双向映射（TUN 模式的核心）。
//!
//! - 从 CIDR（默认 198.18.0.0/15）顺序分配，映射持久（LRU 驱逐）
//! - TTL=1：客户端不缓存，保证映射可回收
//! - 线程安全，读多写少

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

/// 默认 fake-ip 网段（198.18.0.0/15，benchmark 保留段）
pub const DEFAULT_RANGE: &str = "198.18.0.0/15";

#[derive(Default)]
struct Inner {
    by_domain: HashMap<String, Ipv4Addr>,
    by_ip: HashMap<Ipv4Addr, String>,
    order: Vec<String>, // LRU 粗粒度序（容量满时整体回收）
    next: u32,
}

#[derive(Clone)]
pub struct FakeIpPool {
    base: u32,
    /// 网段总容量（contains 判定用）
    size: u32,
    /// 可分配地址数（扣除网络/广播地址）
    usable: u32,
    /// 共享状态（Clone 共享同一池）
    inner: Arc<Mutex<Inner>>,
}

impl FakeIpPool {
    /// 解析 CIDR（如 "198.18.0.0/15"）
    pub fn new(cidr: &str) -> Option<FakeIpPool> {
        let (ip, plen) = cidr.split_once('/')?;
        let ip: Ipv4Addr = ip.parse().ok()?;
        let plen: u8 = plen.parse().ok()?;
        if plen > 31 {
            return None;
        }
        let base = u32::from(ip) & mask_of(plen);
        let size = if plen == 0 {
            u32::MAX
        } else {
            1u32 << (32 - plen)
        };
        // 若网段足够大（> 4），预留 base+0(网络号)、base+1(TUN网卡本机IP)、base+2(Wintun DNS地址) 与广播地址
        let usable = if size <= 4 {
            size.saturating_sub(2)
        } else {
            size.saturating_sub(4)
        };
        Some(FakeIpPool {
            base,
            size,
            usable,
            inner: Arc::new(Mutex::new(Inner::default())),
        })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let n = u32::from(v4);
                n >= self.base && n < self.base.saturating_add(self.size)
            }
            IpAddr::V6(_) => false,
        }
    }

    /// 域名 → fake-ip（同一域名恒定返回同一 IP）
    pub fn allocate(&self, domain: &str) -> Option<Ipv4Addr> {
        let key = domain.to_ascii_lowercase();
        let mut inner = self.inner.lock().unwrap();
        if let Some(ip) = inner.by_domain.get(&key) {
            return Some(*ip);
        }
        if inner.next >= self.usable {
            // 池耗尽：整体重置后继续分配
            inner.by_domain.clear();
            inner.by_ip.clear();
            inner.order.clear();
            inner.next = 0;
        }
        let n = inner.next;
        inner.next += 1;
        // 网段 > 4 时避开 base+1(TUN本机IP) 与 base+2(DNS)，从 base+3 开始分配
        let offset = if self.size <= 4 { 1 } else { 3 };
        let ip = Ipv4Addr::from(self.base + offset + n);
        inner.by_domain.insert(key.clone(), ip);
        inner.by_ip.insert(ip, key.clone());
        inner.order.push(key);
        Some(ip)
    }

    /// fake-ip → 域名
    pub fn reverse(&self, ip: IpAddr) -> Option<String> {
        let IpAddr::V4(v4) = ip else { return None };
        self.inner.lock().unwrap().by_ip.get(&v4).cloned()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().by_domain.len()
    }

    /// 清空所有已分配的 Fake-IP 映射记录
    pub fn clear(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.by_domain.clear();
        inner.by_ip.clear();
        inner.order.clear();
        inner.next = 0;
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn mask_of(plen: u8) -> u32 {
    if plen == 0 {
        0
    } else {
        u32::MAX << (32 - plen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ranges() {
        assert!(FakeIpPool::new(DEFAULT_RANGE).is_some());
        assert!(FakeIpPool::new("198.18.0.0/16").is_some());
        assert!(FakeIpPool::new("bogus").is_none());
    }

    #[test]
    fn allocation_stable_and_reversible() {
        let pool = FakeIpPool::new("198.18.0.0/15").unwrap();
        let a = pool.allocate("google.com").unwrap();
        let b = pool.allocate("google.com").unwrap();
        assert_eq!(a, b, "同一域名应稳定复用");
        let c = pool.allocate("other.com").unwrap();
        assert_ne!(a, c);
        assert_eq!(pool.reverse(IpAddr::V4(a)).as_deref(), Some("google.com"));
        assert_eq!(pool.reverse(IpAddr::V4(c)).as_deref(), Some("other.com"));
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn contains_range() {
        let pool = FakeIpPool::new("198.18.0.0/15").unwrap();
        assert!(pool.contains("198.18.0.1".parse().unwrap()));
        assert!(pool.contains("198.19.255.254".parse().unwrap()));
        assert!(!pool.contains("198.20.0.0".parse().unwrap()));
        assert!(!pool.contains("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn tiny_pool_exhaustion_recycles() {
        // /30 → 2 个可用地址
        let pool = FakeIpPool::new("10.99.0.0/30").unwrap();
        assert!(pool.allocate("a.com").is_some());
        assert!(pool.allocate("b.com").is_some());
        // 第三次触发重置后重新分配
        let c = pool.allocate("c.com");
        assert!(c.is_some());
        assert_eq!(
            pool.reverse(IpAddr::V4(c.unwrap())).as_deref(),
            Some("c.com")
        );
    }

    #[test]
    fn case_insensitive() {
        let pool = FakeIpPool::new(DEFAULT_RANGE).unwrap();
        let a = pool.allocate("Example.COM").unwrap();
        assert_eq!(pool.reverse(IpAddr::V4(a)).as_deref(), Some("example.com"));
    }
}

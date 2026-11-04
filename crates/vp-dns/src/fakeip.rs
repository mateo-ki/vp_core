//! Fake-IP 池：域名 ↔ 保留网段 IP 的双向映射（TUN 模式的核心）。
//!
//! - 从 CIDR（默认 198.18.0.0/15）顺序分配，映射持久（LRU 驱逐）
//! - TTL=1：客户端不缓存，保证映射可回收
//! - 线程安全，读多写少
//! - 支持二进制持久化与冷启动恢复 (FKIP\x01)，支持防抖异步刷盘与断电完整性校验

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use crate::consts::{
    DEFAULT_FAKEIP_RANGE as DEFAULT_RANGE, FAKEIP_EVICTION_DIVISOR, FAKEIP_HEADER_SIZE,
    FAKEIP_MAGIC,
};

#[derive(Default)]
struct Inner {
    by_domain: HashMap<String, (Ipv4Addr, u64)>, // (IP, 最后访问秒级时间戳)
    by_ip: HashMap<Ipv4Addr, String>,
    order: Vec<String>, // LRU 顺序
    next: u32,
    dirty: bool,
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
        let now = now_secs();
        let mut inner = self.inner.lock().unwrap();

        if let Some((ip, last_seen)) = inner.by_domain.get_mut(&key) {
            *last_seen = now;
            return Some(*ip);
        }

        // 容量耗尽时，逐项 LRU 淘汰最老的条目，避免瞬间清空所有活跃连接
        if inner.by_domain.len() as u32 >= self.usable {
            let evict_count = (self.usable / 10).max(1) as usize;
            for _ in 0..evict_count {
                if !inner.order.is_empty() {
                    let oldest = inner.order.remove(0);
                    if let Some((evicted_ip, _)) = inner.by_domain.remove(&oldest) {
                        inner.by_ip.remove(&evicted_ip);
                    }
                }
            }
        }

        let n = if inner.next < self.usable {
            let cur = inner.next;
            inner.next += 1;
            cur
        } else {
            // 水位线已满，循环利用空闲 IP 槽位
            inner.next = 0;
            let cur = inner.next;
            inner.next += 1;
            cur
        };

        // 网段 > 4 时避开 base+1(TUN本机IP) 与 base+2(DNS)，从 base+3 开始分配
        let offset = if self.size <= 4 { 1 } else { 3 };
        let ip = Ipv4Addr::from(self.base + offset + n);

        // 如果旧槽位上有残留映射，先行清理
        if let Some(old_dom) = inner.by_ip.remove(&ip) {
            inner.by_domain.remove(&old_dom);
            inner.order.retain(|d| d != &old_dom);
        }

        inner.by_domain.insert(key.clone(), (ip, now));
        inner.by_ip.insert(ip, key.clone());
        inner.order.push(key);
        inner.dirty = true;
        Some(ip)
    }

    /// fake-ip → 域名
    pub fn reverse(&self, ip: IpAddr) -> Option<String> {
        let IpAddr::V4(v4) = ip else { return None };
        let mut inner = self.inner.lock().unwrap();
        if let Some(dom) = inner.by_ip.get(&v4).cloned() {
            if let Some((_, last_seen)) = inner.by_domain.get_mut(&dom) {
                *last_seen = now_secs();
            }
            Some(dom)
        } else {
            None
        }
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
        inner.dirty = true;
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 标记是否包含未刷盘的脏变更
    pub fn is_dirty(&self) -> bool {
        self.inner.lock().unwrap().dirty
    }

    /// 将 Fake-IP 映射持久化至本地二进制快照文件
    pub fn save_to_file(&self, path: &Path) -> std::io::Result<usize> {
        let (base, size, next, entries) = {
            let mut inner = self.inner.lock().unwrap();
            if !inner.dirty && path.exists() {
                return Ok(0);
            }
            let entries: Vec<(String, u32, u64)> = inner
                .by_domain
                .iter()
                .map(|(d, (ip, seen))| (d.clone(), u32::from(*ip), *seen))
                .collect();
            inner.dirty = false;
            (self.base, self.size, inner.next, entries)
        };

        let mut buf = Vec::with_capacity(24 + entries.len() * 32);
        buf.extend_from_slice(&FAKEIP_MAGIC);
        buf.extend_from_slice(&base.to_be_bytes());
        buf.extend_from_slice(&size.to_be_bytes());
        buf.extend_from_slice(&next.to_be_bytes());
        buf.extend_from_slice(&(entries.len() as u32).to_be_bytes());

        for (domain, ip_num, seen) in &entries {
            let d_bytes = domain.as_bytes();
            let d_len = d_bytes.len().min(u16::MAX as usize) as u16;
            buf.extend_from_slice(&d_len.to_be_bytes());
            buf.extend_from_slice(&d_bytes[..d_len as usize]);
            buf.extend_from_slice(&ip_num.to_be_bytes());
            buf.extend_from_slice(&seen.to_be_bytes());
        }

        // 计算 Adler-32 校验码，防止掉电损坏
        let checksum = adler32(&buf);
        buf.extend_from_slice(&checksum.to_be_bytes());

        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, &buf)?;
        let _ = std::fs::remove_file(path);
        std::fs::rename(&tmp_path, path)?;

        Ok(entries.len())
    }

    /// 从本地二进制快照中恢复 Fake-IP 映射（冷启动恢复）
    pub fn load_from_file(&self, path: &Path) -> std::io::Result<usize> {
        if !path.exists() {
            return Ok(0);
        }
        let buf = std::fs::read(path)?;
        if buf.len() < FAKEIP_HEADER_SIZE {
            return Ok(0);
        }

        let mut cursor = 0;
        if buf[0..4] != FAKEIP_MAGIC {
            return Ok(0);
        }
        cursor += 4;

        let file_base = u32::from_be_bytes(buf[cursor..cursor + 4].try_into().unwrap());
        cursor += 4;
        let file_size = u32::from_be_bytes(buf[cursor..cursor + 4].try_into().unwrap());
        cursor += 4;
        let file_next = u32::from_be_bytes(buf[cursor..cursor + 4].try_into().unwrap());
        cursor += 4;
        let count = u32::from_be_bytes(buf[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;

        // 若配置的 Fake-IP 网段范围已变更，则直接废弃不兼容的旧映射
        if file_base != self.base || file_size != self.size {
            tracing::info!(
                "Fake-IP 网段配置已变更 (旧: 0x{:08x}/0x{:08x}, 新: 0x{:08x}/0x{:08x})，丢弃旧快照",
                file_base,
                file_size,
                self.base,
                self.size
            );
            return Ok(0);
        }

        // 校验 Checksum
        if buf.len() < 4 {
            return Ok(0);
        }
        let payload_len = buf.len() - 4;
        let expected_checksum = u32::from_be_bytes(buf[payload_len..].try_into().unwrap());
        if adler32(&buf[..payload_len]) != expected_checksum {
            tracing::warn!("Fake-IP 缓存文件校验和损坏，已放弃恢复");
            return Ok(0);
        }

        let now = now_secs();
        let max_age_secs = 7 * 86400; // 最长保留 7 天
        let mut loaded = 0usize;

        let mut inner = self.inner.lock().unwrap();
        for _ in 0..count {
            if cursor + 2 > payload_len {
                break;
            }
            let d_len = u16::from_be_bytes(buf[cursor..cursor + 2].try_into().unwrap()) as usize;
            cursor += 2;
            if cursor + d_len + 4 + 8 > payload_len {
                break;
            }
            let domain_bytes = &buf[cursor..cursor + d_len];
            cursor += d_len;
            let ip_num = u32::from_be_bytes(buf[cursor..cursor + 4].try_into().unwrap());
            cursor += 4;
            let seen = u64::from_be_bytes(buf[cursor..cursor + 8].try_into().unwrap());
            cursor += 8;

            // 过滤超期条目
            if now.saturating_sub(seen) > max_age_secs {
                continue;
            }

            if let Ok(domain) = std::str::from_utf8(domain_bytes) {
                let ip = Ipv4Addr::from(ip_num);
                let dom_key = domain.to_ascii_lowercase();
                inner.by_domain.insert(dom_key.clone(), (ip, seen));
                inner.by_ip.insert(ip, dom_key.clone());
                inner.order.push(dom_key);
                loaded += 1;
            }
        }

        inner.next = file_next;
        inner.dirty = false;
        tracing::info!("Fake-IP 已成功从磁盘快照恢复 {} 条映射关系", loaded);
        Ok(loaded)
    }
}

/// Fake-IP 异步防抖持久化守护者
pub struct FakeIpPersister {
    pool: FakeIpPool,
    path: PathBuf,
    stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl FakeIpPersister {
    /// 启动后台持久化定时器，自动加载历史并监听变更防抖落盘
    pub fn start(pool: FakeIpPool, path: PathBuf) -> Self {
        let _ = pool.load_from_file(&path);
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();
        let pool_clone = pool.clone();
        let path_clone = path.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(1000));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let _ = pool_clone.save_to_file(&path_clone);
                    }
                    _ = &mut stop_rx => {
                        let _ = pool_clone.save_to_file(&path_clone);
                        break;
                    }
                }
            }
        });

        Self {
            pool,
            path,
            stop_tx: Some(stop_tx),
        }
    }

    /// 立即强制刷盘
    pub fn flush(&self) {
        let _ = self.pool.save_to_file(&self.path);
    }
}

impl Drop for FakeIpPersister {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        self.flush();
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
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
        // 第三次触发回收后重新分配
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

    #[test]
    fn test_persistence_save_and_reload() {
        let temp_dir = std::env::temp_dir().join(format!("fakeip_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let file_path = temp_dir.join("fakeip.bin");

        let pool = FakeIpPool::new("198.18.0.0/15").unwrap();
        let ip_google = pool.allocate("google.com").unwrap();
        let ip_github = pool.allocate("github.com").unwrap();

        let saved = pool.save_to_file(&file_path).expect("应当成功保存");
        assert_eq!(saved, 2);

        // 创建新池，模拟重启后从文件恢复
        let pool2 = FakeIpPool::new("198.18.0.0/15").unwrap();
        assert_eq!(pool2.len(), 0);
        let loaded = pool2.load_from_file(&file_path).expect("应当成功加载");
        assert_eq!(loaded, 2);
        assert_eq!(
            pool2.reverse(IpAddr::V4(ip_google)).as_deref(),
            Some("google.com")
        );
        assert_eq!(
            pool2.reverse(IpAddr::V4(ip_github)).as_deref(),
            Some("github.com")
        );

        // 再次分配新域名，分配不应与已恢复的产生碰撞
        let ip_new = pool2.allocate("newsite.com").unwrap();
        assert_ne!(ip_new, ip_google);
        assert_ne!(ip_new, ip_github);

        let _ = std::fs::remove_dir_all(temp_dir);
    }
}

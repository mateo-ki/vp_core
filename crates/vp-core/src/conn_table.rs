//! 活动连接表：供外部控制器查询 / 关闭连接。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio::task::AbortHandle;

#[derive(Debug, Clone, Serialize)]
pub struct ConnMeta {
    pub id: u64,
    pub inbound: Arc<str>,
    pub network: &'static str,
    pub host: String,
    pub dst_port: u16,
    pub src: Option<String>,
    pub process: Option<Arc<str>>,
    /// 命中的规则（若有）
    pub rule: Option<String>,
    /// 出站链（组穿透后的最终节点）
    pub chain: Option<Arc<str>>,
    pub start: u64,
}

#[derive(Serialize, Clone)]
pub struct ConnSnapshot {
    #[serde(flatten)]
    pub meta: ConnMeta,
    pub upload: u64,
    pub download: u64,
}

struct ConnEntry {
    meta: ConnMeta,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
    aborts: Vec<AbortHandle>,
}

/// 分片数：16 片把高并发建删连接时的锁竞争摊薄（报告任务4）。
/// 连接表不在数据面热路径上（流量走独立原子计数器），分片是预防性优化；
/// 语义与单锁版本完全一致，既有测试即回归。
const SHARDS: usize = 16;

fn shard_of(id: u64) -> usize {
    // 乘法哈希取高位：连续 id 也能均匀落片
    ((id as usize).wrapping_mul(0x9E37_79B9_7F4A_7C15)) >> (usize::BITS - 4) & (SHARDS - 1)
}

pub struct ConnTable {
    shards: Vec<Mutex<HashMap<u64, ConnEntry>>>,
}

impl Default for ConnTable {
    fn default() -> Self {
        ConnTable {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        }
    }
}

/// register() 的返回：连接 id 与实时流量计数器
pub struct RegisteredConn {
    pub id: u64,
    pub up: Arc<AtomicU64>,
    pub down: Arc<AtomicU64>,
}

impl ConnTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, meta: ConnMeta) -> RegisteredConn {
        let id = meta.id;
        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));
        self.shards[shard_of(id)].lock().unwrap().insert(
            id,
            ConnEntry {
                meta,
                up: up.clone(),
                down: down.clone(),
                aborts: Vec::new(),
            },
        );
        RegisteredConn { id, up, down }
    }

    /// 转发任务 spawn 后挂载终止句柄
    pub fn attach_aborts(&self, id: u64, aborts: Vec<AbortHandle>) {
        if let Some(e) = self.shards[shard_of(id)].lock().unwrap().get_mut(&id) {
            e.aborts = aborts;
        }
    }

    pub fn remove(&self, id: u64) {
        self.shards[shard_of(id)].lock().unwrap().remove(&id);
    }

    pub fn kill(&self, id: u64) -> bool {
        let entry = self.shards[shard_of(id)].lock().unwrap().remove(&id);
        match entry {
            Some(e) => {
                for h in e.aborts {
                    h.abort();
                }
                true
            }
            None => false,
        }
    }

    pub fn close_all(&self) -> usize {
        let mut n = 0;
        for shard in &self.shards {
            let mut inner = shard.lock().unwrap();
            n += inner.len();
            for (_, e) in inner.drain() {
                for h in e.aborts {
                    h.abort();
                }
            }
        }
        n
    }

    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().unwrap().len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.shards.iter().all(|s| s.lock().unwrap().is_empty())
    }

    pub fn list(&self) -> Vec<ConnSnapshot> {
        // 逐片加锁收集，不同时持有两把锁
        let mut v = Vec::new();
        for shard in &self.shards {
            let inner = shard.lock().unwrap();
            v.reserve(inner.len());
            for e in inner.values() {
                v.push(ConnSnapshot {
                    meta: e.meta.clone(),
                    upload: e.up.load(Ordering::Relaxed),
                    download: e.down.load(Ordering::Relaxed),
                });
            }
        }
        v.sort_by_key(|s| s.meta.id);
        v
    }
}

/// 为 API 生成 RFC3339 时间戳
pub fn iso8601(millis: u64) -> String {
    let secs = millis / 1000;
    let ms = millis % 1000;
    let days = secs / 86400;
    let tod = secs % 86400;
    let (h, m, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    // days-from-civil 逆运算（civil_from_days, Howard Hinnant 算法）
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.{ms:03}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_list_kill() {
        let t = ConnTable::new();
        let meta = ConnMeta {
            id: 7,
            inbound: "mixed".into(),
            network: "tcp",
            host: "example.com".into(),
            dst_port: 443,
            src: None,
            process: None,
            rule: None,
            chain: None,
            start: vp_common::now_millis(),
        };
        let rc = t.register(meta);
        assert_eq!(t.len(), 1);
        rc.up.store(123, Ordering::Relaxed);
        let l = t.list();
        assert_eq!(l[0].upload, 123);
        assert_eq!(l[0].meta.host, "example.com");
        assert!(t.kill(7));
        assert!(t.is_empty());
        assert!(!t.kill(7));
    }

    #[test]
    fn iso_format() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601(1_700_000_000_123), "2023-11-14T22:13:20.123Z");
    }
}

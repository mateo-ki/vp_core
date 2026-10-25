//! 原子计数器：全局与每节点流量/连接统计。

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Stats {
    pub connections: AtomicI64,
    pub upload: AtomicU64,
    pub download: AtomicU64,
}

impl Stats {
    pub fn conn_open(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn conn_close(&self) {
        self.connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn add_up(&self, n: u64) {
        self.upload.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_down(&self, n: u64) {
        self.download.fetch_add(n, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            connections: self.connections.load(Ordering::Relaxed),
            upload: self.upload.load(Ordering::Relaxed),
            download: self.download.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct StatsSnapshot {
    pub connections: i64,
    pub upload: u64,
    pub download: u64,
}

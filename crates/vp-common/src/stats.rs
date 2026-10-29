//! 原子计数器：全局与每节点流量/连接统计。

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

#[derive(Debug, Default)]
pub struct Stats {
    pub connections: AtomicI64,
    pub upload: AtomicU64,
    pub download: AtomicU64,
    /// 连接资源预算（缺省不限；服务端配置后生效）
    pub conn_budget: ConnBudget,
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

/// 连接资源限额（审计报告任务2）：全局 / 每入站 TCP 连接上限。
/// None = 不限。缺省全 None（桌面端零行为变化），服务端配置后生效。
#[derive(Debug, Clone, Copy, Default)]
pub struct ResourceLimits {
    pub max_connections: Option<u32>,
    pub max_connections_per_inbound: Option<u32>,
}

/// 连接预算：CAS 计数实现（vp-common 无 tokio 依赖）。
/// 超限"快速拒绝"（报告允许的行为之一）；额度由 [`ConnPermit`] RAII 归还，
/// 连接正常结束 / 出错 / 任务取消都能可靠释放。
#[derive(Debug, Default)]
pub struct ConnBudget {
    limits: RwLock<ResourceLimits>,
    total_active: AtomicUsize,
    per_inbound: Mutex<HashMap<Arc<str>, usize>>,
    rejected_total: AtomicU64,
}

impl ConnBudget {
    /// 应用限额（启动时装配一次；热更可再次调用）
    pub fn configure(&self, limits: ResourceLimits) {
        *self.limits.write().unwrap() = limits;
    }

    /// 申请一个连接额度。返回 None = 超限拒绝。
    pub fn try_acquire(&self, inbound: &Arc<str>) -> Option<ConnPermit<'_>> {
        let limits = *self.limits.read().unwrap();
        if let Some(max) = limits.max_connections {
            let prev = self.total_active.fetch_add(1, Ordering::AcqRel);
            if prev as u64 >= max as u64 {
                self.total_active.fetch_sub(1, Ordering::AcqRel);
                self.rejected_total.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        } else {
            self.total_active.fetch_add(1, Ordering::AcqRel);
        }
        let mut m = self.per_inbound.lock().unwrap();
        let cnt = m.entry(inbound.clone()).or_insert(0);
        if let Some(max) = limits.max_connections_per_inbound {
            if *cnt >= max as usize {
                drop(m);
                self.total_active.fetch_sub(1, Ordering::AcqRel);
                self.rejected_total.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }
        *cnt += 1;
        Some(ConnPermit {
            budget: self,
            inbound: inbound.clone(),
        })
    }

    /// 观测快照：当前活跃 / 已拒绝总数
    pub fn snapshot(&self) -> (usize, u64) {
        (
            self.total_active.load(Ordering::Relaxed),
            self.rejected_total.load(Ordering::Relaxed),
        )
    }
}

/// 连接额度凭证：持有期间占用 1 个全局 + 1 个入站额度，Drop 自动归还。
#[derive(Debug)]
pub struct ConnPermit<'a> {
    budget: &'a ConnBudget,
    inbound: Arc<str>,
}

impl Drop for ConnPermit<'_> {
    fn drop(&mut self) {
        self.budget.total_active.fetch_sub(1, Ordering::AcqRel);
        if let Some(c) = self
            .budget
            .per_inbound
            .lock()
            .unwrap()
            .get_mut(&self.inbound)
        {
            *c = c.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    #[test]
    fn global_limit_rejects_and_releases() {
        let b = ConnBudget::default();
        b.configure(ResourceLimits {
            max_connections: Some(2),
            max_connections_per_inbound: None,
        });
        let inb: Arc<str> = "in".into();
        let p1 = b.try_acquire(&inb);
        let p2 = b.try_acquire(&inb);
        assert!(p1.is_some() && p2.is_some());
        assert!(b.try_acquire(&inb).is_none(), "第三个连接应被拒绝");
        assert_eq!(b.snapshot().1, 1, "拒绝计数");
        drop(p1);
        let p3 = b.try_acquire(&inb);
        assert!(p3.is_some(), "释放后应可再申请");
        drop(p2);
        drop(p3);
        assert_eq!(b.snapshot().0, 0, "全部归还后活跃归零");
    }

    #[test]
    fn per_inbound_limit_is_isolated() {
        let b = ConnBudget::default();
        b.configure(ResourceLimits {
            max_connections: None,
            max_connections_per_inbound: Some(1),
        });
        let a: Arc<str> = "a".into();
        let c: Arc<str> = "c".into();
        let p = b.try_acquire(&a).unwrap();
        assert!(b.try_acquire(&a).is_none(), "同入站第二个应拒绝");
        assert!(b.try_acquire(&c).is_some(), "其他入站不受影响");
        drop(p);
        assert!(b.try_acquire(&a).is_some(), "归还后同入站可再申请");
    }
}

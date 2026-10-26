//! 全局缓冲池：转发引擎按块租借/归还，避免每连接反复分配。
//! 每条连接仅在泵启动时租借一次（而非每次读），锁竞争可忽略。

use std::sync::{Mutex, OnceLock};

pub const BUF_SIZE: usize = 16 * 1024;
/// 缓冲池上限：512 块 * 16KB = 8MB 常驻上限，兼顾高并发零分配与低内存嵌入式/路由器设备不 OOM
const POOL_CAP: usize = 512;

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
        if let Some(buf) = self.buf.take() {
            let mut p = pool().lock().unwrap();
            if p.len() < POOL_CAP {
                p.push(buf);
            }
        }
    }
}

pub fn get_buf() -> PooledBuf {
    let buf = pool()
        .lock()
        .unwrap()
        .pop()
        .unwrap_or_else(|| vec![0u8; BUF_SIZE].try_into().expect("exact size"));
    PooledBuf { buf: Some(buf), len: 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

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

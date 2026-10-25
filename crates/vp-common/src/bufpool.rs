//! 线程本地缓冲池：转发引擎按块租借/归还，避免每连接反复分配。

use std::cell::RefCell;

pub const BUF_SIZE: usize = 16 * 1024;

thread_local! {
    static POOL: RefCell<Vec<Box<[u8; BUF_SIZE]>>> = const { RefCell::new(Vec::new()) };
    static POOL_CAP: std::cell::Cell<usize> = const { std::cell::Cell::new(64) };
}

/// 租借一块缓冲，Drop 时自动归还线程本地池。
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

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        let len = self.len;
        &mut self.buf.as_mut().unwrap()[..len]
    }

    /// 可写区域
    pub fn spare(&mut self) -> &mut [u8] {
        let buf = self.buf.as_mut().unwrap();
        &mut buf[..]
    }

    pub fn set_len(&mut self, len: usize) {
        debug_assert!(len <= BUF_SIZE);
        self.len = len;
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            POOL.with_borrow_mut(|p| {
                if p.len() < POOL_CAP.get() {
                    p.push(buf);
                }
            });
        }
    }
}

pub fn get_buf() -> PooledBuf {
    let buf = POOL
        .with_borrow_mut(|p| p.pop())
        .unwrap_or_else(|| vec![0u8; BUF_SIZE].try_into().expect("exact size"));
    PooledBuf { buf: Some(buf), len: 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rent_return() {
        let mut b = get_buf();
        assert_eq!(b.spare().len(), BUF_SIZE);
        b.set_len(8);
        assert_eq!(b.as_slice().len(), 8);
        drop(b);
        let b2 = get_buf(); // 应从池中复用
        drop(b2);
    }
}

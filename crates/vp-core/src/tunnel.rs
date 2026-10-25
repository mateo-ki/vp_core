//! 双向转发引擎（性能核心）：
//! - 每连接两个泵任务，方向间并行
//! - 池化缓冲，读满写透
//! - 半关闭传播（EOF -> shutdown 对端写侧）
//! - 连接表/统计挂载

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinHandle;
use vp_common::{get_buf, Stats};
use vp_common::bufpool::BUF_SIZE;

use crate::conn_table::{ConnMeta, ConnTable};
use crate::stream::ProxyStream;

pub struct RelayHook {
    pub table: Option<Arc<ConnTable>>,
    pub meta: Option<ConnMeta>,
    pub stats: Option<Arc<Stats>>,
}

impl Default for RelayHook {
    fn default() -> Self {
        RelayHook { table: None, meta: None, stats: None }
    }
}

enum Dir {
    Up,
    Down,
}

/// 双向转发。返回 (up, down) 字节数。任何一侧结束都会向对端传播关闭。
pub async fn relay(left: Box<dyn ProxyStream>, right: Box<dyn ProxyStream>, hook: RelayHook) -> (u64, u64) {
    // 连接注册
    let registered = match (&hook.table, &hook.meta) {
        (Some(t), Some(m)) => {
            if let Some(s) = &hook.stats {
                s.conn_open();
            }
            Some(t.register(m.clone()))
        }
        _ => None,
    };
    let (id, up, down) = match &registered {
        Some(rc) => (Some(rc.id), rc.up.clone(), rc.down.clone()),
        None => (None, Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0))),
    };

    let (lr, lw) = tokio::io::split(left);
    let (rr, rw) = tokio::io::split(right);

    let stats = hook.stats.clone();
    let t1: JoinHandle<()> = tokio::spawn(pump(lr, rw, up.clone(), stats.clone(), Dir::Up));
    let t2: JoinHandle<()> = tokio::spawn(pump(rr, lw, down.clone(), stats, Dir::Down));

    if let (Some(t), Some(id)) = (&hook.table, id) {
        t.attach_aborts(id, vec![t1.abort_handle(), t2.abort_handle()]);
    }

    let _ = tokio::join!(t1, t2);

    if let (Some(t), Some(id)) = (&hook.table, id) {
        t.remove(id);
    }
    if registered.is_some() {
        if let Some(s) = &hook.stats {
            s.conn_close();
        }
    }
    (
        up.load(Ordering::Relaxed),
        down.load(Ordering::Relaxed),
    )
}

/// 拥有式泵：结束后关闭对端写侧。
async fn pump<R, W>(
    mut r: R,
    mut w: W,
    counter: Arc<AtomicU64>,
    stats: Option<Arc<Stats>>,
    dir: Dir,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = get_buf();
    debug_assert_eq!(buf.spare_mut().len(), BUF_SIZE);
    loop {
        match r.read(buf.spare_mut()).await {
            Ok(0) => break,
            Ok(n) => {
                buf.set_len(n);
                if w.write_all(buf.as_slice()).await.is_err() {
                    break;
                }
                counter.fetch_add(n as u64, Ordering::Relaxed);
                if let Some(s) = &stats {
                    match dir {
                        Dir::Up => s.add_up(n as u64),
                        Dir::Down => s.add_down(n as u64),
                    }
                }
            }
            Err(_) => break,
        }
    }
    // 传播半关闭
    let _ = w.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn relay_transfers_both_ways() {
        // left: (a1, a2)  right: (b1, b2)
        let (a1, mut a2) = duplex(4096);
        let (b1, mut b2) = duplex(4096);

        let handle = tokio::spawn(relay(Box::new(a1), Box::new(b1), RelayHook::default()));

        tokio::spawn(async move {
            a2.write_all(b"hello-right").await.unwrap();
            let mut buf = [0u8; 11];
            a2.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello-left!");
        });
        tokio::spawn(async move {
            b2.write_all(b"hello-left!").await.unwrap();
            let mut buf = [0u8; 11];
            b2.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello-right");
        });

        let (up, down) = handle.await.unwrap();
        assert_eq!(up, 11);
        assert_eq!(down, 11);
    }

    #[tokio::test]
    async fn half_close_propagates() {
        let (a1, mut a2) = duplex(4096);
        let (b1, mut b2) = duplex(4096);
        let handle = tokio::spawn(relay(Box::new(a1), Box::new(b1), RelayHook::default()));

        // 客户端写完即关
        a2.write_all(b"ping").await.unwrap();
        a2.shutdown().await.unwrap();

        let mut buf = [0u8; 4];
        b2.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        // 应收到 EOF（读到 0）
        let n = b2.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
        // b2 也关闭后 relay 结束
        b2.shutdown().await.unwrap();
        let _ = handle.await.unwrap();
    }

    #[tokio::test]
    async fn conn_table_integration() {
        let table = Arc::new(ConnTable::new());
        let stats = Arc::new(Stats::default());
        let meta = ConnMeta {
            id: 42,
            inbound: "mixed".into(),
            network: "tcp",
            host: "test.local".into(),
            dst_port: 80,
            src: None,
            process: None,
            rule: None,
            chain: None,
            start: 0,
        };
        let (a1, mut a2) = duplex(4096);
        let (b1, mut b2) = duplex(4096);
        let t = table.clone();
        let handle = tokio::spawn(async move {
            let h = RelayHook { table: Some(t), meta: Some(meta), stats: Some(stats.clone()) };
            let r = relay(Box::new(a1), Box::new(b1), h).await;
            r
        });

        a2.write_all(&[0u8; 100]).await.unwrap();
        let mut buf = [0u8; 100];
        b2.read_exact(&mut buf).await.unwrap();
        a2.shutdown().await.unwrap();
        b2.shutdown().await.unwrap();
        let (up, down) = handle.await.unwrap();
        assert_eq!(up, 100);
        assert_eq!(down, 0);
        assert!(table.is_empty());
    }
}

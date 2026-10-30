//! 双向转发引擎（性能核心）：
//! - 每连接两个泵任务，方向间并行
//! - 池化缓冲，读满写透
//! - 半关闭传播（EOF -> shutdown 对端写侧）
//! - 连接表/统计挂载

use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::task::JoinHandle;
use vp_common::bufpool::BUF_SIZE;
use vp_common::{Stats, get_buf};

use crate::conn_table::{ConnMeta, ConnTable};
#[cfg(target_os = "linux")]
use crate::splice;
use crate::stream::ProxyStream;

#[derive(Default)]
pub struct RelayHook {
    pub table: Option<Arc<ConnTable>>,
    pub meta: Option<ConnMeta>,
    pub stats: Option<Arc<Stats>>,
}

enum Dir {
    Up,
    Down,
}

/// 双向转发。返回 (up, down) 字节数。任何一侧结束都会向对端传播关闭。
pub async fn relay(
    left: Box<dyn ProxyStream>,
    right: Box<dyn ProxyStream>,
    hook: RelayHook,
) -> (u64, u64) {
    // Linux 裸 socket 直连：splice 零拷贝快速路径（数据不过用户态）。
    // 在当前任务内直接 join（relay 本身就是每连接 spawn 的任务，abort 语义不变）；
    // 建管道失败发生在任何数据移动之前，撤销注册后落回通用泵。
    #[cfg(target_os = "linux")]
    {
        if let (Some(a), Some(b)) = (left.raw_socket(), right.raw_socket()) {
            let registered = match (&hook.table, &hook.meta) {
                (Some(t), Some(m)) => {
                    if let Some(s) = &hook.stats {
                        s.conn_open();
                    }
                    Some(t.register(m.clone()))
                }
                _ => None,
            };
            match splice::relay_pair(a, b, hook.stats.clone()).await {
                Ok((up, down)) => {
                    if let (Some(t), Some(rc)) = (&hook.table, &registered) {
                        t.remove(rc.id);
                    }
                    if registered.is_some() {
                        if let Some(s) = &hook.stats {
                            s.conn_close();
                        }
                    }
                    return (up, down);
                }
                Err(_) => {
                    if let (Some(t), Some(rc)) = (&hook.table, &registered) {
                        t.remove(rc.id);
                    }
                    if registered.is_some() {
                        if let Some(s) = &hook.stats {
                            s.conn_close();
                        }
                    }
                    // 落回下方通用泵
                }
            }
        }
    }
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
        None => (
            None,
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        ),
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
    (up.load(Ordering::Relaxed), down.load(Ordering::Relaxed))
}

/// 把若干段内存按顺序写尽。优先一次 vectored 写（Windows = WSASend 多缓冲，一次
/// syscall 落全部块）；`write_vectored` 允许部分写，循环推进剩余部分直到写完。
/// 只剩一段时退回 `write_all`（单块场景 vector 无收益）。
#[allow(dead_code)]
async fn write_chain_vectored<'a, W: AsyncWrite + Unpin>(
    w: &mut W,
    bufs: &'a [vp_common::bufpool::PooledBuf],
) -> bool {
    use std::io::IoSlice;
    // 各块可写视图（'a 直接指向池块，推进时不产生对自身的借用冲突）
    let mut parts: Vec<&'a [u8]> = bufs.iter().map(|b| b.as_slice()).collect();
    loop {
        while !parts.is_empty() && parts[0].is_empty() {
            parts.remove(0);
        }
        if parts.is_empty() {
            return true;
        }
        let written = if parts.len() == 1 {
            match w.write_all(parts[0]).await {
                Ok(()) => parts[0].len(),
                Err(_) => return false,
            }
        } else {
            let iov: Vec<IoSlice<'a>> = parts.iter().map(|p| IoSlice::new(p)).collect();
            match w.write_vectored(&iov).await {
                Ok(n) => n,
                Err(_) => return false,
            }
        };
        if written == 0 {
            return false;
        }
        let mut rem = written;
        let mut next: Vec<&'a [u8]> = Vec::with_capacity(parts.len());
        for p in parts.iter() {
            if rem >= p.len() {
                rem -= p.len();
            } else {
                next.push(&p[rem..]);
                rem = 0;
            }
        }
        parts = next;
    }
}

/// 链读用的"探一眼"读：只 poll 一次。有数据带回 Data/EOF；
/// 没数据（Pending）转成 Empty 立即返回。绝不在手里攒着未送达数据时阻塞
/// 等下一块 —— 请求-响应式对端（发完 2 整块就停下来等回包）会因此死锁：
/// 本端攒着整块数据等第 3 块，对端攥着回包等本端送达。
async fn probe_read<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> Probe {
    poll_fn(|cx| {
        let mut rb = ReadBuf::new(buf);
        match Pin::new(&mut *r).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => {
                let n = rb.filled().len();
                if n == 0 {
                    Poll::Ready(Probe::Eof)
                } else {
                    Poll::Ready(Probe::Data(n))
                }
            }
            Poll::Ready(Err(_)) => Poll::Ready(Probe::Eof),
            // Pending 已在 io 驱动注册了唤醒；这里直接交还控制权，先把已攒数据送达
            Poll::Pending => Poll::Ready(Probe::Empty),
        }
    })
    .await
}

enum Probe {
    Data(usize),
    Eof,
    Empty,
}

/// 拥有式泵：结束后关闭对端写侧。
///
/// syscall 形状（决定裸转发单核吞吐的关键）：
///   - 常规路径 = 1 次读 + 1 次写；读不满（交互式小包）绝不预读，尾延迟零代价。
///   - 读满整块说明发送方在持续灌数据 —— 用"探一眼"读继续链上收集，最多
///     [MAX_CHAIN] 块并成**一次** vectored 写：128KB 生意只需要 4 读 + 1 写。
///     链读收集不到更多（对端停顿）就立刻把已攒数据写出去，不持数据等待。
///   - 链块惰性租借：交互式连接全程只有主块，内存不变；块用完归还全局池。
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
    const MAX_CHAIN: usize = 4;
    let mut bufs: Vec<vp_common::bufpool::PooledBuf> = Vec::with_capacity(MAX_CHAIN);
    bufs.push(get_buf());
    let mut lens = [0usize; MAX_CHAIN];
    loop {
        let mut eof = false;
        let mut count;
        match r.read(bufs[0].spare_mut()).await {
            Ok(0) => break,
            Ok(n) => {
                bufs[0].set_len(n);
                lens[0] = n;
                count = 1;
            }
            Err(_) => break,
        }
        // 只有"读满整块"才继续链读；链读一律"探一眼"：
        // 有数据就追加，没有（或 EOF/错误）就带着已攒数据收手，立刻送达
        while count < MAX_CHAIN && lens[count - 1] == BUF_SIZE {
            if count == bufs.len() {
                bufs.push(get_buf());
            }
            match probe_read(&mut r, bufs[count].spare_mut()).await {
                Probe::Data(n) => {
                    bufs[count].set_len(n);
                    lens[count] = n;
                    count += 1;
                }
                Probe::Eof => {
                    eof = true;
                    break;
                }
                Probe::Empty => break,
            }
        }
        let total: usize = lens[..count].iter().sum();
        let write_ok = {
            let mut ok = true;
            for b in &bufs[..count] {
                if w.write_all(b.as_slice()).await.is_err() {
                    ok = false;
                    break;
                }
            }
            ok
        };
        if !write_ok {
            break;
        }
        counter.fetch_add(total as u64, Ordering::Relaxed);
        if let Some(s) = &stats {
            match dir {
                Dir::Up => s.add_up(total as u64),
                Dir::Down => s.add_down(total as u64),
            }
        }
        if eof {
            break;
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

    /// 走满预读+vectored 合并路径：一次性灌 2×BUF_SIZE+123 字节，收端逐字节校验。
    #[tokio::test]
    async fn bulk_transfer_through_readahead_path_is_byte_exact() {
        let (a1, mut a2) = tokio::io::duplex(64 * 1024);
        let (b1, mut b2) = tokio::io::duplex(64 * 1024);

        let handle = tokio::spawn(relay(Box::new(a1), Box::new(b1), RelayHook::default()));

        // 比整块预读路径多出一截尾巴（1 主块 + 1 预读块 + 123B），覆盖三条分支
        let total = BUF_SIZE * 2 + 123;
        let payload: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        let expect_up = total as u64;

        let payload_tx = payload.clone();
        let writer = tokio::spawn(async move {
            a2.write_all(&payload_tx).await.unwrap();
            a2.shutdown().await.unwrap();
        });
        let reader = tokio::spawn(async move {
            let mut got = vec![0u8; total];
            b2.read_exact(&mut got).await.unwrap();
            // 读端在收满后关写侧，relay 的反方向泵才能收尾
            b2.shutdown().await.unwrap();
            got
        });
        writer.await.unwrap();
        let got = reader.await.unwrap();
        let (up, _down) = handle.await.unwrap();
        assert_eq!(got.len(), total);
        assert!(payload == got, "预读合并路径丢/错字节");
        assert_eq!(up, expect_up, "上行计数应等于全部字节（含预读块合并部分）");
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
            let h = RelayHook {
                table: Some(t),
                meta: Some(meta),
                stats: Some(stats.clone()),
            };
            relay(Box::new(a1), Box::new(b1), h).await
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

    /// 回归：载荷恰好是 BUF_SIZE 整数倍且发端不关闭连接（请求-响应模式）。
    /// 旧链读会攒满 2 整块后继续阻塞等第 3 块，数据被扣住不送达 —— 死锁。
    #[tokio::test]
    async fn readahead_never_holds_data_hostage_on_exact_multiple() {
        let (a1, mut a2) = duplex(BUF_SIZE * 2);
        let (b1, mut b2) = duplex(BUF_SIZE * 2);
        let handle = tokio::spawn(relay(Box::new(a1), Box::new(b1), RelayHook::default()));

        let payload = vec![0x7u8; BUF_SIZE * 2];
        // 中继对端：整块回声，回完继续读（不关闭）
        tokio::spawn(async move {
            let mut buf = vec![0u8; BUF_SIZE];
            loop {
                let n = b2.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                b2.write_all(&buf[..n]).await.unwrap();
            }
        });

        // 发端：写 2 整块后不 shutdown，直接等回程 —— 对端处于"等回包"状态
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            a2.write_all(&payload).await.unwrap();
            let mut back = vec![0u8; payload.len()];
            a2.read_exact(&mut back).await.unwrap();
            assert_eq!(back, payload);
            let _ = done_tx.send(());
        });

        tokio::time::timeout(std::time::Duration::from_secs(10), done_rx)
            .await
            .expect("整块倍数载荷 + 不关闭连接时不得死锁")
            .unwrap();
        let _ = handle.await.unwrap();
    }

    /// 裸 TcpStream 直连 relay：Linux 自动命中 splice 零拷贝路径，其他平台走通用泵。
    /// 真实回环 TCP，双向 512KB + 半关闭传播，两端字节数必须精确对账。
    #[tokio::test]
    async fn relay_over_raw_sockets_transfers_both_ways() {
        let lis_a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let lis_b = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cli = tokio::net::TcpStream::connect(lis_a.local_addr().unwrap())
            .await
            .unwrap();
        let (a, _) = lis_a.accept().await.unwrap();
        let echo_conn = tokio::net::TcpStream::connect(lis_b.local_addr().unwrap())
            .await
            .unwrap();
        let (b, _) = lis_b.accept().await.unwrap();

        // echo 端：读多少回多少，EOF 结束
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(echo_conn);
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                match r.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if w.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let handle = tokio::spawn(relay(Box::new(a), Box::new(b), RelayHook::default()));

        const N: usize = 512 * 1024;
        let payload = vec![0x5au8; N];
        let mut c = cli;
        c.write_all(&payload).await.unwrap();
        c.shutdown().await.unwrap();
        let mut back = vec![0u8; N];
        c.read_exact(&mut back).await.unwrap();
        assert_eq!(back, payload, "回程数据必须逐字节一致");

        let (up, down) = handle.await.unwrap();
        assert_eq!(up, N as u64, "上行字节数不符");
        assert_eq!(down, N as u64, "下行字节数不符");
    }
}

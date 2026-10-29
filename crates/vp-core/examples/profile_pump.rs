//! 转发热路径拆账：转发 CPU 成本到底花在哪。
//!
//! 三种"中段转发单元"逐级叠加，拓扑严格一致（client / echo 基础设施完全相同，
//! 只有中段实现不同），进程级 CPU 差分（GetProcessTimes / getrusage）做度量：
//! - A std-blocking：2 条 std 阻塞线程裸读裸写 —— syscall + 内核拷贝地板，零调度开销
//! - B tokio-bare：  同形态的 2 个 tokio 任务   —— + async 调度/轮询/waker 开销
//! - C relay-full：  完整 relay()               —— + 链读/探针/统计/连接表簿记
//!
//! 结论读法：B−A = tokio 调度成本；C−B = relay 机制成本；A = syscall 地板。
//! 仅作本地分析工具，不进 CI。

use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MB: usize = 1024 * 1024;
const ROUNDS: usize = 7;
const MB_PER_ROUND: usize = 256;
const BUF: usize = 32 * 1024;

#[cfg(windows)]
fn process_cpu_secs() -> f64 {
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
    unsafe {
        let h = GetCurrentProcess();
        let (mut c, mut e, mut k, mut u) = (0i64, 0i64, 0i64, 0i64);
        let ok = GetProcessTimes(
            h,
            &mut c as *mut i64 as *mut _,
            &mut e as *mut i64 as *mut _,
            &mut k as *mut i64 as *mut _,
            &mut u as *mut i64 as *mut _,
        );
        if ok == 0 {
            return 0.0;
        }
        ((k + u) as f64) / 1e7
    }
}

#[cfg(not(windows))]
fn process_cpu_secs() -> f64 {
    unsafe {
        let mut ru: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &mut ru) != 0 {
            return 0.0;
        }
        (ru.ru_utime.tv_sec as f64 + ru.ru_utime.tv_usec as f64 / 1e6)
            + (ru.ru_stime.tv_sec as f64 + ru.ru_stime.tv_usec as f64 / 1e6)
    }
}

/// 客户端（三阶段完全一致）：写 total 字节与读回 total 字节**并行**。
/// 必须并行：echo 会同步回灌，若先写完再读，回程缓冲会灌满整条管线（管道死锁）。
async fn client_round(s: TcpStream, total: usize) {
    // tokio::io::split 返回 (ReadHalf, WriteHalf)
    let (mut r, mut w) = tokio::io::split(s);
    let payload = vec![0xa5u8; MB];
    let wi = async move {
        let mut sent = 0usize;
        while sent < total {
            let n = payload.len().min(total - sent);
            w.write_all(&payload[..n]).await.unwrap();
            sent += n;
        }
        w.shutdown().await.unwrap();
    };
    let ri = async move {
        let mut back = vec![0u8; BUF];
        let mut got = 0usize;
        while got < total {
            let n = r.read(&mut back).await.unwrap();
            assert!(n > 0, "客户端提前 EOF");
            got += n;
        }
    };
    tokio::join!(wi, ri);
}

/// echo 任务（三阶段完全一致）：读多少回多少，EOF 结束。
async fn echo_task(sock: TcpStream, counter: Arc<AtomicU64>) {
    let _ = sock.set_nodelay(true);
    let (mut r, mut w) = tokio::io::split(sock);
    let mut buf = vec![0u8; BUF];
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if w.write_all(&buf[..n]).await.is_err() {
                    break;
                }
                counter.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
    }
}

/// 起一个 echo accept 任务（三阶段完全一致）；listener 按值移入。
async fn spawn_echo(echo_lis: TcpListener) -> tokio::task::JoinHandle<()> {
    let counter = Arc::new(AtomicU64::new(0));
    tokio::spawn(async move {
        let (e, _) = echo_lis.accept().await.unwrap();
        echo_task(e, counter).await;
    })
}

fn summarize(name: &'static str, samples: &[(f64, f64)]) -> (f64, f64) {
    let mut ms = samples.iter().map(|s| s.0).collect::<Vec<_>>();
    let mut cs = samples.iter().map(|s| s.1).collect::<Vec<_>>();
    ms.sort_by(|a, b| b.partial_cmp(a).unwrap());
    cs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let (mps, spmb) = (ms[ms.len() / 2], cs[cs.len() / 2]);
    println!("{name:<14} median {mps:7.1} MB/s   {spmb:8.5} s/MB");
    (mps, spmb)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    println!(
        "每阶段 {} 轮 × {}MB，缓冲 {}KB，进程 CPU 差分\n",
        ROUNDS,
        MB_PER_ROUND,
        BUF / 1024
    );

    let a = phase_a().await;
    let (_a_mps, a_cpu) = summarize("A std-blocking", &a);
    let b = phase_b().await;
    let (_b_mps, b_cpu) = summarize("B tokio-bare", &b);
    let c = phase_c().await;
    let (_c_mps, c_cpu) = summarize("C relay-full", &c);

    println!("\n拆账（相邻阶段的 CPU 增量，s/MB）:");
    println!("  A syscall+memcpy 地板    {a_cpu:8.5}  （{_a_mps:.0} MB/s）");
    println!("  B−A tokio 调度开销       {:8.5}", b_cpu - a_cpu);
    println!("  C−B relay 簿记开销       {:8.5}", c_cpu - b_cpu);
}

/// A：中段 = 2 条 std 阻塞线程（裸 syscall 形态，零运行时调度）。
async fn phase_a() -> Vec<(f64, f64)> {
    let mut samples = Vec::new();

    for round in 0..ROUNDS + 1 {
        let echo_lis = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_addr = echo_lis.local_addr().unwrap();
        let mid_std = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mid_addr = mid_std.local_addr().unwrap();
        let echo = spawn_echo(TcpListener::from_std(echo_lis.try_clone().unwrap()).unwrap()).await;
        let cli = TcpStream::connect(mid_addr).await.unwrap();
        let lis = mid_std;
        let mid = tokio::task::spawn_blocking(move || {
            let (mut cs, _) = lis.accept().unwrap();
            let _ = cs.set_nodelay(true);
            let mut es = std::net::TcpStream::connect(echo_addr).unwrap();
            let _ = es.set_nodelay(true);
            let (mut es2, mut cs2) = (es.try_clone().unwrap(), cs.try_clone().unwrap());
            let h1 = std::thread::spawn(move || {
                let mut buf = vec![0u8; BUF];
                loop {
                    match cs.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if es.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = es.shutdown(std::net::Shutdown::Write);
            });
            let h2 = std::thread::spawn(move || {
                let mut buf = vec![0u8; BUF];
                loop {
                    match es2.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if cs2.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = cs2.shutdown(std::net::Shutdown::Write);
            });
            h1.join().unwrap();
            h2.join().unwrap();
        });

        let c0 = process_cpu_secs();
        let t0 = Instant::now();
        client_round(cli, MB_PER_ROUND * MB).await;
        mid.await.unwrap();
        let dt = t0.elapsed().as_secs_f64();
        let c1 = process_cpu_secs();
        echo.await.unwrap();

        if round > 0 {
            samples.push((MB_PER_ROUND as f64 / dt, (c1 - c0) / MB_PER_ROUND as f64));
        }
    }
    samples
}

/// B：中段 = 2 个 tokio 裸任务（读满即写，无链读/探针/统计）。
async fn phase_b() -> Vec<(f64, f64)> {
    let mut samples = Vec::new();

    for round in 0..ROUNDS + 1 {
        let echo_lis = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_lis.local_addr().unwrap();
        let mid_lis = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mid_addr = mid_lis.local_addr().unwrap();
        let echo = spawn_echo(echo_lis).await;
        let cli = TcpStream::connect(mid_addr).await.unwrap();
        let _ = cli.set_nodelay(true);
        let (cs, _) = mid_lis.accept().await.unwrap();
        let _ = cs.set_nodelay(true);
        let es = TcpStream::connect(echo_addr).await.unwrap();
        let _ = es.set_nodelay(true);

        let mid = tokio::spawn(async move {
            let (cr, cw) = tokio::io::split(cs);
            let (er, ew) = tokio::io::split(es);
            let t1 = tokio::spawn(async move {
                let (mut r, mut w) = (cr, ew);
                let mut buf = vec![0u8; BUF];
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
                let _ = w.shutdown().await;
            });
            let t2 = tokio::spawn(async move {
                let (mut r, mut w) = (er, cw);
                let mut buf = vec![0u8; BUF];
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
                let _ = w.shutdown().await;
            });
            let _ = tokio::join!(t1, t2);
        });

        let c0 = process_cpu_secs();
        let t0 = Instant::now();
        client_round(cli, MB_PER_ROUND * MB).await;
        mid.await.unwrap();
        let dt = t0.elapsed().as_secs_f64();
        let c1 = process_cpu_secs();
        echo.await.unwrap();

        if round > 0 {
            samples.push((MB_PER_ROUND as f64 / dt, (c1 - c0) / MB_PER_ROUND as f64));
        }
    }
    samples
}

/// C：中段 = 完整 relay()（现网路径：链读/探针/统计/池化缓冲）。
async fn phase_c() -> Vec<(f64, f64)> {
    let mut samples = Vec::new();

    for round in 0..ROUNDS + 1 {
        let echo_lis = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_lis.local_addr().unwrap();
        let mid_lis = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mid_addr = mid_lis.local_addr().unwrap();
        let echo = spawn_echo(echo_lis).await;
        let cli = TcpStream::connect(mid_addr).await.unwrap();
        let _ = cli.set_nodelay(true);
        let (cs, _) = mid_lis.accept().await.unwrap();
        let _ = cs.set_nodelay(true);
        let es = TcpStream::connect(echo_addr).await.unwrap();
        let _ = es.set_nodelay(true);

        let mid = tokio::spawn(async move {
            let _ = vp_core::tunnel::relay(Box::new(cs), Box::new(es), Default::default()).await;
        });

        let c0 = process_cpu_secs();
        let t0 = Instant::now();
        client_round(cli, MB_PER_ROUND * MB).await;
        mid.await.unwrap();
        let dt = t0.elapsed().as_secs_f64();
        let c1 = process_cpu_secs();
        echo.await.unwrap();

        if round > 0 {
            samples.push((MB_PER_ROUND as f64 / dt, (c1 - c0) / MB_PER_ROUND as f64));
        }
    }
    samples
}

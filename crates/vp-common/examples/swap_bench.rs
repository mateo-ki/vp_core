//! RouterHandle 热替换读路径微基准（报告任务5）：RwLock<Arc<T>> vs ArcSwap<T>。
//!
//! 模拟真实形态：8 读线程高频 clone 快照（路由 pick 只发生在建连时，
//! 每连接 1 次），1 写线程每 10ms 原子替换整份"路由表"。
//! 结论看数字：差距在一个数量级内就不值得为它换库/换语义。
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;

#[derive(Clone)]
struct FakeRouter {
    #[allow(dead_code)] // 载荷本体：读路径只 clone Arc，字段存在为凑真实体积
    rules: Vec<String>,
}

fn make() -> Arc<FakeRouter> {
    Arc::new(FakeRouter {
        rules: (0..1000)
            .map(|i| format!("MATCH,DIRECT,#rule-{i}"))
            .collect(),
    })
}

fn bench_rwlock(dur: Duration) -> (u64, f64) {
    let router = Arc::new(RwLock::new(make()));
    let stop = Arc::new(AtomicBool::new(false));
    let mut readers = Vec::new();
    for _ in 0..8 {
        let (router, stop) = (router.clone(), stop.clone());
        readers.push(std::thread::spawn(move || {
            let mut ops = 0u64;
            let mut worst: Duration = Duration::ZERO;
            while !stop.load(Ordering::Relaxed) {
                let t0 = Instant::now();
                let _snap: Arc<FakeRouter> = router.read().unwrap().clone();
                worst = worst.max(t0.elapsed());
                ops += 1;
            }
            (ops, worst)
        }));
    }
    let writer = {
        let (router, stop) = (router.clone(), stop.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(10));
                *router.write().unwrap() = make();
            }
        })
    };
    std::thread::sleep(dur);
    stop.store(true, Ordering::Relaxed);
    let mut total = 0u64;
    let mut worst = Duration::ZERO;
    for h in readers {
        let (ops, w) = h.join().unwrap();
        total += ops;
        worst = worst.max(w);
    }
    writer.join().unwrap();
    (total, worst.as_secs_f64() * 1e6)
}

fn bench_arcswap(dur: Duration) -> (u64, f64) {
    let router = Arc::new(ArcSwap::new(make()));
    let stop = Arc::new(AtomicBool::new(false));
    let mut readers = Vec::new();
    for _ in 0..8 {
        let (router, stop) = (router.clone(), stop.clone());
        readers.push(std::thread::spawn(move || {
            let mut ops = 0u64;
            let mut worst: Duration = Duration::ZERO;
            while !stop.load(Ordering::Relaxed) {
                let t0 = Instant::now();
                let _snap: Arc<FakeRouter> = router.load_full();
                worst = worst.max(t0.elapsed());
                ops += 1;
            }
            (ops, worst)
        }));
    }
    let writer = {
        let (router, stop) = (router.clone(), stop.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(10));
                router.store(make());
            }
        })
    };
    std::thread::sleep(dur);
    stop.store(true, Ordering::Relaxed);
    let mut total = 0u64;
    let mut worst = Duration::ZERO;
    for h in readers {
        let (ops, w) = h.join().unwrap();
        total += ops;
        worst = worst.max(w);
    }
    writer.join().unwrap();
    (total, worst.as_secs_f64() * 1e6)
}

fn main() {
    let dur = Duration::from_secs(2);
    let (rw_ops, rw_us) = bench_rwlock(dur);
    let (as_ops, as_us) = bench_arcswap(dur);
    println!("8 读 + 1 写/10ms，{dur:?} 采样：");
    println!(
        "  RwLock<Arc> : {:>10.0} ops/s   单次最差 {:6.2} us",
        rw_ops as f64 / dur.as_secs_f64(),
        rw_us
    );
    println!(
        "  ArcSwap     : {:>10.0} ops/s   单次最差 {:6.2} us",
        as_ops as f64 / dur.as_secs_f64(),
        as_us
    );
    println!("（路由 pick 每连接仅 1 次，两者差距 < 数量级即不值得换）");
}

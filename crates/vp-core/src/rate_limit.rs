//! 令牌桶算法 QoS 带宽限速器 (Token Bucket Rate Limiter)
//!
//! 支持高并发下的平滑流量整形，支持突发容量与持续速率限制。
//! 异步等待让出 Tokio worker 线程，零阻塞开销。

use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug)]
struct BucketState {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Debug)]
pub struct TokenBucket {
    rate: f64,     // 每秒补充的字节数 (bytes/sec)
    capacity: f64, // 最大突发容量 (bytes)
    state: Mutex<BucketState>,
}

impl TokenBucket {
    /// 创建一个新的令牌桶
    /// - `rate_bytes_per_sec`: 每秒允许通过的字节数
    /// - `capacity`: 最大突发令牌数
    pub fn new(rate_bytes_per_sec: f64, capacity: f64) -> Self {
        Self {
            rate: rate_bytes_per_sec,
            capacity,
            state: Mutex::new(BucketState {
                tokens: capacity,
                last_refill: Instant::now(),
            }),
        }
    }

    /// 请求获取 `needed` 字节额度。
    /// 若当前令牌不足，自动计算所需等待时间并通过 `tokio::time::sleep` 挂起让出执行权。
    pub async fn acquire(&self, needed: usize) {
        if needed == 0 || self.rate <= 0.0 {
            return;
        }

        let wait_duration = {
            let mut state = self.state.lock().unwrap();
            let now = Instant::now();
            let elapsed = now.duration_since(state.last_refill).as_secs_f64();
            state.last_refill = now;
            state.tokens = (state.tokens + elapsed * self.rate).min(self.capacity);

            let needed_f64 = needed as f64;
            if state.tokens >= needed_f64 {
                state.tokens -= needed_f64;
                Duration::ZERO
            } else {
                let deficit = needed_f64 - state.tokens;
                state.tokens = 0.0;
                let wait_secs = deficit / self.rate;
                Duration::from_secs_f64(wait_secs)
            }
        };

        if !wait_duration.is_zero() {
            tokio::time::sleep(wait_duration).await;
        }
    }

    pub fn rate(&self) -> f64 {
        self.rate
    }
}

/// 双向带宽限速组合（上行 + 下行）
#[derive(Debug, Clone)]
pub struct BandwidthLimiter {
    pub up: Option<Arc<TokenBucket>>,
    pub down: Option<Arc<TokenBucket>>,
}

/// Brutal 暴力恒速平滑发包调度器 (Brutal Pacer)
///
/// 针对高丢包（10%~30%）、高延迟弱网跨境海缆长肥管道（Long Fat Network），
/// 采用固定时隙平滑发包调度算法。无论是否出现丢包，严格按照目标速率微秒级发包，
/// 忽略丢包导致的拥塞退避，防止突发流量冲垮队列，确保长途网络带宽跑满。
#[derive(Debug)]
pub struct BrutalPacer {
    rate: f64, // 目标发送速率（字节/秒）
    state: Mutex<PacerState>,
}

#[derive(Debug)]
struct PacerState {
    next_send_time: Instant,
}

impl BrutalPacer {
    pub fn new(rate_bytes_per_sec: f64) -> Self {
        Self {
            rate: rate_bytes_per_sec.max(1024.0),
            state: Mutex::new(PacerState {
                next_send_time: Instant::now(),
            }),
        }
    }

    /// 根据目标带宽（单位：Mbps）创建恒速发送器
    pub fn from_mbps(mbps: u32) -> Self {
        let bytes_per_sec = (mbps as f64) * 1_000_000.0 / 8.0;
        Self::new(bytes_per_sec)
    }

    /// 获取设定的发送速率（字节/秒）
    pub fn rate_bytes_per_sec(&self) -> f64 {
        self.rate
    }

    /// 精准 Pacing：根据发送字节数推进发包时钟，超前时微秒级异步等待
    pub async fn pace(&self, bytes: usize) {
        if bytes == 0 || self.rate <= 0.0 {
            return;
        }

        let wait_duration = {
            let mut st = self.state.lock().unwrap();
            let now = Instant::now();

            // 若连接处于空闲（上次发包时间早于当前），时钟对齐至当前
            if st.next_send_time < now {
                st.next_send_time = now;
            }

            let packet_duration = Duration::from_secs_f64((bytes as f64) / self.rate);
            st.next_send_time += packet_duration;

            if st.next_send_time > now {
                st.next_send_time.duration_since(now)
            } else {
                Duration::ZERO
            }
        };

        if !wait_duration.is_zero() {
            tokio::time::sleep(wait_duration.min(Duration::from_millis(500))).await;
        }
    }
}

impl BandwidthLimiter {
    /// 根据上行与下行字节速率（单位：bytes/sec）创建限速器
    pub fn from_bytes_per_sec(rate_up: Option<f64>, rate_down: Option<f64>) -> Self {
        let up = rate_up.filter(|r| *r > 0.0).map(|r| {
            let cap = (r * 0.5).max(131_072.0);
            Arc::new(TokenBucket::new(r, cap))
        });
        let down = rate_down.filter(|r| *r > 0.0).map(|r| {
            let cap = (r * 0.5).max(131_072.0);
            Arc::new(TokenBucket::new(r, cap))
        });
        Self { up, down }
    }

    /// 根据上行与下行带宽（单位：Mbps）创建限速器
    pub fn from_mbps(rate_up_mbps: Option<u32>, rate_down_mbps: Option<u32>) -> Self {
        let up = rate_up_mbps.map(|mbps| {
            let bytes_per_sec = (mbps as f64) * 1_000_000.0 / 8.0;
            let cap = (bytes_per_sec * 0.5).max(131_072.0);
            Arc::new(TokenBucket::new(bytes_per_sec, cap))
        });
        let down = rate_down_mbps.map(|mbps| {
            let bytes_per_sec = (mbps as f64) * 1_000_000.0 / 8.0;
            let cap = (bytes_per_sec * 0.5).max(131_072.0);
            Arc::new(TokenBucket::new(bytes_per_sec, cap))
        });
        Self { up, down }
    }

    /// 获取下行速率（字节/秒）
    pub fn down_rate_bytes_per_sec(&self) -> Option<f64> {
        self.down.as_ref().map(|b| b.rate())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_token_bucket_burst_and_throttle() {
        // 每秒 100KB，容量 50KB
        let bucket = TokenBucket::new(100_000.0, 50_000.0);

        // 第一次消耗 20KB：容量内，无需等待
        let start = Instant::now();
        bucket.acquire(20_000).await;
        assert!(start.elapsed() < Duration::from_millis(50));

        // 消耗完剩余 30KB
        bucket.acquire(30_000).await;
        assert!(start.elapsed() < Duration::from_millis(50));

        // 再次请求 10KB：赤字 10KB / 100KB/s = 100ms
        let start = Instant::now();
        bucket.acquire(10_000).await;
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(80));
    }

    #[tokio::test]
    async fn test_brutal_pacer_smoothness() {
        // 目标速率 50KB/s = 50_000 bytes/sec
        let pacer = BrutalPacer::new(50_000.0);

        let start = Instant::now();
        // 发送 5KB：应当耗时约 5000 / 50000 = 100ms
        pacer.pace(5_000).await;
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(80));
    }
}

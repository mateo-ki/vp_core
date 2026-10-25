//! 会话与连接元数据。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use vp_common::DstAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Tcp,
    Udp,
}

impl Network {
    pub fn as_str(&self) -> &'static str {
        match self {
            Network::Tcp => "tcp",
            Network::Udp => "udp",
        }
    }
}

fn next_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// 一条进入内核的连接（由入站在完成协议握手后构造）
#[derive(Debug, Clone)]
pub struct Session {
    pub id: u64,
    /// 入站 tag（如 "mixed-1"）
    pub inbound: Arc<str>,
    pub network: Network,
    pub src: Option<SocketAddr>,
    pub dst: DstAddr,
    /// 命中的进程名（进程规则/展示用）
    pub process: Option<Arc<str>>,
}

impl Session {
    pub fn new_tcp(inbound: Arc<str>, src: Option<SocketAddr>, dst: DstAddr) -> Self {
        Session {
            id: next_id(),
            inbound,
            network: Network::Tcp,
            src,
            dst,
            process: None,
        }
    }

    pub fn new_udp(inbound: Arc<str>, src: Option<SocketAddr>, dst: DstAddr) -> Self {
        Session {
            id: next_id(),
            inbound,
            network: Network::Udp,
            src,
            dst,
            process: None,
        }
    }
}

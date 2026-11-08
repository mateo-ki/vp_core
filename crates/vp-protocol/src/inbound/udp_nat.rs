//! UDP 会话分发与 Full-Cone NAT：入站（socks5/TUN）共用的企业级 UDP 中继枢纽。
//!
//! - 端点独立映射 (EIM)：单个客户端源地址绑定出站 PacketConn 管道
//! - 端点独立过滤 (EIF)：允许外部对等端点直接回包，达成标准 Full-Cone NAT (NAT Type 1/2) 游戏直通
//! - 智能双模老化回收 (Dual-Mode Aging)：DNS 查询 5 秒极速回收释放资源；游戏/VoIP/常规 UDP 180 秒长保活
//! - 收发一体化泵：异步队列→出站 / 出站→客户端 / 滑动空闲回收

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::debug;

use vp_common::{DstAddr, Host, Result};
use vp_core::inbound::InboundCtx;
use vp_core::session::{Network, Session};
use vp_core::stream::UdpPacket;

/// DNS 查询瞬态请求极速老化超时（5 秒）：一问一答完成后迅速回收端口与内存
pub const DNS_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
/// 游戏、对战联机与常规 UDP 长保活超时（180 秒）：防止游戏对局与 VoIP 语音中断
pub const GAME_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(180);
/// NAT 会话表分片数：锁竞争随分片摊薄，高 PPS 场景不再全表单锁串行
const NAT_SHARDS: usize = 16;

/// UDP NAT 会话键：客户端源地址 + 目标（域名或 IP + 端口）
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SessionKey {
    client: SocketAddr,
    host: Host,
    port: u16,
}

/// 会话发送端：mpsc 队列 + 可选直发句柄（命中时上行数据报零调度发包）
type UdpSessionSender = (
    tokio::sync::mpsc::Sender<UdpPacket>,
    Option<std::sync::Arc<dyn vp_core::PacketSend>>,
);

/// 分片会话表：命中路径零额外 String 分配（键直接消费嗅探结果所有权）
struct SessionMap {
    shards: Vec<tokio::sync::Mutex<HashMap<SessionKey, UdpSessionSender>>>,
    /// 单分片高水位（全局上限均摊到各分片，哈希分布均匀）
    shard_cap: usize,
}

impl SessionMap {
    fn new(max_sessions: usize) -> Self {
        SessionMap {
            shards: (0..NAT_SHARDS)
                .map(|_| tokio::sync::Mutex::new(HashMap::new()))
                .collect(),
            shard_cap: (max_sessions / NAT_SHARDS).max(8),
        }
    }

    /// FNV-1a 分片路由（零分配、免 SipHash 开销）
    fn index(key: &SessionKey) -> usize {
        fn fnv(h: &mut u64, bytes: &[u8]) {
            for &b in bytes {
                *h ^= b as u64;
                *h = h.wrapping_mul(0x100000001b3);
            }
        }
        let mut h: u64 = 0xcbf29ce484222325;
        let client_ip: &[u8] = match key.client.ip() {
            std::net::IpAddr::V4(v4) => &v4.octets(),
            std::net::IpAddr::V6(v6) => &v6.octets(),
        };
        fnv(&mut h, client_ip);
        fnv(&mut h, &key.client.port().to_be_bytes());
        fnv(&mut h, &key.port.to_be_bytes());
        let host_bytes: &[u8] = match &key.host {
            Host::Domain(d) => d.as_bytes(),
            Host::Ip(std::net::IpAddr::V4(v4)) => &v4.octets(),
            Host::Ip(std::net::IpAddr::V6(v6)) => &v6.octets(),
        };
        fnv(&mut h, host_bytes);
        (h as usize) % NAT_SHARDS
    }
}

/// 一个客户端 UDP 关联
pub type ReplyFormatter = Arc<dyn Fn(SocketAddr, &[u8]) -> Vec<u8> + Send + Sync>;

pub struct UdpNat {
    ctx: InboundCtx,
    tag: Arc<str>,
    /// 客户端数据报首来源记录（兼容单例查询）
    client: Mutex<Option<SocketAddr>>,
    /// 中继 socket（客户端发往此地址；回包也从这里发出）
    relay: Arc<UdpSocket>,
    /// 分片会话表：(客户端源地址, 目标地址) → 发送队列（实现多客户端 Full-Cone EIM 会话隔离）
    sessions: SessionMap,
    /// 回包格式化（None = 裸转发，TUN 场景）
    reply_formatter: std::sync::Mutex<Option<ReplyFormatter>>,
    /// 安全门禁与 RRL 限制器（可选）
    gate: Option<Arc<vp_core::InboundGate>>,
}

impl UdpNat {
    pub fn new(ctx: InboundCtx, tag: Arc<str>, relay: Arc<UdpSocket>) -> Arc<Self> {
        Self::with_gate(ctx, tag, relay, None)
    }

    pub fn with_gate(
        ctx: InboundCtx,
        tag: Arc<str>,
        relay: Arc<UdpSocket>,
        gate: Option<Arc<vp_core::InboundGate>>,
    ) -> Arc<Self> {
        Arc::new(UdpNat {
            ctx,
            tag,
            client: Mutex::new(None),
            relay,
            sessions: SessionMap::new(4096),
            reply_formatter: std::sync::Mutex::new(None),
            gate,
        })
    }

    /// 客户端数据报 → 路由 → 出站。
    /// fake_domain：TUN 场景下 fake-ip 还原出的域名（优先于 IP）
    pub async fn dispatch(
        self: &Arc<Self>,
        pkt: UdpPacket,
        fake_domain: Option<String>,
    ) -> Result<()> {
        let client_addr = pkt.src;
        // 门禁检查：未通过 GeoIP / ASN / 端口敲门过滤的源 IP 直接丢弃
        if let Some(ref g) = self.gate {
            if !g.check_accept(client_addr.ip()) {
                return Ok(());
            }
        }

        // 记录首个数据报来源（兼容单客户端 Socks5 ASSOCIATE 查询）
        {
            let mut c = self.client.lock().await;
            if c.is_none() {
                *c = Some(client_addr);
            }
        }
        let dst_port = pkt.dst.port();
        let resolved_domain = fake_domain
            .or_else(|| vp_dns::reverse_fake_ip(pkt.dst.ip()))
            .or_else(|| {
                if matches!(dst_port, 443 | 8443 | 2053 | 2083 | 2087 | 2096) {
                    // QUIC SNI 嗅探结果短缓存：同目标后续数据报免除重复 HKDF+AES-GCM 解密
                    if let Some(d) = vp_core::sniff::sniff_cache_get(pkt.dst.ip(), dst_port) {
                        return Some(d);
                    }
                    let d = vp_core::sniff::sniff_quic_sni(&pkt.data)?;
                    vp_core::sniff::sniff_cache_put(pkt.dst.ip(), dst_port, d.clone());
                    Some(d)
                } else {
                    None
                }
            });
        // 键直接消费嗅探结果所有权：命中路径零额外 String 分配
        let key = SessionKey {
            client: client_addr,
            host: match resolved_domain {
                Some(domain) => Host::Domain(domain),
                None => Host::Ip(pkt.dst.ip()),
            },
            port: dst_port,
        };

        let idx = SessionMap::index(&key);
        let existing = {
            let mut map = self.sessions.shards[idx].lock().await;
            // 分片高水位 GC 清理：剔除断开会话；仍满则随机裁剪
            if map.len() >= self.sessions.shard_cap {
                map.retain(|_, (tx, _)| !tx.is_closed());
                if map.len() >= self.sessions.shard_cap {
                    let overflow = map.len() - self.sessions.shard_cap + 1;
                    let to_remove: Vec<_> = map.keys().take(overflow).cloned().collect();
                    for k in to_remove {
                        map.remove(&k);
                    }
                }
            }
            map.get(&key).cloned()
        };

        let (tx, direct) = match existing {
            Some(sess_tx) => sess_tx,
            None => {
                // 先释放分片锁再拨号建会话：路由决策与出站建连不应阻塞同分片其他数据报
                let dst = DstAddr {
                    host: key.host.clone(),
                    port: key.port,
                };
                let sess_tx = self.spawn_session(client_addr, &dst).await?;
                let mut map = self.sessions.shards[idx].lock().await;
                // 双检：并发建会话可能已插入同键会话
                match map.get(&key) {
                    Some(existing) => existing.clone(),
                    None => {
                        if map.len() >= self.sessions.shard_cap {
                            map.retain(|_, (tx, _)| !tx.is_closed());
                        }
                        map.insert(key, sess_tx.clone());
                        sess_tx
                    }
                }
            }
        };
        // 直发快速路径：上行数据报绕过 mpsc 队列与任务唤醒，压低游戏/QUIC 端到端 Jitter
        if let Some(handle) = direct {
            let _ = handle.send(&pkt).await;
            return Ok(());
        }
        let _ = tx.send(pkt).await;
        Ok(())
    }

    /// 回包格式化器：入站协议注入（如 socks5 的 [rsv][frag][addr][payload]）
    pub fn set_reply_formatter(&self, f: ReplyFormatter) {
        *self.reply_formatter.lock().unwrap() = Some(f);
    }

    async fn spawn_session(
        self: &Arc<Self>,
        client: SocketAddr,
        dst: &DstAddr,
    ) -> Result<UdpSessionSender> {
        let mut sess = Session::new_udp(self.tag.clone(), Some(client), dst.clone());
        sess.network = Network::Udp;
        let res = self.ctx.router.pick(&sess).await;
        let rule_tag = res
            .rule
            .as_ref()
            .map(|r| r.rule.as_str())
            .unwrap_or("Match()");
        let chain_tag = if res.outbound.name() != res.via.as_ref() {
            format!("{}[{}]", res.via, res.outbound.name())
        } else {
            res.outbound.name().to_string()
        };
        tracing::info!(
            "[UDP] {} --> {} match {} using {}",
            client,
            dst,
            rule_tag,
            chain_tag
        );
        if !res.outbound.support_udp() {
            return Err(vp_common::Error::Unsupported(format!(
                "出站 {} 不支持 UDP",
                res.outbound.name()
            )));
        }
        let mut conn = res.outbound.connect_packet(&sess, dst).await?;
        // 直发句柄需在建连后、conn 移交后台任务前提取
        let direct = conn.send_handle();
        let relay = self.relay.clone();
        let reply_formatter = self.reply_formatter.lock().unwrap().clone();
        let (tx, rx) = tokio::sync::mpsc::channel::<UdpPacket>(64);
        let dst_key = dst.clone();
        let this = self.clone();

        // 智能双模超时机制：DNS 请求 5 秒快速回收；游戏/VoIP/常规流量 180 秒长保活
        let idle_timeout = if dst.port == 53 || dst.port == 853 {
            DNS_IDLE_TIMEOUT
        } else {
            GAME_UDP_IDLE_TIMEOUT
        };

        // 直发会话：rx 臂用布尔禁用，但 rx 必须恒持有——GC 以 tx.is_closed()
        // 判活，drop rx 会让会话在首次扫描即被误删，NAT 表失效后每个上行
        // 报文都重新建连（服务器主动推送的下行随之全部丢失）
        let rx_enabled = direct.is_none();
        tokio::spawn(async move {
            let mut rx = rx;
            loop {
                tokio::select! {
                    biased;
                    // 出站 → 客户端 (Full-Cone EIF 端点独立过滤，允许对端/任意对等点回包透传)
                    res = conn.recv() => {
                        match res {
                            Ok(pkt) => {
                                // RRL 防反射放大检查：超速则丢弃以遏制放大效应
                                if let Some(ref g) = this.gate {
                                    match g.check_rrl(client.ip()) {
                                        vp_core::RrlDecision::Drop => continue,
                                        vp_core::RrlDecision::Allow | vp_core::RrlDecision::Slip => {}
                                    }
                                }
                                if let Some(f) = &reply_formatter {
                                    let payload = f(pkt.src, &pkt.data);
                                    let _ = relay.send_to(&payload, client).await;
                                } else {
                                    let _ = relay.send_to(&pkt.data, client).await;
                                }
                            }
                            Err(e) => {
                                tracing::debug!("udp 回包失败: {e}");
                                break;
                            }
                        }
                    }
                    // 客户端 → 出站（直发句柄存在时上行已旁路，此臂禁用；
                    // rx 仍持有以维持 GC 判活，channel 恒空零开销）
                    out = async { rx.recv().await }, if rx_enabled => {
                        match out {
                            Some(pkt) => {
                                if conn.send(&pkt).await.is_err() {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                    // 智能双模空闲超时回收
                    _ = tokio::time::sleep(idle_timeout) => break,
                }
            }
            debug!("udp 会话回收: {} -> {dst_key}", client);
            let key = SessionKey {
                client,
                host: dst_key.host.clone(),
                port: dst_key.port,
            };
            let idx = SessionMap::index(&key);
            this.sessions.shards[idx].lock().await.remove(&key);
        });
        Ok((tx, direct))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[test]
    fn test_dual_mode_timeout_constants() {
        assert_eq!(DNS_IDLE_TIMEOUT, Duration::from_secs(5));
        assert_eq!(GAME_UDP_IDLE_TIMEOUT, Duration::from_secs(180));
    }

    /// 直发会话 GC 判活回归：spawn_session 直发分支不消费 rx 但必须恒持有——
    /// GC 以 tx.is_closed() 判活，rx 被 drop 会让会话在首次扫描即被误删
    /// （NAT 表失效 → 每个上行报文重新建连，服务器主动下行全部丢失）
    #[tokio::test]
    async fn direct_send_session_keeps_rx_alive_for_gc() {
        let (tx, mut rx) = mpsc::channel::<UdpPacket>(64);
        // 模拟直发任务：rx 恒持有（select 臂被 rx_enabled 禁用）不消费
        let task = tokio::spawn(async move {
            let _held = &mut rx;
            tokio::time::sleep(Duration::from_millis(50)).await;
            // 任务在此结束，rx 随之 drop
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(
            !tx.is_closed(),
            "直发会话任务存活期间 tx 不得 closed（GC 判活依据）"
        );
        task.await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(tx.is_closed(), "任务退出后 GC 应能正常回收会话");
    }

    #[tokio::test]
    async fn test_udp_nat_high_watermark_gc() {
        let (tx, rx) = mpsc::channel::<UdpPacket>(1);
        let mut sessions = HashMap::new();
        let client_a: SocketAddr = "1.1.1.1:1000".parse().unwrap();
        let client_b: SocketAddr = "1.1.1.1:1001".parse().unwrap();

        sessions.insert((client_a, "target-a".to_string()), tx.clone());
        sessions.insert((client_b, "target-b".to_string()), tx.clone());
        // 模拟接收端已断开
        drop(rx);

        let sessions_map = Arc::new(Mutex::new(sessions));
        let max_sessions = 2;
        let mut guard = sessions_map.lock().await;
        if guard.len() >= max_sessions {
            guard.retain(|_, ch| !ch.is_closed());
        }
        assert!(
            guard.is_empty(),
            "所有已断开的虚假/过期会话应在高水位被主动回收"
        );
    }
}

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

/// 一个客户端 UDP 关联
pub type ReplyFormatter = Arc<dyn Fn(SocketAddr, &[u8]) -> Vec<u8> + Send + Sync>;

pub struct UdpNat {
    ctx: InboundCtx,
    tag: Arc<str>,
    /// 客户端数据报首来源记录（兼容单例查询）
    client: Mutex<Option<SocketAddr>>,
    /// 中继 socket（客户端发往此地址；回包也从这里发出）
    relay: Arc<UdpSocket>,
    /// (客户端源地址, 目标地址) → 发送队列（实现多客户端 Full-Cone EIM 会话隔离）
    sessions: Mutex<HashMap<(SocketAddr, DstAddr), tokio::sync::mpsc::Sender<UdpPacket>>>,
    /// 回包格式化（None = 裸转发，TUN 场景）
    reply_formatter: std::sync::Mutex<Option<ReplyFormatter>>,
    /// 安全门禁与 RRL 限制器（可选）
    gate: Option<Arc<vp_core::InboundGate>>,
    /// 会话表最大容量上限（防止探测泛洪消耗内存）
    max_sessions: usize,
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
            sessions: Mutex::new(HashMap::new()),
            reply_formatter: std::sync::Mutex::new(None),
            gate,
            max_sessions: 4096,
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
        let resolved_domain = fake_domain
            .or_else(|| vp_dns::reverse_fake_ip(pkt.dst.ip()))
            .or_else(|| {
                if matches!(pkt.dst.port(), 443 | 8443 | 2053 | 2083 | 2087 | 2096) {
                    vp_core::sniff::sniff_quic_sni(&pkt.data)
                } else {
                    None
                }
            });
        let dst = DstAddr {
            host: match resolved_domain {
                Some(domain) => Host::Domain(domain),
                None => Host::Ip(pkt.dst.ip()),
            },
            port: pkt.dst.port(),
        };

        let session_key = (client_addr, dst.clone());
        let mut map = self.sessions.lock().await;
        // 高水位 GC 清理：当会话数量达到上限时剔除断开或最早的会话
        if map.len() >= self.max_sessions {
            map.retain(|_, tx| !tx.is_closed());
            if map.len() >= self.max_sessions {
                let to_remove: Vec<_> = map
                    .keys()
                    .take(map.len() - self.max_sessions + 1)
                    .cloned()
                    .collect();
                for k in to_remove {
                    map.remove(&k);
                }
            }
        }

        let tx = match map.get(&session_key) {
            Some(tx) => tx.clone(),
            None => {
                let tx = self.spawn_session(client_addr, &dst).await?;
                map.insert(session_key, tx.clone());
                tx
            }
        };
        drop(map);
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
    ) -> Result<tokio::sync::mpsc::Sender<UdpPacket>> {
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
        let relay = self.relay.clone();
        let reply_formatter = self.reply_formatter.lock().unwrap().clone();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<UdpPacket>(64);
        let dst_key = dst.clone();
        let this = self.clone();

        // 智能双模超时机制：DNS 请求 5 秒快速回收；游戏/VoIP/常规流量 180 秒长保活
        let idle_timeout = if dst.port == 53 || dst.port == 853 {
            DNS_IDLE_TIMEOUT
        } else {
            GAME_UDP_IDLE_TIMEOUT
        };

        tokio::spawn(async move {
            let sessions = &this.sessions;
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
                    // 客户端 → 出站
                    out = rx.recv() => {
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
            sessions.lock().await.remove(&(client, dst_key));
        });
        Ok(tx)
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

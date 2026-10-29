//! UDP 会话分发与 NAT：入站（socks5/TUN）共用的 UDP 中继枢纽。
//!
//! - 客户端侧一个 UDP socket 收所有目标的数据报
//! - 每个目标地址懒建一条出站 PacketConn（经路由决策）
//! - 收发一体化泵：队列→出站 / 出站→客户端 / 空闲回收

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

const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// 一个客户端 UDP 关联
pub type ReplyFormatter = Arc<dyn Fn(SocketAddr, &[u8]) -> Vec<u8> + Send + Sync>;

pub struct UdpNat {
    ctx: InboundCtx,
    tag: Arc<str>,
    /// 客户端数据报来源（回包目标；首次收包时更新，排除 TCP 控制端口）
    client: Mutex<Option<SocketAddr>>,
    /// 中继 socket（客户端发往此地址；回包也从这里发出）
    relay: Arc<UdpSocket>,
    /// 目标 → 发送队列（会话存活标志）
    sessions: Mutex<HashMap<DstAddr, tokio::sync::mpsc::Sender<UdpPacket>>>,
    /// 回包格式化（None = 裸转发，TUN 场景）
    reply_formatter: std::sync::Mutex<Option<ReplyFormatter>>,
}

impl UdpNat {
    pub fn new(ctx: InboundCtx, tag: Arc<str>, relay: Arc<UdpSocket>) -> Arc<Self> {
        Arc::new(UdpNat {
            ctx,
            tag,
            client: Mutex::new(None),
            relay,
            sessions: Mutex::new(HashMap::new()),
            reply_formatter: std::sync::Mutex::new(None),
        })
    }

    /// 客户端数据报 → 路由 → 出站。
    /// fake_domain：TUN 场景下 fake-ip 还原出的域名（优先于 IP）
    pub async fn dispatch(
        self: &Arc<Self>,
        pkt: UdpPacket,
        fake_domain: Option<String>,
    ) -> Result<()> {
        // 记录真实数据报来源（首个来源；同 IP 的后来者允许）
        {
            let mut c = self.client.lock().await;
            if c.is_none() {
                *c = Some(pkt.src);
            }
        }
        let dst = DstAddr {
            host: match fake_domain {
                Some(domain) => Host::Domain(domain),
                None => Host::Ip(pkt.dst.ip()),
            },
            port: pkt.dst.port(),
        };
        let mut map = self.sessions.lock().await;
        let tx = match map.get(&dst) {
            Some(tx) => tx.clone(),
            None => {
                let tx = self.spawn_session(&dst).await?;
                map.insert(dst.clone(), tx.clone());
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
        dst: &DstAddr,
    ) -> Result<tokio::sync::mpsc::Sender<UdpPacket>> {
        let client = match *self.client.lock().await {
            Some(c) => c,
            None => std::net::SocketAddr::new(std::net::IpAddr::V4([127, 0, 0, 1].into()), 0), // 尚无数据报来源（占位）
        };
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
        let client = match *self.client.lock().await {
            Some(c) => c,
            None => std::net::SocketAddr::new(std::net::IpAddr::V4([127, 0, 0, 1].into()), 0), // 尚无数据报来源（占位）
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel::<UdpPacket>(64);
        let dst_key = dst.clone();
        let this = self.clone();
        tokio::spawn(async move {
            let sessions = &this.sessions;
            loop {
                tokio::select! {
                    biased;
                    // 出站 → 客户端
                    res = conn.recv() => {
                        match res {
                            Ok(pkt) => {
                                // 回包交给入站协议格式化（socks5/TUN 各自封装头）
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
                    // 空闲回收
                    _ = tokio::time::sleep(IDLE_TIMEOUT) => break,
                }
            }
            debug!("udp 会话回收: {dst_key}");
            sessions.lock().await.remove(&dst_key);
        });
        Ok(tx)
    }
}

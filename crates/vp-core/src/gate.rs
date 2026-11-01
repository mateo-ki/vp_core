//! 服务端安全门禁引擎：UDP 响应速率限制（RRL）、端口敲门（Port Knocking）与地理/网络门禁。
//!
//! - `UdpRrlLimiter`：基于源 IP /24 (IPv4) 或 /56 (IPv6) 子网聚合的响应速率限制，带 Slip 采样与认证豁免，根除反射放大 DDoS。
//! - `KnockGate`：轻量级端口敲门服务，支持时间戳防重放 Token 与固定口令，开门维持指定时间窗口，使代理端口对外完全隐身。
//! - `InboundGate`：整合 GeoIP / ASN 访问过滤、Knock 门禁与 RRL 速率决策的统一入站门禁。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// IP 子网聚合键：IPv4 /24（前 3 字节）或 IPv6 /56（前 7 字节）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpSubnet {
    V4([u8; 3]),
    V6([u8; 7]),
}

impl From<IpAddr> for IpSubnet {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                IpSubnet::V4([o[0], o[1], o[2]])
            }
            IpAddr::V6(v6) => {
                let s = v6.octets();
                IpSubnet::V6([s[0], s[1], s[2], s[3], s[4], s[5], s[6]])
            }
        }
    }
}

/// UDP RRL 速率判定决策
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RrlDecision {
    /// 令牌充裕，正常发送响应
    Allow,
    /// 速率超限但命中采样因子，允许发包以维持丢包下的合法客户端握手重试
    Slip,
    /// 速率超限静默丢弃，切断反射放大倍数
    Drop,
}

/// UDP 响应速率限制器（Response Rate Limiting, RRL）
#[derive(Debug)]
pub struct UdpRrlLimiter {
    max_qps: f64,
    burst: f64,
    slip: u32,
    subnets: Mutex<HashMap<IpSubnet, (f64, Instant, u64)>>,
    authenticated_ips: RwLock<HashMap<IpAddr, Instant>>,
}

impl UdpRrlLimiter {
    pub fn new(max_qps: u32, burst: u32, slip: u32) -> Self {
        let max_qps = if max_qps == 0 { 10.0 } else { max_qps as f64 };
        let burst = if burst == 0 { 20.0 } else { burst as f64 };
        Self {
            max_qps,
            burst,
            slip,
            subnets: Mutex::new(HashMap::new()),
            authenticated_ips: RwLock::new(HashMap::new()),
        }
    }

    /// 检查对指定目标客户端 IP 发送响应包的 RRL 决策
    pub fn check_or_slip(&self, ip: IpAddr) -> RrlDecision {
        let now = Instant::now();

        // 1. 已认证成功的客户端直接豁免限速
        if let Some(exp) = self.authenticated_ips.read().unwrap().get(&ip) {
            if now < *exp {
                return RrlDecision::Allow;
            }
        }

        let subnet = IpSubnet::from(ip);
        let mut map = self.subnets.lock().unwrap();

        // 防止极端情况下海量虚假源 IP 导致内存无限膨胀
        if map.len() > 10_000 {
            map.retain(|_, (_, last, _)| now.duration_since(*last) < Duration::from_secs(60));
        }

        let entry = map.entry(subnet).or_insert_with(|| (self.burst, now, 0));

        let elapsed = now.duration_since(entry.1).as_secs_f64();
        entry.0 = (entry.0 + elapsed * self.max_qps).min(self.burst);
        entry.1 = now;

        if entry.0 >= 1.0 {
            entry.0 -= 1.0;
            RrlDecision::Allow
        } else {
            entry.2 += 1;
            if self.slip > 0 && (entry.2 % (self.slip as u64)) == 0 {
                RrlDecision::Slip
            } else {
                RrlDecision::Drop
            }
        }
    }

    /// 握手或身份凭据校验成功后标记豁免（持续 1 小时）
    pub fn mark_authenticated(&self, ip: IpAddr) {
        let mut map = self.authenticated_ips.write().unwrap();
        if map.len() > 5_000 {
            let now = Instant::now();
            map.retain(|_, exp| now < *exp);
        }
        map.insert(ip, Instant::now() + Duration::from_secs(3600));
    }
}

/// 端口敲门防扫描门禁（Port Knocking Gate）
#[derive(Debug)]
pub struct KnockGate {
    secret: String,
    timeout: Duration,
    opened_ips: RwLock<HashMap<IpAddr, Instant>>,
}

impl KnockGate {
    pub fn new(secret: impl Into<String>, timeout: Duration) -> Self {
        Self {
            secret: secret.into(),
            timeout,
            opened_ips: RwLock::new(HashMap::new()),
        }
    }

    /// 检查指定 IP 当前是否处于敲门放行开门窗口期内
    pub fn is_open(&self, ip: IpAddr) -> bool {
        if let Some(exp) = self.opened_ips.read().unwrap().get(&ip) {
            Instant::now() < *exp
        } else {
            false
        }
    }

    /// 向指定 IP 开门并刷新有效期
    pub fn open(&self, ip: IpAddr) {
        let now = Instant::now();
        let mut map = self.opened_ips.write().unwrap();
        if map.len() > 5_000 {
            map.retain(|_, exp| now < *exp);
        }
        map.insert(ip, now + self.timeout);
    }

    /// 校验敲门数据报（支持直接密码或时间戳防重放 SHA256 Token）
    pub fn verify_knock(&self, data: &[u8], client_ip: IpAddr) -> bool {
        // 1. 允许直接匹配口令文本
        if data == self.secret.as_bytes() || data.trim_ascii() == self.secret.as_bytes() {
            self.open(client_ip);
            return true;
        }

        // 2. 允许匹配基于当前分钟的 SHA256 Token（容忍 ±60 秒时间漂移）
        let now_sec = vp_common::now_millis() / 1000;
        let minute = now_sec / 60;
        for m in [minute, minute.saturating_sub(1), minute + 1] {
            let mut hasher = Sha256::new();
            hasher.update(self.secret.as_bytes());
            hasher.update(m.to_be_bytes());
            let digest = hasher.finalize();

            if data == digest.as_slice() {
                self.open(client_ip);
                return true;
            }

            // 十六进制字符串匹配
            let hex = format!("{digest:x}");
            if data == hex.as_bytes() || data.trim_ascii() == hex.as_bytes() {
                self.open(client_ip);
                return true;
            }
        }

        false
    }

    /// 启动后台 UDP 敲门接收器
    pub async fn spawn_listener(self: Arc<Self>, bind: &str, port: u16) -> std::io::Result<u16> {
        let addr = format!("{bind}:{port}");
        let sock = Arc::new(UdpSocket::bind(&addr).await?);
        let actual_port = sock.local_addr()?.port();
        let this = self.clone();
        let bind_str = bind.to_string();

        tokio::spawn(async move {
            info!("端口敲门服务 (Knock Server) 已就绪，监听 UDP {bind_str}:{actual_port}");
            let mut buf = [0u8; 256];
            loop {
                match sock.recv_from(&mut buf).await {
                    Ok((n, peer)) => {
                        let pkt = &buf[..n];
                        if this.verify_knock(pkt, peer.ip()) {
                            info!(
                                "客户端 {} 端口敲门验证成功，已开放门禁 {} 秒",
                                peer.ip(),
                                this.timeout.as_secs()
                            );
                            let _ = sock.send_to(b"OPEN\n", peer).await;
                        } else {
                            debug!("客户端 {} 端口敲门凭据无效", peer.ip());
                        }
                    }
                    Err(e) => {
                        warn!("敲门套接字接收异常: {e}");
                        break;
                    }
                }
            }
        });

        Ok(actual_port)
    }
}

/// 统一入站安全门禁（集成 GeoIP / ASN / 端口敲门 / UDP RRL）
pub struct InboundGate {
    /// 地理位置与 ASN 规则过滤断言（None 表示不限制）
    pub ip_filter: Option<Arc<dyn Fn(IpAddr) -> bool + Send + Sync>>,
    /// 端口敲门门禁（None 表示不限制）
    pub knock: Option<Arc<KnockGate>>,
    /// UDP 响应速率限制器（None 表示不限制）
    pub rrl: Option<Arc<UdpRrlLimiter>>,
}

impl InboundGate {
    pub fn new(
        ip_filter: Option<Arc<dyn Fn(IpAddr) -> bool + Send + Sync>>,
        knock: Option<Arc<KnockGate>>,
        rrl: Option<Arc<UdpRrlLimiter>>,
    ) -> Self {
        Self {
            ip_filter,
            knock,
            rrl,
        }
    }

    /// 检查指定对端 IP 是否允许进入服务（TCP 握手前或 UDP 数据包入口处调用）
    pub fn check_accept(&self, ip: IpAddr) -> bool {
        // 1. 地理位置与 ASN 过滤拦截
        if let Some(ref filter) = self.ip_filter {
            if !filter(ip) {
                debug!("客户端 {} 触发入站 GeoIP/ASN 门禁拦截，已丢弃", ip);
                return false;
            }
        }

        // 2. 端口敲门门禁拦截
        if let Some(ref knock) = self.knock {
            if !knock.is_open(ip) {
                debug!("客户端 {} 未完成端口敲门，已静默隐身丢弃", ip);
                return false;
            }
        }

        true
    }

    /// UDP 回包前检查 RRL 响应速率
    pub fn check_rrl(&self, ip: IpAddr) -> RrlDecision {
        if let Some(ref rrl) = self.rrl {
            rrl.check_or_slip(ip)
        } else {
            RrlDecision::Allow
        }
    }

    /// 客户端认证通过后调用，免除 RRL 限速并刷新开门窗口
    pub fn mark_authenticated(&self, ip: IpAddr) {
        if let Some(ref rrl) = self.rrl {
            rrl.mark_authenticated(ip);
        }
        if let Some(ref knock) = self.knock {
            knock.open(ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_rrl_slip_and_drop() {
        let rrl = UdpRrlLimiter::new(2, 2, 2);
        let client_ip: IpAddr = "1.2.3.4".parse().unwrap();

        // 消耗完容量 2
        assert_eq!(rrl.check_or_slip(client_ip), RrlDecision::Allow);
        assert_eq!(rrl.check_or_slip(client_ip), RrlDecision::Allow);

        // 第 3 包超速: dropped_count=1 -> Drop
        assert_eq!(rrl.check_or_slip(client_ip), RrlDecision::Drop);
        // 第 4 包超速: dropped_count=2 -> 命中 slip=2 采样 Slip
        assert_eq!(rrl.check_or_slip(client_ip), RrlDecision::Slip);

        // 标记已认证后应无条件 Allow
        rrl.mark_authenticated(client_ip);
        assert_eq!(rrl.check_or_slip(client_ip), RrlDecision::Allow);
    }

    #[tokio::test]
    async fn test_knock_gate_flow() {
        let gate = Arc::new(KnockGate::new("secret-knock", Duration::from_secs(2)));
        let client: IpAddr = "192.168.1.100".parse().unwrap();

        // 未敲门时应处于未开门状态
        assert!(!gate.is_open(client));

        // 错误敲门口令验证失败
        assert!(!gate.verify_knock(b"wrong-secret", client));
        assert!(!gate.is_open(client));

        // 正确口令敲门成功
        assert!(gate.verify_knock(b"secret-knock\n", client));
        assert!(gate.is_open(client));

        // 时间戳 Token 敲门测试
        let client2: IpAddr = "192.168.1.101".parse().unwrap();
        let now_sec = vp_common::now_millis() / 1000;
        let minute = now_sec / 60;
        let mut hasher = Sha256::new();
        hasher.update(b"secret-knock");
        hasher.update(minute.to_be_bytes());
        let digest = hasher.finalize();

        assert!(gate.verify_knock(&digest, client2));
        assert!(gate.is_open(client2));
    }

    #[test]
    fn test_inbound_gate_composite() {
        let filter: Arc<dyn Fn(IpAddr) -> bool + Send + Sync> = Arc::new(|ip| {
            if let IpAddr::V4(v4) = ip {
                v4.octets()[0] == 10 // 仅允许 10.0.0.0/8
            } else {
                false
            }
        });

        let knock = Arc::new(KnockGate::new("pwd", Duration::from_secs(60)));
        let gate = InboundGate::new(Some(filter), Some(knock.clone()), None);

        let ip_allowed: IpAddr = "10.0.1.2".parse().unwrap();
        let ip_blocked: IpAddr = "172.16.0.1".parse().unwrap();

        // ip_blocked 在 filter 即被拒
        assert!(!gate.check_accept(ip_blocked));

        // ip_allowed 满足 filter，但在敲门前仍被拒
        assert!(!gate.check_accept(ip_allowed));

        // 敲门开门后放行
        knock.open(ip_allowed);
        assert!(gate.check_accept(ip_allowed));
    }
}

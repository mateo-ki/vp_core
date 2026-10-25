//! 策略组：selector / url-test / fallback / load-balance / relay。
//! 组本身实现 Outbound，天然支持嵌套（构建期保证无环）。

use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use vp_common::{DstAddr, Error, Result};
use vp_core::{Outbound, ProxyStream, Session};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupType {
    Select,
    UrlTest,
    Fallback,
    LoadBalance,
    Relay,
}

impl GroupType {
    pub fn as_str(self) -> &'static str {
        match self {
            GroupType::Select => "Selector",
            GroupType::UrlTest => "URLTest",
            GroupType::Fallback => "Fallback",
            GroupType::LoadBalance => "LoadBalance",
            GroupType::Relay => "Relay",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LbStrategy {
    RoundRobin,
    ConsistentHash,
}

pub struct GroupSpec {
    pub name: String,
    pub ty: GroupType,
    pub members: Vec<String>,
    pub test_url: Option<String>,
    pub interval: u64,
    pub tolerance: u32,
    pub lazy: bool,
    pub lb_strategy: LbStrategy,
}

pub struct Group {
    name: Arc<str>,
    ty: GroupType,
    members: Vec<Arc<dyn Outbound>>,
    member_names: Vec<Arc<str>>,
    select_now: RwLock<usize>,
    rr_counter: AtomicU32,
    /// url-test/fallback 当前选择
    selected: AtomicUsize,
    alive: Mutex<Vec<bool>>,
    delay_ms: Mutex<Vec<Option<u32>>>,
    test_url: String,
    interval: u64,
    tolerance: u32,
    lazy: bool,
    lb_strategy: LbStrategy,
}

impl Group {
    /// 构建组（成员必须已解析为 Outbound）
    pub fn new(spec: GroupSpec, members: Vec<Arc<dyn Outbound>>) -> Arc<Self> {
        let member_names: Vec<Arc<str>> = members.iter().map(|m| m.name().into()).collect();
        let n = members.len();
        Arc::new(Group {
            name: spec.name.into(),
            ty: spec.ty,
            members,
            member_names,
            select_now: RwLock::new(0),
            rr_counter: AtomicU32::new(0),
            selected: AtomicUsize::new(0),
            alive: Mutex::new(vec![false; n]),
            delay_ms: Mutex::new(vec![None; n]),
            test_url: spec.test_url.unwrap_or_else(|| "http://www.gstatic.com/generate_204".into()),
            interval: spec.interval.max(30),
            tolerance: spec.tolerance,
            lazy: spec.lazy,
            lb_strategy: spec.lb_strategy,
        })
    }

    pub fn name(&self) -> Arc<str> {
        self.name.clone()
    }

    pub fn ty(&self) -> GroupType {
        self.ty
    }

    pub fn member_names(&self) -> &[Arc<str>] {
        &self.member_names
    }

    /// 选择下标（Relay 无单选概念，恒 0）
    fn pick_index(&self, sess: &Session) -> usize {
        let n = self.members.len();
        if n == 0 {
            return 0;
        }
        match self.ty {
            GroupType::Select => {
                let i = *self.select_now.read().unwrap();
                i.min(n - 1)
            }
            GroupType::UrlTest | GroupType::Fallback => {
                let i = self.selected.load(Ordering::Relaxed);
                i.min(n - 1)
            }
            GroupType::LoadBalance => match self.lb_strategy {
                LbStrategy::RoundRobin => {
                    (self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize) % n
                }
                LbStrategy::ConsistentHash => {
                    let key = match &sess.dst.host {
                        vp_common::Host::Domain(d) => d.as_str(),
                        vp_common::Host::Ip(ip) => {
                            // 简单 FNV
                            let b = match ip {
                                std::net::IpAddr::V4(v) => v.octets().to_vec(),
                                std::net::IpAddr::V6(v) => v.octets().to_vec(),
                            };
                            return fnv_index(&b, n);
                        }
                    };
                    fnv_index(key.as_bytes(), n)
                }
            },
            GroupType::Relay => 0,
        }
    }

    /// 当前生效成员
    pub fn pick(&self, sess: &Session) -> Arc<dyn Outbound> {
        let i = self.pick_index(sess);
        self.members[i.min(self.members.len().saturating_sub(1))].clone()
    }

    // ---------------- API 操作 ----------------

    /// selector 手动切换
    pub fn set_selected(&self, member: &str) -> bool {
        if self.ty != GroupType::Select {
            return false;
        }
        if let Some(i) = self.member_names.iter().position(|n| &**n == member) {
            *self.select_now.write().unwrap() = i;
            true
        } else {
            false
        }
    }

    pub fn selected_name(&self) -> Arc<str> {
        match self.ty {
            GroupType::Select => {
                let i = *self.select_now.read().unwrap();
                self.member_names[i.min(self.member_names.len() - 1)].clone()
            }
            _ => {
                let i = self.selected.load(Ordering::Relaxed);
                self.member_names[i.min(self.member_names.len() - 1)].clone()
            }
        }
    }

    pub fn member_states(&self) -> Vec<(Arc<str>, Option<u32>, bool)> {
        let delay = self.delay_ms.lock().unwrap();
        let alive = self.alive.lock().unwrap();
        self.member_names
            .iter()
            .enumerate()
            .map(|(i, n)| (n.clone(), delay[i], alive[i]))
            .collect()
    }

    /// 手动触发全部成员测速（API delay 接口）
    pub async fn url_test_all(&self) {
        self.probe_all().await;
    }

    /// 单成员测速（返回毫秒）
    pub async fn url_test_member(&self, member: &str) -> Result<u32> {
        let i = self
            .member_names
            .iter()
            .position(|n| &**n == member)
            .ok_or_else(|| Error::Other(format!("成员 {member:?} 不存在")))?;
        let started = std::time::Instant::now();
        let ok = probe(&self.members[i], &self.test_url).await.is_ok();
        let ms = started.elapsed().as_millis() as u32;
        {
            let mut alive = self.alive.lock().unwrap();
            let mut delay = self.delay_ms.lock().unwrap();
            alive[i] = ok;
            delay[i] = if ok { Some(ms) } else { None };
        }
        if ok {
            Ok(ms)
        } else {
            Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "测速失败",
            )))
        }
    }

    /// 启动后台健康检查（url-test / fallback 且非 lazy）
    pub fn start_health_checks(self: &Arc<Self>) {
        if self.ty != GroupType::UrlTest && self.ty != GroupType::Fallback {
            return;
        }
        if self.lazy {
            return;
        }
        let g = self.clone();
        tokio::spawn(async move {
            loop {
                g.probe_all().await;
                tokio::time::sleep(Duration::from_secs(g.interval)).await;
            }
        });
    }

    async fn probe_all(&self) {
        let mut results = Vec::with_capacity(self.members.len());
        for m in &self.members {
            let started = std::time::Instant::now();
            let ok = probe(m, &self.test_url).await.is_ok();
            let ms = started.elapsed().as_millis() as u32;
            results.push(if ok { Some(ms) } else { None });
        }
        self.apply_probe_results(&results);
    }

    fn apply_probe_results(&self, results: &[Option<u32>]) {
        {
            let mut alive = self.alive.lock().unwrap();
            for (i, r) in results.iter().enumerate() {
                alive[i] = r.is_some();
            }
            let mut delay = self.delay_ms.lock().unwrap();
            for (i, r) in results.iter().enumerate() {
                delay[i] = *r;
            }
        }
        match self.ty {
            GroupType::UrlTest => {
                // 容差滞回：仅当新最优显著优于当前选择时切换
                let cur = self.selected.load(Ordering::Relaxed);
                let cur_ms = self.delay_ms.lock().unwrap()[cur];
                let mut best: Option<(usize, u32)> = None;
                for (i, r) in results.iter().enumerate() {
                    if let Some(ms) = r {
                        if best.is_none_or(|(_, b)| *ms < b) {
                            best = Some((i, *ms));
                        }
                    }
                }
                if let Some((bi, bms)) = best {
                    let switch = match cur_ms {
                        Some(cm) => bms + self.tolerance < cm,
                        None => true,
                    };
                    if switch {
                        debug!("组 {} url-test 切换 -> {}", self.name, self.member_names[bi]);
                        self.selected.store(bi, Ordering::Relaxed);
                    }
                }
            }
            GroupType::Fallback => {
                // 按顺序取第一个存活
                let cur = self.selected.load(Ordering::Relaxed);
                let target = results.iter().position(|r| r.is_some());
                if let Some(ti) = target {
                    if ti != cur {
                        debug!("组 {} fallback 切换 -> {}", self.name, self.member_names[ti]);
                        self.selected.store(ti, Ordering::Relaxed);
                    }
                }
            }
            _ => {}
        }
    }

    /// 链式建链：client → a → b → ... → last → dst
    async fn connect_relay(&self, sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        let n = self.members.len();
        let second_addr: DstAddr = self.members[1]
            .remote_addr()
            .map(|(h, p)| DstAddr::new(h, p))
            .ok_or_else(|| Error::Unsupported("relay 成员缺少服务器地址".into()))?;
        let mut stream = self.members[0].connect_stream(sess, &second_addr).await?;
        for i in 1..n {
            let member = &self.members[i];
            let next_addr: DstAddr = if i + 1 < n {
                member
                    .remote_addr()
                    .map(|(h, p)| DstAddr::new(h, p))
                    .ok_or_else(|| Error::Unsupported("relay 成员缺少服务器地址".into()))?
            } else {
                dst.clone()
            };
            stream = member.connect_over(sess, &next_addr, stream).await?;
        }
        Ok(stream)
    }
}

fn fnv_index(bytes: &[u8], n: usize) -> usize {
    let mut hash: u32 = 0x811c9dc5;
    for &b in bytes {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    (hash as usize) % n.max(1)
}

/// 通过指定出站探测测试 URL，返回耗时
async fn probe(o: &Arc<dyn Outbound>, url: &str) -> Result<Duration> {
    let (host, port, path) = parse_test_url(url)?;
    let dst = DstAddr::new(host.clone(), port);
    let sess = Session::new_tcp("healthcheck".into(), None, dst.clone());
    let started = std::time::Instant::now();
    let mut stream = o.connect_stream(&sess, &dst).await?;
    let req = format!(
        "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: vpcore/health\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    let mut byte = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut byte)).await {
        Ok(r) => {
            r?;
        }
        Err(_) => {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "probe timeout",
            )))
        }
    }
    Ok(started.elapsed())
}

fn parse_test_url(url: &str) -> Result<(String, u16, String)> {
    let (scheme, rest) = url.split_once("://").ok_or(Error::Config("测速 URL 非法".into()))?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let default_port = if scheme == "https" { 443 } else { 80 };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), p.parse().unwrap_or(default_port))
        }
        _ => (hostport.to_string(), default_port),
    };
    Ok((host, port, path.to_string()))
}

// 组自身即出站
#[async_trait]
impl Outbound for Group {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect_stream(&self, sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        if self.members.is_empty() {
            return Err(Error::Unsupported(format!("组 {} 无成员", self.name)));
        }
        if self.ty == GroupType::Relay {
            if self.members.len() == 1 {
                return self.members[0].connect_stream(sess, dst).await;
            }
            return self.connect_relay(sess, dst).await;
        }
        self.pick(sess).connect_stream(sess, dst).await
    }

    async fn connect_over(
        &self,
        sess: &Session,
        dst: &DstAddr,
        underlying: Box<dyn ProxyStream>,
    ) -> Result<Box<dyn ProxyStream>> {
        // 组作为链中的一环：仅叶子协议支持；relay 嵌套走首个成员
        let member = self.pick(sess);
        member.connect_over(sess, dst, underlying).await
    }

    fn support_udp(&self) -> bool {
        if self.ty == GroupType::Relay {
            self.members.iter().all(|m| m.support_udp())
        } else {
            self.members.iter().any(|m| m.support_udp())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct MockOutbound {
        name: Arc<str>,
        remote: Option<(String, u16)>,
        connects: AtomicUsize,
        overs: AtomicUsize,
    }

    impl MockOutbound {
        fn new(name: &str) -> Arc<Self> {
            Arc::new(MockOutbound {
                name: name.into(),
                remote: Some((format!("{}.mock", name), 1080)),
                connects: AtomicUsize::new(0),
                overs: AtomicUsize::new(0),
            })
        }
    }

    #[async_trait]
    impl Outbound for MockOutbound {
        fn name(&self) -> &str {
            &self.name
        }

        async fn connect_stream(
            &self,
            _sess: &Session,
            _dst: &DstAddr,
        ) -> Result<Box<dyn ProxyStream>> {
            self.connects.fetch_add(1, Ordering::Relaxed);
            let (a, _b) = tokio::io::duplex(4096);
            Ok(Box::new(a))
        }

        async fn connect_over(
            &self,
            _sess: &Session,
            _dst: &DstAddr,
            underlying: Box<dyn ProxyStream>,
        ) -> Result<Box<dyn ProxyStream>> {
            self.overs.fetch_add(1, Ordering::Relaxed);
            Ok(underlying)
        }

        fn remote_addr(&self) -> Option<(String, u16)> {
            self.remote.clone()
        }
    }

    fn dst() -> DstAddr {
        DstAddr::new("target.com", 443)
    }

    fn sess() -> Session {
        Session::new_tcp("test".into(), None, dst())
    }

    #[tokio::test]
    async fn selector_switch() {
        let m1 = MockOutbound::new("a");
        let m2 = MockOutbound::new("b");
        let g = Group::new(
            GroupSpec {
                name: "SEL".into(),
                ty: GroupType::Select,
                members: vec!["a".into(), "b".into()],
                test_url: None,
                interval: 300,
                tolerance: 0,
                lazy: true,
                lb_strategy: LbStrategy::RoundRobin,
            },
            vec![m1.clone(), m2.clone()],
        );
        assert_eq!(g.selected_name().as_ref(), "a");
        let _ = g.connect_stream(&sess(), &dst()).await.unwrap();
        assert_eq!(m1.connects.load(Ordering::Relaxed), 1);
        assert_eq!(m2.connects.load(Ordering::Relaxed), 0);
        assert!(g.set_selected("b"));
        let _ = g.connect_stream(&sess(), &dst()).await.unwrap();
        assert_eq!(m2.connects.load(Ordering::Relaxed), 1);
        assert!(!g.set_selected("不存在"));
    }

    #[tokio::test]
    async fn load_balance_round_robin() {
        let m1 = MockOutbound::new("a");
        let m2 = MockOutbound::new("b");
        let g = Group::new(
            GroupSpec {
                name: "LB".into(),
                ty: GroupType::LoadBalance,
                members: vec!["a".into(), "b".into()],
                test_url: None,
                interval: 300,
                tolerance: 0,
                lazy: true,
                lb_strategy: LbStrategy::RoundRobin,
            },
            vec![m1.clone(), m2.clone()],
        );
        for _ in 0..4 {
            let _ = g.connect_stream(&sess(), &dst()).await.unwrap();
        }
        assert_eq!(m1.connects.load(Ordering::Relaxed), 2);
        assert_eq!(m2.connects.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn fallback_selection_logic() {
        let m1 = MockOutbound::new("a");
        let m2 = MockOutbound::new("b");
        let g = Group::new(
            GroupSpec {
                name: "FB".into(),
                ty: GroupType::Fallback,
                members: vec!["a".into(), "b".into()],
                test_url: None,
                interval: 300,
                tolerance: 0,
                lazy: true,
                lb_strategy: LbStrategy::RoundRobin,
            },
            vec![m1.clone(), m2.clone()],
        );
        // 全部失败 → 保持 0
        g.apply_probe_results(&[None, None]);
        assert_eq!(g.selected_name().as_ref(), "a");
        // 首个恢复
        g.apply_probe_results(&[Some(100), None]);
        assert_eq!(g.selected_name().as_ref(), "a");
        // 首个挂掉
        g.apply_probe_results(&[None, Some(200)]);
        assert_eq!(g.selected_name().as_ref(), "b");
        // 首个恢复 → 回切
        g.apply_probe_results(&[Some(120), Some(180)]);
        assert_eq!(g.selected_name().as_ref(), "a");
    }

    #[tokio::test]
    async fn url_test_tolerance() {
        let m1 = MockOutbound::new("a");
        let m2 = MockOutbound::new("b");
        let g = Group::new(
            GroupSpec {
                name: "UT".into(),
                ty: GroupType::UrlTest,
                members: vec!["a".into(), "b".into()],
                test_url: None,
                interval: 300,
                tolerance: 50,
                lazy: true,
                lb_strategy: LbStrategy::RoundRobin,
            },
            vec![m1, m2],
        );
        g.apply_probe_results(&[Some(100), Some(130)]);
        assert_eq!(g.selected_name().as_ref(), "a");
        // b 只快 10ms < tolerance 50：不切换
        g.apply_probe_results(&[Some(105), Some(95)]);
        assert_eq!(g.selected_name().as_ref(), "a");
        // b 快 100ms > tolerance：切换
        g.apply_probe_results(&[Some(200), Some(90)]);
        assert_eq!(g.selected_name().as_ref(), "b");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn relay_chain() {
        let a = MockOutbound::new("a");
        let b = MockOutbound::new("b");
        let g = Group::new(
            GroupSpec {
                name: "RL".into(),
                ty: GroupType::Relay,
                members: vec!["a".into(), "b".into()],
                test_url: None,
                interval: 300,
                tolerance: 0,
                lazy: true,
                lb_strategy: LbStrategy::RoundRobin,
            },
            vec![a.clone(), b.clone()],
        );
        let _s = g.connect_stream(&sess(), &dst()).await.unwrap();
        assert_eq!(a.connects.load(Ordering::Relaxed), 1);
        assert_eq!(b.overs.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_url_parse() {
        let (h, p, path) = parse_test_url("http://www.gstatic.com/generate_204").unwrap();
        assert_eq!((h.as_str(), p, path.as_str()), ("www.gstatic.com", 80, "/generate_204"));
        let (h, p, path) = parse_test_url("https://example.com:8443/x?a=1").unwrap();
        assert_eq!((h.as_str(), p, path.as_str()), ("example.com", 8443, "/x?a=1"));
    }
}

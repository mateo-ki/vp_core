//! vp-app：应用组装层。配置 → 运行时（出站/组/规则/路由/入站/控制器 API）。

pub mod api;

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use tracing::{info, warn};

use vp_common::{Error, Result, Stats};
use vp_config::{Format};
use vp_core::{ConnTable, InboundCtx, Outbound, Resolution, Router, Session};
use vp_dns::Resolver;
use vp_protocol::{build_inbound, build_outbound, group_spec, InboundKind, OutboundDeps};
use vp_router::{Router as InnerRouter, RouterSpec};
use vp_rule::{geosite::GeoSiteDb, CompileEnv};

/// 热替换路由句柄：入站持有它，重载时替换内部 Router
pub struct RouterHandle {
    inner: RwLock<Arc<InnerRouter>>,
}

impl RouterHandle {
    pub fn new(router: Arc<InnerRouter>) -> Self {
        RouterHandle { inner: RwLock::new(router) }
    }

    pub fn swap(&self, router: Arc<InnerRouter>) {
        *self.inner.write().unwrap() = router;
    }

    pub fn current(&self) -> Arc<InnerRouter> {
        self.inner.read().unwrap().clone()
    }
}

#[async_trait]
impl Router for RouterHandle {
    async fn pick(&self, sess: &Session) -> Resolution {
        self.current().pick(sess).await
    }
}

pub struct App {
    pub router: Arc<RouterHandle>,
    pub stats: Arc<Stats>,
    pub conns: Arc<ConnTable>,
    pub listen_ports: Vec<(String, u16)>,
    pub controller: Option<String>,
    /// 重载用：配置文本与格式
    config_text: RwLock<Option<(String, Format, std::path::PathBuf)>>,
}

impl App {
    /// 从配置文本构建并启动（入站开始监听）
    pub async fn start(
        text: &str,
        fmt: Format,
        base_dir: &Path,
        start_listeners: bool,
    ) -> Result<Arc<App>> {
        let app = Self::assemble(text, fmt, base_dir, start_listeners).await?;
        Ok(app)
    }

    /// 热重载用：仅重建（不启动监听），返回新 App 供 router 替换
    pub async fn assemble_for_reload(
        text: &str,
        fmt: vp_config::Format,
        base_dir: &Path,
    ) -> Result<Arc<App>> {
        Self::assemble(text, fmt, base_dir, false).await
    }

    pub async fn reload(&self) -> Result<()> {
        let (text, fmt, dir) = self
            .config_text
            .read()
            .unwrap()
            .clone()
            .ok_or(Error::Config("无可重载配置".into()))?;
        let new = Self::assemble(&text, fmt, &dir, false).await?;
        self.router.swap(new.router.current());
        info!("配置已热重载");
        Ok(())
    }

    async fn assemble(
        text: &str,
        fmt: Format,
        base_dir: &Path,
        start_listeners: bool,
    ) -> Result<Arc<App>> {
        let cfg: vp_config::Config = vp_config::parse(text, fmt).map_err(|e| Error::Config(format!("{e}")))?;
        if let Err(errs) = vp_config::validate::validate(&cfg) {
            return Err(Error::Config(format!("配置校验失败:\n  - {}", errs.join("\n  - "))));
        }

        let dns = Arc::new(if cfg.dns.enable && !cfg.dns.nameserver.is_empty() {
            Resolver::new(cfg.dns.nameserver.clone())
        } else {
            Resolver::system()
        });
        let deps = OutboundDeps { dns: dns.clone(), ipv6: cfg.ipv6 };

        // 出站表
        let mut outbounds: HashMap<String, Arc<dyn Outbound>> = HashMap::new();
        outbounds.insert(
            "DIRECT".into(),
            Arc::new(vp_protocol::DirectOutbound::new(dns.clone(), cfg.ipv6)) as Arc<dyn Outbound>,
        );
        outbounds.insert("REJECT".into(), Arc::new(vp_protocol::RejectOutbound));
        for p in &cfg.proxies {
            let ob = build_outbound(p, &deps).map_err(|e| Error::Config(format!("节点 {:?}: {e}", p.name)))?;
            outbounds.insert(p.name.clone(), ob);
        }
        let outbound_names: Vec<String> = outbounds.keys().cloned().collect();

        // 规则
        let providers = load_providers(&cfg, base_dir)?;
        let geosite = load_geosite(base_dir);
        let geoip = load_geoip(base_dir);
        let known: Vec<String> = outbound_names.iter().cloned().chain(cfg.proxy_groups.iter().map(|g| g.name.clone())).collect();
        let is_known = |t: &str| known.iter().any(|k| k == t) || vp_config::is_builtin(t);
        let env = CompileEnv {
            is_known_target: &is_known,
            geosite: &geosite,
            geoip: &geoip,
            providers: &providers,
            sub_rules: &cfg.sub_rules,
        };
        let rules = vp_rule::compile(&cfg.rules, &env)
            .map_err(|errs| Error::Config(format!("规则编译失败:\n  - {}", errs.join("\n  - "))))?;

        let router = InnerRouter::build(RouterSpec {
            outbounds,
            groups: cfg.proxy_groups.iter().map(group_spec).collect(),
            rules,
            mode: cfg.mode,
            dns: dns.clone(),
            ipv6: cfg.ipv6,
        })?;

        let router_handle = Arc::new(RouterHandle::new(router));
        let stats = Arc::new(Stats::default());
        let conns = Arc::new(ConnTable::new());

        // 入站
        let mut listen_ports = Vec::new();
        if start_listeners {
            let bind = if cfg.allow_lan {
                if cfg.bind_address == "*" { "0.0.0.0".to_string() } else { cfg.bind_address.clone() }
            } else {
                "127.0.0.1".to_string()
            };
            let make_ctx = || InboundCtx {
                router: router_handle.clone(),
                stats: stats.clone(),
                conns: conns.clone(),
            };
            for (kind, port, tag) in [
                (InboundKind::Mixed, cfg.mixed_port, "mixed"),
                (InboundKind::Http, cfg.port, "http"),
                (InboundKind::Socks5, cfg.socks_port, "socks5"),
            ] {
                if let Some(p) = port {
                    let inb = build_inbound(kind, bind.clone(), p, tag);
                    let bound = inb.clone().start(make_ctx()).await?;
                    info!("{tag} 监听 {bind}:{bound}");
                    listen_ports.push((tag.to_string(), bound));
                }
            }

            // redir/tproxy（仅 Linux；非 Linux 明确报错但不阻断启动）
            for (port, tag) in [(cfg.redir_port, "redir"), (cfg.tproxy_port, "tproxy")] {
                if let Some(p) = port {
                    let inb: Arc<dyn vp_core::Inbound> =
                        Arc::new(vp_protocol::redir::RedirInbound::new(&bind, p, tag));
                    match inb.clone().start(make_ctx()).await {
                        Ok(bound) => {
                            info!("{tag} 监听 {bind}:{bound}");
                            listen_ports.push((tag.to_string(), bound));
                        }
                        Err(e) => {
                            warn!("{tag} 未启用: {e}");
                        }
                    }
                }
            }

            // 协议服务端入站（listeners）
            for l in &cfg.listeners {
                let inb: Arc<dyn vp_core::Inbound> = match build_listener(l) {
                    Ok(i) => i,
                    Err(e) => {
                        warn!("listener {:?} 构建失败: {e}", l.name);
                        continue;
                    }
                };
                match inb.clone().start(make_ctx()).await {
                    Ok(bound) => {
                        info!("listener {} [{}] 监听 {bind}:{bound}", l.name, l.kind);
                        listen_ports.push((l.name.clone(), bound));
                    }
                    Err(e) => warn!("listener {:?} 启动失败: {e}", l.name),
                }
            }

            // TUN 模式
            if let Some(tun_cfg) = &cfg.tun {
                if tun_cfg.enable {
                    let pool = vp_dns::FakeIpPool::new(&tun_cfg.fake_ip_range)
                        .ok_or_else(|| Error::Config(format!("fake-ip 网段非法: {}", tun_cfg.fake_ip_range)))?;
                    let dns_listen: std::net::SocketAddr = "0.0.0.0:53"
                        .parse()
                        .map_err(|e| Error::Config(format!("DNS 监听非法: {e}")))?;
                    let dns_srv = vp_dns::DnsServer::new(
                        dns_listen,
                        dns.clone(),
                        Some(Arc::new(pool.clone())),
                        vec![],
                        cfg.ipv6,
                    );
                    match dns_srv.spawn().await {
                        Ok(bound) => info!("dns 服务器（fake-ip 劫持）监听 {bound}"),
                        Err(e) => warn!("dns 服务器启动失败: {e}"),
                    }
                    let t = vp_tun::TunConfig {
                        address: tun_cfg
                            .address
                            .parse()
                            .map_err(|e| Error::Config(format!("tun 地址非法: {e}")))?,
                        netmask: tun_cfg
                            .netmask
                            .parse()
                            .map_err(|e| Error::Config(format!("tun 掩码非法: {e}")))?,
                        mtu: tun_cfg.mtu,
                        fake_ip_range: tun_cfg.fake_ip_range.clone(),
                        dns_hijack: true,
                    };
                    let tun_in: Arc<dyn vp_core::Inbound> = Arc::new(vp_tun::TunInbound::new(t, "tun"));
                    match tun_in.clone().start(make_ctx()).await {
                        Ok(_) => {
                            info!("TUN 模式已启动（{}）", tun_cfg.address);
                            if tun_cfg.auto_route {
                                match vp_tun::auto_route::enable(&tun_cfg.address, &tun_cfg.netmask) {
                                    Ok(()) => info!("auto-route 已启用"),
                                    Err(e) => warn!("auto-route 启用失败（需管理员权限）: {e}"),
                                }
                            }
                        }
                        Err(e) => {
                            warn!("TUN 启动失败（需要管理员权限）: {e}");
                        }
                    }
                }
            }
        }

        // 控制器
        let controller = cfg.external_controller.clone();
        if let Some(addr) = &controller {
            if start_listeners {
                let app_ref = api::ApiState {
                    router: router_handle.clone(),
                    stats: stats.clone(),
                    conns: conns.clone(),
                    secret: cfg.secret.clone().filter(|s| !s.is_empty()),
                    config_text: RwLock::new(Some((text.to_string(), fmt, base_dir.to_path_buf()))),
                };
                let listener = tokio::net::TcpListener::bind(&addr).await?;
                api::spawn_on(listener, Arc::new(app_ref));
                info!("外部控制器 http://{addr}");
            }
        }

        let app = App {
            router: router_handle,
            stats,
            conns,
            listen_ports,
            controller,
            config_text: RwLock::new(Some((text.to_string(), fmt, base_dir.to_path_buf()))),
        };
        Ok(Arc::new(app))
    }

    /// 全组测速（CLI test 用）
    pub async fn url_test_all_groups(&self) {
        for (name, g) in self.router.current().groups() {
            println!("组 {name} [{}]:", g.ty().as_str());
            g.url_test_all().await;
            for (member, delay, alive) in g.member_states() {
                match delay {
                    Some(ms) if alive => println!("  {member:<24} {ms:>5} ms"),
                    _ => println!("  {member:<24} 失败"),
                }
            }
        }
    }
}

/// 构建 listeners 段的服务端入站（trojan/vmess/vless/ss）
fn build_listener(l: &vp_config::ListenerCfg) -> Result<Arc<dyn vp_core::Inbound>> {
    let tag = l.name.as_str();
    match l.kind.as_str() {
        "trojan" => {
            if l.users.is_empty() {
                return Err(Error::Config("trojan listener 需要 users（密码）".into()));
            }
            Ok(Arc::new(vp_protocol::trojan::TrojanInbound::new(
                "0.0.0.0", l.port, tag, &l.users,
            )?))
        }
        "vmess" => {
            if l.users.is_empty() {
                return Err(Error::Config("vmess listener 需要 users（uuid）".into()));
            }
            Ok(Arc::new(vp_protocol::vmess::VmessInbound::new(
                "0.0.0.0", l.port, tag, &l.users,
            )?))
        }
        "vless" => {
            if l.users.is_empty() {
                return Err(Error::Config("vless listener 需要 users（uuid）".into()));
            }
            Ok(Arc::new(vp_protocol::vless::VlessInbound::new(
                "0.0.0.0", l.port, tag, &l.users,
            )?))
        }
        "anytls" => {
            if l.users.is_empty() {
                return Err(Error::Config("anytls listener 需要 users（密码）".into()));
            }
            Ok(Arc::new(vp_protocol::anytls::AnytlsInbound::new(
                "0.0.0.0", l.port, tag, &l.users,
            )?))
        }
        "ss" => {
            let password = l.users.first().ok_or_else(|| {
                Error::Config("ss listener 需要 users[0]（密码）".into())
            })?;
            let cipher = l.cipher.as_deref().unwrap_or("aes-128-gcm");
            let stls = match &l.shadow_tls {
                Some(o) => {
                    let host = o.host.clone().ok_or_else(|| {
                        Error::Config("shadow-tls 入站缺少 host（伪装站）".into())
                    })?;
                    let pw = o.password.clone().ok_or_else(|| {
                        Error::Config("shadow-tls 入站缺少 password".into())
                    })?;
                    Some(vp_protocol::shadowtls::ShadowTlsDial {
                        host,
                        port: o.port.unwrap_or(443),
                        password: pw,
                    })
                }
                None => None,
            };
            Ok(Arc::new(vp_protocol::ss::SsInbound::new_with_shadow_tls(
                "0.0.0.0", l.port, tag, cipher, password, stls,
            )?))
        }
        other => Err(Error::Unsupported(format!("listener 类型 {other:?}（M1 支持 trojan/vmess/vless/ss）"))),
    }
}

fn load_providers(cfg: &vp_config::Config, base_dir: &Path) -> Result<HashMap<String, (vp_rule::provider::Behavior, String)>> {
    let mut out = HashMap::new();
    for (name, p) in &cfg.rule_providers {
        let behavior = p
            .behavior
            .as_deref()
            .ok_or_else(|| Error::Config(format!("rule-provider {name:?} 缺少 behavior")))?;
        let behavior = vp_rule::provider::Behavior::parse(behavior)
            .map_err(|e| Error::Config(format!("rule-provider {name:?}: {e}")))?;
        let path = p
            .path
            .as_ref()
            .map(|p| base_dir.join(p))
            .ok_or_else(|| Error::Config(format!("rule-provider {name:?} 缺少 path")))?;
        let text = std::fs::read_to_string(&path)
            .map_err(|e| Error::Config(format!("rule-provider {name:?} 读取失败: {e}")))?;
        out.insert(name.clone(), (behavior, text));
    }
    Ok(out)
}

fn load_geosite(base_dir: &Path) -> Option<GeoSiteDb> {
    for name in ["geosite.dat", "GeoSite.dat"] {
        let p = base_dir.join(name);
        if p.exists() {
            match std::fs::read(&p) {
                Ok(bytes) => match GeoSiteDb::load(&bytes) {
                    Ok(db) => {
                        info!("geosite 已加载: {}", p.display());
                        return Some(db);
                    }
                    Err(e) => warn!("geosite 解析失败: {e}"),
                },
                Err(e) => warn!("geosite 读取失败: {e}"),
            }
        }
    }
    None
}

fn load_geoip(base_dir: &Path) -> Option<vp_rule::geoip::GeoIpDb> {
    for name in ["geoip.metadb", "Country.mmdb", "geoip.mmdb"] {
        let p = base_dir.join(name);
        if p.exists() {
            return match vp_rule::geoip::GeoIpDb::load(&p) {
                Ok(db) => {
                    info!("geoip 已加载: {}", p.display());
                    Some(db)
                }
                Err(e) => {
                    warn!("geoip 解析失败: {e}");
                    None
                }
            };
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = r#"
mixed-port: 17890
mode: rule
log-level: info
proxies:
  - name: "本地回环"
    type: socks5
    server: 127.0.0.1
    port: 10800
proxy-groups:
  - name: PROXY
    type: select
    proxies: ["本地回环", DIRECT]
rules:
  - DOMAIN-SUFFIX,internal.test,DIRECT
  - IP-CIDR,127.0.0.0/8,DIRECT
  - MATCH,PROXY
"#;

    #[tokio::test]
    async fn app_assemble_and_serve() {
        let dir = std::env::temp_dir();
        let app = App::start(CFG, Format::Yaml, &dir, true).await.unwrap();
        assert_eq!(app.listen_ports.len(), 1);
        assert_eq!(app.listen_ports[0].1, 17890);

        // 经 mixed 端口做一次 socks5 CONNECT（目标 127.0.0.1 的临时 echo）
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut s, _) = echo.accept().await.unwrap();
            let mut b = [0u8; 64];
            let n = s.read(&mut b).await.unwrap();
            s.write_all(&b[..n]).await.unwrap();
        });
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", 17890)).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut b = [0u8; 2];
        c.read_exact(&mut b).await.unwrap();
        let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        req.extend_from_slice(&echo_port.to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut resp = [0u8; 10];
        c.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[1], 0x00);
        c.write_all(b"app-ok").await.unwrap();
        let mut got = [0u8; 6];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"app-ok");
    }

    /// vless/ss listener 数据面 e2e（复用 vmess 最小复现模式）
    #[tokio::test]
    async fn vless_ss_listener_e2e() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        async fn one_echo() -> u16 {
            let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let p = echo.local_addr().unwrap().port();
            tokio::spawn(async move {
                let (mut s, _) = echo.accept().await.unwrap();
                let mut b = [0u8; 256];
                loop {
                    let n = s.read(&mut b).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    s.write_all(&b[..n]).await.unwrap();
                }
            });
            p
        }
        let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
        // vless
        let echo_port = one_echo().await;
        let cfg = format!(
            "listeners:\n  - name: srv-vl\n    type: vless\n    port: 0\n    users: [\"{uuid}\"]\nrules: ['MATCH,DIRECT']\n"
        );
        let app = App::start(&cfg, vp_config::Format::Yaml, &std::env::temp_dir(), true)
            .await
            .unwrap();
        let vl_port = app
            .listen_ports
            .iter()
            .find(|(t, _)| t == "srv-vl")
            .map(|(_, p)| *p)
            .expect("vless listener 应已监听");
        let out = vp_protocol::vless::VlessOutbound::new(&vp_config::VlessCfg {
            server: "127.0.0.1".into(),
            port: vl_port,
            uuid: uuid.into(),
            flow: None,
            tls: false,
            server_name: None,
            skip_cert_verify: false,
            client_fingerprint: None,
            network: None,
            ws_opts: None,
            grpc_opts: None,
            udp: false,
        })
        .unwrap();
        let dst = vp_common::DstAddr::ip("127.0.0.1".parse().unwrap(), echo_port);
        let sess = vp_core::Session::new_tcp("t".into(), None, dst.clone());
        let mut s = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            out.connect_stream(&sess, &dst),
        )
        .await
        .expect("vless 出站应完成")
        .expect("vless 出站应成功");
        s.write_all(b"vl-e2e").await.unwrap();
        let mut buf = [0u8; 6];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"vl-e2e");

        // ss
        let echo_port = one_echo().await;
        let cfg = "listeners:\n  - name: srv-ss\n    type: ss\n    port: 0\n    users: [\"pw\"]\n    cipher: aes-128-gcm\nrules: ['MATCH,DIRECT']\n";
        let app = App::start(cfg, vp_config::Format::Yaml, &std::env::temp_dir(), true)
            .await
            .unwrap();
        let ss_port = app
            .listen_ports
            .iter()
            .find(|(t, _)| t == "srv-ss")
            .map(|(_, p)| *p)
            .expect("ss listener 应已监听");
        let out = vp_protocol::ss::SsOutbound::new(&vp_config::SsCfg {
            server: "127.0.0.1".into(),
            port: ss_port,
            cipher: "aes-128-gcm".into(),
            password: "pw".into(),
            udp: false,
            plugin: None,
            plugin_opts: None,
        })
        .unwrap();
        let dst = vp_common::DstAddr::ip("127.0.0.1".parse().unwrap(), echo_port);
        let sess = vp_core::Session::new_tcp("t".into(), None, dst.clone());
        let mut s = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            out.connect_stream(&sess, &dst),
        )
        .await
        .expect("ss 出站应完成")
        .expect("ss 出站应成功");
        s.write_all(b"ss-e2e").await.unwrap();
        let mut buf = [0u8; 6];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ss-e2e");
    }

    /// vmess listener 数据面最小复现（修上轮挂起缺陷）
    #[tokio::test]
    async fn vmess_listener_e2e() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut b = [0u8; 256];
            loop {
                let n = s.read(&mut b).await.unwrap();
                if n == 0 {
                    break;
                }
                s.write_all(&b[..n]).await.unwrap();
            }
        });
        let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let cfg = format!(
            "listeners:\n  - name: srv-vm\n    type: vmess\n    port: 0\n    users: [\"{uuid}\"]\nrules: ['MATCH,DIRECT']\n"
        );
        let app = App::start(&cfg, vp_config::Format::Yaml, &std::env::temp_dir(), true)
            .await
            .unwrap();
        let vm_port = app
            .listen_ports
            .iter()
            .find(|(t, _)| t == "srv-vm")
            .map(|(_, p)| *p)
            .expect("vmess listener 应已监听");

        let out = vp_protocol::vmess::VmessOutbound::new(&vp_config::VmessCfg {
            server: "127.0.0.1".into(),
            port: vm_port,
            uuid: uuid.into(),
            alter_id: 0,
            cipher: "auto".into(),
            tls: false,
            server_name: None,
            skip_cert_verify: false,
            client_fingerprint: None,
            network: None,
            ws_opts: None,
            grpc_opts: None,
            udp: false,
        })
        .unwrap();
        let dst = vp_common::DstAddr::ip("127.0.0.1".parse().unwrap(), echo_port);
        let sess = vp_core::Session::new_tcp("t".into(), None, dst.clone());
        let mut s = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            out.connect_stream(&sess, &dst),
        )
        .await
        .expect("vmess 出站应完成")
        .expect("vmess 出站应成功");
        s.write_all(b"vm-e2e").await.unwrap();
        let mut buf = [0u8; 6];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"vm-e2e");
    }

    /// listeners 段端到端：trojan 服务端入站 ← TrojanOutbound ← echo
    #[tokio::test]
    async fn trojan_listener_e2e() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // echo
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut b = [0u8; 256];
            loop {
                let n = s.read(&mut b).await.unwrap();
                if n == 0 {
                    break;
                }
                s.write_all(&b[..n]).await.unwrap();
            }
        });
        let cfg = format!(
            "mixed-port: 17895
listeners:
  - name: srv-tj
    type: trojan
    port: 0
    users: [pw-e2e]
rules: ['MATCH,DIRECT']
"
        );
        let app = App::start(&cfg, vp_config::Format::Yaml, &std::env::temp_dir(), true)
            .await
            .unwrap();
        // listeners[0] 实际端口
        let tj_port = app
            .listen_ports
            .iter()
            .find(|(t, _)| t == "srv-tj")
            .map(|(_, p)| *p)
            .expect("trojan listener 应已监听");

        let out = vp_protocol::trojan::TrojanOutbound::new(&vp_config::TrojanCfg {
            server: "127.0.0.1".into(),
            port: tj_port,
            password: "pw-e2e".into(),
            tls: false,
            server_name: None,
            skip_cert_verify: false,
            client_fingerprint: None,
            network: None,
            ws_opts: None,
            grpc_opts: None,
            udp: false,
        })
        .unwrap();
        let dst = vp_common::DstAddr::ip("127.0.0.1".parse().unwrap(), echo_port);
        let sess = vp_core::Session::new_tcp("t".into(), None, dst.clone());
        let mut s = out
            .connect_stream(&sess, &dst)
            .await
            .expect("trojan 出站应成功");
        s.write_all(b"listener-e2e").await.unwrap();
        let mut buf = [0u8; 12];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"listener-e2e");
    }

    /// 全栈：App ss listener + shadow-tls v3 伪装 ← SsOutbound(plugin: shadow-tls) ← echo
    #[tokio::test]
    async fn ss_shadowtls_listener_e2e() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // echo 源站
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut b = [0u8; 256];
            loop {
                let n = s.read(&mut b).await.unwrap();
                if n == 0 {
                    break;
                }
                s.write_all(&b[..n]).await.unwrap();
            }
        });

        // 伪装站 stub：读 ClientHello → 回 TLS1.3 ServerHello + 1 帧伪 appdata
        let cam = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cam_port = cam.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = cam.accept().await.unwrap();
            let mut hdr = [0u8; 5];
            s.read_exact(&mut hdr).await.unwrap();
            let mut ch = vec![0u8; u16::from_be_bytes([hdr[3], hdr[4]]) as usize];
            s.read_exact(&mut ch).await.unwrap();
            // ServerHello（supported_versions=0304）
            let mut body = vec![0x02, 0x03, 0x03];
            body.extend_from_slice(&[0x11u8; 32]); // random
            body.push(32);
            body.extend_from_slice(&[0x42u8; 32]); // sid echo
            body.extend_from_slice(&[0x13, 0x01, 0x01, 0x00]);
            body.extend_from_slice(&6u16.to_be_bytes()); // exts len
            body.extend_from_slice(&43u16.to_be_bytes());
            body.extend_from_slice(&2u16.to_be_bytes());
            body.extend_from_slice(&[0x03, 0x04]);
            let mut msg = vec![0x02, 0x00, 0x00, 0x00];
            msg[1..4].copy_from_slice(&(((body.len() - 1) as u32) << 8).to_be_bytes()[1..]);
            msg.extend_from_slice(&body[1..]);
            let mut rec = vec![0x16, 0x03, 0x03];
            rec.extend_from_slice(&(msg.len() as u16).to_be_bytes());
            rec.extend_from_slice(&msg);
            s.write_all(&rec).await.unwrap();
            // 一帧伪 appdata（供客户端授权判定）
            s.write_all(&[0x17, 0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4])
                .await
                .unwrap();
            let mut b = [0u8; 64];
            let _ = s.read(&mut b).await;
        });

        let cfg = format!(
            "mixed-port: 17898
listeners:
  - name: srv-stls
    type: ss
    port: 0
    users: [ss-pass]
    cipher: aes-128-gcm
    shadow-tls:
      host: 127.0.0.1
      port: {cam_port}
      password: stls-pass
rules: ['MATCH,DIRECT']
"
        );
        let app = App::start(&cfg, vp_config::Format::Yaml, &std::env::temp_dir(), true)
            .await
            .unwrap();
        let ss_port = app
            .listen_ports
            .iter()
            .find(|(t, _)| t == "srv-stls")
            .map(|(_, p)| *p)
            .expect("ss+shadowtls listener 应已监听");

        let out = vp_protocol::ss::SsOutbound::new(&vp_config::SsCfg {
            server: "127.0.0.1".into(),
            port: ss_port,
            cipher: "aes-128-gcm".into(),
            password: "ss-pass".into(),
            udp: false,
            plugin: Some("shadow-tls".into()),
            plugin_opts: Some(vp_config::ShadowTlsCfg {
                host: Some("127.0.0.1".into()),
                password: Some("stls-pass".into()),
                port: Some(cam_port),
                version: Some(3),
            }),
        })
        .unwrap();
        let dst = vp_common::DstAddr::ip("127.0.0.1".parse().unwrap(), echo_port);
        let sess = vp_core::Session::new_tcp("t".into(), None, dst.clone());
        let mut s = out
            .connect_stream(&sess, &dst)
            .await
            .expect("ss over shadow-tls 应成功");
        s.write_all(b"stls-e2e").await.unwrap();
        let mut buf = [0u8; 8];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"stls-e2e");
    }

    #[tokio::test]
    async fn invalid_config_rejected() {
        let bad = "proxies:\n  - name: x\n    type: ss\n    server: 1.1.1.1\n    port: 1\n    cipher: aes-128-gcm\n    password: p\nproxy-groups:\n  - name: G\n    type: select\n    proxies: [不存在]\nrules: ['MATCH,G']\n";
        match App::start(bad, Format::Yaml, Path::new("."), false).await {
            Err(err) => assert!(err.to_string().contains("不存在"), "{err}"),
            Ok(_) => panic!("应当报错"),
        }
    }
    #[tokio::test]
    async fn uot_ss_e2e() {
        // UDP echo 源站
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            loop {
                if let Ok((n, from)) = echo.recv_from(&mut b).await {
                    let _ = echo.send_to(&b[..n], from).await;
                }
            }
        });

        // 先占位取两个空闲端口（避免固定端口撞车）
        async fn free_port() -> u16 {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        }
        let mixed_port = free_port().await;
        let ss_port = free_port().await;

        // ss listener（服务端）+ ss 出站（udp-over-tcp 包装），mixed 入站走 socks5 UDP 关联
        let cfg = format!(
            "mixed-port: {mixed_port}
proxies:
  - name: ss-uot
    type: ss
    server: 127.0.0.1
    port: {ss_port}
    cipher: aes-128-gcm
    password: pw
    udp: true
    udp-over-tcp: true
listeners:
  - name: uot-srv
    type: ss
    port: {ss_port}
    users: [pw]
    cipher: aes-128-gcm
rules: ['MATCH,ss-uot']
"
        );
        let _app = App::start(&cfg, vp_config::Format::Yaml, &std::env::temp_dir(), true)
            .await
            .unwrap();

        // socks5 握手 + UDP ASSOCIATE
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", mixed_port))
            .await
            .unwrap();
        tcp.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut buf = [0u8; 2];
        tcp.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [0x05, 0x00]);
        tcp.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        // 应答：[3 头][ATYP][4B 地址][2B 端口] = 10 字节
        let mut rep = [0u8; 10];
        tcp.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0x00, "ASSOCIATE 应成功");
        let relay_port = u16::from_be_bytes([rep[8], rep[9]]);
        assert_ne!(relay_port, 0);
        let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        relay.connect(("127.0.0.1", relay_port)).await.unwrap();

        // socks5 UDP 帧：[rsv2][frag][ATYP 1][127.0.0.1][port][payload]
        let mut dgram = vec![0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1];
        dgram.extend_from_slice(&echo_port.to_be_bytes());
        dgram.extend_from_slice(b"uot-e2e");
        relay.send(&dgram).await.unwrap();
        let mut rbuf = vec![0u8; 512];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), relay.recv(&mut rbuf))
            .await
            .expect("UoT 回包超时")
            .unwrap();
        // 回包：[rsv2][frag][ATYP 1][127.0.0.1][echo_port][payload]
        assert_eq!(rbuf[3], 0x01, "回包 ATYP 应为 IPv4");
        assert_eq!(&rbuf[4..8], &[127, 0, 0, 1]);
        assert_eq!(
            u16::from_be_bytes([rbuf[8], rbuf[9]]),
            echo_port,
            "源端口应为 echo 端口"
        );
        assert_eq!(&rbuf[10..n], b"uot-e2e");
    }
}

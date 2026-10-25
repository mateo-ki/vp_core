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

    #[tokio::test]
    async fn invalid_config_rejected() {
        let bad = "proxies:\n  - name: x\n    type: ss\n    server: 1.1.1.1\n    port: 1\n    cipher: aes-128-gcm\n    password: p\nproxy-groups:\n  - name: G\n    type: select\n    proxies: [不存在]\nrules: ['MATCH,G']\n";
        match App::start(bad, Format::Yaml, Path::new("."), false).await {
            Err(err) => assert!(err.to_string().contains("不存在"), "{err}"),
            Ok(_) => panic!("应当报错"),
        }
    }
}

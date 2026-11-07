//! vp-app：应用组装层。配置 → 运行时（出站/组/规则/路由/入站/控制器 API）。

pub mod api;
pub mod consts;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
#[allow(unused_imports)]
use tracing::{debug, info, warn};

use vp_common::{Error, Result, Stats};
use vp_config::Format;
use vp_core::{ConnTable, InboundCtx, Outbound, Resolution, Router, Session};
use vp_dns::Resolver;
use vp_protocol::{InboundKind, OutboundDeps, build_inbound_with_gate, build_outbound};
use vp_router::{Router as InnerRouter, RouterSpec, group_spec};
use vp_rule::{CompileEnv, geosite::GeoSiteDb};

/// 热替换路由句柄：入站持有它，重载时替换内部 Router
pub struct RouterHandle {
    inner: RwLock<Arc<InnerRouter>>,
}

impl RouterHandle {
    pub fn new(router: Arc<InnerRouter>) -> Self {
        RouterHandle {
            inner: RwLock::new(router),
        }
    }

    pub fn swap(&self, router: Arc<InnerRouter>) {
        let old = {
            let mut guard = self.inner.write().unwrap();
            std::mem::replace(&mut *guard, router)
        };
        // 旧 Router 的健康检查等后台任务随即终止，防止热更新后任务滞留
        old.abort_background_tasks();
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

    async fn explain(&self, sess: &Session) -> vp_core::RouteTrace {
        self.current().explain(sess).await
    }

    fn needs_process(&self) -> bool {
        self.current().needs_process()
    }

    fn fallback_proxy_outbound(&self) -> Option<Arc<dyn vp_core::Outbound>> {
        self.current().fallback_proxy_outbound()
    }
}

#[derive(Debug, Clone)]
pub struct ConfigMeta {
    pub path: Option<std::path::PathBuf>,
    pub text: String,
    pub fmt: Format,
    pub base_dir: std::path::PathBuf,
}

/// TUN 运行时：热重载可动态增删的 TUN 三件套。
/// 数据面任务 + fake-ip DNS 服务器任务 + auto-route 路由守卫。
pub struct TunRuntime {
    pub data_plane: tokio::task::JoinHandle<()>,
    pub dns_server: Option<tokio::task::JoinHandle<()>>,
    pub route_guard: Option<vp_tun::auto_route::AutoRouteGuard>,
}

impl TunRuntime {
    /// 热停用 TUN：先 drop 路由守卫（Drop 内自动恢复路由表），再停 DNS 劫持与数据面。
    pub fn shutdown(mut self) {
        #[cfg(windows)]
        vp_transport::set_bind_interface_index(0);
        let _ = self.route_guard.take();
        if let Some(h) = self.dns_server.take() {
            h.abort();
        }
        self.data_plane.abort();
    }
}

impl Drop for TunRuntime {
    fn drop(&mut self) {
        #[cfg(windows)]
        vp_transport::set_bind_interface_index(0);
    }
}

/// 热重载后的 TUN 差量同步：新配置 `tun.enable` 与运行时不一致时，动态启停 TUN 入站。
/// 开关一致则为空操作（mtu 等参数变化仍需走重启路径，这里只处理免重启的开关切换）。
/// 失败时保持原状（旧配置、旧 TUN 状态原样保留），由调用方向控制端回报错误。
pub async fn sync_tun_state(
    tun_runtime: &Arc<RwLock<Option<TunRuntime>>>,
    router: &Arc<RouterHandle>,
    stats: &Arc<Stats>,
    conns: &Arc<ConnTable>,
    dns: &Arc<Resolver>,
    new_cfg: &vp_config::Config,
) -> Result<()> {
    let want_on = new_cfg.tun.as_ref().map(|t| t.enable).unwrap_or(false);
    let is_on = tun_runtime.read().unwrap().is_some();
    if want_on == is_on {
        return Ok(());
    }
    if want_on {
        let ctx = InboundCtx {
            router: router.clone(),
            stats: stats.clone(),
            conns: conns.clone(),
        };
        let rt = start_tun_runtime(new_cfg, dns.clone(), ctx).await?;
        info!("TUN 模式已热开启（无重启）");
        *tun_runtime.write().unwrap() = Some(rt);
    } else if let Some(rt) = tun_runtime.write().unwrap().take() {
        info!("TUN 模式已热关闭（无重启），路由表已恢复");
        rt.shutdown();
    }
    Ok(())
}

fn parse_dns_listen(s: &str, default_bind: &str) -> Result<std::net::SocketAddr> {
    let s = s.trim();
    if let Ok(addr) = s.parse::<std::net::SocketAddr>() {
        return Ok(addr);
    }
    let default_ip = if default_bind == "*" || default_bind.is_empty() {
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        default_bind
            .parse::<std::net::IpAddr>()
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
    };

    if let Some(port_str) = s.strip_prefix(':') {
        let port: u16 = port_str
            .parse()
            .map_err(|e| Error::Config(format!("dns.listen 端口非法 {s}: {e}")))?;
        return Ok(std::net::SocketAddr::new(default_ip, port));
    }
    if let Ok(port) = s.parse::<u16>() {
        return Ok(std::net::SocketAddr::new(default_ip, port));
    }
    Err(Error::Config(format!("dns.listen 地址格式非法: {s}")))
}

/// 启动 TUN 三件套（fake-ip DNS 服务器、TUN 数据面、auto-route 路由守卫）。
/// 启动与热重载共用：设备创建失败返回 Err；DNS 监听 / auto-route 失败仅告警
/// （与既有启动语义一致：TUN 建不起来不该拦住整个内核）。
async fn start_tun_runtime(
    cfg: &vp_config::Config,
    dns: Arc<Resolver>,
    ctx: InboundCtx,
) -> Result<TunRuntime> {
    let tun_cfg = cfg
        .tun
        .as_ref()
        .ok_or_else(|| Error::Config("配置缺少 tun 段".into()))?;
    if !tun_cfg.enable {
        return Err(Error::Config("tun.enable = false".into()));
    }
    let pool_arc =
        match dns
            .fake_ip()
            .cloned()
            .or_else(vp_dns::get_global_fake_ip_pool)
        {
            Some(p) => p,
            None => {
                let p = Arc::new(vp_dns::FakeIpPool::new(&tun_cfg.fake_ip_range).ok_or_else(
                    || Error::Config(format!("fake-ip 网段非法: {}", tun_cfg.fake_ip_range)),
                )?);
                vp_dns::set_global_fake_ip_pool(Some(p.clone()));
                p
            }
        };
    let dns_handle = if cfg.dns.listen.is_none() {
        let dns_listen: std::net::SocketAddr = "0.0.0.0:53".parse().unwrap();
        let dns_srv = vp_dns::DnsServer::new(
            dns_listen,
            dns.clone(),
            Some(pool_arc.clone()),
            cfg.dns.fake_ip_filter.clone(),
            cfg.dns.is_ipv6(cfg.ipv6),
        );
        match dns_srv.spawn_handle().await {
            Ok((bound, handle)) => {
                info!("dns 服务器（fake-ip 劫持）监听 {bound}");
                Some(handle)
            }
            Err(e) => {
                tracing::info!(
                    "宿主机 53 端口外部监听未占用 (TUN 模式下由虚拟网卡 IP 协议栈无损劫持接管 53 端口流量): {e}"
                );
                None
            }
        }
    } else {
        None
    };
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
        fd: tun_cfg.fd,
        ring_capacity: tun_cfg.ring_capacity,
    };
    let tun_in = Arc::new(vp_tun::TunInbound::new(t, "tun").with_dns(
        pool_arc,
        dns,
        cfg.dns.fake_ip_filter.clone(),
        cfg.dns.is_ipv6(cfg.ipv6),
    ));
    if tun_cfg.auto_route {
        #[cfg(windows)]
        if let Some(if_idx) = vp_transport::detect_default_physical_interface() {
            vp_transport::set_bind_interface_index(if_idx);
        }
        #[cfg(not(windows))]
        if cfg.interface_name.is_none() {
            if let Some(if_name) = vp_transport::detect_default_physical_interface_name() {
                vp_transport::set_bind_interface_name(Some(if_name));
            }
        }
    }

    let data_plane = tun_in
        .clone()
        .start_with_handle(ctx)
        .await
        .map_err(|e| Error::Other(format!("TUN 启动失败（需要管理员权限）: {e}")))?;
    info!("TUN 模式已启动（{}）", tun_cfg.address);
    let mut route_guard = None;
    if tun_cfg.auto_route {
        let route_opts = vp_tun::auto_route::AutoRouteOptions {
            mode: tun_cfg.auto_route_mode.clone(),
            route_address: tun_cfg.route_address.clone(),
            route_exclude_address: tun_cfg.route_exclude_address.clone(),
        };
        match vp_tun::auto_route::enable_with_options(
            &tun_cfg.address,
            &tun_cfg.netmask,
            &route_opts,
        ) {
            Ok(guard) => {
                info!("auto-route 已启用 (mode: {:?})", tun_cfg.auto_route_mode);
                route_guard = Some(guard);
            }
            Err(e) => {
                let err_msg = format!("auto-route 启用失败（需管理员权限）: {e}");
                tracing::error!("{err_msg}");
                if tun_cfg.strict.unwrap_or(false) {
                    return Err(Error::Other(err_msg));
                }
            }
        }
    }
    Ok(TunRuntime {
        data_plane,
        dns_server: dns_handle,
        route_guard,
    })
}

/// TUN 运行时健康状态（供宿主、GUI 与 GET /configs 实时获知真实运行状态）
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct TunStatus {
    pub enabled: bool,
    pub running: bool,
    pub device: Option<String>,
    pub dns_hijack: bool,
    pub auto_route: bool,
    pub error: Option<String>,
}

/// 独立 DNS 服务端运行时健康状态
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct DnsStatus {
    pub enabled: bool,
    pub running: bool,
    pub listen: Option<String>,
    pub error: Option<String>,
}

pub struct App {
    pub router: Arc<RouterHandle>,
    pub stats: Arc<Stats>,
    pub conns: Arc<ConnTable>,
    pub listen_ports: Vec<(String, u16)>,
    pub controller: Option<String>,
    /// 重载用：配置元数据
    pub config_meta: Arc<RwLock<Option<ConfigMeta>>>,
    /// TUN 运行时：Some = TUN 已启用。热重载按配置差量动态增删（免重启热切换）。
    pub tun_runtime: Arc<RwLock<Option<TunRuntime>>>,
    /// TUN 运行健康状态
    pub tun_status: Arc<RwLock<TunStatus>>,
    /// 独立 DNS 运行健康状态
    pub dns_status: Arc<RwLock<DnsStatus>>,
    /// 全局 DNS 解析器：热开启 TUN 时复用它建 fake-ip 劫持服务器
    pub dns: Arc<Resolver>,
    /// 多用户管理器（控制面动态管理 + 认证配额限速）
    pub user_manager: Arc<vp_core::UserManager>,
    /// 内核级 UDP 端口重定向守卫（RAII 自动管理 iptables/ip6tables 规则）
    pub port_redirect_guards: Arc<RwLock<Vec<vp_tun::port_redirect::IptablesPortRedirectGuard>>>,
    /// Fake-IP 持久化守护者（异步防抖落盘与优雅关机）
    pub fakeip_persister: Option<Arc<vp_dns::FakeIpPersister>>,
}

impl App {
    /// 是否存在已在内核中激活生效的 iptables 端口重定向守卫
    pub fn has_port_redirects(&self) -> bool {
        let guards = self
            .port_redirect_guards
            .read()
            .unwrap_or_else(|e| e.into_inner());
        guards.iter().any(|g| g.is_active())
    }
    /// 从配置文本构建并启动（入站开始监听）
    pub async fn start(
        text: &str,
        fmt: Format,
        base_dir: &Path,
        start_listeners: bool,
    ) -> Result<Arc<App>> {
        Self::start_with_tun_fd(text, fmt, base_dir, start_listeners, None).await
    }

    /// 从配置文本与可选 TUN 文件描述符构建并启动（移动端 FFI 用）
    pub async fn start_with_tun_fd(
        text: &str,
        fmt: Format,
        base_dir: &Path,
        start_listeners: bool,
        tun_fd: Option<i32>,
    ) -> Result<Arc<App>> {
        let app = Self::assemble(
            text.to_string(),
            fmt,
            base_dir.to_path_buf(),
            start_listeners,
            None,
            tun_fd,
        )
        .await?;
        if start_listeners {
            app.start_background_tasks();
        }
        Ok(app)
    }

    /// 从配置文件路径构建并启动
    pub async fn start_from_file(config_path: &Path, start_listeners: bool) -> Result<Arc<App>> {
        Self::start_from_file_with_dir(config_path, None, start_listeners).await
    }

    /// 从配置文件路径与指定工作目录构建并启动
    pub async fn start_from_file_with_dir(
        config_path: &Path,
        work_dir: Option<&Path>,
        start_listeners: bool,
    ) -> Result<Arc<App>> {
        let text = tokio::fs::read_to_string(config_path)
            .await
            .map_err(|e| Error::Config(format!("读取 {} 失败: {e}", config_path.display())))?;
        let fmt = Format::from_path(&config_path.to_string_lossy());
        let base_dir = work_dir
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| config_path.parent().unwrap_or(Path::new(".")).to_path_buf());
        let app = Self::assemble(
            text,
            fmt,
            base_dir,
            start_listeners,
            Some(config_path.to_path_buf()),
            None,
        )
        .await?;
        if start_listeners {
            app.start_background_tasks();
        }
        Ok(app)
    }

    /// 热重载用：仅重建（不启动监听），返回新 App 供 router 替换
    pub async fn assemble_for_reload(
        text: &str,
        fmt: vp_config::Format,
        base_dir: &Path,
    ) -> Result<Arc<App>> {
        Self::assemble(
            text.to_string(),
            fmt,
            base_dir.to_path_buf(),
            false,
            None,
            None,
        )
        .await
    }

    pub async fn reload(&self) -> Result<()> {
        let meta = self
            .config_meta
            .read()
            .unwrap()
            .clone()
            .ok_or(Error::Config("无可重载配置".into()))?;

        // 若保留了文件路径，优先从磁盘重新读取最新文本
        let (new_text, new_fmt, new_dir) = if let Some(ref path) = meta.path {
            let t = tokio::fs::read_to_string(path)
                .await
                .map_err(|e| Error::Config(format!("读取 {} 失败: {e}", path.display())))?;
            let fmt = Format::from_path(&path.to_string_lossy());
            let dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
            (t, fmt, dir)
        } else {
            (meta.text, meta.fmt, meta.base_dir)
        };

        let new_app = Self::assemble(
            new_text.clone(),
            new_fmt,
            new_dir.clone(),
            false,
            meta.path.clone(),
            None,
        )
        .await?;

        // TUN 开关差量同步（先于路由替换：失败则整体放弃重载，旧状态原样保留）
        let new_cfg = parse_config_for_fmt(&new_text, new_fmt)?;
        sync_tun_state(
            &self.tun_runtime,
            &self.router,
            &self.stats,
            &self.conns,
            &self.dns,
            &new_cfg,
        )
        .await?;

        self.router.swap(new_app.router.current());

        *self.config_meta.write().unwrap() = Some(ConfigMeta {
            path: meta.path,
            text: new_text,
            fmt: new_fmt,
            base_dir: new_dir,
        });

        info!("配置已平滑热重载");
        Ok(())
    }

    pub async fn reload_with_text(&self, new_text: &str) -> Result<()> {
        let meta = self
            .config_meta
            .read()
            .unwrap()
            .clone()
            .ok_or(Error::Config("无可重载配置".into()))?;

        let new_app = Self::assemble(
            new_text.to_string(),
            meta.fmt,
            meta.base_dir.clone(),
            false,
            meta.path.clone(),
            None,
        )
        .await?;

        // TUN 开关差量同步（先于路由替换：失败则整体放弃重载，旧状态原样保留）
        let new_cfg = parse_config_for_fmt(new_text, meta.fmt)?;
        sync_tun_state(
            &self.tun_runtime,
            &self.router,
            &self.stats,
            &self.conns,
            &self.dns,
            &new_cfg,
        )
        .await?;

        self.router.swap(new_app.router.current());

        *self.config_meta.write().unwrap() = Some(ConfigMeta {
            path: meta.path,
            text: new_text.to_string(),
            fmt: meta.fmt,
            base_dir: meta.base_dir,
        });

        info!("配置已通过文本平滑热重载");
        Ok(())
    }
}

fn parse_config_for_fmt(text: &str, fmt: Format) -> Result<vp_config::Config> {
    match fmt {
        Format::Dsl => {
            let ir = vp_dsl::parse(text).map_err(Error::Config)?;
            Ok(vp_config::Config::from(ir))
        }
        Format::Yaml | Format::Json => {
            vp_config::parse(text, fmt).map_err(|e| Error::Config(format!("{e}")))
        }
    }
}

impl App {
    /// 从纯净统一中间表示 VpIr 直接装配并启动运行时
    pub async fn start_from_ir(
        ir: vp_ir::VpIr,
        base_dir: &Path,
        start_listeners: bool,
    ) -> Result<Arc<App>> {
        let cfg = vp_config::Config::from(ir);
        if let Err(errs) = vp_config::validate::validate(&cfg) {
            return Err(Error::Config(format!(
                "IR 配置校验失败:\n  - {}",
                errs.join("\n  - ")
            )));
        }
        let app = Self::assemble_cfg(cfg, base_dir.to_path_buf(), start_listeners, None).await?;
        if start_listeners {
            app.start_background_tasks();
        }
        Ok(app)
    }

    async fn assemble(
        text: String,
        fmt: Format,
        base_dir: PathBuf,
        start_listeners: bool,
        config_path: Option<std::path::PathBuf>,
        tun_fd: Option<i32>,
    ) -> Result<Arc<App>> {
        let mut cfg = parse_config_for_fmt(&text, fmt)?;
        if let Some(fd) = tun_fd {
            let mut tun = cfg.tun.take().unwrap_or_default();
            tun.enable = true;
            tun.fd = Some(fd);
            cfg.tun = Some(tun);
        }
        if let Err(errs) = vp_config::validate::validate(&cfg) {
            return Err(Error::Config(format!(
                "配置校验失败:\n  - {}",
                errs.join("\n  - ")
            )));
        }
        let meta = ConfigMeta {
            path: config_path,
            text,
            fmt,
            base_dir: base_dir.clone(),
        };
        Self::assemble_cfg(cfg, base_dir, start_listeners, Some(meta)).await
    }

    async fn assemble_cfg(
        cfg: vp_config::Config,
        base_dir: PathBuf,
        start_listeners: bool,
        initial_meta: Option<ConfigMeta>,
    ) -> Result<Arc<App>> {
        let t_start = std::time::Instant::now();

        if let Some(tuning) = &cfg.tuning {
            let rcv = tuning.so_rcvbuf.or(tuning.socket_buffer_size).unwrap_or(0);
            let snd = tuning.so_sndbuf.or(tuning.socket_buffer_size).unwrap_or(0);
            let nodelay = tuning.tcp_nodelay;
            let ka_secs = tuning.tcp_keepalive_secs.unwrap_or(60);
            vp_transport::set_global_tuning(
                rcv,
                snd,
                nodelay,
                ka_secs,
                tuning.tcp_bbr,
                tuning.tcp_fast_open,
                tuning.reuse_port,
            );
        }

        if let Some(mark) = cfg.routing_mark {
            vp_transport::set_routing_mark(mark);
        } else if start_listeners {
            vp_transport::set_routing_mark(0);
        }
        if cfg.interface_name.is_some() {
            vp_transport::set_bind_interface_name(cfg.interface_name.clone());
        } else if start_listeners {
            vp_transport::set_bind_interface_name(None);
        }

        let geosite = load_geosite(&base_dir, cfg.geosite_url.as_deref()).await;
        if let Some(ref db) = geosite {
            vp_dns::set_global_geosite_db(Some(Arc::new(db.clone())));
        }
        let t_geosite = t_start.elapsed();
        let geoip = load_geoip(&base_dir, cfg.geoip_url.as_deref()).await;
        let asn = load_asn(&base_dir, cfg.asn_url.as_deref()).await;
        let t_geoip = t_start.elapsed();

        // 全局统一 Fake-IP 池：供独立 dns.listen、TUN 数据面以及 redir/tproxy/mixed/socks5/udp 全入站共享反查
        let global_fake_pool = if cfg.dns.enhanced_mode.as_deref() == Some("fake-ip")
            || cfg.tun.as_ref().map(|t| t.enable).unwrap_or(false)
            || cfg.dns.fake_ip_range.is_some()
        {
            let range = cfg
                .dns
                .fake_ip_range
                .as_deref()
                .or_else(|| cfg.tun.as_ref().map(|t| t.fake_ip_range.as_str()))
                .unwrap_or("198.18.0.0/16");
            vp_dns::FakeIpPool::new(range).map(Arc::new)
        } else {
            None
        };
        if global_fake_pool.is_some() {
            vp_dns::set_global_fake_ip_pool(global_fake_pool.clone());
        }

        let fakeip_persister = if let Some(ref pool) = global_fake_pool {
            let fakeip_path = base_dir.join(".cache").join("fakeip.bin");
            Some(Arc::new(vp_dns::FakeIpPersister::start(
                (**pool).clone(),
                fakeip_path,
            )))
        } else {
            None
        };

        // 解析静态 hosts 映射表
        let mut hosts_map: HashMap<String, Vec<std::net::IpAddr>> = HashMap::new();
        for (domain, ip_strs) in &cfg.hosts {
            let ips: Vec<std::net::IpAddr> = ip_strs
                .iter()
                .filter_map(|s| s.trim().parse::<std::net::IpAddr>().ok())
                .collect();
            if !ips.is_empty() {
                hosts_map.insert(domain.clone(), ips);
            }
        }

        let dns = Arc::new(
            if cfg.dns.enable {
                let policies =
                    vp_dns::compile_nameserver_policy(&cfg.dns.nameserver_policy, geosite.as_ref());
                let fallback_filter = cfg.dns.fallback_filter.as_ref().map(|ff| {
                    vp_dns::compile_fallback_filter(ff, geosite.as_ref(), geoip.as_ref())
                });
                Resolver::build(
                    cfg.dns.nameserver.clone(),
                    cfg.dns.fallback.clone(),
                    policies,
                    fallback_filter,
                )
                .with_default_nameservers(cfg.dns.default_nameserver.clone())
            } else {
                Resolver::system()
            }
            .with_hosts(hosts_map)
            .with_fake_ip(global_fake_pool.clone()),
        );
        let t_dns = t_start.elapsed();
        // 节点自身的域名拨号走全局解析器（多上游并集 + 缓存 + 竞速拨号，
        // 对抗节点域名被污染/多 A 记录中混有失效地址导致的"时通时不通"）
        vp_transport::set_global_node_resolver(dns.clone(), cfg.dns.is_ipv6(cfg.ipv6));
        // ECH（ech-opts）的 HTTPS(type65) 记录查询也走全局解析器
        vp_transport::tls::set_global_resolver(dns.clone());
        let deps = OutboundDeps {
            dns: dns.clone(),
            ipv6: cfg.ipv6,
        };

        // 出站表
        let mut outbounds: HashMap<String, Arc<dyn Outbound>> = HashMap::new();
        outbounds.insert(
            "DIRECT".into(),
            Arc::new(vp_protocol::DirectOutbound::new(dns.clone(), cfg.ipv6)) as Arc<dyn Outbound>,
        );
        outbounds.insert("REJECT".into(), Arc::new(vp_protocol::RejectOutbound));
        for p in &cfg.proxies {
            let ob = build_outbound(p, &deps)
                .map_err(|e| Error::Config(format!("节点 {:?}: {e}", p.name)))?;
            outbounds.insert(p.name.clone(), ob);
        }

        // 代理集合提供者 (proxy-providers)
        let (proxy_providers, _proxy_provider_texts) =
            load_proxy_providers(&cfg, &base_dir).await?;
        for plist in proxy_providers.values() {
            for p in plist {
                let ob = build_outbound(p, &deps)
                    .map_err(|e| Error::Config(format!("节点 {:?}: {e}", p.name)))?;
                outbounds.insert(p.name.clone(), ob);
            }
        }
        let outbound_names: Vec<String> = outbounds.keys().cloned().collect();

        // 规则
        let providers = load_providers(&cfg, &base_dir).await?;
        let known: std::collections::HashSet<String> = outbound_names
            .into_iter()
            .chain(cfg.proxy_groups.iter().map(|g| g.name.clone()))
            .collect();
        let rules = {
            let is_known = |t: &str| known.contains(t) || vp_config::is_builtin(t);
            let env = CompileEnv {
                is_known_target: &is_known,
                geosite: &geosite,
                geoip: &geoip,
                asn: &asn,
                providers: &providers,
                sub_rules: &cfg.sub_rules,
            };
            vp_rule::compile(&cfg.rules, &env).map_err(|errs| {
                Error::Config(format!("规则编译失败:\n  - {}", errs.join("\n  - ")))
            })?
        };
        let t_rules = t_start.elapsed();
        tracing::debug!(
            "assemble 阶段耗时: geosite={:?}, geoip={:?}, dns={:?}, rules={:?}",
            t_geosite,
            t_geoip - t_geosite,
            t_dns - t_geoip,
            t_rules - t_dns
        );

        let mut group_specs = Vec::new();
        for g in &cfg.proxy_groups {
            let mut gs = group_spec(g);
            let filter_re = g.filter.as_ref().and_then(|f| regex::Regex::new(f).ok());
            let exclude_re = g
                .exclude_filter
                .as_ref()
                .and_then(|ef| regex::Regex::new(ef).ok());

            // 1. 若配置了 filter / exclude_filter 且有静态 proxies 成员，按规则筛选非内置出站节点
            if (filter_re.is_some() || exclude_re.is_some()) && !g.proxies.is_empty() {
                gs.members.retain(|m| {
                    if vp_config::is_builtin(m) {
                        return true;
                    }
                    let match_filter = filter_re.as_ref().is_none_or(|re| re.is_match(m));
                    let match_exclude = exclude_re.as_ref().is_some_and(|re| re.is_match(m));
                    match_filter && !match_exclude
                });
            }

            // 2. 解析外部 proxy-providers (use) 并执行动态正则过滤
            for u in &g.r#use {
                if let Some(plist) = proxy_providers.get(u) {
                    for p in plist {
                        let match_filter = filter_re.as_ref().is_none_or(|re| re.is_match(&p.name));
                        let match_exclude =
                            exclude_re.as_ref().is_some_and(|re| re.is_match(&p.name));
                        if match_filter && !match_exclude && !gs.members.contains(&p.name) {
                            gs.members.push(p.name.clone());
                        }
                    }
                }
            }
            group_specs.push(gs);
        }

        // 收集节点声明的 dialer-proxy / detour
        let mut dialers = HashMap::new();
        for p in &cfg.proxies {
            if let Some(ref d) = p.dialer_proxy {
                dialers.insert(p.name.clone(), d.clone());
            }
        }
        for plist in proxy_providers.values() {
            for p in plist {
                if let Some(ref d) = p.dialer_proxy {
                    dialers.insert(p.name.clone(), d.clone());
                }
            }
        }

        let router = InnerRouter::build(RouterSpec {
            outbounds,
            groups: group_specs,
            dialers,
            rules,
            mode: cfg.mode,
            dns: dns.clone(),
            ipv6: cfg.ipv6,
            start_health_checks: start_listeners,
        })?;

        let router_handle = Arc::new(RouterHandle::new(router));
        let stats = Arc::new(Stats::default());
        // 连接资源预算（审计报告任务2）：缺省不限，配置后生效
        stats.conn_budget.configure(vp_common::ResourceLimits {
            max_connections: cfg.resource_limits.max_connections,
            max_connections_per_inbound: cfg.resource_limits.max_connections_per_inbound,
        });
        let conns = Arc::new(ConnTable::new());
        let user_manager = Arc::new(vp_core::UserManager::new());

        // 规则提供者定时后台更新任务
        if start_listeners {
            let providers_state = Arc::new(RwLock::new(providers.clone()));
            for (name, p) in &cfg.rule_providers {
                if let Some(ref url) = p.url {
                    let interval = p.interval.unwrap_or(0);
                    if interval > 0 {
                        let name = name.clone();
                        let url = url.clone();
                        let behavior = match vp_rule::provider::Behavior::parse(
                            p.behavior.as_deref().unwrap_or("domain"),
                        ) {
                            Ok(b) => b,
                            Err(_) => continue,
                        };
                        let cache_path = p
                            .path
                            .as_ref()
                            .map(|p| base_dir.join(p))
                            .unwrap_or_else(|| base_dir.join(".cache").join(format!("{name}.txt")));
                        let router_handle = router_handle.clone();
                        let providers_state = providers_state.clone();
                        let rules_spec = cfg.rules.clone();
                        let sub_rules = cfg.sub_rules.clone();
                        let known = known.clone();
                        let geosite = geosite.clone();
                        let geoip = geoip.clone();
                        let asn = asn.clone();

                        tokio::spawn(async move {
                            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
                                interval.max(1),
                            ));
                            ticker.tick().await; // 消耗初次立即触发的 tick
                            loop {
                                ticker.tick().await;
                                let u = url.clone();
                                let fetch_res = tokio::task::spawn_blocking(move || {
                                    fetch_remote_binary(&u, crate::consts::USER_AGENT_RULE_PROVIDER)
                                })
                                .await;
                                match fetch_res {
                                    Ok(Ok(new_bytes)) => {
                                        let is_same = {
                                            let guard = providers_state.read().unwrap();
                                            guard
                                                .get(&name)
                                                .map(|(_, old)| old == &new_bytes)
                                                .unwrap_or(false)
                                        };
                                        if is_same {
                                            continue;
                                        }
                                        if let Err(e) = vp_rule::provider::load_payload_bytes(
                                            &new_bytes, behavior, None,
                                        ) {
                                            warn!(
                                                "rule-provider {name} 定时拉取内容校验未通过: {e}"
                                            );
                                            continue;
                                        }
                                        if let Some(parent) = cache_path.parent() {
                                            let _ = tokio::fs::create_dir_all(parent).await;
                                        }
                                        let _ = tokio::fs::write(&cache_path, &new_bytes).await;
                                        providers_state
                                            .write()
                                            .unwrap()
                                            .insert(name.clone(), (behavior, new_bytes));

                                        let providers_guard = providers_state.read().unwrap();
                                        let is_known = |t: &str| {
                                            known.iter().any(|k| k == t) || vp_config::is_builtin(t)
                                        };
                                        let env = CompileEnv {
                                            is_known_target: &is_known,
                                            geosite: &geosite,
                                            geoip: &geoip,
                                            asn: &asn,
                                            providers: &providers_guard,
                                            sub_rules: &sub_rules,
                                        };
                                        match vp_rule::compile(&rules_spec, &env) {
                                            Ok(new_rules) => {
                                                let cur_router = router_handle.current();
                                                let new_router =
                                                    cur_router.clone_with_rules(new_rules);
                                                router_handle.swap(new_router);
                                                info!(
                                                    "rule-provider {name} 定时刷新完成，规则引擎已平滑替换"
                                                );
                                            }
                                            Err(errs) => {
                                                warn!(
                                                    "rule-provider {name} 规则重编译失败: {errs:?}"
                                                );
                                            }
                                        }
                                    }
                                    Ok(Err(e)) => {
                                        warn!("rule-provider {name} 定时拉取失败: {e}");
                                    }
                                    Err(e) => {
                                        warn!("rule-provider {name} 任务异常: {e}");
                                    }
                                }
                            }
                        });
                    }
                }
            }
        }

        // 入站
        let mut listen_ports = Vec::new();
        let mut port_redirect_guards = Vec::new();
        let mut tun_runtime_opt: Option<TunRuntime> = None;
        let tun_status: Arc<RwLock<TunStatus>>;
        let dns_status: Arc<RwLock<DnsStatus>>;
        if start_listeners {
            let bind = if cfg.allow_lan {
                if cfg.bind_address == "*" {
                    "0.0.0.0".to_string()
                } else {
                    cfg.bind_address.clone()
                }
            } else {
                "127.0.0.1".to_string()
            };
            let inb_ctx = InboundCtx {
                router: router_handle.clone(),
                stats: stats.clone(),
                conns: conns.clone(),
            };

            // 全局敲门门禁服务与全局 InboundGate
            let global_knock_gate = if let Some(ref kc) = cfg.knock {
                let k = Arc::new(vp_core::KnockGate::new(
                    &kc.secret,
                    std::time::Duration::from_secs(kc.timeout_secs.unwrap_or(60)),
                ));
                match k.clone().spawn_listener(&bind, kc.port).await {
                    Ok(bound_port) => {
                        info!(
                            "全局 knock 监听 UDP {bind}:{bound_port} (window: {}s)",
                            kc.timeout_secs.unwrap_or(60)
                        );
                    }
                    Err(e) => {
                        warn!("全局端口敲门服务启动失败: {e}");
                    }
                }
                Some(k)
            } else {
                None
            };

            let global_gate = compile_inbound_gate(
                &cfg.allow_geoip,
                &cfg.block_geoip,
                &cfg.allow_asn,
                &cfg.block_asn,
                global_knock_gate.clone(),
                cfg.rrl.as_ref(),
                geoip.as_ref(),
                asn.as_ref(),
            );

            for (kind, port, tag) in [
                (InboundKind::Mixed, cfg.mixed_port, "mixed"),
                (InboundKind::Http, cfg.port, "http"),
                (InboundKind::Socks5, cfg.socks_port, "socks5"),
            ] {
                if let Some(p) = port {
                    let inb =
                        build_inbound_with_gate(kind, bind.clone(), p, tag, global_gate.clone());
                    let bound = inb.clone().start(inb_ctx.clone()).await?;
                    info!("{tag} 监听 {bind}:{bound}");
                    listen_ports.push((tag.to_string(), bound));
                }
            }

            // redir 透明代理（仅 Linux；非 Linux 明确报错但不阻断启动）
            if let Some(p) = cfg.redir_port {
                let inb: Arc<dyn vp_core::Inbound> =
                    Arc::new(vp_protocol::redir::RedirInbound::new(&bind, p, "redir"));
                match inb.clone().start(inb_ctx.clone()).await {
                    Ok(bound) => {
                        info!("redir 监听 {bind}:{bound}");
                        listen_ports.push(("redir".to_string(), bound));
                    }
                    Err(e) => {
                        warn!("redir 未启用: {e}");
                    }
                }
            }

            // tproxy 透明代理（仅 Linux 支持 TCP+UDP 透明代理与 IP_TRANSPARENT 辅助控制报文）
            if let Some(p) = cfg.tproxy_port {
                let inb: Arc<dyn vp_core::Inbound> =
                    Arc::new(vp_protocol::tproxy::TproxyInbound::new(&bind, p, "tproxy"));
                match inb.clone().start(inb_ctx.clone()).await {
                    Ok(bound) => {
                        info!("tproxy 监听 {bind}:{bound}");
                        listen_ports.push(("tproxy".to_string(), bound));
                    }
                    Err(e) => {
                        warn!("tproxy 未启用: {e}");
                    }
                }
            }

            // 协议服务端入站（listeners）
            for l in &cfg.listeners {
                let knock_gate = if let Some(ref kc) = l.knock {
                    let k = Arc::new(vp_core::KnockGate::new(
                        &kc.secret,
                        std::time::Duration::from_secs(kc.timeout_secs.unwrap_or(60)),
                    ));
                    match k.clone().spawn_listener(&bind, kc.port).await {
                        Ok(bound_port) => {
                            info!(
                                "listener [{}] 独立 knock 监听 UDP {bind}:{bound_port} (window: {}s)",
                                l.name,
                                kc.timeout_secs.unwrap_or(60)
                            );
                        }
                        Err(e) => {
                            warn!("listener {} 端口敲门服务启动失败: {e}", l.name);
                        }
                    }
                    Some(k)
                } else {
                    global_knock_gate.clone()
                };

                let allow_geo = if !l.allow_geoip.is_empty() {
                    &l.allow_geoip
                } else {
                    &cfg.allow_geoip
                };
                let block_geo = if !l.block_geoip.is_empty() {
                    &l.block_geoip
                } else {
                    &cfg.block_geoip
                };
                let allow_asn = if !l.allow_asn.is_empty() {
                    &l.allow_asn
                } else {
                    &cfg.allow_asn
                };
                let block_asn = if !l.block_asn.is_empty() {
                    &l.block_asn
                } else {
                    &cfg.block_asn
                };
                let rrl_cfg = l.rrl.as_ref().or(cfg.rrl.as_ref());

                let gate = compile_inbound_gate(
                    allow_geo,
                    block_geo,
                    allow_asn,
                    block_asn,
                    knock_gate,
                    rrl_cfg,
                    geoip.as_ref(),
                    asn.as_ref(),
                );

                let inb: Arc<dyn vp_core::Inbound> =
                    match build_listener(l, user_manager.clone(), gate) {
                        Ok(i) => i,
                        Err(e) => {
                            warn!("listener {:?} 构建失败: {e}", l.name);
                            continue;
                        }
                    };
                match inb.clone().start(inb_ctx.clone()).await {
                    Ok(bound) => {
                        info!("listener {} [{}] 监听 {bind}:{bound}", l.name, l.kind);
                        listen_ports.push((l.name.clone(), bound));
                        if let Some(port_spec) = l.ports.as_deref() {
                            match vp_tun::port_redirect::IptablesPortRedirectGuard::setup(
                                &l.name, port_spec, bound, cfg.ipv6,
                            ) {
                                Ok(guard) => {
                                    port_redirect_guards.push(guard);
                                }
                                Err(e) => {
                                    warn!(
                                        "listener [{}] 配置 iptables 端口重定向失败: {e}",
                                        l.name
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => warn!("listener {:?} 启动失败: {e}", l.name),
                }
            }

            let mut dns_st = DnsStatus::default();
            // 独立 DNS 服务端：只要配置了 dns.listen（例如 "0.0.0.0:53" 或 ":53"），
            // 无论是否启用 TUN，均作为独立 DNS 服务对外监听并提供智能分流/解析
            if let Some(listen_str) = &cfg.dns.listen {
                dns_st.enabled = true;
                dns_st.listen = Some(listen_str.clone());
                match parse_dns_listen(listen_str, &bind) {
                    Ok(listen_addr) => {
                        let dns_srv = vp_dns::DnsServer::new(
                            listen_addr,
                            dns.clone(),
                            global_fake_pool.clone(),
                            cfg.dns.fake_ip_filter.clone(),
                            cfg.dns.is_ipv6(cfg.ipv6),
                        );

                        match dns_srv.spawn_handle().await {
                            Ok((bound, _handle)) => {
                                info!(
                                    "dns 独立服务端监听 {bound} (enhanced-mode: {:?})",
                                    cfg.dns.enhanced_mode
                                );
                                listen_ports.push(("dns".to_string(), bound.port()));
                                dns_st.running = true;
                            }
                            Err(e) => {
                                let err_msg = format!("dns.listen 监听 {listen_addr} 失败: {e}");
                                tracing::error!("{err_msg}");
                                dns_st.error = Some(err_msg.clone());
                                if cfg.tun.as_ref().and_then(|t| t.strict).unwrap_or(false)
                                    || std::env::var("VPCORE_STRICT")
                                        .map(|v| v == "1" || v == "true")
                                        .unwrap_or(false)
                                {
                                    return Err(Error::Other(err_msg));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let err_msg = format!("dns.listen 解析失败: {e}");
                        tracing::error!("{err_msg}");
                        dns_st.error = Some(err_msg.clone());
                        if cfg.tun.as_ref().and_then(|t| t.strict).unwrap_or(false)
                            || std::env::var("VPCORE_STRICT")
                                .map(|v| v == "1" || v == "true")
                                .unwrap_or(false)
                        {
                            return Err(Error::Config(err_msg));
                        }
                    }
                }
            }

            let mut tun_st = TunStatus::default();
            // TUN 模式
            if let Some(tun_cfg) = &cfg.tun {
                tun_st.enabled = tun_cfg.enable;
                if tun_cfg.enable {
                    let ctx = InboundCtx {
                        router: router_handle.clone(),
                        stats: stats.clone(),
                        conns: conns.clone(),
                    };
                    match start_tun_runtime(&cfg, dns.clone(), ctx).await {
                        Ok(rt) => {
                            tun_st.running = true;
                            tun_st.device = Some("vpcore-tun".into());
                            tun_st.dns_hijack = true;
                            tun_st.auto_route = tun_cfg.auto_route;
                            tun_runtime_opt = Some(rt);
                        }
                        Err(e) => {
                            let err_msg = format!("TUN 启动失败（需要管理员权限）: {e}");
                            tracing::error!("{err_msg}");
                            tun_st.error = Some(err_msg.clone());
                            if tun_cfg.strict.unwrap_or(false)
                                || std::env::var("VPCORE_STRICT")
                                    .map(|v| v == "1" || v == "true")
                                    .unwrap_or(false)
                            {
                                return Err(Error::Other(err_msg));
                            }
                        }
                    }
                }
            }
            tun_status = Arc::new(RwLock::new(tun_st));
            dns_status = Arc::new(RwLock::new(dns_st));
        } else {
            tun_status = Arc::new(RwLock::new(TunStatus::default()));
            dns_status = Arc::new(RwLock::new(DnsStatus::default()));
        }

        let config_meta = Arc::new(RwLock::new(initial_meta));

        // TUN 运行时：App 与外部控制器共享同一份（热重载差量同步用）
        let tun_runtime = Arc::new(RwLock::new(tun_runtime_opt));

        // 控制器
        let controller = cfg.external_controller.clone();
        if let Some(addr) = &controller {
            if start_listeners {
                let app_ref = api::ApiState {
                    router: router_handle.clone(),
                    stats: stats.clone(),
                    conns: conns.clone(),
                    secret: cfg.secret.clone().filter(|s| !s.is_empty()),
                    config_meta: config_meta.clone(),
                    tun_runtime: tun_runtime.clone(),
                    tun_status: tun_status.clone(),
                    dns_status: dns_status.clone(),
                    dns: dns.clone(),
                    user_manager: user_manager.clone(),
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
            config_meta,
            tun_runtime,
            tun_status,
            dns_status,
            dns,
            user_manager,
            port_redirect_guards: Arc::new(RwLock::new(port_redirect_guards)),
            fakeip_persister,
        };
        Ok(Arc::new(app))
    }

    /// 全组测速（CLI test 用）
    pub async fn url_test_all_groups(&self) {
        let router = self.router.current();
        let groups = router.groups();
        if groups.is_empty() {
            println!("没有可测速的策略组");
            return;
        }

        // 收集所有策略组中所有唯一的底层节点名称，避免多组重叠导致同一节点被重复连接测速数次
        let mut unique_members: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for g in groups.values() {
            for m in g.member_names() {
                if router.outbound(m).is_some() && seen.insert(m.to_string()) {
                    unique_members.push(m.to_string());
                }
            }
        }

        let test_url = groups
            .values()
            .next()
            .map(|g| g.test_url())
            .unwrap_or("http://www.gstatic.com/generate_204");

        // 一次性高并发（128 并发通道）批量探测所有唯一节点，结果自动同步回填至所有策略组
        let mut set = tokio::task::JoinSet::new();
        for member in unique_members {
            let r_clone = router.clone();
            let url = test_url.to_string();
            set.spawn(async move {
                let _ = r_clone.url_test_node(&member, &url).await;
            });
        }
        while set.join_next().await.is_some() {}

        for (name, g) in groups {
            println!("组 {name} [{}]:", g.ty().as_str());
            for (member, delay, alive) in g.member_states() {
                match delay {
                    Some(ms) if alive => println!("  {member:<24} {ms:>5} ms"),
                    _ => println!("  {member:<24} 失败"),
                }
            }
        }
    }

    /// 启动 proxy-providers 后台定时自动刷新任务
    pub fn start_background_tasks(self: &Arc<Self>) {
        let meta = match self.config_meta.read().unwrap().clone() {
            Some(m) => m,
            None => return,
        };
        let cfg: vp_config::Config = match vp_config::parse(&meta.text, meta.fmt) {
            Ok(c) => c,
            Err(_) => return,
        };
        let app_weak = Arc::downgrade(self);
        for (name, p) in cfg.proxy_providers {
            if let Some(url) = p.url {
                let interval = p.interval.unwrap_or(0);
                if interval > 0 {
                    let name = name.clone();
                    let filter = p.filter.clone();
                    let cache_path = p
                        .path
                        .as_ref()
                        .map(|p| meta.base_dir.join(p))
                        .unwrap_or_else(|| {
                            meta.base_dir.join(".cache").join(format!("{name}.yaml"))
                        });
                    let app_weak = app_weak.clone();

                    tokio::spawn(async move {
                        let mut ticker =
                            tokio::time::interval(std::time::Duration::from_secs(interval.max(1)));
                        ticker.tick().await; // 消耗初始即刻 tick
                        loop {
                            ticker.tick().await;
                            let app = match app_weak.upgrade() {
                                Some(a) => a,
                                None => break, // App 实例已释放，终止任务
                            };
                            let u = url.clone();
                            let fetch_res = tokio::task::spawn_blocking(move || {
                                fetch_remote_provider(&u, "vpcore/proxy-provider")
                            })
                            .await;
                            match fetch_res {
                                Ok(Ok(new_text)) => {
                                    if let Err(e) = vp_protocol::sub::parse_provider_proxies(
                                        &new_text,
                                        filter.as_deref(),
                                    ) {
                                        warn!("proxy-provider {name} 定时拉取内容校验未通过: {e}");
                                        continue;
                                    }
                                    let is_unchanged = tokio::fs::read_to_string(&cache_path)
                                        .await
                                        .ok()
                                        .as_deref()
                                        == Some(&new_text);
                                    if is_unchanged {
                                        tracing::debug!(
                                            "proxy-provider {name} 内容未发生变更，跳过写入与重载"
                                        );
                                        continue;
                                    }
                                    if let Some(parent) = cache_path.parent() {
                                        let _ = tokio::fs::create_dir_all(parent).await;
                                    }
                                    let _ = tokio::fs::write(&cache_path, &new_text).await;
                                    if let Err(e) = app.reload().await {
                                        warn!("proxy-provider {name} 重载失败: {e}");
                                    } else {
                                        info!(
                                            "proxy-provider {name} 定时刷新完成，节点与路由已平滑替换"
                                        );
                                    }
                                }
                                Ok(Err(e)) => warn!("proxy-provider {name} 定时拉取失败: {e}"),
                                Err(e) => warn!("proxy-provider {name} 任务异常: {e}"),
                            }
                        }
                    });
                }
            }
        }
    }
}

fn populate_user_manager(
    mgr: &vp_core::UserManager,
    user_configs: &[vp_config::UserConfig],
    plain_users: &[String],
) {
    for uc in user_configs {
        let limiter = if uc.rate_limit_up.is_some() || uc.rate_limit_down.is_some() {
            Some(Arc::new(vp_core::BandwidthLimiter::from_mbps(
                uc.rate_limit_up,
                uc.rate_limit_down,
            )))
        } else {
            None
        };
        let username = uc.name.clone().unwrap_or_else(|| uc.secret.clone());
        let brutal = uc
            .brutal_mbps
            .map(|mbps| Arc::new(vp_core::BrutalPacer::from_mbps(mbps)));
        let account = Arc::new(
            vp_core::UserAccount::new(username, uc.secret.clone(), uc.quota_bytes, limiter)
                .with_brutal(brutal),
        );
        mgr.add_user(account);
    }
    for u in plain_users {
        if mgr.get_user(u).is_none() {
            let account = Arc::new(vp_core::UserAccount::new(u.clone(), u.clone(), None, None));
            mgr.add_user(account);
        }
    }
}

fn parse_ports_list(s: &str) -> Vec<u16> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.trim().parse::<u16>(), end.trim().parse::<u16>()) {
                for p in s..=e {
                    out.push(p);
                }
            }
        } else if let Ok(p) = part.parse::<u16>() {
            out.push(p);
        }
    }
    out
}

/// 编译入站安全门禁（GeoIP / ASN 白黑名单、端口敲门与 UDP RRL 速率限制）
#[allow(clippy::too_many_arguments)]
pub fn compile_inbound_gate(
    allow_geoip: &[String],
    block_geoip: &[String],
    allow_asn: &[u32],
    block_asn: &[u32],
    knock: Option<Arc<vp_core::KnockGate>>,
    rrl_cfg: Option<&vp_config::RrlConfig>,
    geoip: Option<&vp_rule::GeoIpDb>,
    asn: Option<&vp_rule::AsnDb>,
) -> Option<Arc<vp_core::InboundGate>> {
    let has_geoip = !allow_geoip.is_empty() || !block_geoip.is_empty();
    let has_asn = !allow_asn.is_empty() || !block_asn.is_empty();

    let ip_filter: Option<Arc<dyn Fn(std::net::IpAddr) -> bool + Send + Sync>> = if has_geoip
        || has_asn
    {
        let mut allow_geo_matchers = Vec::new();
        for code in allow_geoip {
            let code_up = code.trim().to_ascii_uppercase();
            if code_up == "LAN" || code_up == "PRIVATE" {
                allow_geo_matchers.push(vp_rule::GeoIpMatcher::LanOrPrivate);
            } else if let Some(db) = geoip {
                if let Some(m) = db.matcher(code.clone()) {
                    allow_geo_matchers.push(m);
                }
            } else {
                warn!("配置了 allow_geoip: {code} 但未加载 GeoIP 数据库，该规则将无法匹配外网 IP");
            }
        }

        let mut block_geo_matchers = Vec::new();
        for code in block_geoip {
            let code_up = code.trim().to_ascii_uppercase();
            if code_up == "LAN" || code_up == "PRIVATE" {
                block_geo_matchers.push(vp_rule::GeoIpMatcher::LanOrPrivate);
            } else if let Some(db) = geoip {
                if let Some(m) = db.matcher(code.clone()) {
                    block_geo_matchers.push(m);
                }
            }
        }

        let allow_asn_matcher = if !allow_asn.is_empty() {
            if let Some(db) = asn {
                let s = allow_asn
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                db.matcher(&s)
            } else {
                warn!("配置了 allow_asn 但未加载 ASN 数据库");
                None
            }
        } else {
            None
        };

        let block_asn_matcher = if !block_asn.is_empty() {
            if let Some(db) = asn {
                let s = block_asn
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                db.matcher(&s)
            } else {
                warn!("配置了 block_asn 但未加载 ASN 数据库");
                None
            }
        } else {
            None
        };

        let has_allow_geo = !allow_geoip.is_empty();
        let has_allow_asn = !allow_asn.is_empty();

        Some(Arc::new(move |ip: std::net::IpAddr| {
            // 1. 显式黑名单 block_geoip 匹配直接拒绝
            for m in &block_geo_matchers {
                if m.matches(ip) {
                    return false;
                }
            }
            // 2. 显式黑名单 block_asn 匹配直接拒绝
            if let Some(ref m) = block_asn_matcher {
                if m.matches(ip) {
                    return false;
                }
            }
            // 3. 白名单 allow_geoip 检查（非空时必须命中任一）
            if has_allow_geo {
                let matched = allow_geo_matchers.iter().any(|m| m.matches(ip));
                if !matched {
                    return false;
                }
            }
            // 4. 白名单 allow_asn 检查（非空时必须命中任一）
            if has_allow_asn {
                let matched = allow_asn_matcher
                    .as_ref()
                    .map(|m| m.matches(ip))
                    .unwrap_or(false);
                if !matched {
                    return false;
                }
            }
            true
        }))
    } else {
        None
    };

    let rrl = rrl_cfg.map(|rc| {
        Arc::new(vp_core::UdpRrlLimiter::new(
            rc.max_qps.unwrap_or(10),
            rc.burst.unwrap_or(20),
            rc.slip.unwrap_or(2),
        ))
    });

    if ip_filter.is_some() || knock.is_some() || rrl.is_some() {
        Some(Arc::new(vp_core::InboundGate::new(ip_filter, knock, rrl)))
    } else {
        None
    }
}

/// 构建 listeners / inbounds 段的服务端入站（tproxy/redir/mixed/socks5/http/trojan/vmess/vless/ss...）
fn build_listener(
    l: &vp_config::ListenerCfg,
    global_user_mgr: Arc<vp_core::UserManager>,
    gate: Option<Arc<vp_core::InboundGate>>,
) -> Result<Arc<dyn vp_core::Inbound>> {
    let tag = l.name.as_str();
    let bind = l.listen.as_deref().unwrap_or("0.0.0.0");
    match l.kind.as_str() {
        "tproxy" => Ok(Arc::new(vp_protocol::tproxy::TproxyInbound::new(
            bind, l.port, tag,
        ))),
        "redir" => Ok(Arc::new(vp_protocol::redir::RedirInbound::new(
            bind, l.port, tag,
        ))),
        "mixed" => Ok(Arc::new(vp_protocol::inbound::MixedInbound::with_gate(
            bind.to_string(),
            l.port,
            tag,
            gate,
        ))),
        "socks" | "socks5" => Ok(Arc::new(vp_protocol::inbound::Socks5Inbound::with_gate(
            bind.to_string(),
            l.port,
            tag,
            gate,
        ))),
        "http" => Ok(Arc::new(vp_protocol::inbound::HttpInbound::with_gate(
            bind.to_string(),
            l.port,
            tag,
            gate,
        ))),
        "trojan" => {
            populate_user_manager(&global_user_mgr, &l.user_configs, &l.users);
            let mut users = l.users.clone();
            for u in global_user_mgr.all_users() {
                if !users.iter().any(|s| s == &*u.secret) {
                    users.push(u.secret.to_string());
                }
            }
            if users.is_empty() && l.fallback.is_none() {
                return Err(Error::Config(
                    "trojan listener 需要 users（密码）或 fallback 回落目标".into(),
                ));
            }
            Ok(Arc::new(vp_protocol::trojan::TrojanInbound::with_gate(
                bind,
                l.port,
                tag,
                &users,
                l.fallback.clone(),
                Some(global_user_mgr),
                gate,
            )?))
        }
        "vmess" => {
            if l.users.is_empty() {
                return Err(Error::Config("vmess listener 需要 users（uuid）".into()));
            }
            Ok(Arc::new(vp_protocol::vmess::VmessInbound::new(
                bind, l.port, tag, &l.users,
            )?))
        }
        "vless" => {
            populate_user_manager(&global_user_mgr, &l.user_configs, &l.users);
            let mut users = l.users.clone();
            for u in global_user_mgr.all_users() {
                if !users.iter().any(|s| s == &*u.secret) {
                    users.push(u.secret.to_string());
                }
            }
            if users.is_empty() && l.fallback.is_none() {
                return Err(Error::Config(
                    "vless listener 需要 users（uuid）或 fallback 回落目标".into(),
                ));
            }
            Ok(Arc::new(vp_protocol::vless::VlessInbound::with_gate(
                bind,
                l.port,
                tag,
                &users,
                l.fallback.clone(),
                Some(global_user_mgr),
                gate,
            )?))
        }
        "anytls" => {
            if l.users.is_empty() {
                return Err(Error::Config("anytls listener 需要 users（密码）".into()));
            }
            Ok(Arc::new(vp_protocol::anytls::AnytlsInbound::new(
                bind, l.port, tag, &l.users,
            )?))
        }
        "mieru" => {
            if l.users.is_empty() {
                return Err(Error::Config(
                    "mieru listener 需要 users（username:password）".into(),
                ));
            }
            Ok(Arc::new(vp_protocol::mieru::MieruInbound::new(
                bind, l.port, tag, &l.users,
            )?))
        }
        "brook" => {
            if l.users.is_empty() {
                return Err(Error::Config("brook listener 需要 users（密码）".into()));
            }
            Ok(Arc::new(vp_protocol::brook::BrookInbound::new(
                bind, l.port, tag, &l.users,
            )?))
        }
        "snell" => {
            if l.users.is_empty() {
                return Err(Error::Config(
                    "snell listener 需要 users（psk 凭据）".into(),
                ));
            }
            Ok(Arc::new(vp_protocol::snell::SnellInbound::new(
                bind,
                l.port,
                tag,
                &l.users,
                vp_protocol::snell::VERSION_4,
            )?))
        }
        "naive" => {
            if l.users.is_empty() {
                return Err(Error::Config(
                    "naive listener 需要 users（username:password）".into(),
                ));
            }
            Ok(Arc::new(vp_protocol::naive::NaiveInbound::new(
                bind, l.port, tag, &l.users,
            )?))
        }
        "ss" => {
            populate_user_manager(&global_user_mgr, &l.user_configs, &l.users);
            let password = l.users.first().cloned().unwrap_or_else(|| {
                l.user_configs
                    .first()
                    .map(|u| u.secret.clone())
                    .unwrap_or_default()
            });
            let cipher = l.cipher.as_deref().unwrap_or("aes-128-gcm");
            let stls = match &l.shadow_tls {
                Some(o) => {
                    let host = o.host.clone().ok_or_else(|| {
                        Error::Config("shadow-tls 入站缺少 host（伪装站）".into())
                    })?;
                    let pw = o
                        .password
                        .clone()
                        .ok_or_else(|| Error::Config("shadow-tls 入站缺少 password".into()))?;
                    Some(vp_protocol::shadowtls::ShadowTlsDial {
                        host,
                        port: o.port.unwrap_or(443),
                        password: pw,
                    })
                }
                None => None,
            };
            Ok(Arc::new(vp_protocol::ss::SsInbound::with_gate(
                bind,
                l.port,
                tag,
                cipher,
                &password,
                stls,
                Some(global_user_mgr),
                gate,
            )?))
        }
        "tuic" | "tuic5" | "tuic-v5" => {
            populate_user_manager(&global_user_mgr, &l.user_configs, &[]);
            let cert_val = l.cert.as_deref().ok_or_else(|| {
                Error::Config("tuic listener 需要 cert 证书配置 (文件路径或 PEM)".into())
            })?;
            let key_val = l.key.as_deref().ok_or_else(|| {
                Error::Config("tuic listener 需要 key 私钥配置 (文件路径或 PEM)".into())
            })?;
            let cert_pem = load_pem(cert_val, "tuic cert")?;
            let key_pem = load_pem(key_val, "tuic key")?;
            if l.users.is_empty() && l.user_configs.is_empty() {
                return Err(Error::Config(
                    "tuic listener 需要 users（'uuid:password' 格式）或 user_configs".into(),
                ));
            }
            let mut users = Vec::new();
            for u in &l.users {
                if let Some((uuid, pw)) = u.split_once(':') {
                    users.push((uuid.trim().to_string(), pw.trim().to_string()));
                } else {
                    return Err(Error::Config(format!(
                        "tuic user 格式非法 (期望 'uuid:password'，收到: {u})"
                    )));
                }
            }
            for uc in &l.user_configs {
                if let Some((uuid, pw)) = uc.secret.split_once(':') {
                    users.push((uuid.trim().to_string(), pw.trim().to_string()));
                } else if let Some(ref name) = uc.name {
                    users.push((name.trim().to_string(), uc.secret.trim().to_string()));
                }
            }
            Ok(Arc::new(vp_protocol::tuic::TuicInbound::with_gate(
                bind,
                l.port,
                tag,
                users,
                cert_pem,
                key_pem,
                Some(global_user_mgr),
                gate,
            )))
        }
        "hy2" | "hysteria2" => {
            populate_user_manager(&global_user_mgr, &l.user_configs, &l.users);
            let cert_val = l.cert.as_deref().ok_or_else(|| {
                Error::Config("hysteria2 listener 需要 cert 证书配置 (文件路径或 PEM)".into())
            })?;
            let key_val = l.key.as_deref().ok_or_else(|| {
                Error::Config("hysteria2 listener 需要 key 私钥配置 (文件路径或 PEM)".into())
            })?;
            let cert_pem = load_pem(cert_val, "hysteria2 cert")?;
            let key_pem = load_pem(key_val, "hysteria2 key")?;
            let mut users = l.users.clone();
            for u in global_user_mgr.all_users() {
                if !users.iter().any(|s| s == &*u.secret) {
                    users.push(u.secret.to_string());
                }
            }
            if users.is_empty() {
                return Err(Error::Config(
                    "hysteria2 listener 需要 users（密码列表）或 user_configs".into(),
                ));
            }
            let salamander_pw = if l.obfs.as_deref() == Some("salamander") {
                l.obfs_password
                    .as_deref()
                    .or_else(|| users.first().map(|s| s.as_str()))
            } else {
                l.obfs_password.as_deref()
            };
            let ports = l.ports.as_deref().and_then(|spec| {
                let list = parse_ports_list(spec);
                if list.len() > 64 {
                    #[cfg(target_os = "linux")]
                    {
                        debug!(
                            "listener [{}] ports 包含 {} 个端口，将由内核级 iptables REDIRECT 接管，避免用户态海量 socket 绑定",
                            l.name,
                            list.len()
                        );
                        None
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        warn!(
                            "listener [{}] ports 包含 {} 个端口，非 Linux 环境用户态最多绑定前 64 个端口以防文件描述符耗尽",
                            l.name,
                            list.len()
                        );
                        Some(list[..64].to_vec())
                    }
                } else if list.is_empty() {
                    None
                } else {
                    Some(list)
                }
            });
            Ok(Arc::new(
                vp_protocol::hysteria2::Hysteria2Inbound::with_gate(
                    bind,
                    l.port,
                    tag,
                    &users,
                    cert_pem,
                    key_pem,
                    Some(global_user_mgr),
                    salamander_pw,
                    ports,
                    gate,
                ),
            ))
        }
        "mux" | "multiplex" | "tls-mux" => {
            populate_user_manager(&global_user_mgr, &l.user_configs, &l.users);
            let mut users = l.users.clone();
            for u in global_user_mgr.all_users() {
                if !users.iter().any(|s| s == &*u.secret) {
                    users.push(u.secret.to_string());
                }
            }
            let cert_pem = match l.cert.as_deref() {
                Some(c) => Some(load_pem(c, "tls-mux cert")?),
                None => None,
            };
            let key_pem = match l.key.as_deref() {
                Some(k) => Some(load_pem(k, "tls-mux key")?),
                None => None,
            };
            let reality = if let Some(ref r) = l.reality {
                let pri_key =
                    vp_transport::reality_server::parse_reality_private_key(&r.private_key)?;
                let mut sids = Vec::new();
                for sid_str in &r.short_ids {
                    sids.push(vp_transport::reality_server::parse_short_id(sid_str)?);
                }
                Some(Arc::new(
                    vp_transport::reality_server::RealityServerConfig::new(
                        pri_key,
                        sids,
                        r.dest.clone(),
                        r.server_names.clone(),
                    ),
                ))
            } else {
                None
            };

            let options = vp_protocol::inbound::TlsMuxOptions {
                cert_pem,
                key_pem,
                reality,
                sni_routes: l.sni_routes.clone(),
                fallback: l.fallback.clone(),
                users,
                user_mgr: Some(global_user_mgr),
                gate,
            };
            Ok(Arc::new(vp_protocol::inbound::TlsMuxInbound::new(
                bind, l.port, tag, options,
            )?))
        }
        other => Err(Error::Unsupported(format!(
            "listener 类型 {other:?}（支持 tproxy/redir/mixed/socks5/http/trojan/vmess/vless/ss/tuic/hysteria2/mux 等）"
        ))),
    }
}

fn load_pem(val: &str, what: &str) -> Result<Vec<u8>> {
    let trimmed = val.trim_start();
    if trimmed.starts_with("-----BEGIN") {
        Ok(val.as_bytes().to_vec())
    } else {
        std::fs::read(val).map_err(|e| Error::Config(format!("读取 {what} 失败 ({val}): {e}")))
    }
}

pub(crate) fn fetch_remote_provider(url: &str, ua: &str) -> std::result::Result<String, String> {
    let resp = ureq::get(url)
        .timeout(std::time::Duration::from_secs(15))
        .set("User-Agent", ua)
        .call()
        .map_err(|e| format!("{e}"))?;
    let mut body = String::new();
    use std::io::Read;
    resp.into_reader()
        .take(16 << 20)
        .read_to_string(&mut body)
        .map_err(|e| format!("{e}"))?;
    Ok(body)
}

async fn load_proxy_providers(
    cfg: &vp_config::Config,
    base_dir: &Path,
) -> Result<(
    HashMap<String, Vec<vp_config::ProxyCfg>>,
    HashMap<String, String>,
)> {
    let mut out_proxies = HashMap::new();
    let mut out_texts = HashMap::new();

    for (name, p) in &cfg.proxy_providers {
        let cache_path = p
            .path
            .as_ref()
            .map(|p| base_dir.join(p))
            .unwrap_or_else(|| base_dir.join(".cache").join(format!("{name}.yaml")));

        let text = if let Some(ref url) = p.url {
            let u = url.clone();
            let filter = p.filter.clone();
            let res = tokio::task::spawn_blocking(move || {
                fetch_remote_provider(&u, "vpcore/proxy-provider")
            })
            .await
            .map_err(|e| Error::Config(format!("proxy-provider 拉取任务失败: {e}")))?;
            match res {
                Ok(t)
                    if vp_protocol::sub::parse_provider_proxies(&t, filter.as_deref()).is_ok() =>
                {
                    if let Some(parent) = cache_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = std::fs::write(&cache_path, &t);
                    info!("proxy-provider {name:?} 在线拉取成功并已写入缓存");
                    t
                }
                other => {
                    let err_msg = match other {
                        Ok(_) => "在线拉取内容格式校验未通过".to_string(),
                        Err(e) => e,
                    };
                    if cache_path.exists() {
                        warn!(
                            "proxy-provider {name:?} 在线拉取失败 ({err_msg})，降级使用本地缓存: {}",
                            cache_path.display()
                        );
                        std::fs::read_to_string(&cache_path).map_err(|e| {
                            Error::Config(format!("proxy-provider {name:?} 缓存读取失败: {e}"))
                        })?
                    } else {
                        return Err(Error::Config(format!(
                            "proxy-provider {name:?} 在线拉取失败且无可用本地缓存: {err_msg}"
                        )));
                    }
                }
            }
        } else {
            std::fs::read_to_string(&cache_path)
                .map_err(|e| Error::Config(format!("proxy-provider {name:?} 读取失败: {e}")))?
        };

        let proxies = vp_protocol::sub::parse_provider_proxies(&text, p.filter.as_deref())
            .map_err(|e| Error::Config(format!("proxy-provider {name:?} 解析失败: {e}")))?;

        out_texts.insert(name.clone(), text);
        out_proxies.insert(name.clone(), proxies);
    }

    Ok((out_proxies, out_texts))
}

async fn load_providers(
    cfg: &vp_config::Config,
    base_dir: &Path,
) -> Result<HashMap<String, (vp_rule::provider::Behavior, Vec<u8>)>> {
    let mut out = HashMap::new();
    for (name, p) in &cfg.rule_providers {
        let behavior = p
            .behavior
            .as_deref()
            .ok_or_else(|| Error::Config(format!("rule-provider {name:?} 缺少 behavior")))?;
        let behavior = vp_rule::provider::Behavior::parse(behavior)
            .map_err(|e| Error::Config(format!("rule-provider {name:?}: {e}")))?;

        // 缓存路径：优先配置的 path，否则使用 .cache/{name}.txt
        let cache_path = p
            .path
            .as_ref()
            .map(|p| base_dir.join(p))
            .unwrap_or_else(|| base_dir.join(".cache").join(format!("{name}.txt")));

        let bytes = if let Some(ref url) = p.url {
            // 在线拉取尝试
            let u = url.clone();
            let res = tokio::task::spawn_blocking(move || {
                fetch_remote_binary(&u, "vpcore/rule-provider")
            })
            .await
            .map_err(|e| Error::Config(format!("拉取任务失败: {e}")))?;
            match res {
                Ok(t) if vp_rule::provider::load_payload_bytes(&t, behavior, None).is_ok() => {
                    if let Some(parent) = cache_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = std::fs::write(&cache_path, &t);
                    info!("rule-provider {name:?} 在线拉取成功并已写入缓存");
                    t
                }
                other => {
                    let err_msg = match other {
                        Ok(_) => "在线拉取内容格式校验未通过".to_string(),
                        Err(e) => e,
                    };
                    if cache_path.exists() {
                        warn!(
                            "rule-provider {name:?} 在线拉取失败 ({err_msg})，降级使用本地缓存: {}",
                            cache_path.display()
                        );
                        std::fs::read(&cache_path).map_err(|e| {
                            Error::Config(format!("rule-provider {name:?} 缓存读取失败: {e}"))
                        })?
                    } else {
                        return Err(Error::Config(format!(
                            "rule-provider {name:?} 在线拉取失败且无可用本地缓存: {err_msg}"
                        )));
                    }
                }
            }
        } else {
            // 本地文件读取
            std::fs::read(&cache_path)
                .map_err(|e| Error::Config(format!("rule-provider {name:?} 读取失败: {e}")))?
        };

        out.insert(name.clone(), (behavior, bytes));
    }
    Ok(out)
}

fn fetch_remote_binary(url: &str, ua: &str) -> std::result::Result<Vec<u8>, String> {
    let resp = ureq::get(url)
        .timeout(std::time::Duration::from_secs(30))
        .set("User-Agent", ua)
        .call()
        .map_err(|e| format!("{e}"))?;
    let mut bytes = Vec::new();
    use std::io::Read;
    resp.into_reader()
        .take(128 << 20)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{e}"))?;
    Ok(bytes)
}

fn candidate_dirs(base_dir: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    dirs.push(base_dir.to_path_buf());
    if let Ok(cwd) = std::env::current_dir() {
        if !dirs.contains(&cwd) {
            dirs.push(cwd);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let pb = parent.to_path_buf();
            if !dirs.contains(&pb) {
                dirs.push(pb);
            }
        }
    }
    dirs
}

async fn load_geosite(base_dir: &Path, url: Option<&str>) -> Option<GeoSiteDb> {
    let dirs = candidate_dirs(base_dir);
    for d in &dirs {
        for name in ["geosite.dat", "GeoSite.dat"] {
            let p = d.join(name);
            if p.exists() {
                if let Ok(db) = GeoSiteDb::load_file(&p) {
                    info!("geosite 已加载(mmap零拷贝): {}", p.display());
                    return Some(db);
                } else if let Ok(bytes) = std::fs::read(&p) {
                    if let Ok(db) = GeoSiteDb::load(&bytes) {
                        info!("geosite 已加载: {}", p.display());
                        return Some(db);
                    }
                }
            }
        }
    }
    if let Some(u) = url {
        let u = u.to_string();
        let target = base_dir.join("geosite.dat");
        info!("正在从远程拉取 geosite: {u}");
        let res =
            tokio::task::spawn_blocking(move || fetch_remote_binary(&u, "vpcore/geosite")).await;
        if let Ok(Ok(bytes)) = res {
            if let Ok(db) = GeoSiteDb::load(&bytes) {
                let _ = std::fs::write(&target, &bytes);
                info!("geosite 远程拉取成功并已写入: {}", target.display());
                return Some(db);
            }
        }
    }
    info!("未找到 geosite 数据库文件 (geosite.dat)，相关 GEOSITE 规则将优雅跳过");
    None
}

async fn load_geoip(base_dir: &Path, url: Option<&str>) -> Option<vp_rule::geoip::GeoIpDb> {
    let dirs = candidate_dirs(base_dir);
    for d in &dirs {
        for name in [
            "geoip.metadb",
            "Country.mmdb",
            "geoip.dat",
            "GeoIP.dat",
            "geoip.mmdb",
        ] {
            let p = d.join(name);
            if p.exists() {
                if let Ok(db) = vp_rule::geoip::GeoIpDb::load(&p) {
                    info!("geoip 已加载: {}", p.display());
                    return Some(db);
                }
            }
        }
    }
    if let Some(u) = url {
        let u = u.to_string();
        let target = base_dir.join("geoip.metadb");
        info!("正在从远程拉取 geoip: {u}");
        let res =
            tokio::task::spawn_blocking(move || fetch_remote_binary(&u, "vpcore/geoip")).await;
        if let Ok(Ok(bytes)) = res {
            let _ = std::fs::write(&target, &bytes);
            if let Ok(db) = vp_rule::geoip::GeoIpDb::load(&target) {
                info!("geoip 远程拉取成功并已写入: {}", target.display());
                return Some(db);
            }
        }
    }
    info!("未找到 geoip 数据库文件 (geoip.metadb / Country.mmdb)，相关 GEOIP 规则将优雅跳过");
    None
}

/// 加载 ASN 数据库（GeoLite2-ASN.mmdb，用于 IP-ASN / SRC-IP-ASN 规则）
async fn load_asn(base_dir: &Path, url: Option<&str>) -> Option<vp_rule::asn::AsnDb> {
    let dirs = candidate_dirs(base_dir);
    for d in &dirs {
        for name in ["ASN.mmdb", "GeoLite2-ASN.mmdb", "asn.mmdb"] {
            let p = d.join(name);
            if p.exists() {
                if let Ok(db) = vp_rule::asn::AsnDb::load(&p) {
                    info!("asn 已加载: {}", p.display());
                    return Some(db);
                }
            }
        }
    }
    if let Some(u) = url {
        let u = u.to_string();
        let target = base_dir.join("ASN.mmdb");
        info!("正在从远程拉取 asn: {u}");
        let res = tokio::task::spawn_blocking(move || fetch_remote_binary(&u, "vpcore/asn")).await;
        if let Ok(Ok(bytes)) = res {
            let _ = std::fs::write(&target, &bytes);
            if let Ok(db) = vp_rule::asn::AsnDb::load(&target) {
                info!("asn 远程拉取成功并已写入: {}", target.display());
                return Some(db);
            }
        }
    }
    info!("未找到 ASN 数据库文件 (ASN.mmdb / GeoLite2-ASN.mmdb)，IP-ASN 规则将优雅跳过");
    None
}

#[cfg(test)]
#[cfg(test)]
mod tests;

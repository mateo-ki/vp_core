//! vp-protocol：出入站协议实现。
//!
//! M1：direct / reject / socks5 / http / shadowsocks / vmess / vless / trojan（出+入对称）

pub mod anytls;
pub mod basic_out;
pub mod brook;
pub mod chained;
pub mod direct;
pub mod h3_min;
pub mod hysteria;
pub mod hysteria2;
pub mod inbound;
pub mod mieru;
pub mod naive;
pub mod redir;
pub mod shadowtls;
pub mod smux;
#[cfg(feature = "snell")]
pub mod snell;
pub mod sniff;
#[cfg(feature = "ss")]
pub mod ss;
pub mod ssh;
pub mod ssr;
pub mod sub;
pub mod tailscale;
pub mod tproxy;
#[cfg(feature = "trojan")]
pub mod trojan;
pub mod tuic;
pub mod udp_out;
pub mod uot;
#[cfg(feature = "vless")]
pub mod vless;
#[cfg(feature = "vless")]
pub mod vless_vision;
#[cfg(feature = "vmess")]
pub mod vmess;
pub mod wireguard;

use std::sync::Arc;

use vp_common::DstAddr;
use vp_common::{Error, Result};
use vp_config::{
    AnytlsCfg, HttpCfg, NaiveCfg, ProxyCfg, ProxyKind, SocksCfg, SsCfg, TrojanCfg, VlessCfg,
    VmessCfg, WsOpts,
};
use vp_core::{Outbound, PacketConn, ProxyStream, Session};
use vp_dns::Resolver;
use vp_transport::{TransportConfig, WsConfig};

pub use basic_out::{HttpOutbound, RejectOutbound, Socks5Outbound};

/// 名称装饰器：让出站以配置名呈现
pub struct NamedOutbound<T> {
    name: Arc<str>,
    inner: T,
}

impl<T> NamedOutbound<T> {
    pub fn new_named(name: &str, inner: T) -> Self {
        NamedOutbound {
            name: name.into(),
            inner,
        }
    }
}

#[async_trait::async_trait]
impl<T: Outbound> Outbound for NamedOutbound<T> {
    fn name(&self) -> &str {
        &self.name
    }
    async fn connect_stream(&self, sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        self.inner.connect_stream(sess, dst).await
    }
    async fn connect_over(
        &self,
        sess: &Session,
        dst: &DstAddr,
        underlying: Box<dyn ProxyStream>,
    ) -> Result<Box<dyn ProxyStream>> {
        self.inner.connect_over(sess, dst, underlying).await
    }
    fn support_udp(&self) -> bool {
        self.inner.support_udp()
    }
    async fn connect_packet(&self, sess: &Session, dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        self.inner.connect_packet(sess, dst).await
    }
    fn remote_addr(&self) -> Option<(String, u16)> {
        self.inner.remote_addr()
    }
}
pub use direct::DirectOutbound;
pub use inbound::{InboundKind, build_inbound, build_inbound_with_gate, dispatch_stream};

/// 出站构建依赖
#[derive(Clone)]
pub struct OutboundDeps {
    pub dns: Arc<Resolver>,
    pub ipv6: bool,
}

fn ws_config(opts: &Option<WsOpts>) -> Option<WsConfig> {
    opts.as_ref().map(|w| WsConfig {
        path: w.path.clone().unwrap_or_else(|| "/".into()),
        headers: w
            .headers
            .clone()
            .map(|h| h.into_iter().collect::<Vec<_>>())
            .unwrap_or_default(),
        v2ray_http_upgrade: w.v2ray_http_upgrade,
    })
}

/// 从协议配置字段提取传输配置
pub fn transport_of(
    tls: bool,
    server_name: &Option<String>,
    skip_cert_verify: bool,
    network: &Option<String>,
    ws_opts: &Option<WsOpts>,
    fingerprint: &Option<String>,
) -> Result<TransportConfig> {
    transport_of_full(
        tls,
        server_name,
        skip_cert_verify,
        network,
        ws_opts,
        &None,
        fingerprint,
        &None,
        &None,
        &None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn transport_of_full(
    tls: bool,
    server_name: &Option<String>,
    skip_cert_verify: bool,
    network: &Option<String>,
    ws_opts: &Option<WsOpts>,
    grpc_opts: &Option<vp_config::GrpcOpts>,
    fingerprint: &Option<String>,
    reality_opts: &Option<vp_config::RealityOpts>,
    http_opts: &Option<vp_config::HttpOpts>,
    ech_opts: &Option<vp_config::EchOpts>,
) -> Result<TransportConfig> {
    let ws = match network.as_deref() {
        None | Some("tcp") | Some("") => None,
        Some("ws") => Some(ws_config(ws_opts).unwrap_or_default()),
        Some("httpupgrade") | Some("v2ray-http-upgrade") => {
            let mut cfg = ws_config(ws_opts).unwrap_or_default();
            cfg.v2ray_http_upgrade = true;
            Some(cfg)
        }
        Some("grpc") => None,
        Some("http") | Some("h2") => None,
        Some(other) => {
            return Err(Error::Unsupported(format!("传输 {other:?} 暂不支持")));
        }
    };
    let http = match network.as_deref() {
        Some("http") | Some("h2") => {
            let o = http_opts.clone().unwrap_or_default();
            Some(vp_transport::http::HttpConfig {
                method: o.method.unwrap_or_else(|| "GET".into()),
                path: o
                    .path
                    .and_then(|p| p.into_iter().next())
                    .unwrap_or_else(|| "/".into()),
                headers: o
                    .headers
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(k, vs)| (k, vs.join(", ")))
                    .collect(),
            })
        }
        _ => None,
    };
    let grpc = match network.as_deref() {
        Some("grpc") => Some(vp_transport::grpc::GrpcConfig {
            service_name: grpc_opts
                .as_ref()
                .and_then(|g| g.grpc_service_name.clone())
                .unwrap_or_else(|| "Turbo".into()),
        }),
        _ => None,
    };
    let reality = match reality_opts {
        Some(r) => Some(vp_transport::parse_reality_config(
            &r.public_key,
            r.short_id.as_deref(),
            r.spider_x.clone(),
        )?),
        None => None,
    };
    let ech = match ech_opts {
        Some(e) if e.enable => {
            let config = match &e.config {
                Some(c) => match crate::sub::decode_base64_flexible(c) {
                    Some(b) if !b.is_empty() => Some(b),
                    _ => {
                        tracing::warn!("ech-opts.config 不是合法 base64，忽略并改用 DNS 获取");
                        None
                    }
                },
                None => None,
            };
            Some(vp_transport::EchRequest {
                config,
                query_name: e.query_server_name.clone(),
                doh: e.doh.clone(),
            })
        }
        _ => None,
    };
    Ok(TransportConfig {
        tls: tls || reality.is_some(),
        server_name: server_name.clone(),
        skip_cert_verify,
        fingerprint: fingerprint.clone(),
        alpn: Vec::new(),
        ws,
        http,
        grpc,
        reality,
        ech,
        socket_opts: None,
    })
}

/// 惰性懒加载出站代理（Lazy Outbound）：
/// 启动时不创建 TLS 客户端配置、不派生加解密套件、不分配传输缓冲区；
/// 仅当该节点被选为活动流出口或被主动测速时，才由 OnceLock 线程安全地按需初始化。
/// 对拥有数百至上千节点的机场订阅，可直接降低 15~20 MB 堆内存常驻。
pub struct LazyOutbound {
    name: Arc<str>,
    cfg: ProxyCfg,
    deps: OutboundDeps,
    inner: std::sync::OnceLock<std::result::Result<Arc<dyn Outbound>, String>>,
}

impl LazyOutbound {
    pub fn new(cfg: ProxyCfg, deps: OutboundDeps) -> Self {
        Self {
            name: cfg.name.as_str().into(),
            cfg,
            deps,
            inner: std::sync::OnceLock::new(),
        }
    }

    fn get_or_init(&self) -> Result<Arc<dyn Outbound>> {
        let res = self
            .inner
            .get_or_init(|| build_outbound_eager(&self.cfg, &self.deps).map_err(|e| e.to_string()));
        match res {
            Ok(ob) => Ok(ob.clone()),
            Err(e) => Err(Error::Config(e.clone())),
        }
    }
}

#[async_trait::async_trait]
impl Outbound for LazyOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        if let Some(Ok(inner)) = self.inner.get() {
            return inner.remote_addr();
        }
        self.cfg.kind.remote_addr()
    }

    fn support_udp(&self) -> bool {
        if let Some(Ok(inner)) = self.inner.get() {
            return inner.support_udp();
        }
        if self.cfg.udp_over_tcp {
            return true;
        }
        self.cfg.kind.support_udp()
    }

    async fn connect_stream(&self, sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        self.get_or_init()?.connect_stream(sess, dst).await
    }

    async fn connect_over(
        &self,
        sess: &Session,
        dst: &DstAddr,
        underlying: Box<dyn ProxyStream>,
    ) -> Result<Box<dyn ProxyStream>> {
        self.get_or_init()?
            .connect_over(sess, dst, underlying)
            .await
    }

    async fn connect_packet(&self, sess: &Session, dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        self.get_or_init()?.connect_packet(sess, dst).await
    }
}

/// 根据配置构建单个出站（默认使用 LazyOutbound 惰性懒加载，大幅节省启动期内存）
pub fn build_outbound(cfg: &ProxyCfg, deps: &OutboundDeps) -> Result<Arc<dyn Outbound>> {
    match cfg.kind {
        ProxyKind::Direct => Ok(Arc::new(DirectOutbound::new(deps.dns.clone(), deps.ipv6))),
        ProxyKind::Reject => Ok(Arc::new(RejectOutbound)),
        _ => Ok(Arc::new(LazyOutbound::new(cfg.clone(), deps.clone()))),
    }
}

/// 立即全量构建出站协议实例（急切加载）
pub fn build_outbound_eager(cfg: &ProxyCfg, deps: &OutboundDeps) -> Result<Arc<dyn Outbound>> {
    let o: Arc<dyn Outbound> = match &cfg.kind {
        ProxyKind::Direct => Arc::new(DirectOutbound::new(deps.dns.clone(), deps.ipv6)),
        ProxyKind::Reject => Arc::new(RejectOutbound),
        ProxyKind::Hysteria(h) => Arc::new(hysteria::Hysteria1Outbound::new(h)?),
        ProxyKind::Hysteria2(h) => Arc::new(hysteria2::Hysteria2Outbound::new(h)?),
        ProxyKind::Tuic(t) => Arc::new(tuic::TuicOutbound::new(t)?),
        ProxyKind::Socks5(SocksCfg {
            server,
            port,
            username,
            password,
            udp,
            ..
        }) => Arc::new(NamedOutbound::new_named(
            &cfg.name,
            Socks5Outbound {
                server: server.clone(),
                port: *port,
                username: username.clone(),
                password: password.clone(),
                udp: *udp,
            },
        )),
        ProxyKind::Http(HttpCfg {
            server,
            port,
            username,
            password,
            tls,
            skip_cert_verify,
            sni,
        }) => Arc::new(NamedOutbound::new_named(
            &cfg.name,
            HttpOutbound {
                server: server.clone(),
                port: *port,
                username: username.clone(),
                password: password.clone(),
                tls: *tls,
                skip_cert_verify: *skip_cert_verify,
                sni: sni.clone(),
            },
        )),
        ProxyKind::Https(HttpCfg {
            server,
            port,
            username,
            password,
            tls: _,
            skip_cert_verify,
            sni,
        }) => Arc::new(NamedOutbound::new_named(
            &cfg.name,
            HttpOutbound {
                server: server.clone(),
                port: *port,
                username: username.clone(),
                password: password.clone(),
                tls: true,
                skip_cert_verify: *skip_cert_verify,
                sni: sni.clone(),
            },
        )),
        ProxyKind::Wireguard(wg) => Arc::new(wireguard::WgOutbound::new_named(
            cfg.name.as_str(),
            wg,
            deps.dns.clone(),
        )?),
        ProxyKind::Ss(ss) => build_ss(cfg.name.as_str(), ss)?,
        ProxyKind::Ssr(s) => Arc::new(ssr::SsrOutbound::new_named(
            cfg.name.as_str(),
            s,
            deps.dns.clone(),
        )?),
        ProxyKind::Vmess(vm) => build_vmess(cfg.name.as_str(), vm)?,
        ProxyKind::Vless(vl) => build_vless(cfg.name.as_str(), vl)?,
        ProxyKind::Trojan(tr) => build_trojan(cfg.name.as_str(), tr)?,
        #[cfg(feature = "snell")]
        ProxyKind::Snell(sn) => Arc::new(snell::SnellOutbound::new_named(cfg.name.as_str(), sn)?),
        #[cfg(not(feature = "snell"))]
        ProxyKind::Snell(_) => return Err(Error::Unsupported("snell 特性未编译".into())),
        ProxyKind::Anytls(a) => build_anytls(cfg, a)?,
        ProxyKind::Ssh(sh) => Arc::new(ssh::SshOutbound::new_named(cfg.name.as_str(), sh)?),
        ProxyKind::Brook(b) => Arc::new(brook::BrookOutbound::new_named(cfg.name.as_str(), b)?),
        ProxyKind::Mieru(m) => Arc::new(mieru::MieruOutbound::new_named(cfg.name.as_str(), m)?),
        ProxyKind::Naive(n) => build_naive(cfg, n)?,
        ProxyKind::Tailscale(ts) => Arc::new(tailscale::TailscaleOutbound::new_named(
            cfg.name.as_str(),
            ts,
        )?),
    };
    // udp-over-tcp（UoT）：流型协议出站的 UDP 包装
    let o = match cfg.kind {
        ProxyKind::Wireguard(_)
        | ProxyKind::Hysteria(_)
        | ProxyKind::Hysteria2(_)
        | ProxyKind::Tuic(_)
        | ProxyKind::Brook(_)
        | ProxyKind::Direct
        | ProxyKind::Reject => o,
        _ if cfg.udp_over_tcp => Arc::new(uot::UotOutbound::new(o, uot_version(cfg))),
        _ => o,
    };
    // smux 多路复用包装（仅流型协议出站生效）
    let o = match cfg.kind {
        ProxyKind::Wireguard(_)
        | ProxyKind::Hysteria(_)
        | ProxyKind::Hysteria2(_)
        | ProxyKind::Tuic(_)
        | ProxyKind::Direct
        | ProxyKind::Reject => o,
        _ => {
            if let Some(ref smux_cfg) = cfg.smux {
                if smux_cfg.enabled {
                    Arc::new(smux::SmuxOutbound::new(o, smux_cfg.clone()))
                } else {
                    o
                }
            } else {
                o
            }
        }
    };
    // 节点独立网络绑定包装（仅在节点显式配置了 interface-name 或 routing-mark 时生效）
    let o = if cfg.interface_name.is_some() || cfg.routing_mark.is_some() {
        let opts = vp_transport::SocketOpts {
            interface_name: cfg.interface_name.clone(),
            routing_mark: cfg.routing_mark,
        };
        Arc::new(BoundOutbound::new(o, opts))
    } else {
        o
    };
    Ok(o)
}

/// 节点专属出站网络绑定装饰器（为节点注入独立的 interface-name 与 routing-mark）
pub struct BoundOutbound {
    inner: Arc<dyn Outbound>,
    opts: vp_transport::SocketOpts,
}

impl BoundOutbound {
    pub fn new(inner: Arc<dyn Outbound>, opts: vp_transport::SocketOpts) -> Self {
        Self { inner, opts }
    }
}

#[async_trait::async_trait]
impl Outbound for BoundOutbound {
    fn name(&self) -> &str {
        self.inner.name()
    }

    async fn connect_stream(&self, sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        let opts = Some(self.opts.clone());
        vp_transport::CURRENT_SOCKET_OPTS
            .scope(opts, self.inner.connect_stream(sess, dst))
            .await
    }

    async fn connect_over(
        &self,
        sess: &Session,
        dst: &DstAddr,
        underlying: Box<dyn ProxyStream>,
    ) -> Result<Box<dyn ProxyStream>> {
        let opts = Some(self.opts.clone());
        vp_transport::CURRENT_SOCKET_OPTS
            .scope(opts, self.inner.connect_over(sess, dst, underlying))
            .await
    }

    fn support_udp(&self) -> bool {
        self.inner.support_udp()
    }

    async fn connect_packet(&self, sess: &Session, dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        let opts = Some(self.opts.clone());
        vp_transport::CURRENT_SOCKET_OPTS
            .scope(opts, self.inner.connect_packet(sess, dst))
            .await
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        self.inner.remote_addr()
    }
}

#[cfg(feature = "ss")]
use ss::SsOutbound;
#[cfg(feature = "ss")]
fn build_ss(name: &str, ss_cfg: &SsCfg) -> Result<Arc<dyn Outbound>> {
    Ok(Arc::new(SsOutbound::new_named(name, ss_cfg)?))
}

#[cfg(not(feature = "ss"))]
fn build_ss(_name: &str, _ss_cfg: &SsCfg) -> Result<Arc<dyn Outbound>> {
    Err(Error::Unsupported("此构建未启用 shadowsocks".into()))
}

#[cfg(feature = "vmess")]
use vmess::VmessOutbound;
#[cfg(feature = "vmess")]
fn build_vmess(name: &str, vm: &VmessCfg) -> Result<Arc<dyn Outbound>> {
    Ok(Arc::new(VmessOutbound::new_named(name, vm)?))
}

#[cfg(not(feature = "vmess"))]
fn build_vmess(_name: &str, _vm: &VmessCfg) -> Result<Arc<dyn Outbound>> {
    Err(Error::Unsupported("此构建未启用 vmess".into()))
}

#[cfg(feature = "vless")]
use vless::VlessOutbound;
#[cfg(feature = "vless")]
fn build_vless(name: &str, vl: &VlessCfg) -> Result<Arc<dyn Outbound>> {
    Ok(Arc::new(VlessOutbound::new_named(name, vl)?))
}

#[cfg(not(feature = "vless"))]
fn build_vless(_name: &str, _vl: &VlessCfg) -> Result<Arc<dyn Outbound>> {
    Err(Error::Unsupported("此构建未启用 vless".into()))
}

#[cfg(feature = "trojan")]
use trojan::TrojanOutbound;
#[cfg(feature = "trojan")]
fn build_trojan(name: &str, tr: &TrojanCfg) -> Result<Arc<dyn Outbound>> {
    Ok(Arc::new(TrojanOutbound::new_named(name, tr)?))
}

#[cfg(not(feature = "trojan"))]
fn build_trojan(_name: &str, _tr_cfg: &TrojanCfg) -> Result<Arc<dyn Outbound>> {
    Err(Error::Unsupported("此构建未启用 trojan".into()))
}

/// UoT 版本：显式配置优先；naive / anytls 缺省 2（sing-box 与 anytls 规范：anytls-go 服务端
/// 不论魔法地址都按 v2 读请求头），其余缺省 1（同 mihomo 文档）
fn uot_version(cfg: &ProxyCfg) -> u8 {
    cfg.udp_over_tcp_version.unwrap_or(match cfg.kind {
        ProxyKind::Naive(_) | ProxyKind::Anytls(_) => 2,
        _ => 1,
    })
}

fn build_anytls(cfg: &ProxyCfg, a: &AnytlsCfg) -> Result<Arc<dyn Outbound>> {
    let base: Arc<dyn Outbound> =
        Arc::new(anytls::AnytlsOutbound::new_named(cfg.name.as_str(), a)?);
    // anytls 无原生 UDP：udp: true 时经 UoT 提供（显式 udp-over-tcp 标志避免双包装）
    if a.udp && !cfg.udp_over_tcp {
        Ok(Arc::new(uot::UotOutbound::new(base, uot_version(cfg))))
    } else {
        Ok(base)
    }
}

fn build_naive(cfg: &ProxyCfg, n: &NaiveCfg) -> Result<Arc<dyn Outbound>> {
    let base: Arc<dyn Outbound> = Arc::new(naive::NaiveOutbound::new_named(cfg.name.as_str(), n)?);
    if n.udp && !cfg.udp_over_tcp {
        Ok(Arc::new(uot::UotOutbound::new(base, uot_version(cfg))))
    } else {
        Ok(base)
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use async_trait::async_trait;
    use std::sync::Arc;

    use vp_core::{Resolution, Router as RouterTrait, Session};

    pub struct NoopRouter();

    #[async_trait]
    impl RouterTrait for NoopRouter {
        async fn pick(&self, _sess: &Session) -> Resolution {
            let direct = Arc::new(crate::direct::DirectOutbound::new(
                Arc::new(vp_dns::Resolver::system()),
                false,
            ));
            Resolution {
                outbound: direct,
                via: "DIRECT".into(),
                rule: None,
            }
        }
    }

    /// 本地 UDP echo（原样回发）
    pub async fn udp_echo() -> std::net::SocketAddr {
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 65535];
            while let Ok((n, from)) = echo.recv_from(&mut b).await {
                let _ = echo.send_to(&b[..n], from).await;
            }
        });
        addr
    }

    /// 经 PacketConn 发几个数据报（含一个大包，验证分帧边界），逐个等回包核对
    pub async fn assert_udp_roundtrip(
        conn: &mut Box<dyn vp_core::PacketConn>,
        echo: std::net::SocketAddr,
    ) {
        let big = vec![0x5au8; 8000];
        for payload in [&b"first"[..], &big, b"third"] {
            conn.send(&vp_core::stream::UdpPacket {
                src: "0.0.0.0:0".parse().unwrap(),
                dst: echo,
                data: bytes::Bytes::copy_from_slice(payload),
            })
            .await
            .unwrap();
            let pkt = tokio::time::timeout(std::time::Duration::from_secs(5), conn.recv())
                .await
                .expect("UDP 回包超时")
                .unwrap();
            assert_eq!(&pkt.data[..], payload, "数据报内容 / 边界不一致");
        }
    }

    /// 同一个 PacketConn 发往第二个目标（full-cone：XUDP / packetaddr 单连接多目标），
    /// 回包来源必须是第二个目标
    pub async fn assert_udp_second_target(conn: &mut Box<dyn vp_core::PacketConn>) {
        let echo2 = udp_echo().await;
        conn.send(&vp_core::stream::UdpPacket {
            src: "0.0.0.0:0".parse().unwrap(),
            dst: echo2,
            data: bytes::Bytes::from_static(b"to-second"),
        })
        .await
        .unwrap();
        let pkt = tokio::time::timeout(std::time::Duration::from_secs(5), conn.recv())
            .await
            .expect("第二目标回包超时")
            .unwrap();
        assert_eq!(&pkt.data[..], b"to-second");
        assert_eq!(pkt.src, echo2, "回包来源应为第二个目标");
    }
}

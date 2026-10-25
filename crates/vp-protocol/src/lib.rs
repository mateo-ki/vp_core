//! vp-protocol：出入站协议实现。
//!
//! M1：direct / reject / socks5 / http / shadowsocks / vmess / vless / trojan（出+入对称）

pub mod basic_out;
pub mod direct;
pub mod hysteria2;
pub mod tuic;
pub mod redir;
pub mod inbound;
#[cfg(feature = "ss")]
pub mod ss;
#[cfg(feature = "trojan")]
pub mod trojan;
pub mod udp_out;
#[cfg(feature = "vless")]
pub mod vless;
#[cfg(feature = "vmess")]
pub mod vmess;

use std::sync::Arc;

use vp_common::{Error, Result};
use vp_config::{GroupCfg, GroupKind, HttpCfg, ProxyCfg, ProxyKind, SocksCfg, SsCfg, TrojanCfg, VlessCfg, VmessCfg, WsOpts};
use vp_core::{Outbound, PacketConn, ProxyStream, Session};
use vp_common::DstAddr;
use vp_dns::Resolver;
use vp_router::{GroupSpec, GroupType, LbStrategy};
use vp_transport::{TransportConfig, WsConfig};

#[cfg(test)]
pub(crate) mod test_support {
    use async_trait::async_trait;
    
    use vp_core::{Resolution, Router as RouterTrait, Session};

    pub struct NoopRouter();

    #[async_trait]
    impl RouterTrait for NoopRouter {
        async fn pick(&self, _sess: &Session) -> Resolution {
            unreachable!("noop router")
        }
    }

}

pub use basic_out::{HttpOutbound, RejectOutbound, Socks5Outbound};

/// 名称装饰器：让出站以配置名呈现
pub struct NamedOutbound<T> {
    name: Arc<str>,
    inner: T,
}

impl<T> NamedOutbound<T> {
    pub fn new_named(name: &str, inner: T) -> Self {
        NamedOutbound { name: name.into(), inner }
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
pub use inbound::{build_inbound, dispatch_stream, InboundKind};

/// 出站构建依赖
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
    })
}

/// 从协议配置字段提取传输配置
pub fn transport_of(
    tls: bool,
    server_name: &Option<String>,
    skip_cert_verify: bool,
    network: &Option<String>,
    ws_opts: &Option<WsOpts>,
) -> Result<TransportConfig> {
    transport_of_full(tls, server_name, skip_cert_verify, network, ws_opts, &None)
}

pub fn transport_of_full(
    tls: bool,
    server_name: &Option<String>,
    skip_cert_verify: bool,
    network: &Option<String>,
    ws_opts: &Option<WsOpts>,
    grpc_opts: &Option<vp_config::GrpcOpts>,
) -> Result<TransportConfig> {
    let ws = match network.as_deref() {
        None | Some("tcp") | Some("") => None,
        Some("ws") => Some(ws_config(ws_opts).unwrap_or_default()),
        Some("grpc") => None,
        Some(other) => {
            return Err(Error::Unsupported(format!("传输 {other:?} 暂不支持")));
        }
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
    Ok(TransportConfig {
        tls,
        server_name: server_name.clone(),
        skip_cert_verify,
        ws,
        grpc,
    })
}

/// 根据配置构建单个出站（不含组）
pub fn build_outbound(cfg: &ProxyCfg, deps: &OutboundDeps) -> Result<Arc<dyn Outbound>> {
    let o: Arc<dyn Outbound> = match &cfg.kind {
        ProxyKind::Direct => Arc::new(DirectOutbound::new(deps.dns.clone(), deps.ipv6)),
        ProxyKind::Reject => Arc::new(RejectOutbound),
        ProxyKind::Hysteria2(h) => Arc::new(hysteria2::Hysteria2Outbound::new(h)?),
        ProxyKind::Tuic(t) => Arc::new(tuic::TuicOutbound::new(t)?),
        ProxyKind::Socks5(SocksCfg { server, port, username, password, udp, .. }) => {
            Arc::new(NamedOutbound::new_named(
                &cfg.name,
                Socks5Outbound {
                    server: server.clone(),
                    port: *port,
                    username: username.clone(),
                    password: password.clone(),
                    udp: *udp,
                },
            ))
        }
        ProxyKind::Http(HttpCfg { server, port, username, password, .. }) => {
            Arc::new(NamedOutbound::new_named(
                &cfg.name,
                HttpOutbound {
                    server: server.clone(),
                    port: *port,
                    username: username.clone(),
                    password: password.clone(),
                },
            ))
        }
        ProxyKind::Ss(ss) => build_ss(cfg.name.as_str(), ss)?,
        ProxyKind::Vmess(vm) => build_vmess(cfg.name.as_str(), vm)?,
        ProxyKind::Vless(vl) => build_vless(cfg.name.as_str(), vl)?,
        ProxyKind::Trojan(tr) => build_trojan(cfg.name.as_str(), tr)?,
    };
    Ok(o)
}

/// 组定义转换
pub fn group_spec(g: &GroupCfg) -> GroupSpec {
    let ty = match g.kind {
        GroupKind::Select => GroupType::Select,
        GroupKind::UrlTest => GroupType::UrlTest,
        GroupKind::Fallback => GroupType::Fallback,
        GroupKind::LoadBalance => GroupType::LoadBalance,
        GroupKind::Relay => GroupType::Relay,
    };
    GroupSpec {
        name: g.name.clone(),
        ty,
        members: g.proxies.clone(),
        test_url: g.url.clone(),
        interval: g.interval.unwrap_or(300),
        tolerance: g.tolerance.unwrap_or(0),
        lazy: g.lazy.unwrap_or(true),
        lb_strategy: match g.strategy.as_deref() {
            Some("consistent-hashing") => LbStrategy::ConsistentHash,
            _ => LbStrategy::RoundRobin,
        },
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
fn build_trojan(_name: &str, _tr: &TrojanCfg) -> Result<Arc<dyn Outbound>> {
    Err(Error::Unsupported("此构建未启用 trojan".into()))
}

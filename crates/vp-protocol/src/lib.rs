//! vp-protocol：出入站协议实现。
//!
//! M1：direct / reject / socks5 / http / shadowsocks / vmess / vless / trojan（出+入对称）

pub mod basic_out;
pub mod direct;
pub mod inbound;
#[cfg(feature = "ss")]
pub mod ss;
#[cfg(feature = "trojan")]
pub mod trojan;
#[cfg(feature = "vless")]
pub mod vless;
#[cfg(feature = "vmess")]
pub mod vmess;

use std::sync::Arc;

use vp_common::{Error, Result};
use vp_config::{GroupCfg, GroupKind, HttpCfg, ProxyCfg, ProxyKind, SocksCfg, SsCfg, TrojanCfg, VlessCfg, VmessCfg, WsOpts};
use vp_core::Outbound;
use vp_dns::Resolver;
use vp_router::{GroupSpec, GroupType, LbStrategy};
use vp_transport::{TransportConfig, WsConfig};

pub use basic_out::{HttpOutbound, RejectOutbound, Socks5Outbound};
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
    let ws = match network.as_deref() {
        None | Some("tcp") | Some("") => None,
        Some("ws") => Some(ws_config(ws_opts).unwrap_or_default()),
        Some(other) => {
            return Err(Error::Unsupported(format!("传输 {other:?} 将在 M3 里程碑提供")));
        }
    };
    Ok(TransportConfig {
        tls,
        server_name: server_name.clone(),
        skip_cert_verify,
        ws,
    })
}

/// 根据配置构建单个出站（不含组）
pub fn build_outbound(cfg: &ProxyCfg, deps: &OutboundDeps) -> Result<Arc<dyn Outbound>> {
    let o: Arc<dyn Outbound> = match &cfg.kind {
        ProxyKind::Direct => Arc::new(DirectOutbound::new(deps.dns.clone(), deps.ipv6)),
        ProxyKind::Reject => Arc::new(RejectOutbound),
        ProxyKind::Socks5(SocksCfg { server, port, username, password, .. }) => {
            Arc::new(Socks5Outbound {
                server: server.clone(),
                port: *port,
                username: username.clone(),
                password: password.clone(),
            })
        }
        ProxyKind::Http(HttpCfg { server, port, username, password, .. }) => Arc::new(HttpOutbound {
            server: server.clone(),
            port: *port,
            username: username.clone(),
            password: password.clone(),
        }),
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
fn build_ss(_name: &str, ss_cfg: &SsCfg) -> Result<Arc<dyn Outbound>> {
    Ok(Arc::new(SsOutbound::new(ss_cfg)?))
}

#[cfg(not(feature = "ss"))]
fn build_ss(_name: &str, _ss_cfg: &SsCfg) -> Result<Arc<dyn Outbound>> {
    Err(Error::Unsupported("此构建未启用 shadowsocks".into()))
}

#[cfg(feature = "vmess")]
use vmess::VmessOutbound;
#[cfg(feature = "vmess")]
fn build_vmess(_name: &str, vm: &VmessCfg) -> Result<Arc<dyn Outbound>> {
    Ok(Arc::new(VmessOutbound::new(vm)?))
}

#[cfg(not(feature = "vmess"))]
fn build_vmess(_name: &str, _vm: &VmessCfg) -> Result<Arc<dyn Outbound>> {
    Err(Error::Unsupported("此构建未启用 vmess".into()))
}

#[cfg(feature = "vless")]
use vless::VlessOutbound;
#[cfg(feature = "vless")]
fn build_vless(_name: &str, vl: &VlessCfg) -> Result<Arc<dyn Outbound>> {
    Ok(Arc::new(VlessOutbound::new(vl)?))
}

#[cfg(not(feature = "vless"))]
fn build_vless(_name: &str, _vl: &VlessCfg) -> Result<Arc<dyn Outbound>> {
    Err(Error::Unsupported("此构建未启用 vless".into()))
}

#[cfg(feature = "trojan")]
use trojan::TrojanOutbound;
#[cfg(feature = "trojan")]
fn build_trojan(_name: &str, tr: &TrojanCfg) -> Result<Arc<dyn Outbound>> {
    Ok(Arc::new(TrojanOutbound::new(tr)?))
}

#[cfg(not(feature = "trojan"))]
fn build_trojan(_name: &str, _tr: &TrojanCfg) -> Result<Arc<dyn Outbound>> {
    Err(Error::Unsupported("此构建未启用 trojan".into()))
}

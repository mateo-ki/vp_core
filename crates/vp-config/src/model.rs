//! 配置 IR：Clash 兼容 schema（YAML / JSON 同构双前端）。

use serde::{Deserialize, Deserializer};
use std::collections::HashMap;

/// null 视为缺省（兼容手写配置中的空键）
fn null_to_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn default_mode() -> Mode {
    Mode::Rule
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Rule,
    Global,
    Direct,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// HTTP+SOCKS5 同端口
    #[serde(alias = "mixed-port", alias = "mixed_port", default)]
    pub mixed_port: Option<u16>,
    /// 纯 HTTP 代理端口
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(alias = "socks-port", alias = "socks_port", default)]
    pub socks_port: Option<u16>,
    #[serde(alias = "redir-port", alias = "redir_port", default)]
    pub redir_port: Option<u16>,
    #[serde(alias = "tproxy-port", alias = "tproxy_port", default)]
    pub tproxy_port: Option<u16>,
    #[serde(alias = "allow-lan", alias = "allow_lan", default)]
    pub allow_lan: bool,
    #[serde(alias = "bind-address", alias = "bind_address", default = "default_bind")]
    pub bind_address: String,
    #[serde(default = "default_mode")]
    pub mode: Mode,
    #[serde(alias = "log-level", alias = "log_level", default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub ipv6: bool,
    #[serde(alias = "external-controller", alias = "external_controller", default)]
    pub external_controller: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub dns: DnsConfig,
    #[serde(default, deserialize_with = "null_to_default")]
    pub proxies: Vec<ProxyCfg>,
    #[serde(alias = "proxy-groups", alias = "proxy_groups", default, deserialize_with = "null_to_default")]
    pub proxy_groups: Vec<GroupCfg>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub rules: Vec<String>,
    #[serde(alias = "sub-rules", alias = "sub_rules", default, deserialize_with = "null_to_default")]
    pub sub_rules: HashMap<String, Vec<String>>,
    #[serde(alias = "rule-providers", alias = "rule_providers", default, deserialize_with = "null_to_default")]
    pub rule_providers: HashMap<String, RuleProviderCfg>,
    #[serde(default)]
    pub tun: Option<TunCfg>,
    /// 协议服务端入站（自建服务器场景）
    #[serde(default)]
    pub listeners: Vec<ListenerCfg>,
}

/// 服务端入站定义（M1：trojan/vmess/vless/ss，TLS 证书项随 M3 补）
#[derive(Debug, Clone, Deserialize)]
pub struct ListenerCfg {
    pub name: String,
    /// trojan / vmess / vless / ss
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub port: u16,
    /// trojan: 密码列表；vmess/vless: uuid 列表；ss: 单密码
    #[serde(default)]
    pub users: Vec<String>,
    /// ss 加密方式
    #[serde(default)]
    pub cipher: Option<String>,
    /// TLS 证书 PEM 路径（可选；提供则套 TLS）
    #[serde(default)]
    pub cert: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    /// shadow-tls v3 外层伪装（ss listener 可选；host 为伪装转发目标）
    #[serde(alias = "shadow-tls", alias = "shadowtls", alias = "shadow-tls-opts", alias = "shadow_tls_opts", default)]
    pub shadow_tls: Option<ShadowTlsCfg>,
}

/// TUN 配置段（Clash 风格）
#[derive(Debug, Clone, Deserialize)]
pub struct TunCfg {
    #[serde(default = "default_true")]
    pub enable: bool,
    #[serde(default = "default_tun_addr")]
    pub address: String,
    #[serde(default = "default_tun_mask")]
    pub netmask: String,
    #[serde(default = "default_tun_mtu")]
    pub mtu: u16,
    #[serde(alias = "fake-ip-range", alias = "fake_ip_range", default = "default_fake_range")]
    pub fake_ip_range: String,
    #[serde(alias = "auto-route", alias = "auto_route", default = "default_true")]
    pub auto_route: bool,
    #[serde(default)]
    pub auto_redirect: Option<bool>,
}

fn default_true() -> bool {
    true
}

fn default_tun_addr() -> String {
    "198.18.0.1".into()
}

fn default_tun_mask() -> String {
    "255.255.0.0".into()
}

fn default_tun_mtu() -> u16 {
    1500
}

fn default_fake_range() -> String {
    "198.18.0.0/16".into()
}

fn default_bind() -> String {
    "*".into()
}

fn default_log_level() -> String {
    "info".into()
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DnsConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(default)]
    pub ipv6: bool,
    #[serde(alias = "enhanced-mode", alias = "enhanced_mode", default)]
    pub enhanced_mode: Option<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub nameserver: Vec<String>,
    #[serde(alias = "default-nameserver", alias = "default_nameserver", default)]
    pub default_nameserver: Vec<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub fallback: Vec<String>,
    #[serde(alias = "fake-ip-range", alias = "fake_ip_range", default)]
    pub fake_ip_range: Option<String>,
}

/// 节点定义：name + 扁平化协议参数
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyCfg {
    pub name: String,
    /// UDP over TCP（UoT v1）：仅流型协议出站生效
    #[serde(default, alias = "udp_over_tcp")]
    pub udp_over_tcp: bool,
    #[serde(flatten)]
    pub kind: ProxyKind,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ProxyKind {
    Ss(SsCfg),
    Vmess(VmessCfg),
    Vless(VlessCfg),
    Trojan(TrojanCfg),
    Anytls(AnytlsCfg),
    Socks5(SocksCfg),
    Tuic(TuicCfg),
    Hysteria2(Hysteria2Cfg),
    Http(HttpCfg),
    Wireguard(WgCfg),
    Direct,
    Reject,
}

impl ProxyKind {
    /// 协议类型名（与配置 "type" 一致）
    pub fn type_name(&self) -> &'static str {
        match self {
            ProxyKind::Ss(_) => "ss",
            ProxyKind::Vmess(_) => "vmess",
            ProxyKind::Vless(_) => "vless",
            ProxyKind::Trojan(_) => "trojan",
            ProxyKind::Anytls(_) => "anytls",
            ProxyKind::Socks5(_) => "socks5",
            ProxyKind::Hysteria2(_) => "hysteria2",
            ProxyKind::Tuic(_) => "tuic",
            ProxyKind::Http(_) => "http",
            ProxyKind::Wireguard(_) => "wireguard",
            ProxyKind::Direct => "direct",
            ProxyKind::Reject => "reject",
        }
    }
}

/// TLS 相关公共字段说明（各协议结构体中显式重复声明以保持 serde 派生简单）：
/// tls / server_name(aliases: servername, sni) / skip_cert_verify / network / ws_opts

#[derive(Debug, Clone, Deserialize)]
pub struct GrpcOpts {
    #[serde(alias = "grpc-service-name", alias = "grpc_service_name", default)]
    pub grpc_service_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WsOpts {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    #[serde(alias = "max-early-data", alias = "max_early_data", default)]
    pub max_early_data: Option<u64>,
}

/// shadow-tls v3 伪装选项。字段全 Option 以容忍其它插件（如 simple-obfs）的
/// plugin-opts 形状——只在 plugin 为 shadow-tls 时才要求 host/password。
#[derive(Debug, Clone, Deserialize)]
pub struct ShadowTlsCfg {
    /// 伪装站域名（客户端写入 ClientHello SNI；服务端转发伪装目标）
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// 伪装站端口（默认 443）
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub version: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SsCfg {
    pub server: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
    #[serde(default)]
    pub udp: bool,
    /// 插件名：shadow-tls 由内核原生支持；其它（如 simple-obfs）记录警告并忽略
    #[serde(default)]
    pub plugin: Option<String>,
    #[serde(alias = "plugin-opts", alias = "plugin_opts", default)]
    pub plugin_opts: Option<ShadowTlsCfg>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VmessCfg {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    #[serde(alias = "alterId", alias = "alter_id", default)]
    pub alter_id: u32,
    #[serde(alias = "cipher", alias = "security", default = "default_vmess_cipher")]
    pub cipher: String,
    #[serde(default)]
    pub tls: bool,
    #[serde(alias = "servername", alias = "server-name", alias = "server_name", alias = "sni", default)]
    pub server_name: Option<String>,
    #[serde(alias = "skip-cert-verify", alias = "skip_cert_verify", default)]
    pub skip_cert_verify: bool,
    #[serde(alias = "client-fingerprint", alias = "client_fingerprint", default)]
    pub client_fingerprint: Option<String>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(alias = "ws-opts", alias = "ws_opts", default)]
    pub ws_opts: Option<WsOpts>,
    #[serde(alias = "grpc-opts", alias = "grpc_opts", default)]
    pub grpc_opts: Option<GrpcOpts>,
    #[serde(default)]
    pub udp: bool,
}

fn default_vmess_cipher() -> String {
    "auto".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct VlessCfg {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub tls: bool,
    #[serde(alias = "servername", alias = "server-name", alias = "server_name", alias = "sni", default)]
    pub server_name: Option<String>,
    #[serde(alias = "skip-cert-verify", alias = "skip_cert_verify", default)]
    pub skip_cert_verify: bool,
    #[serde(alias = "client-fingerprint", alias = "client_fingerprint", default)]
    pub client_fingerprint: Option<String>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(alias = "ws-opts", alias = "ws_opts", default)]
    pub ws_opts: Option<WsOpts>,
    #[serde(alias = "grpc-opts", alias = "grpc_opts", default)]
    pub grpc_opts: Option<GrpcOpts>,
    #[serde(default)]
    pub udp: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrojanCfg {
    pub server: String,
    pub port: u16,
    pub password: String,
    #[serde(default)]
    pub tls: bool,
    #[serde(alias = "servername", alias = "server-name", alias = "server_name", alias = "sni", default)]
    pub server_name: Option<String>,
    #[serde(alias = "skip-cert-verify", alias = "skip_cert_verify", default)]
    pub skip_cert_verify: bool,
    #[serde(alias = "client-fingerprint", alias = "client_fingerprint", default)]
    pub client_fingerprint: Option<String>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(alias = "ws-opts", alias = "ws_opts", default)]
    pub ws_opts: Option<WsOpts>,
    #[serde(alias = "grpc-opts", alias = "grpc_opts", default)]
    pub grpc_opts: Option<GrpcOpts>,
    #[serde(default)]
    pub udp: bool,
}

/// anytls：TLS 之上的多路复用流协议（sing-anytls v2）。协议本身强制 TLS。
#[derive(Debug, Clone, Deserialize)]
pub struct AnytlsCfg {
    pub server: String,
    pub port: u16,
    pub password: String,
    #[serde(alias = "servername", alias = "server-name", alias = "server_name", alias = "sni", default)]
    pub server_name: Option<String>,
    #[serde(alias = "skip-cert-verify", alias = "skip_cert_verify", default)]
    pub skip_cert_verify: bool,
    #[serde(alias = "client-fingerprint", alias = "client_fingerprint", default)]
    pub client_fingerprint: Option<String>,
    #[serde(default)]
    pub udp: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Hysteria2Cfg {
    pub server: String,
    pub port: u16,
    pub password: String,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(alias = "skip-cert-verify", alias = "skip_cert_verify", default)]
    pub skip_cert_verify: bool,
    #[serde(default)]
    pub up: Option<u32>,
    #[serde(default)]
    pub down: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TuicCfg {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub password: String,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(alias = "skip-cert-verify", alias = "skip_cert_verify", default)]
    pub skip_cert_verify: bool,
    #[serde(alias = "congestion-controller", alias = "congestion_controller", default)]
    pub congestion_controller: Option<String>,
    #[serde(default)]
    pub udp_relay_mode: Option<String>,
}

/// WireGuard 出站配置（Clash 语法）。
#[derive(Debug, Clone, Deserialize)]
pub struct WgCfg {
    pub server: String,
    pub port: u16,
    #[serde(alias = "private-key", alias = "private_key")]
    pub private_key: String,
    #[serde(alias = "public-key", alias = "public_key")]
    pub public_key: String,
    #[serde(alias = "pre-shared-key", alias = "pre_shared_key", default)]
    pub pre_shared_key: Option<String>,
    #[serde(alias = "persistent-keepalive", alias = "persistent_keepalive", default)]
    pub persistent_keepalive: Option<u16>,
    /// 本机隧道 IPv4 地址（点对点）
    pub ip: String,
    /// 本机隧道 IPv6 地址（可选）
    #[serde(default)]
    pub ipv6: Option<String>,
    #[serde(default)]
    pub udp: bool,
    #[serde(default)]
    pub mtu: Option<u16>,
}

impl WgCfg {
    pub fn local_v4(&self) -> Option<std::net::Ipv4Addr> {
        self.ip.parse().ok()
    }

    pub fn local_v6(&self) -> Option<std::net::Ipv6Addr> {
        self.ipv6.as_deref().and_then(|s| s.parse().ok())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SocksCfg {
    pub server: String,
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub udp: bool,
    #[serde(default)]
    pub tls: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HttpCfg {
    pub server: String,
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub tls: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GroupCfg {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: GroupKind,
    pub proxies: Vec<String>,
    #[serde(default)]
    pub url: Option<String>,
    /// 健康检查间隔（秒）
    #[serde(default)]
    pub interval: Option<u64>,
    /// url-test 容差（毫秒）
    #[serde(default)]
    pub tolerance: Option<u32>,
    #[serde(default)]
    pub lazy: Option<bool>,
    #[serde(default)]
    pub strategy: Option<String>,
    #[serde(alias = "disable-udp", alias = "disable_udp", default)]
    pub disable_udp: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupKind {
    Select,
    UrlTest,
    Fallback,
    LoadBalance,
    Relay,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleProviderCfg {
    /// domain / ipcidr / classical
    #[serde(default)]
    pub behavior: Option<String>,
    /// yaml / text / mrs
    #[serde(default)]
    pub format: Option<String>,
    pub path: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub interval: Option<u64>,
}

/// 内置出站名
pub const BUILTIN_DIRECT: &str = "DIRECT";
pub const BUILTIN_REJECT: &str = "REJECT";

pub fn is_builtin(name: &str) -> bool {
    matches!(name, "DIRECT" | "REJECT" | "REJECT-DROP" | "PASS" | "GLOBAL" | "COMPATIBLE")
}

//! 配置 IR：Clash 兼容 schema（YAML / JSON 同构双前端）。

use serde::Deserialize;
use std::collections::HashMap;

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
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub proxies: Vec<ProxyCfg>,
    #[serde(alias = "proxy-groups", alias = "proxy_groups", default)]
    pub proxy_groups: Vec<GroupCfg>,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(alias = "sub-rules", alias = "sub_rules", default)]
    pub sub_rules: HashMap<String, Vec<String>>,
    #[serde(alias = "rule-providers", alias = "rule_providers", default)]
    pub rule_providers: HashMap<String, RuleProviderCfg>,
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
    #[serde(default)]
    pub nameserver: Vec<String>,
    #[serde(alias = "default-nameserver", alias = "default_nameserver", default)]
    pub default_nameserver: Vec<String>,
    #[serde(default)]
    pub fallback: Vec<String>,
    #[serde(alias = "fake-ip-range", alias = "fake_ip_range", default)]
    pub fake_ip_range: Option<String>,
}

/// 节点定义：name + 扁平化协议参数
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyCfg {
    pub name: String,
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
    Socks5(SocksCfg),
    Http(HttpCfg),
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
            ProxyKind::Socks5(_) => "socks5",
            ProxyKind::Http(_) => "http",
            ProxyKind::Direct => "direct",
            ProxyKind::Reject => "reject",
        }
    }
}

/// TLS 相关公共字段说明（各协议结构体中显式重复声明以保持 serde 派生简单）：
/// tls / server_name(aliases: servername, sni) / skip_cert_verify / network / ws_opts

#[derive(Debug, Clone, Deserialize)]
pub struct WsOpts {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    #[serde(alias = "max-early-data", alias = "max_early_data", default)]
    pub max_early_data: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SsCfg {
    pub server: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
    #[serde(default)]
    pub udp: bool,
    /// 插件名（如 simple-obfs）；M1 记录并警告，转发能力由内核插件体系承担
    #[serde(default)]
    pub plugin: Option<String>,
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
    #[serde(default)]
    pub network: Option<String>,
    #[serde(alias = "ws-opts", alias = "ws_opts", default)]
    pub ws_opts: Option<WsOpts>,
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
    #[serde(default)]
    pub network: Option<String>,
    #[serde(alias = "ws-opts", alias = "ws_opts", default)]
    pub ws_opts: Option<WsOpts>,
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
    #[serde(default)]
    pub network: Option<String>,
    #[serde(alias = "ws-opts", alias = "ws_opts", default)]
    pub ws_opts: Option<WsOpts>,
    #[serde(default)]
    pub udp: bool,
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

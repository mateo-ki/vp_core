//! 配置 IR：Clash 兼容 schema（YAML / JSON 同构双前端）。

use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

/// null 视为缺省（兼容手写配置中的空键）
fn null_to_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// 数字字段宽容反序列化：真实订阅里 "0"/"443" 这类字符串数字很常见，
/// 严格 u32/u16 会让整个内核因单个节点拒绝启动。
#[derive(Deserialize)]
#[serde(untagged)]
enum LenientNum {
    Num(u64),
    Str(String),
}

fn de_u64_lenient<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error as _;
    match LenientNum::deserialize(deserializer)? {
        LenientNum::Num(n) => Ok(n),
        LenientNum::Str(s) => s
            .trim()
            .parse::<u64>()
            .map_err(|_| D::Error::custom(format!("无效数字: {s}"))),
    }
}

fn de_u32_lenient<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    de_u64_lenient(deserializer).map(|v| v as u32)
}

fn de_u16_lenient<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    de_u64_lenient(deserializer).map(|v| v as u16)
}

/// ALPN 宽容反序列化：接受字符串（逗号分隔或单值）或字符串列表
fn de_alpn_list_lenient<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    let val = Option::<serde_yaml::Value>::deserialize(deserializer)?;
    let Some(val) = val else {
        return Ok(Vec::new());
    };
    match val {
        serde_yaml::Value::Sequence(items) => Ok(items
            .into_iter()
            .filter_map(|v| v.as_str().map(|s| s.trim().to_owned()))
            .filter(|s| !s.is_empty())
            .collect()),
        serde_yaml::Value::String(s) => Ok(s
            .split(',')
            .map(|p| p.trim().to_owned())
            .filter(|p| !p.is_empty())
            .collect()),
        serde_yaml::Value::Null => Ok(Vec::new()),
        other => Err(D::Error::custom(format!("alpn 非法: {other:?}"))),
    }
}

fn de_opt_bandwidth_mbps<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error as _;
    let opt = Option::<LenientNum>::deserialize(deserializer)?;
    let Some(item) = opt else {
        return Ok(None);
    };
    match item {
        LenientNum::Num(n) => Ok(Some(n as u32)),
        LenientNum::Str(s) => {
            let s = s.trim();
            if s.is_empty() {
                return Ok(None);
            }
            let lower = s.to_ascii_lowercase();
            let (num_part, unit) = if let Some(idx) = lower.find(|c: char| c.is_alphabetic()) {
                (&lower[..idx], lower[idx..].trim())
            } else {
                (lower.as_str(), "")
            };
            let num: f64 = num_part
                .trim()
                .parse()
                .map_err(|_| D::Error::custom(format!("无效带宽数字: {s}")))?;
            let mbps = if unit.contains("gb") {
                (num * 1000.0) as u32
            } else if unit.contains("kb") {
                (num / 1000.0).max(1.0) as u32
            } else if unit.contains("mb") || unit.contains('m') {
                num as u32
            } else if unit.contains("bps") || unit.contains('b') {
                (num / 1_000_000.0).max(1.0) as u32
            } else {
                num as u32
            };
            Ok(Some(mbps))
        }
    }
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
    #[serde(
        alias = "bind-address",
        alias = "bind_address",
        default = "default_bind"
    )]
    pub bind_address: String,
    #[serde(default = "default_mode")]
    pub mode: Mode,
    #[serde(
        alias = "log-level",
        alias = "log_level",
        default = "default_log_level"
    )]
    pub log_level: String,
    #[serde(default)]
    pub ipv6: bool,
    /// 连接资源预算（审计报告任务2；缺省不限）
    #[serde(
        alias = "resource-limits",
        alias = "resource_limits",
        default,
        deserialize_with = "null_to_default"
    )]
    pub resource_limits: ResourceLimitsConfig,
    #[serde(alias = "external-controller", alias = "external_controller", default)]
    pub external_controller: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub dns: DnsConfig,
    #[serde(default, deserialize_with = "null_to_default")]
    pub proxies: Vec<ProxyCfg>,
    #[serde(
        alias = "proxy-groups",
        alias = "proxy_groups",
        default,
        deserialize_with = "null_to_default"
    )]
    pub proxy_groups: Vec<GroupCfg>,
    #[serde(
        alias = "proxy-providers",
        alias = "proxy_providers",
        default,
        deserialize_with = "null_to_default"
    )]
    pub proxy_providers: HashMap<String, ProxyProviderCfg>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub rules: Vec<String>,
    #[serde(
        alias = "sub-rules",
        alias = "sub_rules",
        default,
        deserialize_with = "null_to_default"
    )]
    pub sub_rules: HashMap<String, Vec<String>>,
    #[serde(
        alias = "rule-providers",
        alias = "rule_providers",
        default,
        deserialize_with = "null_to_default"
    )]
    pub rule_providers: HashMap<String, RuleProviderCfg>,
    #[serde(alias = "geosite-url", alias = "geosite_url", default)]
    pub geosite_url: Option<String>,
    #[serde(alias = "geoip-url", alias = "geoip_url", default)]
    pub geoip_url: Option<String>,
    /// ASN 数据库（GeoLite2-ASN.mmdb）下载地址，用于 IP-ASN / SRC-IP-ASN 规则
    #[serde(alias = "asn-url", alias = "asn_url", default)]
    pub asn_url: Option<String>,
    #[serde(default)]
    pub tun: Option<TunCfg>,
    /// 协议服务端入站（自建服务器/透明网关/多入站场景）
    #[serde(alias = "inbounds", default)]
    pub listeners: Vec<ListenerCfg>,
    /// 性能与套接字缓冲区调优
    #[serde(default)]
    pub tuning: Option<TuningConfig>,
    /// Linux 出站数据包路由标记（SO_MARK / fwmark，用于 iptables/nftables TPROXY 防环路）
    #[serde(alias = "routing-mark", alias = "fwmark", default)]
    pub routing_mark: Option<u32>,
    /// 出站强制绑定的物理网卡名称（如 eth0 / en0，用于透明网关或 TUN 模式防环路）
    #[serde(
        alias = "interface-name",
        alias = "bind-interface",
        alias = "bind_interface",
        default
    )]
    pub interface_name: Option<String>,
    /// 静态域名解析映射表（hosts 节，值可为单个 IP 字符串或 IP 列表）
    #[serde(default, deserialize_with = "de_hosts_map")]
    pub hosts: HashMap<String, Vec<String>>,
}

fn de_hosts_map<'de, D>(deserializer: D) -> Result<HashMap<String, Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<HashMap<String, serde_yaml::Value>>::deserialize(deserializer)?;
    let Some(raw) = opt else {
        return Ok(HashMap::new());
    };
    let mut out = HashMap::new();
    for (k, v) in raw {
        let mut list = Vec::new();
        match v {
            serde_yaml::Value::String(s) => list.push(s),
            serde_yaml::Value::Sequence(seq) => {
                for item in seq {
                    if let Some(s) = item.as_str() {
                        list.push(s.to_string());
                    }
                }
            }
            _ => {}
        }
        if !list.is_empty() {
            out.insert(k, list);
        }
    }
    Ok(out)
}

/// 连接资源预算配置（resource-limits 节）
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ResourceLimitsConfig {
    #[serde(
        alias = "max-connections",
        alias = "max_connections",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_connections: Option<u32>,
    #[serde(
        alias = "max-connections-per-inbound",
        alias = "max_connections_per_inbound",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_connections_per_inbound: Option<u32>,
}

/// 性能与套接字参数调优配置
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct TuningConfig {
    /// 统一设置 SO_RCVBUF 与 SO_SNDBUF 大小（字节，如 524288 即 512KB）
    #[serde(alias = "socket-buffer-size", alias = "socket_buffer_size", default)]
    pub socket_buffer_size: Option<usize>,
    #[serde(alias = "so-rcvbuf", alias = "so_rcvbuf", default)]
    pub so_rcvbuf: Option<usize>,
    #[serde(alias = "so-sndbuf", alias = "so_sndbuf", default)]
    pub so_sndbuf: Option<usize>,
    /// 禁用 Nagle 算法以降低交互式数据包延迟（默认 true）
    #[serde(alias = "tcp-nodelay", alias = "tcp_nodelay", default = "default_true")]
    pub tcp_nodelay: bool,
    /// TCP Keepalive 保活空闲周期（秒，默认 60）
    #[serde(alias = "tcp-keepalive-secs", alias = "tcp_keepalive_secs", default)]
    pub tcp_keepalive_secs: Option<u64>,
}

/// 服务端入站定义（支持 tproxy/redir/mixed/socks5/http/trojan/vmess/vless/ss）
#[derive(Debug, Clone, Deserialize)]
pub struct ListenerCfg {
    pub name: String,
    /// trojan / vmess / vless / ss / anytls / mieru / tproxy / redir / mixed / socks5 / http
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    #[serde(deserialize_with = "de_u16_lenient")]
    pub port: u16,
    /// 监听绑定 IP（默认 "0.0.0.0"）
    #[serde(
        alias = "bind-address",
        alias = "bind_address",
        alias = "listen",
        default
    )]
    pub listen: Option<String>,
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
    #[serde(
        alias = "shadow-tls",
        alias = "shadowtls",
        alias = "shadow-tls-opts",
        alias = "shadow_tls_opts",
        default
    )]
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
    #[serde(
        alias = "fake-ip-range",
        alias = "fake_ip_range",
        default = "default_fake_range"
    )]
    pub fake_ip_range: String,
    #[serde(alias = "auto-route", alias = "auto_route", default = "default_true")]
    pub auto_route: bool,
    /// 自动路由模式：full（默认，接管 0.0.0.0/1 与 128.0.0.0/1 全流量）或 fake-ip-only（仅接管 fake-ip 网段）
    #[serde(alias = "auto-route-mode", alias = "auto_route_mode", default)]
    pub auto_route_mode: Option<String>,
    /// 自定义 TUN 接管的目标 CIDR 地址列表（若指定则额外下发）
    #[serde(
        alias = "route-address",
        alias = "route_address",
        default,
        deserialize_with = "null_to_default"
    )]
    pub route_address: Vec<String>,
    /// 排除的 CIDR 路由列表
    #[serde(
        alias = "route-exclude-address",
        alias = "route_exclude_address",
        default,
        deserialize_with = "null_to_default"
    )]
    pub route_exclude_address: Vec<String>,
    #[serde(default)]
    pub auto_redirect: Option<bool>,
    /// 移动端 (Android / iOS) 外部注入的文件描述符
    #[serde(default)]
    pub fd: Option<i32>,
    /// Windows Wintun 环形缓冲区容量（字节，必须为 2 的幂，范围 128KB ~ 64MB，默认 4MB: 0x400000）
    #[serde(alias = "ring-capacity", alias = "ring_capacity", default)]
    pub ring_capacity: Option<u32>,
    /// 严格模式：TUN / DNS 启动失败时不静默降级，直接报错返回
    #[serde(default)]
    pub strict: Option<bool>,
}

impl Default for TunCfg {
    fn default() -> Self {
        Self {
            enable: true,
            address: default_tun_addr(),
            netmask: default_tun_mask(),
            mtu: default_tun_mtu(),
            fake_ip_range: default_fake_range(),
            auto_route: true,
            auto_route_mode: None,
            route_address: Vec::new(),
            route_exclude_address: Vec::new(),
            auto_redirect: None,
            fd: None,
            ring_capacity: None,
            strict: None,
        }
    }
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
    pub ipv6: Option<bool>,
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
    /// fake-ip 过滤名单：命中域名返回真实 IP 而非假 IP（`+.x` / `*.x` / 裸域名）
    #[serde(alias = "fake-ip-filter", alias = "fake_ip_filter", default)]
    pub fake_ip_filter: Vec<String>,
    #[serde(alias = "nameserver-policy", alias = "nameserver_policy", default)]
    pub nameserver_policy: HashMap<String, serde_yaml::Value>,
    #[serde(alias = "fallback-filter", alias = "fallback_filter", default)]
    pub fallback_filter: Option<FallbackFilterConfig>,
}

impl DnsConfig {
    /// 获取实际生效的 IPv6 解析开关（优先采用 dns.ipv6；未配置时继承顶层全局 ipv6）
    pub fn is_ipv6(&self, global_ipv6: bool) -> bool {
        self.ipv6.unwrap_or(global_ipv6)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct FallbackFilterConfig {
    #[serde(default = "default_true")]
    pub geoip: bool,
    #[serde(
        alias = "geoip-code",
        alias = "geoip_code",
        default = "default_geoip_code"
    )]
    pub geoip_code: String,
    #[serde(default)]
    pub ipcidr: Vec<String>,
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub geosite: Vec<String>,
}

fn default_geoip_code() -> String {
    "CN".into()
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SmuxConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(alias = "max-connections", alias = "max_connections", default)]
    pub max_connections: Option<usize>,
    #[serde(alias = "max-streams", alias = "max_streams", default)]
    pub max_streams: Option<usize>,
}

/// 节点定义：name + 扁平化协议参数
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyCfg {
    pub name: String,
    /// UDP over TCP（UoT v1）：仅流型协议出站生效
    #[serde(default, alias = "udp_over_tcp")]
    pub udp_over_tcp: bool,
    /// 链式代理/前置代理（dialer-proxy / detour）
    #[serde(alias = "dialer-proxy", alias = "detour", default)]
    pub dialer_proxy: Option<String>,
    /// 多路复用（smux）
    #[serde(default)]
    pub smux: Option<SmuxConfig>,
    /// 节点专属出站绑卡（优先于全局 bind-interface / interface-name）
    #[serde(alias = "interface-name", alias = "bind-interface", default)]
    pub interface_name: Option<String>,
    /// 节点专属路由标记（优先于全局 routing-mark / fwmark）
    #[serde(alias = "routing-mark", alias = "fwmark", default)]
    pub routing_mark: Option<u32>,
    #[serde(flatten)]
    pub kind: ProxyKind,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ProxyKind {
    Ss(SsCfg),
    Ssr(SsrCfg),
    Vmess(VmessCfg),
    Vless(VlessCfg),
    Trojan(TrojanCfg),
    Snell(SnellCfg),
    Anytls(AnytlsCfg),
    Ssh(SshCfg),
    Brook(BrookCfg),
    Mieru(MieruCfg),
    Naive(NaiveCfg),
    Socks5(SocksCfg),
    Tuic(TuicCfg),
    Hysteria(Hysteria1Cfg),
    Hysteria2(Hysteria2Cfg),
    Http(HttpCfg),
    Https(HttpCfg),
    Wireguard(WgCfg),
    Tailscale(TailscaleCfg),
    Direct,
    Reject,
}

impl ProxyKind {
    /// 协议类型名（与配置 "type" 一致）
    pub fn type_name(&self) -> &'static str {
        match self {
            ProxyKind::Ss(_) => "ss",
            ProxyKind::Ssr(_) => "ssr",
            ProxyKind::Vmess(_) => "vmess",
            ProxyKind::Vless(_) => "vless",
            ProxyKind::Trojan(_) => "trojan",
            ProxyKind::Snell(_) => "snell",
            ProxyKind::Anytls(_) => "anytls",
            ProxyKind::Ssh(_) => "ssh",
            ProxyKind::Brook(_) => "brook",
            ProxyKind::Mieru(_) => "mieru",
            ProxyKind::Naive(_) => "naive",
            ProxyKind::Socks5(_) => "socks5",
            ProxyKind::Hysteria(_) => "hysteria",
            ProxyKind::Hysteria2(_) => "hysteria2",
            ProxyKind::Tuic(_) => "tuic",
            ProxyKind::Http(_) => "http",
            ProxyKind::Https(_) => "https",
            ProxyKind::Wireguard(_) => "wireguard",
            ProxyKind::Tailscale(_) => "tailscale",
            ProxyKind::Direct => "direct",
            ProxyKind::Reject => "reject",
        }
    }

    /// 提取节点服务器地址与端口（用于在出站惰性懒加载前提供节点元数据）
    pub fn remote_addr(&self) -> Option<(String, u16)> {
        match self {
            ProxyKind::Ss(s) => Some((s.server.clone(), s.port)),
            ProxyKind::Ssr(s) => Some((s.server.clone(), s.port)),
            ProxyKind::Vmess(v) => Some((v.server.clone(), v.port)),
            ProxyKind::Vless(v) => Some((v.server.clone(), v.port)),
            ProxyKind::Trojan(t) => Some((t.server.clone(), t.port)),
            ProxyKind::Snell(s) => Some((s.server.clone(), s.port)),
            ProxyKind::Anytls(a) => Some((a.server.clone(), a.port)),
            ProxyKind::Ssh(s) => Some((s.server.clone(), s.port)),
            ProxyKind::Brook(b) => Some((b.server.clone(), b.port)),
            ProxyKind::Mieru(m) => Some((m.server.clone(), m.port)),
            ProxyKind::Naive(n) => Some((n.server.clone(), n.port)),
            ProxyKind::Socks5(s) => Some((s.server.clone(), s.port)),
            ProxyKind::Tuic(t) => Some((t.server.clone(), t.port)),
            ProxyKind::Hysteria(h) => Some((h.server.clone(), h.port)),
            ProxyKind::Hysteria2(h) => Some((h.server.clone(), h.port)),
            ProxyKind::Http(h) | ProxyKind::Https(h) => Some((h.server.clone(), h.port)),
            ProxyKind::Wireguard(w) => Some((w.server.clone(), w.port)),
            ProxyKind::Tailscale(t) => Some((t.server.clone(), t.port)),
            ProxyKind::Direct | ProxyKind::Reject => None,
        }
    }

    /// 探测协议是否支持原生 UDP 转发
    pub fn support_udp(&self) -> bool {
        match self {
            ProxyKind::Ss(s) => s.udp,
            ProxyKind::Ssr(s) => s.udp,
            ProxyKind::Vmess(v) => v.udp,
            ProxyKind::Vless(v) => v.udp,
            ProxyKind::Trojan(t) => t.udp,
            ProxyKind::Snell(s) => s.udp,
            ProxyKind::Anytls(_) => true,
            ProxyKind::Ssh(_) => false,
            ProxyKind::Brook(b) => b.udp,
            ProxyKind::Mieru(_) => false,
            ProxyKind::Naive(_) => true,
            ProxyKind::Socks5(s) => s.udp,
            ProxyKind::Tuic(_) => true,
            ProxyKind::Hysteria(_) => true,
            ProxyKind::Hysteria2(_) => true,
            ProxyKind::Http(_) | ProxyKind::Https(_) => false,
            ProxyKind::Wireguard(_) => true,
            ProxyKind::Tailscale(t) => t.udp,
            ProxyKind::Direct => true,
            ProxyKind::Reject => false,
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

/// ECH（Encrypted Client Hello）选项（Clash `ech-opts`）。
/// config 为 base64 的 ECHConfigList；未提供时通过 DNS HTTPS(type65) 记录自动获取。
/// doh 为查询 ECH 记录专用的 DoH 服务器 URL（如 https://dns.alidns.com/dns-query）——
/// 系统解析器常拿不到 HTTPS 记录或被污染，分享链接 `ech=name+doh` 形式会携带。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct EchOpts {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub config: Option<String>,
    #[serde(alias = "query-server-name", alias = "query_server_name", default)]
    pub query_server_name: Option<String>,
    #[serde(alias = "doh-url", alias = "doh_url", default)]
    pub doh: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WsOpts {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    #[serde(alias = "max-early-data", alias = "max_early_data", default)]
    pub max_early_data: Option<u64>,
    #[serde(
        alias = "v2ray-http-upgrade",
        alias = "v2ray_http_upgrade",
        alias = "http-upgrade",
        default
    )]
    pub v2ray_http_upgrade: bool,
}

/// HTTP 伪装传输选项（Clash `http-opts`，network: "http"）。
/// headers 的值是数组（mihomo 语义），序列化时取首个（或多值逗号连接）。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct HttpOpts {
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub path: Option<Vec<String>>,
    #[serde(default)]
    pub headers: Option<HashMap<String, Vec<String>>>,
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
    #[serde(deserialize_with = "de_u16_lenient")]
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
    #[serde(deserialize_with = "de_u16_lenient")]
    pub port: u16,
    pub uuid: String,
    #[serde(
        alias = "alterId",
        alias = "alter_id",
        default,
        deserialize_with = "de_u32_lenient"
    )]
    pub alter_id: u32,
    #[serde(alias = "cipher", alias = "security", default = "default_vmess_cipher")]
    pub cipher: String,
    #[serde(default)]
    pub tls: bool,
    #[serde(
        alias = "servername",
        alias = "server-name",
        alias = "server_name",
        alias = "sni",
        default
    )]
    pub server_name: Option<String>,
    #[serde(
        alias = "skip-cert-verify",
        alias = "skip_cert_verify",
        alias = "allowInsecure",
        alias = "allow_insecure",
        alias = "insecure",
        default
    )]
    pub skip_cert_verify: bool,
    #[serde(alias = "client-fingerprint", alias = "client_fingerprint", default)]
    pub client_fingerprint: Option<String>,
    #[serde(default)]
    pub network: Option<String>,
    /// TLS ALPN 列表（Clash 语义：["h2","http/1.1"]）
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    #[serde(alias = "ech-opts", alias = "ech_opts", default)]
    pub ech_opts: Option<EchOpts>,
    #[serde(alias = "ws-opts", alias = "ws_opts", default)]
    pub ws_opts: Option<WsOpts>,
    #[serde(alias = "grpc-opts", alias = "grpc_opts", default)]
    pub grpc_opts: Option<GrpcOpts>,
    #[serde(alias = "http-opts", alias = "http_opts", default)]
    pub http_opts: Option<HttpOpts>,
    #[serde(default)]
    pub udp: bool,
}

fn default_vmess_cipher() -> String {
    "auto".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct VlessCfg {
    pub server: String,
    #[serde(deserialize_with = "de_u16_lenient")]
    pub port: u16,
    pub uuid: String,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub tls: bool,
    #[serde(
        alias = "servername",
        alias = "server-name",
        alias = "server_name",
        alias = "sni",
        default
    )]
    pub server_name: Option<String>,
    #[serde(
        alias = "skip-cert-verify",
        alias = "skip_cert_verify",
        alias = "allowInsecure",
        alias = "allow_insecure",
        alias = "insecure",
        default
    )]
    pub skip_cert_verify: bool,
    #[serde(alias = "client-fingerprint", alias = "client_fingerprint", default)]
    pub client_fingerprint: Option<String>,
    #[serde(default)]
    pub network: Option<String>,
    /// TLS ALPN 列表（Clash 语义：["h2","http/1.1"]）
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    #[serde(alias = "ws-opts", alias = "ws_opts", default)]
    pub ws_opts: Option<WsOpts>,
    #[serde(alias = "grpc-opts", alias = "grpc_opts", default)]
    pub grpc_opts: Option<GrpcOpts>,
    #[serde(alias = "reality-opts", alias = "reality_opts", default)]
    pub reality_opts: Option<RealityOpts>,
    #[serde(alias = "ech-opts", alias = "ech_opts", default)]
    pub ech_opts: Option<EchOpts>,
    #[serde(alias = "http-opts", alias = "http_opts", default)]
    pub http_opts: Option<HttpOpts>,
    #[serde(default)]
    pub udp: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RealityOpts {
    #[serde(alias = "public-key", alias = "publicKey", alias = "pbk")]
    pub public_key: String,
    #[serde(alias = "short-id", alias = "shortId", alias = "sid", default)]
    pub short_id: Option<String>,
    #[serde(alias = "spider-x", alias = "spiderX", alias = "spx", default)]
    pub spider_x: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrojanCfg {
    pub server: String,
    #[serde(deserialize_with = "de_u16_lenient")]
    pub port: u16,
    pub password: String,
    /// Clash 语义：trojan 天然 TLS，缺省即 true（显式 `tls: false` 仍可覆盖）
    #[serde(default = "default_true")]
    pub tls: bool,
    #[serde(
        alias = "servername",
        alias = "server-name",
        alias = "server_name",
        alias = "sni",
        default
    )]
    pub server_name: Option<String>,
    #[serde(
        alias = "skip-cert-verify",
        alias = "skip_cert_verify",
        alias = "allowInsecure",
        alias = "allow_insecure",
        alias = "insecure",
        default
    )]
    pub skip_cert_verify: bool,
    #[serde(alias = "client-fingerprint", alias = "client_fingerprint", default)]
    pub client_fingerprint: Option<String>,
    #[serde(default)]
    pub network: Option<String>,
    /// TLS ALPN 列表（Clash 语义：["h2","http/1.1"]）
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    #[serde(alias = "ws-opts", alias = "ws_opts", default)]
    pub ws_opts: Option<WsOpts>,
    #[serde(alias = "grpc-opts", alias = "grpc_opts", default)]
    pub grpc_opts: Option<GrpcOpts>,
    #[serde(alias = "reality-opts", alias = "reality_opts", default)]
    pub reality_opts: Option<RealityOpts>,
    #[serde(alias = "ech-opts", alias = "ech_opts", default)]
    pub ech_opts: Option<EchOpts>,
    #[serde(alias = "http-opts", alias = "http_opts", default)]
    pub http_opts: Option<HttpOpts>,
    #[serde(default)]
    pub udp: bool,
}

/// ssh：SSH-2.0 出站（direct-tcpip 通道）。password 与 private-key 二选一。
#[derive(Debug, Clone, Deserialize)]
pub struct SshCfg {
    pub server: String,
    #[serde(deserialize_with = "de_u16_lenient")]
    pub port: u16,
    pub username: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(alias = "private-key", alias = "private_key", default)]
    pub private_key: Option<String>,
    /// 期望的主机密钥（"SHA256:base64" 指纹或原始 blob base64）；None 不校验
    #[serde(alias = "host-key", alias = "host_key", default)]
    pub host_key: Option<String>,
}

/// mieru：enfein/mieru v3（PBKDF2 时间盐 + XChaCha20-Poly1305，TCP 传输）
#[derive(Debug, Clone, Deserialize)]
pub struct MieruCfg {
    pub server: String,
    #[serde(deserialize_with = "de_u16_lenient")]
    pub port: u16,
    pub username: String,
    pub password: String,
}

/// brook：txthinking/brook 原生协议（HKDF-SHA256 + AES-256-GCM 记录流）
#[derive(Debug, Clone, Deserialize)]
pub struct BrookCfg {
    pub server: String,
    #[serde(deserialize_with = "de_u16_lenient")]
    pub port: u16,
    pub password: String,
    /// UDP over TCP（brook 原生 UoT 模式）
    #[serde(default)]
    pub udp: bool,
}

/// snell：Surge / Clash.Meta 原生协议（v1-v4，HKDF-SHA256 + ChaCha20-Poly1305 / AES-128-GCM）
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct SnellObfsOpts {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct SnellCfg {
    pub server: String,
    #[serde(deserialize_with = "de_u16_lenient")]
    pub port: u16,
    pub psk: String,
    #[serde(default = "default_snell_version")]
    pub version: u8,
    #[serde(default)]
    pub obfs: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(alias = "obfs-opts", alias = "obfs_opts", default)]
    pub obfs_opts: Option<SnellObfsOpts>,
    #[serde(default)]
    pub udp: bool,
}

fn default_snell_version() -> u8 {
    4
}

/// ssr：ShadowsocksR 协议
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct SsrCfg {
    pub server: String,
    #[serde(deserialize_with = "de_u16_lenient")]
    pub port: u16,
    pub password: String,
    pub cipher: String,
    #[serde(default = "default_ssr_protocol")]
    pub protocol: String,
    #[serde(alias = "protocol-param", alias = "protocol_param", default)]
    pub protocol_param: Option<String>,
    #[serde(default = "default_ssr_obfs")]
    pub obfs: String,
    #[serde(alias = "obfs-param", alias = "obfs_param", default)]
    pub obfs_param: Option<String>,
    #[serde(default)]
    pub udp: bool,
}

fn default_ssr_protocol() -> String {
    "origin".into()
}

fn default_ssr_obfs() -> String {
    "plain".into()
}

/// anytls：TLS 之上的多路复用流协议（sing-anytls v2）。协议本身强制 TLS。
#[derive(Debug, Clone, Deserialize)]
pub struct AnytlsCfg {
    pub server: String,
    #[serde(deserialize_with = "de_u16_lenient")]
    pub port: u16,
    pub password: String,
    #[serde(
        alias = "servername",
        alias = "server-name",
        alias = "server_name",
        alias = "sni",
        default
    )]
    pub server_name: Option<String>,
    #[serde(
        alias = "skip-cert-verify",
        alias = "skip_cert_verify",
        alias = "allowInsecure",
        alias = "allow_insecure",
        alias = "insecure",
        default
    )]
    pub skip_cert_verify: bool,
    #[serde(alias = "client-fingerprint", alias = "client_fingerprint", default)]
    pub client_fingerprint: Option<String>,
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    #[serde(
        alias = "reality-opts",
        alias = "reality_opts",
        alias = "realityOpts",
        default
    )]
    pub reality_opts: Option<RealityOpts>,
    #[serde(default)]
    pub udp: bool,
}

/// naive：NaiveProxy 协议（基于 HTTP/2 CONNECT + 8 包 Padding）
#[derive(Debug, Clone, Deserialize)]
pub struct NaiveCfg {
    pub server: String,
    #[serde(deserialize_with = "de_u16_lenient")]
    pub port: u16,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(
        alias = "servername",
        alias = "server-name",
        alias = "server_name",
        alias = "sni",
        default
    )]
    pub server_name: Option<String>,
    #[serde(
        alias = "skip-cert-verify",
        alias = "skip_cert_verify",
        alias = "allowInsecure",
        alias = "allow_insecure",
        alias = "insecure",
        default
    )]
    pub skip_cert_verify: bool,
    #[serde(alias = "client-fingerprint", alias = "client_fingerprint", default)]
    pub client_fingerprint: Option<String>,
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    #[serde(default = "default_true")]
    pub tls: bool,
    #[serde(default)]
    pub udp: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Hysteria2Cfg {
    pub server: String,
    #[serde(deserialize_with = "de_u16_lenient")]
    pub port: u16,
    pub password: String,
    #[serde(
        alias = "server_name",
        alias = "server-name",
        alias = "servername",
        alias = "sni",
        default
    )]
    pub sni: Option<String>,
    #[serde(
        alias = "skip-cert-verify",
        alias = "skip_cert_verify",
        alias = "allowInsecure",
        alias = "allow_insecure",
        alias = "insecure",
        default
    )]
    pub skip_cert_verify: bool,
    #[serde(
        alias = "up-mbps",
        alias = "up_mbps",
        default,
        deserialize_with = "de_opt_bandwidth_mbps"
    )]
    pub up: Option<u32>,
    #[serde(
        alias = "down-mbps",
        alias = "down_mbps",
        default,
        deserialize_with = "de_opt_bandwidth_mbps"
    )]
    pub down: Option<u32>,
    #[serde(alias = "obfs-type", alias = "obfs_type", default)]
    pub obfs: Option<String>,
    #[serde(alias = "obfs-password", alias = "obfs_password", default)]
    pub obfs_password: Option<String>,
    /// 端口跳跃范围（如 "20000-50000" 或 "20000-30000,40000-50000"）
    #[serde(alias = "mport", default)]
    pub ports: Option<String>,
    /// 端口跳跃周期（秒，默认 30）
    #[serde(alias = "hop-interval", alias = "hop_interval", default)]
    pub hop_interval: Option<u64>,
}

/// Hysteria v1 出站配置（Clash/mihomo 语法）。
/// 协议：QUIC（ALPN hysteria）+ struc 大端二进制帧 + XPlus 混淆。
#[derive(Debug, Clone, Deserialize)]
pub struct Hysteria1Cfg {
    pub server: String,
    #[serde(deserialize_with = "de_u16_lenient")]
    pub port: u16,
    #[serde(alias = "auth-str", alias = "auth_str", default)]
    pub auth_str: Option<String>,
    #[serde(default)]
    pub auth: Option<String>,
    #[serde(
        alias = "up-mbps",
        alias = "up_mbps",
        default,
        deserialize_with = "de_opt_bandwidth_mbps"
    )]
    pub up: Option<u32>,
    #[serde(
        alias = "down-mbps",
        alias = "down_mbps",
        default,
        deserialize_with = "de_opt_bandwidth_mbps"
    )]
    pub down: Option<u32>,
    /// 传输层伪装：仅支持 udp（默认）；wechat-video / faketcp 不支持
    #[serde(default)]
    pub protocol: Option<String>,
    /// 混淆：salamander（v1 的 XPlus 实现）
    #[serde(default)]
    pub obfs: Option<String>,
    #[serde(alias = "obfs-password", alias = "obfs_password", default)]
    pub obfs_password: Option<String>,
    #[serde(alias = "sni", alias = "servername", alias = "server_name", default)]
    pub sni: Option<String>,
    /// ALPN：兼容字符串与列表两种写法（mihomo 为列表）；空则默认 ["hysteria"]
    #[serde(alias = "alpn", default, deserialize_with = "de_alpn_list_lenient")]
    pub alpn: Vec<String>,
    #[serde(
        alias = "skip-cert-verify",
        alias = "skip_cert_verify",
        alias = "allowInsecure",
        alias = "allow_insecure",
        alias = "insecure",
        default
    )]
    pub skip_cert_verify: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TuicCfg {
    pub server: String,
    #[serde(deserialize_with = "de_u16_lenient")]
    pub port: u16,
    pub uuid: String,
    pub password: String,
    #[serde(
        alias = "server_name",
        alias = "server-name",
        alias = "servername",
        alias = "sni",
        default
    )]
    pub sni: Option<String>,
    #[serde(
        alias = "skip-cert-verify",
        alias = "skip_cert_verify",
        alias = "allowInsecure",
        alias = "allow_insecure",
        alias = "insecure",
        default
    )]
    pub skip_cert_verify: bool,
    #[serde(
        alias = "congestion-controller",
        alias = "congestion_controller",
        default
    )]
    pub congestion_controller: Option<String>,
    #[serde(default)]
    pub udp_relay_mode: Option<String>,
}

/// WireGuard 出站配置（Clash 语法）。
#[derive(Debug, Clone, Deserialize)]
pub struct WgCfg {
    pub server: String,
    #[serde(deserialize_with = "de_u16_lenient")]
    pub port: u16,
    #[serde(alias = "private-key", alias = "private_key")]
    pub private_key: String,
    #[serde(alias = "public-key", alias = "public_key")]
    pub public_key: String,
    #[serde(alias = "pre-shared-key", alias = "pre_shared_key", default)]
    pub pre_shared_key: Option<String>,
    #[serde(
        alias = "persistent-keepalive",
        alias = "persistent_keepalive",
        default
    )]
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

/// Tailscale 节点配置（支持通过本地或远程 Tailscale Connector/Socks5 接入或出口节点路由）
#[derive(Debug, Clone, Deserialize)]
pub struct TailscaleCfg {
    #[serde(default = "default_tailscale_server")]
    pub server: String,
    #[serde(
        default = "default_tailscale_port",
        deserialize_with = "de_u16_lenient"
    )]
    pub port: u16,
    #[serde(alias = "auth-key", alias = "auth_key", default)]
    pub auth_key: Option<String>,
    #[serde(alias = "control-url", alias = "control_url", default)]
    pub control_url: Option<String>,
    #[serde(alias = "exit-node", alias = "exit_node", default)]
    pub exit_node: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(alias = "state-dir", alias = "state_dir", default)]
    pub state_dir: Option<String>,
    #[serde(default = "default_true")]
    pub udp: bool,
}

fn default_tailscale_server() -> String {
    "127.0.0.1".into()
}

fn default_tailscale_port() -> u16 {
    1055
}

#[derive(Debug, Clone, Deserialize)]
pub struct SocksCfg {
    pub server: String,
    #[serde(deserialize_with = "de_u16_lenient")]
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
    #[serde(deserialize_with = "de_u16_lenient")]
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub tls: bool,
    #[serde(alias = "skip-cert-verify", default)]
    pub skip_cert_verify: bool,
    #[serde(
        alias = "server_name",
        alias = "server-name",
        alias = "servername",
        alias = "sni",
        default
    )]
    pub sni: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GroupCfg {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: GroupKind,
    #[serde(default)]
    pub proxies: Vec<String>,
    #[serde(alias = "use", default)]
    pub r#use: Vec<String>,
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

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
pub struct ProviderHealthCheckCfg {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub interval: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProxyProviderCfg {
    /// http / file
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
    pub url: Option<String>,
    pub path: Option<String>,
    #[serde(default)]
    pub interval: Option<u64>,
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(alias = "health-check", alias = "health_check", default)]
    pub health_check: Option<ProviderHealthCheckCfg>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleProviderCfg {
    /// http / file
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
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
    matches!(
        name,
        "DIRECT" | "REJECT" | "REJECT-DROP" | "PASS" | "GLOBAL" | "COMPATIBLE"
    )
}

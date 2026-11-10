use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundSpec {
    pub name: String,
    pub kind: OutboundKind,
    pub transport: TransportSpec,
    pub dialer_proxy: Option<String>,
    pub routing_mark: Option<u32>,
    pub bind_interface: Option<String>,
    pub udp_over_tcp: Option<UotVersion>,
    pub smux: Option<SmuxSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UotVersion {
    V1,
    V2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutboundKind {
    Direct,
    Reject,
    Ss {
        server: String,
        port: u16,
        cipher: String,
        password: String,
        udp: bool,
    },
    Ssr {
        server: String,
        port: u16,
        password: String,
        cipher: String,
        protocol: String,
        obfs: String,
        obfs_param: Option<String>,
        protocol_param: Option<String>,
        udp: bool,
    },
    Vmess {
        server: String,
        port: u16,
        uuid: String,
        alter_id: u32,
        security: Option<String>,
        udp: bool,
    },
    Vless {
        server: String,
        port: u16,
        uuid: String,
        flow: Option<String>,
        packet_encoding: Option<String>,
        udp: bool,
    },
    Trojan {
        server: String,
        port: u16,
        password: String,
        network: Option<String>,
        udp: bool,
    },
    Hysteria {
        server: String,
        port: u16,
        auth: Option<String>,
        up_mbps: Option<u64>,
        down_mbps: Option<u64>,
        obfs: Option<String>,
        obfs_password: Option<String>,
        sni: Option<String>,
        alpn: Vec<String>,
        insecure: bool,
    },
    Hysteria2 {
        server: String,
        port: u16,
        ports: Option<String>,
        password: Option<String>,
        up_mbps: Option<u64>,
        down_mbps: Option<u64>,
        obfs: Option<String>,
        obfs_password: Option<String>,
        sni: Option<String>,
        insecure: bool,
    },
    Tuic {
        server: String,
        port: u16,
        uuid: String,
        password: String,
        congestion_controller: Option<String>,
        udp_relay_mode: Option<String>,
        zero_rtt_handshake: bool,
        heartbeat: Option<String>,
        sni: Option<String>,
        insecure: bool,
    },
    Wireguard {
        server: String,
        port: u16,
        ip: String,
        ipv6: Option<String>,
        private_key: String,
        public_key: String,
        preshared_key: Option<String>,
        mtu: Option<u16>,
        reserved: Option<[u8; 3]>,
        workers: Option<usize>,
        udp: bool,
    },
    Tailscale {
        server: String,
        port: u16,
        authkey: Option<String>,
        control_url: Option<String>,
        hostname: Option<String>,
        state_dir: Option<String>,
        exit_node: Option<String>,
        exit_node_allow_lan: bool,
    },
    Snell {
        server: String,
        port: u16,
        psk: String,
        version: u8,
        obfs_opts: Option<SnellObfsSpec>,
        udp: bool,
    },
    Anytls {
        server: String,
        port: u16,
        password: String,
        sni: Option<String>,
        client_fingerprint: Option<String>,
        udp: bool,
    },
    Ssh {
        server: String,
        port: u16,
        username: String,
        password: Option<String>,
        private_key: Option<String>,
        private_key_passphrase: Option<String>,
        host_key: Option<String>,
    },
    Brook {
        server: String,
        port: u16,
        password: String,
        protocol: Option<String>,
        udp: bool,
    },
    Mieru {
        server: String,
        port: u16,
        username: String,
        password: String,
        transport: Option<String>,
        multiplexing: Option<String>,
    },
    Naive {
        server: String,
        port: u16,
        username: String,
        password: String,
        sni: Option<String>,
        client_fingerprint: Option<String>,
        udp: bool,
    },
    Socks5 {
        server: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
        tls: bool,
        sni: Option<String>,
        insecure: bool,
        udp: bool,
    },
    Http {
        server: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
        tls: bool,
        sni: Option<String>,
        insecure: bool,
        headers: HashMap<String, String>,
    },
    Masque {
        server: String,
        port: u16,
        private_key: String,
        public_key: Option<String>,
        ip: Option<String>,
        ipv6: Option<String>,
        uri: Option<String>,
        sni: Option<String>,
        mtu: Option<u16>,
        udp: bool,
        remote_dns_resolve: bool,
        dns: Vec<String>,
        skip_cert_verify: bool,
        network: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SnellObfsSpec {
    pub mode: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TransportSpec {
    pub network: Option<String>,
    pub tls: bool,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub insecure: bool,
    pub client_fingerprint: Option<String>,
    pub ws: Option<WsSpec>,
    pub grpc: Option<GrpcSpec>,
    pub http: Option<HttpSpec>,
    pub reality: Option<RealitySpec>,
    pub ech: Option<EchSpec>,
    pub shadow_tls: Option<ShadowTlsSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WsSpec {
    pub path: String,
    pub headers: HashMap<String, String>,
    pub max_early_data: Option<u64>,
    pub v2ray_http_upgrade: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GrpcSpec {
    pub service_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HttpSpec {
    pub method: Option<String>,
    pub path: Vec<String>,
    pub headers: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RealitySpec {
    pub public_key: String,
    pub short_id: Option<String>,
    pub spider_x: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EchSpec {
    pub enable: bool,
    pub config: Option<String>,
    pub query_server_name: Option<String>,
    pub doh: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ShadowTlsSpec {
    pub password: String,
    pub sni: String,
    pub version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SmuxSpec {
    pub enabled: bool,
    pub protocol: Option<String>,
    pub max_connections: Option<usize>,
    pub min_streams: Option<usize>,
    pub max_streams: Option<usize>,
    pub padding: bool,
}

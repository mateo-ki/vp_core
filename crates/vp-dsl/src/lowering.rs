use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use vp_ir::*;

use crate::ast::*;

pub fn lower_to_ir(blocks: Vec<Block>) -> Result<VpIr, String> {
    let mut inbounds = Vec::new();
    let mut outbounds = vec![
        OutboundSpec {
            name: "DIRECT".into(),
            kind: OutboundKind::Direct,
            transport: TransportSpec::default(),
            dialer_proxy: None,
            routing_mark: None,
            bind_interface: None,
            udp_over_tcp: None,
            smux: None,
        },
        OutboundSpec {
            name: "REJECT".into(),
            kind: OutboundKind::Reject,
            transport: TransportSpec::default(),
            dialer_proxy: None,
            routing_mark: None,
            bind_interface: None,
            udp_over_tcp: None,
            smux: None,
        },
    ];
    let mut groups = Vec::new();
    let mut routes = Vec::new();
    let mut sub_rules: HashMap<String, Vec<RouteRuleSpec>> = HashMap::new();
    let rule_providers = HashMap::new();
    let proxy_providers = HashMap::new();
    let mut dns = DnsSpec::default();
    let mut tun = None;
    let mut services = ServiceSpec::default();
    let mut security = SecuritySpec::default();

    for block in blocks {
        match block {
            Block::Inbound {
                kind,
                name,
                sub_kind,
                props,
            } => {
                let map: HashMap<String, DslValue> = props.into_iter().collect();
                let lower_kind = kind.to_ascii_lowercase();
                match lower_kind.as_str() {
                    "mixed" => {
                        let listen = parse_listen_addr(&map, 7890)?;
                        inbounds.push(InboundSpec::Mixed { listen });
                    }
                    "http" => {
                        let listen = parse_listen_addr(&map, 8080)?;
                        inbounds.push(InboundSpec::Http { listen });
                    }
                    "socks" | "socks5" => {
                        let listen = parse_listen_addr(&map, 1080)?;
                        inbounds.push(InboundSpec::Socks5 { listen });
                    }
                    "redir" => {
                        let listen = parse_listen_addr(&map, 1082)?;
                        inbounds.push(InboundSpec::Redir { listen });
                    }
                    "tproxy" => {
                        let listen = parse_listen_addr(&map, 1083)?;
                        inbounds.push(InboundSpec::Tproxy { listen });
                    }
                    "tun" => {
                        let enable = map.get("enable").and_then(|v| v.as_bool()).unwrap_or(true);
                        let address = map
                            .get("address")
                            .and_then(|v| v.as_str())
                            .unwrap_or("198.18.0.1")
                            .to_string();
                        let netmask = map
                            .get("netmask")
                            .and_then(|v| v.as_str())
                            .unwrap_or("255.255.0.0")
                            .to_string();
                        let mtu = map.get("mtu").and_then(|v| v.as_u16()).unwrap_or(1500);
                        let auto_route = map
                            .get("auto_route")
                            .or_else(|| map.get("auto-route"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(true);
                        let auto_route_mode = map
                            .get("auto_route_mode")
                            .or_else(|| map.get("auto-route-mode"))
                            .and_then(|v| v.as_str())
                            .map(ToString::to_string);
                        let strict = map.get("strict").and_then(|v| v.as_bool()).unwrap_or(false);
                        let route_address = map
                            .get("route_address")
                            .or_else(|| map.get("route-address"))
                            .and_then(|v| v.as_str_list())
                            .unwrap_or_default();
                        let route_exclude_address = map
                            .get("route_exclude_address")
                            .or_else(|| map.get("route-exclude-address"))
                            .and_then(|v| v.as_str_list())
                            .unwrap_or_default();

                        tun = Some(TunSpec {
                            enable,
                            device: None,
                            address,
                            netmask,
                            mtu,
                            auto_route,
                            auto_route_mode,
                            auto_detect_interface: true,
                            route_address,
                            route_exclude_address,
                            dns_hijack: Vec::new(),
                            strict,
                        });
                    }
                    "server" => {
                        let server_name = name.unwrap_or_else(|| "server-in".into());
                        let server_protocol = sub_kind.unwrap_or_else(|| "shadowsocks".into());
                        let listen = parse_listen_addr(&map, 8388)?;
                        let cipher = map
                            .get("cipher")
                            .and_then(|v| v.as_str())
                            .map(ToString::to_string);
                        let cert = map
                            .get("cert")
                            .and_then(|v| v.as_str())
                            .map(ToString::to_string);
                        let key = map
                            .get("key")
                            .and_then(|v| v.as_str())
                            .map(ToString::to_string);
                        let fallback = map
                            .get("fallback")
                            .and_then(|v| v.as_str())
                            .map(ToString::to_string);
                        let obfs = map
                            .get("obfs")
                            .and_then(|v| v.as_str())
                            .map(ToString::to_string);
                        let obfs_password = map
                            .get("obfs_password")
                            .or_else(|| map.get("obfs-password"))
                            .and_then(|v| v.as_str())
                            .map(ToString::to_string);
                        let ports = map
                            .get("ports")
                            .or_else(|| map.get("mport"))
                            .and_then(|v| v.as_str())
                            .map(ToString::to_string);

                        let users = if let Some(us) = map.get("users").and_then(|v| v.as_str_list())
                        {
                            us.into_iter()
                                .map(|sec| ServerUserSpec {
                                    username: String::new(),
                                    secret: sec,
                                    quota_bytes: None,
                                    rate_limit_bps: None,
                                })
                                .collect()
                        } else if let Some(pass) = map.get("password").and_then(|v| v.as_str()) {
                            vec![ServerUserSpec {
                                username: String::new(),
                                secret: pass.to_string(),
                                quota_bytes: None,
                                rate_limit_bps: None,
                            }]
                        } else {
                            Vec::new()
                        };

                        inbounds.push(InboundSpec::Server(Box::new(ServerInboundSpec {
                            name: server_name,
                            kind: server_protocol,
                            listen,
                            cipher,
                            cert,
                            key,
                            users,
                            fallback,
                            shadow_tls: None,
                            reality: None,
                            sni_routes: HashMap::new(),
                            obfs,
                            obfs_password,
                            ports,
                            allow_geoip: Vec::new(),
                            block_geoip: Vec::new(),
                            allow_asn: Vec::new(),
                            block_asn: Vec::new(),
                            knock: None,
                            rrl: None,
                        })));
                    }
                    other => return Err(format!("未知的 inbound 类型: '{other}'")),
                }
            }
            Block::Node { name, kind, props } => {
                let node = lower_node(name, kind, props)?;
                outbounds.push(node);
            }
            Block::Group { name, kind, props } => {
                let group = lower_group(name, kind, props)?;
                groups.push(group);
            }
            Block::Dns { props } => {
                dns = lower_dns(props)?;
            }
            Block::Services { props } => {
                services = lower_services(props)?;
            }
            Block::Security { props } => {
                security = lower_security(props)?;
            }
            Block::Route {
                name,
                rules: r_list,
            } => {
                let mut lowered_rules = Vec::with_capacity(r_list.len());
                for r in r_list {
                    lowered_rules.push(lower_route_rule(r)?);
                }
                if let Some(sub_name) = name {
                    sub_rules.insert(sub_name, lowered_rules);
                } else {
                    routes.extend(lowered_rules);
                }
            }
        }
    }

    Ok(VpIr {
        inbounds,
        outbounds,
        groups,
        routes,
        sub_rules,
        rule_providers,
        proxy_providers,
        dns,
        tun,
        services,
        security,
    })
}

fn parse_listen_addr(
    map: &HashMap<String, DslValue>,
    default_port: u16,
) -> Result<SocketAddr, String> {
    if let Some(listen_str) = map.get("listen").and_then(|v| v.as_str()) {
        if let Ok(addr) = listen_str.parse::<SocketAddr>() {
            return Ok(addr);
        }
        if let Ok(ip) = listen_str.parse::<IpAddr>() {
            let port = map
                .get("port")
                .and_then(|v| v.as_u16())
                .unwrap_or(default_port);
            return Ok(SocketAddr::new(ip, port));
        }
    }
    let port = map
        .get("port")
        .and_then(|v| v.as_u16())
        .unwrap_or(default_port);
    Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))
}

fn lower_node(
    name: String,
    kind_str: String,
    props: Vec<(String, DslValue)>,
) -> Result<OutboundSpec, String> {
    let map: HashMap<String, DslValue> = props.into_iter().collect();
    let lower_kind = kind_str.to_ascii_lowercase();

    let server = map
        .get("server")
        .or_else(|| map.get("host"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let port = map.get("port").and_then(|v| v.as_u16()).unwrap_or(443);
    let password = map
        .get("password")
        .or_else(|| map.get("secret"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let udp = map.get("udp").and_then(|v| v.as_bool()).unwrap_or(false);

    let mut transport = TransportSpec::default();
    if let Some(sni) = map
        .get("sni")
        .or_else(|| map.get("server_name"))
        .or_else(|| map.get("servername"))
        .and_then(|v| v.as_str())
    {
        transport.sni = Some(sni.to_string());
    }
    if let Some(insecure) = map
        .get("insecure")
        .or_else(|| map.get("skip_cert_verify"))
        .or_else(|| map.get("skip-cert-verify"))
        .and_then(|v| v.as_bool())
    {
        transport.insecure = insecure;
    }
    if let Some(fp) = map
        .get("client_fingerprint")
        .or_else(|| map.get("client-fingerprint"))
        .or_else(|| map.get("fp"))
        .and_then(|v| v.as_str())
    {
        transport.client_fingerprint = Some(fp.to_string());
    }
    if let Some(alpn) = map.get("alpn").and_then(|v| v.as_str_list()) {
        transport.alpn = alpn;
    }
    if let Some(tls) = map.get("tls").and_then(|v| v.as_bool()) {
        transport.tls = tls;
    }

    // Sub-objects: ws, grpc, reality, ech
    if let Some(ws_val) = map
        .get("ws")
        .or_else(|| map.get("ws_opts"))
        .or_else(|| map.get("ws-opts"))
    {
        if let Some(ws_map) = ws_val.as_map() {
            let wm: HashMap<String, DslValue> = ws_map.iter().cloned().collect();
            let path = wm
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("/")
                .to_string();
            let mut headers = HashMap::new();
            if let Some(hm) = wm.get("headers").and_then(|v| v.as_map()) {
                for (hk, hv) in hm {
                    headers.insert(hk.clone(), hv.to_string_lossy());
                }
            }
            transport.ws = Some(WsSpec {
                path,
                headers,
                max_early_data: wm.get("max_early_data").and_then(|v| v.as_u64()),
                v2ray_http_upgrade: wm
                    .get("v2ray_http_upgrade")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            });
        }
    }

    let reality_val = map
        .get("reality")
        .or_else(|| map.get("reality_opts"))
        .or_else(|| map.get("reality-opts"))
        .or_else(|| {
            if let Some(tls_val) = map.get("tls") {
                if let Some(m) = tls_val.as_map() {
                    if m.iter()
                        .any(|(k, v)| k == "__type" && v.as_str() == Some("reality"))
                    {
                        return Some(tls_val);
                    }
                }
            }
            None
        });

    if let Some(r_val) = reality_val {
        if let Some(rm) = r_val.as_map() {
            let r_map: HashMap<String, DslValue> = rm.iter().cloned().collect();
            if let Some(sni) = r_map.get("sni").and_then(|v| v.as_str()) {
                if transport.sni.is_none() {
                    transport.sni = Some(sni.to_string());
                }
            }
            let pbk = r_map
                .get("public_key")
                .or_else(|| r_map.get("public-key"))
                .or_else(|| r_map.get("pbk"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let sid = r_map
                .get("short_id")
                .or_else(|| r_map.get("short-id"))
                .or_else(|| r_map.get("sid"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let spx = r_map
                .get("spider_x")
                .or_else(|| r_map.get("spider-x"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            transport.reality = Some(RealitySpec {
                public_key: pbk,
                short_id: sid,
                spider_x: spx,
            });
            transport.tls = true;
        }
    }

    // grpc 子对象（serializer 输出形态: grpc: { service_name: "..." }）
    if transport.grpc.is_none() {
        if let Some(g_val) = map.get("grpc").or_else(|| map.get("grpc_opts")) {
            if let Some(gm) = g_val.as_map() {
                let g_map: HashMap<String, DslValue> = gm.iter().cloned().collect();
                let service_name = g_map
                    .get("service_name")
                    .or_else(|| g_map.get("grpc_service_name"))
                    .or_else(|| g_map.get("grpc-service-name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                transport.grpc = Some(GrpcSpec { service_name });
            }
        }
    }

    // xhttp 子对象（serializer 输出形态: xhttp: { path: "...", mode: "...", headers: {...} }）
    if transport.xhttp.is_none() {
        if let Some(x_val) = map.get("xhttp").or_else(|| map.get("xhttp_opts")) {
            if let Some(xm) = x_val.as_map() {
                let x_map: HashMap<String, DslValue> = xm.iter().cloned().collect();
                let path = x_map
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/")
                    .to_string();
                let host = x_map
                    .get("host")
                    .and_then(|v| v.as_str())
                    .map(ToString::to_string);
                let mode = x_map
                    .get("mode")
                    .and_then(|v| v.as_str())
                    .map(ToString::to_string);
                let mut headers = HashMap::new();
                if let Some(hm) = x_map.get("headers").and_then(|v| v.as_map()) {
                    for (k, v) in hm {
                        if let Some(vs) = v.as_str() {
                            headers.insert(k.clone(), vs.to_string());
                        }
                    }
                }
                transport.network = Some("xhttp".into());
                transport.xhttp = Some(XhttpSpec {
                    path,
                    host,
                    mode,
                    headers,
                });
            }
        }
    }

    // shadow_tls 子对象（serializer 输出形态: shadow_tls: { password: "...", sni: "..." }）
    if transport.shadow_tls.is_none() {
        if let Some(st_val) = map.get("shadow_tls") {
            if let Some(sm) = st_val.as_map() {
                let st_map: HashMap<String, DslValue> = sm.iter().cloned().collect();
                let password = st_map
                    .get("password")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let sni = st_map
                    .get("sni")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let version = st_map
                    .get("version")
                    .and_then(|v| v.as_str())
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap_or(3);
                transport.shadow_tls = Some(ShadowTlsSpec {
                    password,
                    sni,
                    version,
                });
            }
        }
    }

    // network 显式标识（httpupgrade / splithttp 等经 network 字符串表达的传输；
    // xhttp 子对象已在上方自行设置，此处不覆盖）
    if transport.network.is_none() {
        if let Some(net) = map
            .get("network")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            transport.network = Some(net.to_string());
        }
    }

    let kind = match lower_kind.as_str() {
        "vless" => {
            let uuid = map
                .get("uuid")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let flow = map
                .get("flow")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let packet_encoding = map
                .get("packet_encoding")
                .or_else(|| map.get("packet-encoding"))
                .or_else(|| map.get("packetEncoding"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            OutboundKind::Vless {
                server,
                port,
                uuid,
                flow,
                packet_encoding,
                udp,
            }
        }
        "vmess" => {
            let uuid = map
                .get("uuid")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let alter_id = map.get("alter_id").and_then(|v| v.as_u32()).unwrap_or(0);
            let cipher = map
                .get("cipher")
                .or_else(|| map.get("security"))
                .and_then(|v| v.as_str())
                .unwrap_or("auto")
                .to_string();
            OutboundKind::Vmess {
                server,
                port,
                uuid,
                alter_id,
                security: Some(cipher),
                udp,
            }
        }
        "ss" | "shadowsocks" => {
            let cipher = map
                .get("cipher")
                .and_then(|v| v.as_str())
                .unwrap_or("aes-128-gcm")
                .to_string();
            OutboundKind::Ss {
                server,
                port,
                cipher,
                password,
                udp,
            }
        }
        "trojan" => {
            transport.tls = true;
            let network = map
                .get("network")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            OutboundKind::Trojan {
                server,
                port,
                password,
                network,
                udp,
            }
        }
        "brook" => {
            let protocol = map
                .get("protocol")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            OutboundKind::Brook {
                server,
                port,
                password,
                protocol,
                udp,
            }
        }
        "naive" | "naiveproxy" => OutboundKind::Naive {
            server,
            port,
            username: map
                .get("username")
                .or_else(|| map.get("user"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            password,
            sni: transport.sni.clone(),
            client_fingerprint: transport.client_fingerprint.clone(),
            udp,
        },
        "hysteria2" | "hy2" => {
            let up_mbps = map.get("up").and_then(|v| v.as_u64());
            let down_mbps = map.get("down").and_then(|v| v.as_u64());
            let obfs = map
                .get("obfs")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let obfs_password = map
                .get("obfs_password")
                .or_else(|| map.get("obfs-password"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            OutboundKind::Hysteria2 {
                server,
                port,
                ports: map
                    .get("ports")
                    .and_then(|v| v.as_str())
                    .map(ToString::to_string),
                password: (!password.is_empty()).then_some(password),
                up_mbps,
                down_mbps,
                obfs,
                obfs_password,
                sni: transport.sni.clone(),
                insecure: transport.insecure,
            }
        }
        "tuic" => {
            let uuid = map
                .get("uuid")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            OutboundKind::Tuic {
                server,
                port,
                uuid,
                password,
                congestion_controller: map
                    .get("congestion_controller")
                    .or_else(|| map.get("congestion-controller"))
                    .or_else(|| map.get("congestion_control"))
                    .and_then(|v| v.as_str())
                    .map(ToString::to_string),
                udp_relay_mode: map
                    .get("udp_relay_mode")
                    .and_then(|v| v.as_str())
                    .map(ToString::to_string),
                zero_rtt_handshake: map
                    .get("zero_rtt_handshake")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                heartbeat: map
                    .get("heartbeat")
                    .and_then(|v| v.as_str())
                    .map(ToString::to_string),
                sni: transport.sni.clone(),
                insecure: transport.insecure,
            }
        }
        "juicity" => OutboundKind::Juicity {
            server,
            port,
            uuid: map
                .get("uuid")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            password,
            congestion_controller: map
                .get("congestion_controller")
                .or_else(|| map.get("congestion-controller"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            sni: transport.sni.clone(),
            insecure: transport.insecure,
            pinned_cert_chain: map
                .get("pinned_cert_chain")
                .or_else(|| map.get("pinned-cert-chain"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
        },
        "openvpn" => OutboundKind::OpenVpn {
            server,
            port,
            proto: map
                .get("proto")
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            username: map
                .get("username")
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            password: if password.is_empty() {
                None
            } else {
                Some(password.clone())
            },
            ca: map
                .get("ca")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            cert: map
                .get("cert")
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            key: map
                .get("key")
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            cipher: map
                .get("cipher")
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            insecure: transport.insecure,
            udp: map.get("udp").and_then(|v| v.as_bool()).unwrap_or(false),
        },
        "socks" | "socks5" => {
            let username = map
                .get("username")
                .or_else(|| map.get("user"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            OutboundKind::Socks5 {
                server,
                port,
                username,
                password: if password.is_empty() {
                    None
                } else {
                    Some(password)
                },
                tls: transport.tls,
                sni: transport.sni.clone(),
                insecure: transport.insecure,
                udp,
            }
        }
        "http" | "https" => {
            let username = map
                .get("username")
                .or_else(|| map.get("user"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let is_https = lower_kind == "https" || transport.tls;
            OutboundKind::Http {
                server,
                port,
                username,
                password: if password.is_empty() {
                    None
                } else {
                    Some(password)
                },
                tls: is_https,
                sni: transport.sni.clone(),
                insecure: transport.insecure,
                headers: HashMap::new(),
            }
        }
        "wireguard" | "wg" => {
            let ip = map
                .get("ip")
                .and_then(|v| v.as_str())
                .unwrap_or("10.0.0.2")
                .to_string();
            let ipv6 = map
                .get("ipv6")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let private_key = map
                .get("private_key")
                .or_else(|| map.get("private-key"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let public_key = map
                .get("public_key")
                .or_else(|| map.get("public-key"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let preshared_key = map
                .get("preshared_key")
                .or_else(|| map.get("preshared-key"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let mtu = map.get("mtu").and_then(|v| v.as_u16());
            OutboundKind::Wireguard {
                server,
                port,
                ip,
                ipv6,
                private_key,
                public_key,
                preshared_key,
                mtu,
                reserved: None,
                workers: None,
                udp: true,
            }
        }
        "tailscale" => {
            let authkey = map
                .get("authkey")
                .or_else(|| map.get("auth_key"))
                .or_else(|| map.get("auth-key"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let control_url = map
                .get("control_url")
                .or_else(|| map.get("control-url"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let hostname = map
                .get("hostname")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let state_dir = map
                .get("state_dir")
                .or_else(|| map.get("state-dir"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let exit_node = map
                .get("exit_node")
                .or_else(|| map.get("exit-node"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            OutboundKind::Tailscale {
                server,
                port,
                authkey,
                control_url,
                hostname,
                state_dir,
                exit_node,
                exit_node_allow_lan: false,
            }
        }
        "masque" => {
            let private_key = map
                .get("private_key")
                .or_else(|| map.get("private-key"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| "masque 节点缺少 private_key".to_string())?
                .to_string();
            let public_key = map
                .get("public_key")
                .or_else(|| map.get("public-key"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let ip = map
                .get("ip")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let ipv6 = map
                .get("ipv6")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let uri = map
                .get("uri")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let sni = map
                .get("sni")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let mtu = map.get("mtu").and_then(|v| v.as_u16());
            let udp = map.get("udp").and_then(|v| v.as_bool()).unwrap_or(true);
            let remote_dns_resolve = map
                .get("remote_dns_resolve")
                .or_else(|| map.get("remote-dns-resolve"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let dns = map
                .get("dns")
                .and_then(|v| v.as_str_list())
                .unwrap_or_default();
            let skip_cert_verify = map
                .get("skip_cert_verify")
                .or_else(|| map.get("skip-cert-verify"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let network = map
                .get("network")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);

            OutboundKind::Masque {
                server,
                port,
                private_key,
                public_key,
                ip,
                ipv6,
                uri,
                sni,
                mtu,
                udp,
                remote_dns_resolve,
                dns,
                skip_cert_verify,
                network,
            }
        }
        "snell" => {
            let psk = map
                .get("psk")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let version = map.get("version").and_then(|v| v.as_u64()).unwrap_or(4) as u8;
            OutboundKind::Snell {
                server,
                port,
                psk,
                version,
                obfs_opts: None,
                udp,
            }
        }
        "ssh" => {
            let username = map
                .get("username")
                .or_else(|| map.get("user"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let private_key = map
                .get("private_key")
                .or_else(|| map.get("private-key"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let host_key = map
                .get("host_key")
                .or_else(|| map.get("host-key"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            OutboundKind::Ssh {
                server,
                port,
                username,
                password: if password.is_empty() {
                    None
                } else {
                    Some(password)
                },
                private_key,
                private_key_passphrase: None,
                host_key,
            }
        }
        "anytls" => OutboundKind::Anytls {
            server,
            port,
            password,
            sni: transport.sni.clone(),
            client_fingerprint: transport.client_fingerprint.clone(),
            udp,
        },
        "ssr" => {
            let cipher = map
                .get("cipher")
                .and_then(|v| v.as_str())
                .unwrap_or("aes-128-gcm")
                .to_string();
            let protocol = map
                .get("protocol")
                .and_then(|v| v.as_str())
                .unwrap_or("origin")
                .to_string();
            let obfs = map
                .get("obfs")
                .and_then(|v| v.as_str())
                .unwrap_or("plain")
                .to_string();
            let obfs_param = map
                .get("obfs_param")
                .or_else(|| map.get("obfs-param"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let protocol_param = map
                .get("protocol_param")
                .or_else(|| map.get("protocol-param"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            OutboundKind::Ssr {
                server,
                port,
                password,
                cipher,
                protocol,
                obfs,
                obfs_param,
                protocol_param,
                udp,
            }
        }
        "hysteria" | "hy" => {
            let auth = map
                .get("auth")
                .or_else(|| map.get("auth_str"))
                .or_else(|| map.get("auth-str"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string)
                .or_else(|| (!password.is_empty()).then_some(password));
            let up_mbps = map.get("up").and_then(|v| v.as_u64());
            let down_mbps = map.get("down").and_then(|v| v.as_u64());
            let obfs = map
                .get("obfs")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let obfs_password = map
                .get("obfs_password")
                .or_else(|| map.get("obfs-password"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            OutboundKind::Hysteria {
                server,
                port,
                auth,
                up_mbps,
                down_mbps,
                obfs,
                obfs_password,
                sni: transport.sni.clone(),
                alpn: transport.alpn.clone(),
                insecure: transport.insecure,
            }
        }
        "mieru" => {
            let username = map
                .get("username")
                .or_else(|| map.get("user"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let mieru_transport = map
                .get("transport")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let multiplexing = map
                .get("multiplexing")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            OutboundKind::Mieru {
                server,
                port,
                username,
                password,
                transport: mieru_transport,
                multiplexing,
            }
        }
        "direct" => OutboundKind::Direct,
        "reject" => OutboundKind::Reject,
        other => return Err(format!("未识别的节点协议类型: '{other}'")),
    };

    Ok(OutboundSpec {
        name,
        kind,
        transport,
        dialer_proxy: map
            .get("dialer_proxy")
            .or_else(|| map.get("dialer-proxy"))
            .and_then(|v| v.as_str())
            .map(ToString::to_string),
        routing_mark: map.get("routing_mark").and_then(|v| v.as_u32()),
        bind_interface: map
            .get("interface")
            .and_then(|v| v.as_str())
            .map(ToString::to_string),
        udp_over_tcp: None,
        smux: None,
    })
}

fn lower_group(
    name: String,
    kind_str: String,
    props: Vec<(String, DslValue)>,
) -> Result<GroupSpec, String> {
    let map: HashMap<String, DslValue> = props.into_iter().collect();
    let lower_kind = kind_str.to_ascii_lowercase();

    let ty = match lower_kind.as_str() {
        "select" | "selector" => GroupType::Select,
        "url_test" | "url-test" | "auto" => GroupType::UrlTest,
        "fallback" => GroupType::Fallback,
        "load_balance" | "load-balance" | "lb" => GroupType::LoadBalance,
        "relay" => GroupType::Relay,
        other => return Err(format!("未知的策略组类型: '{other}'")),
    };

    let members = map
        .get("members")
        .or_else(|| map.get("proxies"))
        .and_then(|v| v.as_str_list())
        .unwrap_or_default();
    let providers = map
        .get("providers")
        .or_else(|| map.get("use"))
        .and_then(|v| v.as_str_list())
        .unwrap_or_default();
    let test_url = map
        .get("test_url")
        .or_else(|| map.get("url"))
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let interval = map
        .get("interval")
        .and_then(|v| v.as_duration_secs())
        .unwrap_or(300);
    let tolerance = map
        .get("tolerance")
        .and_then(|v| v.as_duration_millis())
        .unwrap_or(50);
    let lazy = map.get("lazy").and_then(|v| v.as_bool()).unwrap_or(true);
    let filter = map
        .get("filter")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let exclude_filter = map
        .get("exclude_filter")
        .or_else(|| map.get("exclude-filter"))
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let fallback = map
        .get("fallback")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);

    Ok(GroupSpec {
        name,
        ty,
        members,
        providers,
        test_url,
        interval,
        tolerance,
        lazy,
        lb_strategy: LbStrategy::RoundRobin,
        filter,
        exclude_filter,
        fallback,
        disable_udp: false,
    })
}

fn lower_dns(props: Vec<(String, DslValue)>) -> Result<DnsSpec, String> {
    let map: HashMap<String, DslValue> = props.into_iter().collect();
    let enable = map.get("enable").and_then(|v| v.as_bool()).unwrap_or(true);
    let listen = map
        .get("listen")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let ipv6 = map.get("ipv6").and_then(|v| v.as_bool()).unwrap_or(false);
    let nameserver = map
        .get("nameservers")
        .or_else(|| map.get("nameserver"))
        .and_then(|v| v.as_str_list())
        .unwrap_or_default();
    let default_nameserver = map
        .get("default_nameserver")
        .or_else(|| map.get("default-nameserver"))
        .and_then(|v| v.as_str_list())
        .unwrap_or_default();
    let fallback = map
        .get("fallback")
        .and_then(|v| v.as_str_list())
        .unwrap_or_default();

    let fake_ip = map
        .get("fake_ip")
        .or_else(|| map.get("fake-ip"))
        .and_then(|v| v.as_str())
        .map(|range| FakeIpSpec {
            enabled: true,
            ip_range: range.to_string(),
            filters: Vec::new(),
            persist: true,
        });

    Ok(DnsSpec {
        enable,
        listen,
        ipv6,
        default_nameserver,
        nameserver,
        fallback,
        fallback_filter: None,
        nameserver_policy: HashMap::new(),
        hosts: HashMap::new(),
        fake_ip,
    })
}

fn lower_services(props: Vec<(String, DslValue)>) -> Result<ServiceSpec, String> {
    let map: HashMap<String, DslValue> = props.into_iter().collect();
    let external_controller = map
        .get("external_controller")
        .or_else(|| map.get("external-controller"))
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let secret = map
        .get("secret")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let mode = match map
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("rule")
        .to_ascii_lowercase()
        .as_str()
    {
        "global" => RoutingMode::Global,
        "direct" => RoutingMode::Direct,
        _ => RoutingMode::Rule,
    };
    let log_level = map
        .get("log_level")
        .or_else(|| map.get("log-level"))
        .and_then(|v| v.as_str())
        .unwrap_or("info")
        .to_string();
    let routing_mark = map
        .get("routing_mark")
        .or_else(|| map.get("routing-mark"))
        .and_then(|v| v.as_u32());
    let interface_name = map
        .get("interface")
        .or_else(|| map.get("interface-name"))
        .and_then(|v| v.as_str())
        .map(ToString::to_string);

    Ok(ServiceSpec {
        external_controller,
        secret,
        mode,
        log_level,
        routing_mark,
        interface_name,
        tuning: TuningSpec::default(),
        resource_limits: ResourceLimitsSpec::default(),
    })
}

fn lower_security(props: Vec<(String, DslValue)>) -> Result<SecuritySpec, String> {
    let map: HashMap<String, DslValue> = props.into_iter().collect();
    let allow_geoip = map
        .get("allow_geoip")
        .or_else(|| map.get("allow-geoip"))
        .and_then(|v| v.as_str_list())
        .unwrap_or_default();
    let block_geoip = map
        .get("block_geoip")
        .or_else(|| map.get("block-geoip"))
        .and_then(|v| v.as_str_list())
        .unwrap_or_default();

    Ok(SecuritySpec {
        allow_geoip,
        block_geoip,
        allow_asn: Vec::new(),
        block_asn: Vec::new(),
        knock: None,
        rrl: None,
    })
}

fn lower_route_rule(r: RouteRuleAst) -> Result<RouteRuleSpec, String> {
    let cond = r.condition.trim();
    let target = r.target;
    let no_resolve = r.no_resolve;

    // 1. Wildcard / MatchAll: _ or * or MATCH
    if cond == "_" || cond == "*" || cond.eq_ignore_ascii_case("match") {
        return Ok(RouteRuleSpec {
            payload: RulePayload::MatchAll,
            target,
            no_resolve,
        });
    }

    // 2. Legacy Clash style condition, e.g. "DOMAIN-SUFFIX, google.com"
    if let Some((kind, val)) = cond.split_once(',') {
        let kind = kind.trim().to_ascii_uppercase();
        let val = val.trim().trim_matches('"').trim_matches('\'').to_string();
        let payload = match kind.as_str() {
            "DOMAIN" => RulePayload::Domain(val),
            "DOMAIN-SUFFIX" => RulePayload::DomainSuffix(val),
            "DOMAIN-KEYWORD" => RulePayload::DomainKeyword(val),
            "DOMAIN-REGEX" => RulePayload::DomainRegex(val),
            "IP-CIDR" | "IP-CIDR6" => RulePayload::IpCidr {
                cidr: val,
                src: false,
            },
            "GEOIP" => RulePayload::GeoIp(val),
            "GEOSITE" => RulePayload::GeoSite(val),
            "PROCESS-NAME" => RulePayload::ProcessName(val),
            "NETWORK" => RulePayload::Network(val),
            _ => RulePayload::Cel(cond.to_string()),
        };
        return Ok(RouteRuleSpec {
            payload,
            target,
            no_resolve,
        });
    }

    // 3. Google CEL expression: validate against vp_rule parser to fail early on typos
    let clean_expr = cond
        .strip_prefix('(')
        .and_then(|e| e.strip_suffix(')'))
        .unwrap_or(cond);

    // Verify syntax with vp_rule CEL Pratt parser
    vp_rule::dsl::Parser::parse(clean_expr)
        .map_err(|e| format!("CEL 表达式解析失败: '{clean_expr}': {e}"))?;

    Ok(RouteRuleSpec {
        payload: RulePayload::Cel(clean_expr.to_string()),
        target,
        no_resolve,
    })
}

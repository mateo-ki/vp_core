use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use vp_ir::*;

use crate::model::*;
use crate::validate;

impl Config {
    pub fn into_ir(self) -> std::result::Result<VpIr, Vec<String>> {
        validate::validate(&self)?;

        let bind_ip: IpAddr = if self.bind_address == "*" || self.bind_address.is_empty() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            self.bind_address
                .parse()
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        };

        // 1. Inbounds
        let mut inbounds = Vec::new();
        if let Some(p) = self.mixed_port {
            inbounds.push(InboundSpec::Mixed {
                listen: SocketAddr::new(bind_ip, p),
            });
        }
        if let Some(p) = self.port {
            inbounds.push(InboundSpec::Http {
                listen: SocketAddr::new(bind_ip, p),
            });
        }
        if let Some(p) = self.socks_port {
            inbounds.push(InboundSpec::Socks5 {
                listen: SocketAddr::new(bind_ip, p),
            });
        }
        if let Some(p) = self.redir_port {
            inbounds.push(InboundSpec::Redir {
                listen: SocketAddr::new(bind_ip, p),
            });
        }
        if let Some(p) = self.tproxy_port {
            inbounds.push(InboundSpec::Tproxy {
                listen: SocketAddr::new(bind_ip, p),
            });
        }
        for l in self.listeners {
            inbounds.push(InboundSpec::Server(Box::new(lower_server_listener(l))));
        }

        // 2. Outbounds
        let mut outbounds = Vec::with_capacity(self.proxies.len() + 2);
        outbounds.push(OutboundSpec {
            name: "DIRECT".into(),
            kind: OutboundKind::Direct,
            transport: TransportSpec::default(),
            dialer_proxy: None,
            routing_mark: None,
            bind_interface: None,
            udp_over_tcp: None,
            smux: None,
        });
        outbounds.push(OutboundSpec {
            name: "REJECT".into(),
            kind: OutboundKind::Reject,
            transport: TransportSpec::default(),
            dialer_proxy: None,
            routing_mark: None,
            bind_interface: None,
            udp_over_tcp: None,
            smux: None,
        });
        for p in self.proxies {
            outbounds.push(lower_proxy_cfg(p));
        }

        // 3. Groups
        let groups = self.proxy_groups.into_iter().map(lower_group_cfg).collect();

        // 4. Routes
        let routes = self.rules.into_iter().map(lower_rule_str).collect();
        let sub_rules = self
            .sub_rules
            .into_iter()
            .map(|(k, list)| (k, list.into_iter().map(lower_rule_str).collect()))
            .collect();

        // 5. Providers
        let rule_providers = self
            .rule_providers
            .into_iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    RuleProviderSpec {
                        name: k,
                        behavior: v.behavior.unwrap_or_else(|| "domain".into()),
                        format: v.format.unwrap_or_else(|| "yaml".into()),
                        url: v.url,
                        path: v.path,
                        interval: v.interval.unwrap_or(86400),
                    },
                )
            })
            .collect();

        let proxy_providers = self
            .proxy_providers
            .into_iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    ProxyProviderSpec {
                        name: k,
                        url: v.url,
                        path: v.path,
                        interval: v.interval.unwrap_or(86400),
                        filter: v.filter,
                    },
                )
            })
            .collect();

        // 6. DNS
        let dns = lower_dns_cfg(self.dns, self.hosts, self.ipv6);

        // 7. TUN
        let tun = self.tun.map(lower_tun_cfg);

        // 8. Services
        let services = ServiceSpec {
            external_controller: self.external_controller,
            secret: self.secret,
            mode: match self.mode {
                Mode::Rule => RoutingMode::Rule,
                Mode::Global => RoutingMode::Global,
                Mode::Direct => RoutingMode::Direct,
            },
            log_level: self.log_level,
            routing_mark: self.routing_mark,
            interface_name: self.interface_name,
            tuning: self.tuning.map(lower_tuning_cfg).unwrap_or_default(),
            resource_limits: ResourceLimitsSpec {
                max_connections: self.resource_limits.max_connections,
                max_connections_per_inbound: self.resource_limits.max_connections_per_inbound,
            },
        };

        // 9. Security
        let security = SecuritySpec {
            allow_geoip: self.allow_geoip,
            block_geoip: self.block_geoip,
            allow_asn: self.allow_asn,
            block_asn: self.block_asn,
            knock: self.knock.map(|k| KnockSpec {
                port: k.port,
                secret: k.secret,
                timeout_secs: k.timeout_secs.unwrap_or(60),
            }),
            rrl: self.rrl.map(|r| RrlSpec {
                max_qps: r.max_qps.unwrap_or(10),
                burst: r.burst.unwrap_or(20),
                slip: r.slip.unwrap_or(2),
            }),
        };

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
}

impl From<VpIr> for Config {
    fn from(ir: VpIr) -> Self {
        let mut mixed_port = None;
        let mut port = None;
        let mut socks_port = None;
        let mut redir_port = None;
        let mut tproxy_port = None;
        let mut bind_address = "*".to_string();
        let mut listeners = Vec::new();

        for inb in ir.inbounds {
            match inb {
                InboundSpec::Mixed { listen } => {
                    mixed_port = Some(listen.port());
                    if !listen.ip().is_unspecified() {
                        bind_address = listen.ip().to_string();
                    }
                }
                InboundSpec::Http { listen } => {
                    port = Some(listen.port());
                    if !listen.ip().is_unspecified() {
                        bind_address = listen.ip().to_string();
                    }
                }
                InboundSpec::Socks5 { listen } => {
                    socks_port = Some(listen.port());
                    if !listen.ip().is_unspecified() {
                        bind_address = listen.ip().to_string();
                    }
                }
                InboundSpec::Redir { listen } => {
                    redir_port = Some(listen.port());
                    if !listen.ip().is_unspecified() {
                        bind_address = listen.ip().to_string();
                    }
                }
                InboundSpec::Tproxy { listen } => {
                    tproxy_port = Some(listen.port());
                    if !listen.ip().is_unspecified() {
                        bind_address = listen.ip().to_string();
                    }
                }
                InboundSpec::Server(box_s) => {
                    let s = *box_s;
                    listeners.push(ListenerCfg {
                        name: s.name,
                        kind: s.kind,
                        port: s.listen.port(),
                        listen: Some(s.listen.ip().to_string()),
                        users: s.users.iter().map(|u| u.secret.clone()).collect(),
                        user_configs: s
                            .users
                            .into_iter()
                            .map(|u| UserConfig {
                                name: if u.username.is_empty() {
                                    None
                                } else {
                                    Some(u.username)
                                },
                                secret: u.secret,
                                rate_limit_up: u.rate_limit_bps.map(|b| (b / 1_000_000) as u32),
                                rate_limit_down: None,
                                quota_bytes: u.quota_bytes,
                                brutal_mbps: None,
                            })
                            .collect(),
                        fallback: s.fallback,
                        cipher: s.cipher,
                        cert: s.cert,
                        key: s.key,
                        shadow_tls: s.shadow_tls.map(|st| ShadowTlsCfg {
                            host: Some(st.sni),
                            password: Some(st.password),
                            port: Some(443),
                            version: Some(st.version),
                        }),
                        reality: s.reality.map(|r| RealityListenerCfg {
                            private_key: String::new(),
                            short_ids: r.short_id.into_iter().collect(),
                            dest: r.public_key,
                            server_names: Vec::new(),
                        }),
                        sni_routes: s.sni_routes,
                        obfs: s.obfs,
                        obfs_password: s.obfs_password,
                        ports: s.ports,
                        allow_geoip: s.allow_geoip,
                        block_geoip: s.block_geoip,
                        allow_asn: s.allow_asn,
                        block_asn: s.block_asn,
                        knock: s.knock.map(|k| KnockConfig {
                            port: k.port,
                            secret: k.secret,
                            timeout_secs: Some(k.timeout_secs),
                        }),
                        rrl: s.rrl.map(|r| RrlConfig {
                            max_qps: Some(r.max_qps),
                            burst: Some(r.burst),
                            slip: Some(r.slip),
                        }),
                    });
                }
            }
        }

        let proxies = ir
            .outbounds
            .into_iter()
            .filter(|o| o.name != "DIRECT" && o.name != "REJECT")
            .map(ProxyCfg::from)
            .collect();

        let proxy_groups = ir
            .groups
            .into_iter()
            .map(|g| GroupCfg {
                name: g.name,
                kind: match g.ty {
                    GroupType::Select => GroupKind::Select,
                    GroupType::UrlTest => GroupKind::UrlTest,
                    GroupType::Fallback => GroupKind::Fallback,
                    GroupType::LoadBalance => GroupKind::LoadBalance,
                    GroupType::Relay => GroupKind::Relay,
                },
                proxies: g.members,
                r#use: g.providers,
                url: g.test_url,
                interval: Some(g.interval),
                tolerance: Some(g.tolerance),
                lazy: Some(g.lazy),
                strategy: match g.lb_strategy {
                    LbStrategy::ConsistentHash => Some("consistent-hashing".into()),
                    LbStrategy::RoundRobin => None,
                },
                filter: g.filter,
                exclude_filter: g.exclude_filter,
                fallback: g.fallback,
                disable_udp: Some(g.disable_udp),
            })
            .collect();

        let rules = ir.routes.into_iter().map(route_spec_to_string).collect();

        let sub_rules = ir
            .sub_rules
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().map(route_spec_to_string).collect()))
            .collect();

        let hosts = ir
            .dns
            .hosts
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().map(|ip| ip.to_string()).collect()))
            .collect();

        let dns = DnsConfig {
            enable: ir.dns.enable,
            listen: ir.dns.listen,
            ipv6: Some(ir.dns.ipv6),
            default_nameserver: ir.dns.default_nameserver,
            nameserver: ir.dns.nameserver,
            fallback: ir.dns.fallback,
            fallback_filter: ir.dns.fallback_filter.map(|f| FallbackFilterConfig {
                geoip: f.geoip,
                geoip_code: f.geoip_code,
                geosite: f.geosite,
                ipcidr: f.ipcidr,
                domain: f.domain,
            }),
            nameserver_policy: ir
                .dns
                .nameserver_policy
                .into_iter()
                .map(|(k, v)| (k, serde_yaml::Value::String(v)))
                .collect(),
            fake_ip_range: ir.dns.fake_ip.as_ref().map(|f| f.ip_range.clone()),
            fake_ip_filter: ir.dns.fake_ip.map(|f| f.filters).unwrap_or_default(),
            enhanced_mode: None,
        };

        let tun = ir.tun.map(|t| TunCfg {
            enable: t.enable,
            address: t.address,
            netmask: t.netmask,
            mtu: t.mtu,
            fake_ip_range: "198.18.0.0/16".into(),
            auto_route: t.auto_route,
            auto_route_mode: t.auto_route_mode,
            route_address: t.route_address,
            route_exclude_address: t.route_exclude_address,
            auto_redirect: None,
            fd: None,
            ring_capacity: None,
            strict: Some(t.strict),
        });

        let mode = match ir.services.mode {
            RoutingMode::Rule => Mode::Rule,
            RoutingMode::Global => Mode::Global,
            RoutingMode::Direct => Mode::Direct,
        };

        let tuning = Some(TuningConfig {
            socket_buffer_size: ir.services.tuning.socket_buffer_size,
            so_rcvbuf: None,
            so_sndbuf: None,
            tcp_nodelay: ir.services.tuning.tcp_nodelay,
            tcp_keepalive_secs: ir.services.tuning.tcp_keepalive_secs,
            tcp_bbr: ir.services.tuning.tcp_bbr,
            tcp_fast_open: ir.services.tuning.tcp_fast_open,
            reuse_port: ir.services.tuning.reuse_port,
        });

        let resource_limits = ResourceLimitsConfig {
            max_connections: ir.services.resource_limits.max_connections,
            max_connections_per_inbound: ir.services.resource_limits.max_connections_per_inbound,
        };

        let knock = ir.security.knock.map(|k| KnockConfig {
            port: k.port,
            secret: k.secret,
            timeout_secs: Some(k.timeout_secs),
        });

        let rrl = ir.security.rrl.map(|r| RrlConfig {
            max_qps: Some(r.max_qps),
            burst: Some(r.burst),
            slip: Some(r.slip),
        });

        Config {
            mixed_port,
            port,
            socks_port,
            redir_port,
            tproxy_port,
            allow_lan: true,
            bind_address,
            mode,
            log_level: ir.services.log_level,
            ipv6: ir.dns.ipv6,
            resource_limits,
            external_controller: ir.services.external_controller,
            secret: ir.services.secret,
            dns,
            proxies,
            proxy_groups,
            proxy_providers: HashMap::new(),
            rules,
            sub_rules,
            rule_providers: HashMap::new(),
            geosite_url: None,
            geoip_url: None,
            asn_url: None,
            tun,
            listeners,
            tuning,
            routing_mark: ir.services.routing_mark,
            interface_name: ir.services.interface_name,
            hosts,
            allow_geoip: ir.security.allow_geoip,
            block_geoip: ir.security.block_geoip,
            allow_asn: ir.security.allow_asn,
            block_asn: ir.security.block_asn,
            rrl,
            knock,
        }
    }
}

fn route_spec_to_string(r: RouteRuleSpec) -> String {
    let mut base = match r.payload {
        RulePayload::MatchAll => format!("MATCH,{}", r.target),
        RulePayload::Cel(expr) => format!("EXPR,({expr}),{}", r.target),
        RulePayload::Domain(d) => format!("DOMAIN,{d},{}", r.target),
        RulePayload::DomainSuffix(d) => format!("DOMAIN-SUFFIX,{d},{}", r.target),
        RulePayload::DomainKeyword(d) => format!("DOMAIN-KEYWORD,{d},{}", r.target),
        RulePayload::DomainRegex(d) => format!("DOMAIN-REGEX,{d},{}", r.target),
        RulePayload::IpCidr { cidr, src: false } => format!("IP-CIDR,{cidr},{}", r.target),
        RulePayload::IpCidr { cidr, src: true } => format!("SRC-IP-CIDR,{cidr},{}", r.target),
        RulePayload::IpAsn { asn, src: false } => format!("IP-ASN,{asn},{}", r.target),
        RulePayload::IpAsn { asn, src: true } => format!("SRC-IP-ASN,{asn},{}", r.target),
        RulePayload::Port { ranges, src: false } => {
            let port_str = ranges
                .iter()
                .map(|(a, b)| {
                    if a == b {
                        a.to_string()
                    } else {
                        format!("{a}-{b}")
                    }
                })
                .collect::<Vec<_>>()
                .join("/");
            format!("DST-PORT,{port_str},{}", r.target)
        }
        RulePayload::Port { ranges, src: true } => {
            let port_str = ranges
                .iter()
                .map(|(a, b)| {
                    if a == b {
                        a.to_string()
                    } else {
                        format!("{a}-{b}")
                    }
                })
                .collect::<Vec<_>>()
                .join("/");
            format!("SRC-PORT,{port_str},{}", r.target)
        }
        RulePayload::InPort(ranges) => {
            let port_str = ranges
                .iter()
                .map(|(a, b)| {
                    if a == b {
                        a.to_string()
                    } else {
                        format!("{a}-{b}")
                    }
                })
                .collect::<Vec<_>>()
                .join("/");
            format!("IN-PORT,{port_str},{}", r.target)
        }
        RulePayload::GeoIp(g) => format!("GEOIP,{g},{}", r.target),
        RulePayload::GeoSite(s) => format!("GEOSITE,{s},{}", r.target),
        RulePayload::ProcessName(p) => format!("PROCESS-NAME,{p},{}", r.target),
        RulePayload::ProcessPath(p) => format!("PROCESS-PATH,{p},{}", r.target),
        RulePayload::Inbound(i) => format!("IN-NAME,{i},{}", r.target),
        RulePayload::InUser(u) => format!("IN-USER,{u},{}", r.target),
        RulePayload::Network(n) => format!("NETWORK,{n},{}", r.target),
        RulePayload::RuleSet(s) => format!("RULE-SET,{s},{}", r.target),
        RulePayload::SubRule(s) => format!("SUB-RULE,{s},{}", r.target),
    };
    if r.no_resolve {
        base.push_str(",no-resolve");
    }
    base
}

fn lower_server_listener(l: ListenerCfg) -> ServerInboundSpec {
    let listen_ip = l
        .listen
        .as_deref()
        .and_then(|s| s.parse::<IpAddr>().ok())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let listen = SocketAddr::new(listen_ip, l.port);

    let users = if !l.user_configs.is_empty() {
        l.user_configs
            .into_iter()
            .map(|u| ServerUserSpec {
                username: u.name.unwrap_or_default(),
                secret: u.secret,
                quota_bytes: u.quota_bytes,
                rate_limit_bps: u.rate_limit_up.map(|mbps| (mbps as u64) * 1_000_000),
            })
            .collect()
    } else {
        l.users
            .into_iter()
            .map(|secret| ServerUserSpec {
                username: String::new(),
                secret,
                quota_bytes: None,
                rate_limit_bps: None,
            })
            .collect()
    };

    let shadow_tls = l.shadow_tls.map(|st| ShadowTlsSpec {
        password: st.password.unwrap_or_default(),
        sni: st.host.unwrap_or_default(),
        version: st.version.unwrap_or(3),
    });

    let reality = l.reality.map(|r| RealitySpec {
        public_key: r.dest,
        short_id: r.short_ids.first().cloned(),
        spider_x: None,
    });

    let knock = l.knock.map(|k| KnockSpec {
        port: k.port,
        secret: k.secret,
        timeout_secs: k.timeout_secs.unwrap_or(60),
    });

    let rrl = l.rrl.map(|r| RrlSpec {
        max_qps: r.max_qps.unwrap_or(10),
        burst: r.burst.unwrap_or(20),
        slip: r.slip.unwrap_or(2),
    });

    ServerInboundSpec {
        name: l.name,
        kind: l.kind,
        listen,
        cipher: l.cipher,
        cert: l.cert,
        key: l.key,
        users,
        fallback: l.fallback,
        shadow_tls,
        reality,
        sni_routes: l.sni_routes,
        obfs: l.obfs,
        obfs_password: l.obfs_password,
        ports: l.ports,
        allow_geoip: l.allow_geoip,
        block_geoip: l.block_geoip,
        allow_asn: l.allow_asn,
        block_asn: l.block_asn,
        knock,
        rrl,
    }
}

fn lower_proxy_cfg(p: ProxyCfg) -> OutboundSpec {
    let uot = if p.udp_over_tcp {
        match p.udp_over_tcp_version {
            Some(2) => Some(UotVersion::V2),
            _ => Some(UotVersion::V1),
        }
    } else {
        None
    };

    let smux = p.smux.map(|s| SmuxSpec {
        enabled: s.enabled,
        protocol: s.protocol,
        max_connections: s.max_connections,
        min_streams: s.min_streams,
        max_streams: s.max_streams,
        padding: s.padding.unwrap_or(false),
    });

    let (kind, transport) = match p.kind {
        ProxyKind::Direct => (OutboundKind::Direct, TransportSpec::default()),
        ProxyKind::Reject => (OutboundKind::Reject, TransportSpec::default()),
        ProxyKind::Ss(s) => {
            let shadow_tls = if s.plugin.as_deref() == Some("shadow-tls") {
                s.plugin_opts.map(|po| ShadowTlsSpec {
                    password: po.password.unwrap_or_default(),
                    sni: po.host.unwrap_or_default(),
                    version: po.version.unwrap_or(3),
                })
            } else {
                None
            };
            (
                OutboundKind::Ss {
                    server: s.server,
                    port: s.port,
                    cipher: s.cipher,
                    password: s.password,
                    udp: s.udp,
                },
                TransportSpec {
                    shadow_tls,
                    ..Default::default()
                },
            )
        }
        ProxyKind::Ssr(s) => (
            OutboundKind::Ssr {
                server: s.server,
                port: s.port,
                password: s.password,
                cipher: s.cipher,
                protocol: s.protocol,
                obfs: s.obfs,
                obfs_param: s.obfs_param,
                protocol_param: s.protocol_param,
                udp: s.udp,
            },
            TransportSpec::default(),
        ),
        ProxyKind::Vmess(v) => (
            OutboundKind::Vmess {
                server: v.server,
                port: v.port,
                uuid: v.uuid,
                alter_id: v.alter_id,
                security: Some(v.cipher),
                udp: false,
            },
            TransportSpec {
                network: v.network,
                tls: v.tls,
                sni: v.server_name.clone(),
                alpn: v.alpn.unwrap_or_default(),
                insecure: v.skip_cert_verify,
                client_fingerprint: v.client_fingerprint,
                ws: v.ws_opts.map(|w| WsSpec {
                    path: w.path.unwrap_or_else(|| "/".into()),
                    headers: w.headers.unwrap_or_default(),
                    max_early_data: w.max_early_data,
                    v2ray_http_upgrade: w.v2ray_http_upgrade,
                }),
                grpc: v.grpc_opts.map(|g| GrpcSpec {
                    service_name: g.grpc_service_name.unwrap_or_default(),
                }),
                http: v.http_opts.map(|h| HttpSpec {
                    method: h.method,
                    path: h.path.unwrap_or_default(),
                    headers: h.headers.unwrap_or_default(),
                }),
                ech: v.ech_opts.map(|e| EchSpec {
                    enable: e.enable,
                    config: e.config,
                    query_server_name: e.query_server_name,
                    doh: e.doh,
                }),
                ..Default::default()
            },
        ),
        ProxyKind::Vless(v) => (
            OutboundKind::Vless {
                server: v.server,
                port: v.port,
                uuid: v.uuid,
                flow: v.flow,
                packet_encoding: v.packet_encoding,
                udp: v.udp,
            },
            TransportSpec {
                network: v.network,
                tls: v.tls,
                sni: v.server_name.clone(),
                alpn: v.alpn.unwrap_or_default(),
                insecure: v.skip_cert_verify,
                client_fingerprint: v.client_fingerprint,
                ws: v.ws_opts.map(|w| WsSpec {
                    path: w.path.unwrap_or_else(|| "/".into()),
                    headers: w.headers.unwrap_or_default(),
                    max_early_data: w.max_early_data,
                    v2ray_http_upgrade: w.v2ray_http_upgrade,
                }),
                grpc: v.grpc_opts.map(|g| GrpcSpec {
                    service_name: g.grpc_service_name.unwrap_or_default(),
                }),
                reality: v.reality_opts.map(|r| RealitySpec {
                    public_key: r.public_key,
                    short_id: r.short_id,
                    spider_x: r.spider_x,
                }),
                ech: v.ech_opts.map(|e| EchSpec {
                    enable: e.enable,
                    config: e.config,
                    query_server_name: e.query_server_name,
                    doh: e.doh,
                }),
                ..Default::default()
            },
        ),
        ProxyKind::Trojan(t) => (
            OutboundKind::Trojan {
                server: t.server,
                port: t.port,
                password: t.password,
                network: t.network.clone(),
                udp: t.udp,
            },
            TransportSpec {
                network: t.network,
                tls: t.tls,
                sni: t.server_name.clone(),
                alpn: t.alpn.unwrap_or_default(),
                insecure: t.skip_cert_verify,
                client_fingerprint: t.client_fingerprint,
                ws: t.ws_opts.map(|w| WsSpec {
                    path: w.path.unwrap_or_else(|| "/".into()),
                    headers: w.headers.unwrap_or_default(),
                    max_early_data: w.max_early_data,
                    v2ray_http_upgrade: w.v2ray_http_upgrade,
                }),
                grpc: t.grpc_opts.map(|g| GrpcSpec {
                    service_name: g.grpc_service_name.unwrap_or_default(),
                }),
                reality: t.reality_opts.map(|r| RealitySpec {
                    public_key: r.public_key,
                    short_id: r.short_id,
                    spider_x: r.spider_x,
                }),
                ech: t.ech_opts.map(|e| EchSpec {
                    enable: e.enable,
                    config: e.config,
                    query_server_name: e.query_server_name,
                    doh: e.doh,
                }),
                ..Default::default()
            },
        ),
        ProxyKind::Hysteria(h) => (
            OutboundKind::Hysteria {
                server: h.server,
                port: h.port,
                auth: h.auth_str.or(h.auth),
                up_mbps: h.up.map(|u| u as u64),
                down_mbps: h.down.map(|d| d as u64),
                obfs: h.obfs,
                obfs_password: h.obfs_password,
                sni: h.sni,
                alpn: h.alpn,
                insecure: h.skip_cert_verify,
            },
            TransportSpec::default(),
        ),
        ProxyKind::Hysteria2(h) => (
            OutboundKind::Hysteria2 {
                server: h.server,
                port: h.port,
                ports: h.ports,
                password: Some(h.password),
                up_mbps: h.up.map(|u| u as u64),
                down_mbps: h.down.map(|d| d as u64),
                obfs: h.obfs,
                obfs_password: h.obfs_password,
                sni: h.sni,
                insecure: h.skip_cert_verify,
            },
            TransportSpec::default(),
        ),
        ProxyKind::Tuic(t) => (
            OutboundKind::Tuic {
                server: t.server,
                port: t.port,
                uuid: t.uuid,
                password: t.password,
                congestion_controller: t.congestion_controller,
                udp_relay_mode: t.udp_relay_mode,
                zero_rtt_handshake: false,
                heartbeat: None,
                sni: t.sni,
                insecure: t.skip_cert_verify,
            },
            TransportSpec::default(),
        ),
        ProxyKind::Wireguard(w) => (
            OutboundKind::Wireguard {
                server: w.server,
                port: w.port,
                ip: w.ip,
                ipv6: w.ipv6,
                private_key: w.private_key,
                public_key: w.public_key,
                preshared_key: w.pre_shared_key,
                mtu: w.mtu,
                reserved: None,
                workers: None,
                udp: w.udp,
            },
            TransportSpec::default(),
        ),
        ProxyKind::Tailscale(t) => (
            OutboundKind::Tailscale {
                server: t.server,
                port: t.port,
                authkey: t.auth_key,
                control_url: t.control_url,
                hostname: t.hostname,
                state_dir: t.state_dir,
                exit_node: t.exit_node,
                exit_node_allow_lan: false,
            },
            TransportSpec::default(),
        ),
        ProxyKind::Snell(s) => (
            OutboundKind::Snell {
                server: s.server,
                port: s.port,
                psk: s.psk,
                version: s.version,
                obfs_opts: s.obfs_opts.map(|o| SnellObfsSpec {
                    mode: o.mode,
                    host: o.host,
                    path: o.path,
                }),
                udp: s.udp,
            },
            TransportSpec::default(),
        ),
        ProxyKind::Anytls(a) => (
            OutboundKind::Anytls {
                server: a.server,
                port: a.port,
                password: a.password,
                sni: a.server_name.clone(),
                client_fingerprint: a.client_fingerprint,
                udp: a.udp,
            },
            TransportSpec {
                tls: true,
                sni: a.server_name,
                alpn: a.alpn.unwrap_or_default(),
                insecure: a.skip_cert_verify,
                reality: a.reality_opts.map(|r| RealitySpec {
                    public_key: r.public_key,
                    short_id: r.short_id,
                    spider_x: r.spider_x,
                }),
                ..Default::default()
            },
        ),
        ProxyKind::Ssh(s) => (
            OutboundKind::Ssh {
                server: s.server,
                port: s.port,
                username: s.username,
                password: s.password,
                private_key: s.private_key,
                private_key_passphrase: None,
                host_key: s.host_key,
            },
            TransportSpec::default(),
        ),
        ProxyKind::Brook(b) => (
            OutboundKind::Brook {
                server: b.server,
                port: b.port,
                password: b.password,
                protocol: None,
                udp: b.udp,
            },
            TransportSpec::default(),
        ),
        ProxyKind::Mieru(m) => (
            OutboundKind::Mieru {
                server: m.server,
                port: m.port,
                username: m.username,
                password: m.password,
                transport: None,
                multiplexing: None,
            },
            TransportSpec::default(),
        ),
        ProxyKind::Naive(n) => (
            OutboundKind::Naive {
                server: n.server,
                port: n.port,
                username: n.username,
                password: n.password,
                sni: n.server_name.clone(),
                client_fingerprint: n.client_fingerprint,
                udp: n.udp,
            },
            TransportSpec {
                tls: n.tls,
                sni: n.server_name,
                alpn: n.alpn.unwrap_or_default(),
                insecure: n.skip_cert_verify,
                ..Default::default()
            },
        ),
        ProxyKind::Socks5(s) => (
            OutboundKind::Socks5 {
                server: s.server,
                port: s.port,
                username: s.username,
                password: s.password,
                tls: s.tls,
                sni: None,
                insecure: false,
                udp: s.udp,
            },
            TransportSpec {
                tls: s.tls,
                ..Default::default()
            },
        ),
        ProxyKind::Http(h) | ProxyKind::Https(h) => (
            OutboundKind::Http {
                server: h.server,
                port: h.port,
                username: h.username,
                password: h.password,
                tls: h.tls,
                sni: None,
                insecure: false,
                headers: HashMap::new(),
            },
            TransportSpec {
                tls: h.tls,
                ..Default::default()
            },
        ),
    };

    OutboundSpec {
        name: p.name,
        kind,
        transport,
        dialer_proxy: p.dialer_proxy,
        routing_mark: p.routing_mark,
        bind_interface: p.interface_name,
        udp_over_tcp: uot,
        smux,
    }
}

fn lower_group_cfg(g: GroupCfg) -> GroupSpec {
    let ty = match g.kind {
        GroupKind::Select => GroupType::Select,
        GroupKind::UrlTest => GroupType::UrlTest,
        GroupKind::Fallback => GroupType::Fallback,
        GroupKind::LoadBalance => GroupType::LoadBalance,
        GroupKind::Relay => GroupType::Relay,
    };

    GroupSpec {
        name: g.name,
        ty,
        members: g.proxies,
        providers: g.r#use,
        test_url: g.url,
        interval: g.interval.unwrap_or(300),
        tolerance: g.tolerance.unwrap_or(50),
        lazy: g.lazy.unwrap_or(true),
        lb_strategy: match g.strategy.as_deref() {
            Some("consistent-hashing") | Some("consistent_hashing") => LbStrategy::ConsistentHash,
            _ => LbStrategy::RoundRobin,
        },
        filter: g.filter,
        exclude_filter: g.exclude_filter,
        fallback: g.fallback,
        disable_udp: g.disable_udp.unwrap_or(false),
    }
}

fn lower_rule_str(raw: String) -> RouteRuleSpec {
    let s = raw.trim();
    let parts: Vec<&str> = s.split(',').map(str::trim).collect();
    if parts.is_empty() {
        return RouteRuleSpec {
            payload: RulePayload::MatchAll,
            target: "DIRECT".into(),
            no_resolve: false,
        };
    }

    let ty = parts[0].to_ascii_uppercase();
    let target = parts.get(2).copied().unwrap_or("DIRECT").to_string();
    let no_resolve = parts
        .iter()
        .skip(3)
        .any(|p| p.eq_ignore_ascii_case("no-resolve"));

    let payload = match ty.as_str() {
        "MATCH" => RulePayload::MatchAll,
        "EXPR" | "CEL" => {
            let expr = parts.get(1).copied().unwrap_or("");
            let clean = expr
                .strip_prefix('(')
                .and_then(|e| e.strip_suffix(')'))
                .unwrap_or(expr);
            RulePayload::Cel(clean.to_string())
        }
        "DOMAIN" => RulePayload::Domain(parts.get(1).copied().unwrap_or("").to_string()),
        "DOMAIN-SUFFIX" => {
            RulePayload::DomainSuffix(parts.get(1).copied().unwrap_or("").to_string())
        }
        "DOMAIN-KEYWORD" => {
            RulePayload::DomainKeyword(parts.get(1).copied().unwrap_or("").to_string())
        }
        "DOMAIN-REGEX" => RulePayload::DomainRegex(parts.get(1).copied().unwrap_or("").to_string()),
        "IP-CIDR" | "IP-CIDR6" => RulePayload::IpCidr {
            cidr: parts.get(1).copied().unwrap_or("").to_string(),
            src: false,
        },
        "SRC-IP-CIDR" => RulePayload::IpCidr {
            cidr: parts.get(1).copied().unwrap_or("").to_string(),
            src: true,
        },
        "GEOIP" => RulePayload::GeoIp(parts.get(1).copied().unwrap_or("").to_string()),
        "GEOSITE" => RulePayload::GeoSite(parts.get(1).copied().unwrap_or("").to_string()),
        "PROCESS-NAME" => RulePayload::ProcessName(parts.get(1).copied().unwrap_or("").to_string()),
        "PROCESS-PATH" => RulePayload::ProcessPath(parts.get(1).copied().unwrap_or("").to_string()),
        "IN-NAME" | "IN-TAG" | "IN-TYPE" => {
            RulePayload::Inbound(parts.get(1).copied().unwrap_or("").to_string())
        }
        "IN-USER" => RulePayload::InUser(parts.get(1).copied().unwrap_or("").to_string()),
        "NETWORK" => RulePayload::Network(parts.get(1).copied().unwrap_or("").to_string()),
        "RULE-SET" => RulePayload::RuleSet(parts.get(1).copied().unwrap_or("").to_string()),
        "SUB-RULE" => RulePayload::SubRule(parts.get(1).copied().unwrap_or("").to_string()),
        _ => RulePayload::Cel(s.to_string()),
    };

    RouteRuleSpec {
        payload,
        target,
        no_resolve,
    }
}

fn lower_dns_cfg(
    dns: DnsConfig,
    hosts: HashMap<String, Vec<String>>,
    global_ipv6: bool,
) -> DnsSpec {
    let ipv6 = dns.is_ipv6(global_ipv6);
    let hosts_parsed = hosts
        .into_iter()
        .map(|(domain, ips)| {
            let parsed_ips = ips
                .into_iter()
                .filter_map(|s| s.parse::<IpAddr>().ok())
                .collect();
            (domain, parsed_ips)
        })
        .collect();

    let fallback_filter = dns.fallback_filter.map(|f| FallbackFilterSpec {
        geoip: f.geoip,
        geoip_code: f.geoip_code,
        geosite: f.geosite,
        ipcidr: f.ipcidr,
        domain: f.domain,
    });

    let fake_ip = dns.fake_ip_range.map(|range| FakeIpSpec {
        enabled: true,
        ip_range: range,
        filters: dns.fake_ip_filter,
        persist: true,
    });

    let nameserver_policy = dns
        .nameserver_policy
        .into_iter()
        .map(|(k, v)| {
            let s = match v {
                serde_yaml::Value::String(str_val) => str_val,
                serde_yaml::Value::Sequence(seq) => seq
                    .into_iter()
                    .filter_map(|item| item.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
                    .join(","),
                _ => String::new(),
            };
            (k, s)
        })
        .collect();

    DnsSpec {
        enable: dns.enable,
        listen: dns.listen,
        ipv6,
        default_nameserver: dns.default_nameserver,
        nameserver: dns.nameserver,
        fallback: dns.fallback,
        fallback_filter,
        nameserver_policy,
        hosts: hosts_parsed,
        fake_ip,
    }
}

fn lower_tun_cfg(t: TunCfg) -> TunSpec {
    TunSpec {
        enable: t.enable,
        device: None,
        address: t.address,
        netmask: t.netmask,
        mtu: t.mtu,
        auto_route: t.auto_route,
        auto_route_mode: t.auto_route_mode,
        auto_detect_interface: true,
        route_address: t.route_address,
        route_exclude_address: t.route_exclude_address,
        dns_hijack: Vec::new(),
        strict: t.strict.unwrap_or(false),
    }
}

fn lower_tuning_cfg(t: TuningConfig) -> TuningSpec {
    TuningSpec {
        socket_buffer_size: t.socket_buffer_size,
        tcp_nodelay: t.tcp_nodelay,
        tcp_keepalive_secs: t.tcp_keepalive_secs,
        tcp_bbr: t.tcp_bbr,
        tcp_fast_open: t.tcp_fast_open,
        reuse_port: t.reuse_port,
    }
}

impl From<OutboundSpec> for ProxyCfg {
    fn from(spec: OutboundSpec) -> Self {
        let (udp_over_tcp, udp_over_tcp_version) = match spec.udp_over_tcp {
            Some(UotVersion::V1) => (true, Some(1)),
            Some(UotVersion::V2) => (true, Some(2)),
            None => (false, None),
        };
        let smux = spec.smux.map(|s| SmuxConfig {
            enabled: s.enabled,
            protocol: s.protocol,
            max_connections: s.max_connections,
            min_streams: s.min_streams,
            max_streams: s.max_streams,
            padding: Some(s.padding),
        });

        let t = spec.transport;
        let kind = match spec.kind {
            OutboundKind::Direct => ProxyKind::Direct,
            OutboundKind::Reject => ProxyKind::Reject,
            OutboundKind::Ss {
                server,
                port,
                cipher,
                password,
                udp,
            } => {
                let plugin = if t.shadow_tls.is_some() {
                    Some("shadow-tls".into())
                } else {
                    None
                };
                let plugin_opts = t.shadow_tls.map(|st| ShadowTlsCfg {
                    host: Some(st.sni),
                    password: Some(st.password),
                    port: Some(443),
                    version: Some(st.version),
                });
                ProxyKind::Ss(SsCfg {
                    server,
                    port,
                    cipher,
                    password,
                    udp,
                    plugin,
                    plugin_opts,
                })
            }
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
            } => ProxyKind::Ssr(SsrCfg {
                server,
                port,
                password,
                cipher,
                protocol,
                protocol_param,
                obfs,
                obfs_param,
                udp,
            }),
            OutboundKind::Vmess {
                server,
                port,
                uuid,
                alter_id,
                security,
                udp: _,
            } => ProxyKind::Vmess(VmessCfg {
                server,
                port,
                uuid,
                alter_id,
                cipher: security.unwrap_or_else(|| "auto".into()),
                tls: t.tls,
                server_name: t.sni,
                skip_cert_verify: t.insecure,
                client_fingerprint: t.client_fingerprint,
                network: t.network,
                alpn: if t.alpn.is_empty() {
                    None
                } else {
                    Some(t.alpn)
                },
                ech_opts: t.ech.map(|e| EchOpts {
                    enable: e.enable,
                    config: e.config,
                    query_server_name: e.query_server_name,
                    doh: e.doh,
                }),
                ws_opts: t.ws.map(|w| WsOpts {
                    path: Some(w.path),
                    headers: if w.headers.is_empty() {
                        None
                    } else {
                        Some(w.headers)
                    },
                    max_early_data: w.max_early_data,
                    v2ray_http_upgrade: w.v2ray_http_upgrade,
                }),
                grpc_opts: t.grpc.map(|g| GrpcOpts {
                    grpc_service_name: Some(g.service_name),
                }),
                http_opts: t.http.as_ref().map(|h| HttpOpts {
                    method: h.method.clone(),
                    path: Some(h.path.clone()),
                    headers: Some(h.headers.clone()),
                }),
                udp: false,
                packet_encoding: None,
                xudp: false,
                packet_addr: false,
            }),
            OutboundKind::Vless {
                server,
                port,
                uuid,
                flow,
                packet_encoding,
                udp,
            } => ProxyKind::Vless(VlessCfg {
                server,
                port,
                uuid,
                flow,
                tls: t.tls,
                server_name: t.sni,
                skip_cert_verify: t.insecure,
                client_fingerprint: t.client_fingerprint,
                network: t.network,
                alpn: if t.alpn.is_empty() {
                    None
                } else {
                    Some(t.alpn)
                },
                reality_opts: t.reality.map(|r| RealityOpts {
                    public_key: r.public_key,
                    short_id: r.short_id,
                    spider_x: r.spider_x,
                }),
                ech_opts: t.ech.map(|e| EchOpts {
                    enable: e.enable,
                    config: e.config,
                    query_server_name: e.query_server_name,
                    doh: e.doh,
                }),
                ws_opts: t.ws.map(|w| WsOpts {
                    path: Some(w.path),
                    headers: if w.headers.is_empty() {
                        None
                    } else {
                        Some(w.headers)
                    },
                    max_early_data: w.max_early_data,
                    v2ray_http_upgrade: w.v2ray_http_upgrade,
                }),
                grpc_opts: t.grpc.map(|g| GrpcOpts {
                    grpc_service_name: Some(g.service_name),
                }),
                http_opts: t.http.map(|h| HttpOpts {
                    method: h.method,
                    path: Some(h.path),
                    headers: Some(h.headers),
                }),
                udp,
                packet_encoding,
                xudp: false,
                packet_addr: false,
            }),
            OutboundKind::Trojan {
                server,
                port,
                password,
                network,
                udp,
            } => ProxyKind::Trojan(TrojanCfg {
                server,
                port,
                password,
                tls: t.tls,
                server_name: t.sni,
                skip_cert_verify: t.insecure,
                client_fingerprint: t.client_fingerprint,
                network: network.or(t.network),
                alpn: if t.alpn.is_empty() {
                    None
                } else {
                    Some(t.alpn)
                },
                ws_opts: t.ws.map(|w| WsOpts {
                    path: Some(w.path),
                    headers: if w.headers.is_empty() {
                        None
                    } else {
                        Some(w.headers)
                    },
                    max_early_data: w.max_early_data,
                    v2ray_http_upgrade: w.v2ray_http_upgrade,
                }),
                grpc_opts: t.grpc.map(|g| GrpcOpts {
                    grpc_service_name: Some(g.service_name),
                }),
                reality_opts: t.reality.map(|r| RealityOpts {
                    public_key: r.public_key,
                    short_id: r.short_id,
                    spider_x: r.spider_x,
                }),
                ech_opts: t.ech.map(|e| EchOpts {
                    enable: e.enable,
                    config: e.config,
                    query_server_name: e.query_server_name,
                    doh: e.doh,
                }),
                http_opts: t.http.map(|h| HttpOpts {
                    method: h.method,
                    path: Some(h.path),
                    headers: Some(h.headers),
                }),
                udp,
            }),
            OutboundKind::Hysteria {
                server,
                port,
                auth,
                up_mbps,
                down_mbps,
                obfs,
                obfs_password,
                sni,
                alpn,
                insecure,
            } => ProxyKind::Hysteria(Hysteria1Cfg {
                server,
                port,
                auth_str: auth,
                auth: None,
                up: up_mbps.map(|u| u as u32),
                down: down_mbps.map(|d| d as u32),
                protocol: Some("udp".into()),
                obfs,
                obfs_password,
                sni,
                alpn,
                skip_cert_verify: insecure,
            }),
            OutboundKind::Hysteria2 {
                server,
                port,
                ports,
                password,
                up_mbps,
                down_mbps,
                obfs,
                obfs_password,
                sni,
                insecure,
            } => ProxyKind::Hysteria2(Hysteria2Cfg {
                server,
                port,
                password: password.unwrap_or_default(),
                sni,
                skip_cert_verify: insecure,
                up: up_mbps.map(|u| u as u32),
                down: down_mbps.map(|d| d as u32),
                obfs,
                obfs_password,
                ports,
                hop_interval: None,
            }),
            OutboundKind::Tuic {
                server,
                port,
                uuid,
                password,
                congestion_controller,
                udp_relay_mode,
                zero_rtt_handshake: _,
                heartbeat: _,
                sni,
                insecure,
            } => ProxyKind::Tuic(TuicCfg {
                server,
                port,
                uuid,
                password,
                sni,
                skip_cert_verify: insecure,
                congestion_controller,
                udp_relay_mode,
            }),
            OutboundKind::Wireguard {
                server,
                port,
                ip,
                ipv6,
                private_key,
                public_key,
                preshared_key,
                mtu,
                reserved: _,
                workers: _,
                udp,
            } => ProxyKind::Wireguard(WgCfg {
                server,
                port,
                private_key,
                public_key,
                pre_shared_key: preshared_key,
                persistent_keepalive: None,
                ip,
                ipv6,
                udp,
                mtu,
            }),
            OutboundKind::Tailscale {
                server,
                port,
                authkey,
                control_url,
                hostname,
                state_dir,
                exit_node,
                exit_node_allow_lan: _,
            } => ProxyKind::Tailscale(TailscaleCfg {
                server,
                port,
                auth_key: authkey,
                control_url,
                exit_node,
                hostname,
                state_dir,
                udp: true,
            }),
            OutboundKind::Snell {
                server,
                port,
                psk,
                version,
                obfs_opts,
                udp,
            } => ProxyKind::Snell(SnellCfg {
                server,
                port,
                psk,
                version,
                obfs: None,
                host: None,
                obfs_opts: obfs_opts.map(|o| SnellObfsOpts {
                    mode: o.mode,
                    host: o.host,
                    path: o.path,
                }),
                udp,
            }),
            OutboundKind::Anytls {
                server,
                port,
                password,
                sni,
                client_fingerprint,
                udp,
            } => ProxyKind::Anytls(AnytlsCfg {
                server,
                port,
                password,
                server_name: sni.or(t.sni),
                skip_cert_verify: t.insecure,
                client_fingerprint,
                alpn: if t.alpn.is_empty() {
                    None
                } else {
                    Some(t.alpn)
                },
                reality_opts: t.reality.map(|r| RealityOpts {
                    public_key: r.public_key,
                    short_id: r.short_id,
                    spider_x: r.spider_x,
                }),
                udp,
            }),
            OutboundKind::Ssh {
                server,
                port,
                username,
                password,
                private_key,
                private_key_passphrase: _,
                host_key,
            } => ProxyKind::Ssh(SshCfg {
                server,
                port,
                username,
                password,
                private_key,
                host_key,
            }),
            OutboundKind::Brook {
                server,
                port,
                password,
                protocol: _,
                udp,
            } => ProxyKind::Brook(BrookCfg {
                server,
                port,
                password,
                udp,
            }),
            OutboundKind::Mieru {
                server,
                port,
                username,
                password,
                transport: _,
                multiplexing: _,
            } => ProxyKind::Mieru(MieruCfg {
                server,
                port,
                username,
                password,
            }),
            OutboundKind::Naive {
                server,
                port,
                username,
                password,
                sni,
                client_fingerprint,
                udp,
            } => ProxyKind::Naive(NaiveCfg {
                server,
                port,
                username,
                password,
                server_name: sni.or(t.sni),
                skip_cert_verify: t.insecure,
                client_fingerprint,
                alpn: if t.alpn.is_empty() {
                    None
                } else {
                    Some(t.alpn)
                },
                tls: t.tls,
                udp,
            }),
            OutboundKind::Socks5 {
                server,
                port,
                username,
                password,
                tls,
                sni: _,
                insecure: _,
                udp,
            } => ProxyKind::Socks5(SocksCfg {
                server,
                port,
                username,
                password,
                udp,
                tls,
            }),
            OutboundKind::Http {
                server,
                port,
                username,
                password,
                tls,
                sni: _,
                insecure: _,
                headers: _,
            } => {
                let cfg = HttpCfg {
                    server,
                    port,
                    username,
                    password,
                    tls,
                    skip_cert_verify: false,
                    sni: None,
                };
                if tls {
                    ProxyKind::Https(cfg)
                } else {
                    ProxyKind::Http(cfg)
                }
            }
        };

        ProxyCfg {
            name: spec.name,
            udp_over_tcp,
            udp_over_tcp_version,
            dialer_proxy: spec.dialer_proxy,
            smux,
            interface_name: spec.bind_interface,
            routing_mark: spec.routing_mark,
            kind,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Format, parse};

    #[test]
    fn test_into_ir_conversion() {
        let yaml = r#"
mixed-port: 7890
mode: rule
log-level: info
proxies:
  - name: "node-1"
    type: ss
    server: 1.1.1.1
    port: 8388
    cipher: aes-128-gcm
    password: pass
    udp: true
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - node-1
rules:
  - DOMAIN-SUFFIX,google.com,PROXY
  - MATCH,DIRECT
"#;
        let cfg = parse(yaml, Format::Yaml).expect("parse yaml");
        let ir = cfg.into_ir().expect("into_ir");
        assert_eq!(ir.inbounds.len(), 1);
        assert_eq!(ir.outbounds.len(), 3); // DIRECT, REJECT, node-1
        assert_eq!(ir.groups.len(), 1);
        assert_eq!(ir.routes.len(), 2);
        assert_eq!(ir.groups[0].name, "PROXY");
        assert_eq!(ir.routes[0].target, "PROXY");
    }
}

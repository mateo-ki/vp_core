use vp_ir::*;

/// 将统一中间表示 `VpIr` 序列化输出为标准的 `.vp` DSL 文本。
pub fn ir_to_dsl(ir: &VpIr) -> String {
    let mut out = String::with_capacity(4096);

    // 1. Inbounds (入站)
    for inbound in &ir.inbounds {
        serialize_inbound(inbound, &mut out);
    }

    // 2. Tun
    if let Some(tun) = &ir.tun {
        if tun.enable {
            serialize_tun(tun, &mut out);
        }
    }

    // 3. Outbounds (出站代理节点，剔除内置的 DIRECT / REJECT)
    for ob in &ir.outbounds {
        let name_upper = ob.name.to_ascii_uppercase();
        if name_upper == "DIRECT" || name_upper == "REJECT" {
            continue;
        }
        serialize_outbound(ob, &mut out);
    }

    // 4. Groups (策略组)
    for g in &ir.groups {
        serialize_group(g, &mut out);
    }

    // 5. DNS
    if ir.dns.enable
        || !ir.dns.nameserver.is_empty()
        || ir.dns.fake_ip.is_some()
        || ir.dns.listen.is_some()
    {
        serialize_dns(&ir.dns, &mut out);
    }

    // 6. Services
    serialize_services(&ir.services, &mut out);

    // 7. Security (如果配置了门禁规则)
    if !ir.security.allow_geoip.is_empty()
        || !ir.security.block_geoip.is_empty()
        || ir.security.knock.is_some()
        || ir.security.rrl.is_some()
    {
        serialize_security(&ir.security, &mut out);
    }

    // 8. Routes (主路由流向)
    if !ir.routes.is_empty() {
        out.push_str("route {\n");
        for r in &ir.routes {
            out.push_str("    ");
            out.push_str(&format_route_rule(r));
            out.push('\n');
        }
        out.push_str("}\n\n");
    }

    // 9. Sub-rules (子规则流向)
    let mut sub_names: Vec<&String> = ir.sub_rules.keys().collect();
    sub_names.sort();
    for sub_name in sub_names {
        let rules = &ir.sub_rules[sub_name];
        out.push_str(&format!("sub_rule \"{}\" {{\n", escape_str(sub_name)));
        for r in rules {
            out.push_str("    ");
            out.push_str(&format_route_rule(r));
            out.push('\n');
        }
        out.push_str("}\n\n");
    }

    out.trim_end().to_string() + "\n"
}

/// 格式化 DSL 脚本文本：先解析为 VpIr，再生成规范排版的 DSL 文本。
pub fn format_dsl(input: &str) -> Result<String, String> {
    let ir = crate::parse(input)?;
    Ok(ir_to_dsl(&ir))
}

fn escape_str(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn serialize_inbound(inbound: &InboundSpec, out: &mut String) {
    match inbound {
        InboundSpec::Mixed { listen } => {
            out.push_str("inbound mixed {\n");
            out.push_str(&format!("    listen: \"{listen}\"\n"));
            out.push_str("}\n\n");
        }
        InboundSpec::Http { listen } => {
            out.push_str("inbound http {\n");
            out.push_str(&format!("    listen: \"{listen}\"\n"));
            out.push_str("}\n\n");
        }
        InboundSpec::Socks5 { listen } => {
            out.push_str("inbound socks5 {\n");
            out.push_str(&format!("    listen: \"{listen}\"\n"));
            out.push_str("}\n\n");
        }
        InboundSpec::Redir { listen } => {
            out.push_str("inbound redir {\n");
            out.push_str(&format!("    listen: \"{listen}\"\n"));
            out.push_str("}\n\n");
        }
        InboundSpec::Tproxy { listen } => {
            out.push_str("inbound tproxy {\n");
            out.push_str(&format!("    listen: \"{listen}\"\n"));
            out.push_str("}\n\n");
        }
        InboundSpec::Server(box_s) => {
            let s = box_s.as_ref();
            out.push_str(&format!(
                "inbound server \"{}\" {} {{\n",
                escape_str(&s.name),
                s.kind
            ));
            out.push_str(&format!("    listen: \"{}\"\n", s.listen));
            if let Some(c) = &s.cipher {
                out.push_str(&format!("    cipher: \"{}\"\n", escape_str(c)));
            }
            if let Some(c) = &s.cert {
                out.push_str(&format!("    cert: \"{}\"\n", escape_str(c)));
            }
            if let Some(k) = &s.key {
                out.push_str(&format!("    key: \"{}\"\n", escape_str(k)));
            }
            if let Some(f) = &s.fallback {
                out.push_str(&format!("    fallback: \"{}\"\n", escape_str(f)));
            }
            if let Some(o) = &s.obfs {
                out.push_str(&format!("    obfs: \"{}\"\n", escape_str(o)));
            }
            if let Some(p) = &s.obfs_password {
                out.push_str(&format!("    obfs_password: \"{}\"\n", escape_str(p)));
            }
            if let Some(p) = &s.ports {
                out.push_str(&format!("    ports: \"{}\"\n", escape_str(p)));
            }
            if !s.users.is_empty() {
                let user_secrets: Vec<String> = s
                    .users
                    .iter()
                    .map(|u| format!("\"{}\"", escape_str(&u.secret)))
                    .collect();
                out.push_str(&format!("    users: [{}]\n", user_secrets.join(", ")));
            }
            out.push_str("}\n\n");
        }
    }
}

fn serialize_tun(tun: &TunSpec, out: &mut String) {
    out.push_str("inbound tun {\n");
    out.push_str(&format!("    address: \"{}\"\n", escape_str(&tun.address)));
    out.push_str(&format!("    netmask: \"{}\"\n", escape_str(&tun.netmask)));
    if tun.mtu != 1500 && tun.mtu > 0 {
        out.push_str(&format!("    mtu: {}\n", tun.mtu));
    }
    out.push_str(&format!("    auto_route: {}\n", tun.auto_route));
    if let Some(mode) = &tun.auto_route_mode {
        out.push_str(&format!("    auto_route_mode: \"{}\"\n", escape_str(mode)));
    }
    if tun.strict {
        out.push_str("    strict: true\n");
    }
    if !tun.route_address.is_empty() {
        let list: Vec<String> = tun
            .route_address
            .iter()
            .map(|s| format!("\"{}\"", escape_str(s)))
            .collect();
        out.push_str(&format!("    route_address: [{}]\n", list.join(", ")));
    }
    if !tun.route_exclude_address.is_empty() {
        let list: Vec<String> = tun
            .route_exclude_address
            .iter()
            .map(|s| format!("\"{}\"", escape_str(s)))
            .collect();
        out.push_str(&format!(
            "    route_exclude_address: [{}]\n",
            list.join(", ")
        ));
    }
    out.push_str("}\n\n");
}

fn serialize_outbound(ob: &OutboundSpec, out: &mut String) {
    let kind_name = match &ob.kind {
        OutboundKind::Direct => return,
        OutboundKind::Reject => return,
        OutboundKind::Ss { .. } => "ss",
        OutboundKind::Ssr { .. } => "ssr",
        OutboundKind::Vmess { .. } => "vmess",
        OutboundKind::Vless { .. } => "vless",
        OutboundKind::Trojan { .. } => "trojan",
        OutboundKind::Hysteria { .. } => "hysteria",
        OutboundKind::Hysteria2 { .. } => "hysteria2",
        OutboundKind::Tuic { .. } => "tuic",
        OutboundKind::Wireguard { .. } => "wireguard",
        OutboundKind::Tailscale { .. } => "tailscale",
        OutboundKind::Snell { .. } => "snell",
        OutboundKind::Anytls { .. } => "anytls",
        OutboundKind::Ssh { .. } => "ssh",
        OutboundKind::Brook { .. } => "brook",
        OutboundKind::Mieru { .. } => "mieru",
        OutboundKind::Naive { .. } => "naive",
        OutboundKind::Socks5 { .. } => "socks5",
        OutboundKind::Http { .. } => "http",
    };

    out.push_str(&format!(
        "node \"{}\" {} {{\n",
        escape_str(&ob.name),
        kind_name
    ));

    match &ob.kind {
        OutboundKind::Ss {
            server,
            port,
            cipher,
            password,
            udp,
        } => {
            out.push_str(&format!("    server: \"{}\"\n", escape_str(server)));
            out.push_str(&format!("    port: {port}\n"));
            out.push_str(&format!("    cipher: \"{}\"\n", escape_str(cipher)));
            out.push_str(&format!("    password: \"{}\"\n", escape_str(password)));
            if *udp {
                out.push_str("    udp: true\n");
            }
        }
        OutboundKind::Vless {
            server,
            port,
            uuid,
            flow,
            packet_encoding,
            udp,
        } => {
            out.push_str(&format!("    server: \"{}\"\n", escape_str(server)));
            out.push_str(&format!("    port: {port}\n"));
            out.push_str(&format!("    uuid: \"{}\"\n", escape_str(uuid)));
            if let Some(f) = flow {
                out.push_str(&format!("    flow: \"{}\"\n", escape_str(f)));
            }
            if let Some(p) = packet_encoding {
                out.push_str(&format!("    packet_encoding: \"{}\"\n", escape_str(p)));
            }
            if *udp {
                out.push_str("    udp: true\n");
            }
        }
        OutboundKind::Vmess {
            server,
            port,
            uuid,
            alter_id,
            security,
            udp,
        } => {
            out.push_str(&format!("    server: \"{}\"\n", escape_str(server)));
            out.push_str(&format!("    port: {port}\n"));
            out.push_str(&format!("    uuid: \"{}\"\n", escape_str(uuid)));
            if *alter_id > 0 {
                out.push_str(&format!("    alter_id: {alter_id}\n"));
            }
            if let Some(sec) = security {
                out.push_str(&format!("    cipher: \"{}\"\n", escape_str(sec)));
            }
            if *udp {
                out.push_str("    udp: true\n");
            }
        }
        OutboundKind::Trojan {
            server,
            port,
            password,
            network,
            udp,
        } => {
            out.push_str(&format!("    server: \"{}\"\n", escape_str(server)));
            out.push_str(&format!("    port: {port}\n"));
            out.push_str(&format!("    password: \"{}\"\n", escape_str(password)));
            if let Some(net) = network {
                out.push_str(&format!("    network: \"{}\"\n", escape_str(net)));
            }
            if *udp {
                out.push_str("    udp: true\n");
            }
        }
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
        } => {
            out.push_str(&format!("    server: \"{}\"\n", escape_str(server)));
            out.push_str(&format!("    port: {port}\n"));
            if let Some(p) = ports {
                out.push_str(&format!("    ports: \"{}\"\n", escape_str(p)));
            }
            if let Some(pwd) = password {
                out.push_str(&format!("    password: \"{}\"\n", escape_str(pwd)));
            }
            if let Some(up) = up_mbps {
                out.push_str(&format!("    up: {up}\n"));
            }
            if let Some(down) = down_mbps {
                out.push_str(&format!("    down: {down}\n"));
            }
            if let Some(o) = obfs {
                out.push_str(&format!("    obfs: \"{}\"\n", escape_str(o)));
            }
            if let Some(op) = obfs_password {
                out.push_str(&format!("    obfs_password: \"{}\"\n", escape_str(op)));
            }
            if let Some(s) = sni {
                out.push_str(&format!("    sni: \"{}\"\n", escape_str(s)));
            }
            if *insecure {
                out.push_str("    insecure: true\n");
            }
        }
        OutboundKind::Tuic {
            server,
            port,
            uuid,
            password,
            congestion_controller,
            udp_relay_mode,
            zero_rtt_handshake,
            heartbeat,
            sni,
            insecure,
        } => {
            out.push_str(&format!("    server: \"{}\"\n", escape_str(server)));
            out.push_str(&format!("    port: {port}\n"));
            out.push_str(&format!("    uuid: \"{}\"\n", escape_str(uuid)));
            out.push_str(&format!("    password: \"{}\"\n", escape_str(password)));
            if let Some(cc) = congestion_controller {
                out.push_str(&format!(
                    "    congestion_controller: \"{}\"\n",
                    escape_str(cc)
                ));
            }
            if let Some(urm) = udp_relay_mode {
                out.push_str(&format!("    udp_relay_mode: \"{}\"\n", escape_str(urm)));
            }
            if *zero_rtt_handshake {
                out.push_str("    zero_rtt_handshake: true\n");
            }
            if let Some(hb) = heartbeat {
                out.push_str(&format!("    heartbeat: \"{}\"\n", escape_str(hb)));
            }
            if let Some(s) = sni {
                out.push_str(&format!("    sni: \"{}\"\n", escape_str(s)));
            }
            if *insecure {
                out.push_str("    insecure: true\n");
            }
        }
        OutboundKind::Wireguard {
            server,
            port,
            ip,
            ipv6,
            private_key,
            public_key,
            preshared_key,
            mtu,
            udp,
            ..
        } => {
            out.push_str(&format!("    server: \"{}\"\n", escape_str(server)));
            out.push_str(&format!("    port: {port}\n"));
            out.push_str(&format!("    ip: \"{}\"\n", escape_str(ip)));
            if let Some(v6) = ipv6 {
                out.push_str(&format!("    ipv6: \"{}\"\n", escape_str(v6)));
            }
            out.push_str(&format!(
                "    private_key: \"{}\"\n",
                escape_str(private_key)
            ));
            out.push_str(&format!("    public_key: \"{}\"\n", escape_str(public_key)));
            if let Some(psk) = preshared_key {
                out.push_str(&format!("    preshared_key: \"{}\"\n", escape_str(psk)));
            }
            if let Some(m) = mtu {
                out.push_str(&format!("    mtu: {m}\n"));
            }
            if *udp {
                out.push_str("    udp: true\n");
            }
        }
        OutboundKind::Socks5 {
            server,
            port,
            username,
            password,
            tls,
            sni,
            insecure,
            udp,
        } => {
            out.push_str(&format!("    server: \"{}\"\n", escape_str(server)));
            out.push_str(&format!("    port: {port}\n"));
            if let Some(u) = username {
                out.push_str(&format!("    username: \"{}\"\n", escape_str(u)));
            }
            if let Some(p) = password {
                out.push_str(&format!("    password: \"{}\"\n", escape_str(p)));
            }
            if *tls {
                out.push_str("    tls: true\n");
            }
            if let Some(s) = sni {
                out.push_str(&format!("    sni: \"{}\"\n", escape_str(s)));
            }
            if *insecure {
                out.push_str("    insecure: true\n");
            }
            if *udp {
                out.push_str("    udp: true\n");
            }
        }
        OutboundKind::Http {
            server,
            port,
            username,
            password,
            tls,
            sni,
            insecure,
            ..
        } => {
            out.push_str(&format!("    server: \"{}\"\n", escape_str(server)));
            out.push_str(&format!("    port: {port}\n"));
            if let Some(u) = username {
                out.push_str(&format!("    username: \"{}\"\n", escape_str(u)));
            }
            if let Some(p) = password {
                out.push_str(&format!("    password: \"{}\"\n", escape_str(p)));
            }
            if *tls {
                out.push_str("    tls: true\n");
            }
            if let Some(s) = sni {
                out.push_str(&format!("    sni: \"{}\"\n", escape_str(s)));
            }
            if *insecure {
                out.push_str("    insecure: true\n");
            }
        }
        OutboundKind::Snell {
            server,
            port,
            psk,
            version,
            udp,
            ..
        } => {
            out.push_str(&format!("    server: \"{}\"\n", escape_str(server)));
            out.push_str(&format!("    port: {port}\n"));
            out.push_str(&format!("    psk: \"{}\"\n", escape_str(psk)));
            out.push_str(&format!("    version: {version}\n"));
            if *udp {
                out.push_str("    udp: true\n");
            }
        }
        OutboundKind::Ssh {
            server,
            port,
            username,
            password,
            private_key,
            host_key,
            ..
        } => {
            out.push_str(&format!("    server: \"{}\"\n", escape_str(server)));
            out.push_str(&format!("    port: {port}\n"));
            out.push_str(&format!("    username: \"{}\"\n", escape_str(username)));
            if let Some(p) = password {
                out.push_str(&format!("    password: \"{}\"\n", escape_str(p)));
            }
            if let Some(pk) = private_key {
                out.push_str(&format!("    private_key: \"{}\"\n", escape_str(pk)));
            }
            if let Some(hk) = host_key {
                out.push_str(&format!("    host_key: \"{}\"\n", escape_str(hk)));
            }
        }
        OutboundKind::Anytls {
            server,
            port,
            password,
            udp,
            ..
        } => {
            out.push_str(&format!("    server: \"{}\"\n", escape_str(server)));
            out.push_str(&format!("    port: {port}\n"));
            out.push_str(&format!("    password: \"{}\"\n", escape_str(password)));
            if *udp {
                out.push_str("    udp: true\n");
            }
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
        } => {
            out.push_str(&format!("    server: \"{}\"\n", escape_str(server)));
            out.push_str(&format!("    port: {port}\n"));
            out.push_str(&format!("    password: \"{}\"\n", escape_str(password)));
            out.push_str(&format!("    cipher: \"{}\"\n", escape_str(cipher)));
            out.push_str(&format!("    protocol: \"{}\"\n", escape_str(protocol)));
            out.push_str(&format!("    obfs: \"{}\"\n", escape_str(obfs)));
            if let Some(op) = obfs_param {
                out.push_str(&format!("    obfs_param: \"{}\"\n", escape_str(op)));
            }
            if let Some(pp) = protocol_param {
                out.push_str(&format!("    protocol_param: \"{}\"\n", escape_str(pp)));
            }
            if *udp {
                out.push_str("    udp: true\n");
            }
        }
        OutboundKind::Hysteria {
            server,
            port,
            auth,
            up_mbps,
            down_mbps,
            obfs,
            obfs_password,
            sni,
            insecure,
            ..
        } => {
            out.push_str(&format!("    server: \"{}\"\n", escape_str(server)));
            out.push_str(&format!("    port: {port}\n"));
            if let Some(a) = auth {
                out.push_str(&format!("    auth: \"{}\"\n", escape_str(a)));
            }
            if let Some(up) = up_mbps {
                out.push_str(&format!("    up: {up}\n"));
            }
            if let Some(down) = down_mbps {
                out.push_str(&format!("    down: {down}\n"));
            }
            if let Some(o) = obfs {
                out.push_str(&format!("    obfs: \"{}\"\n", escape_str(o)));
            }
            if let Some(op) = obfs_password {
                out.push_str(&format!("    obfs_password: \"{}\"\n", escape_str(op)));
            }
            if let Some(s) = sni {
                out.push_str(&format!("    sni: \"{}\"\n", escape_str(s)));
            }
            if *insecure {
                out.push_str("    insecure: true\n");
            }
        }
        _ => {}
    }

    if let Some(dp) = &ob.dialer_proxy {
        out.push_str(&format!("    dialer_proxy: \"{}\"\n", escape_str(dp)));
    }
    if let Some(rm) = ob.routing_mark {
        out.push_str(&format!("    routing_mark: {rm}\n"));
    }
    if let Some(bi) = &ob.bind_interface {
        out.push_str(&format!("    interface: \"{}\"\n", escape_str(bi)));
    }

    // 传输层参数序列化 (TransportSpec)
    serialize_transport(&ob.transport, out);

    out.push_str("}\n\n");
}

fn serialize_transport(t: &TransportSpec, out: &mut String) {
    if let Some(r) = &t.reality {
        out.push_str("    tls: reality {\n");
        if let Some(sni) = &t.sni {
            out.push_str(&format!("        sni: \"{}\"\n", escape_str(sni)));
        }
        out.push_str(&format!(
            "        public_key: \"{}\"\n",
            escape_str(&r.public_key)
        ));
        if let Some(sid) = &r.short_id {
            out.push_str(&format!("        short_id: \"{}\"\n", escape_str(sid)));
        }
        out.push_str("    }\n");
    } else {
        if t.tls {
            out.push_str("    tls: true\n");
        }
        if let Some(sni) = &t.sni {
            out.push_str(&format!("    sni: \"{}\"\n", escape_str(sni)));
        }
        if t.insecure {
            out.push_str("    insecure: true\n");
        }
        if let Some(fp) = &t.client_fingerprint {
            out.push_str(&format!("    client_fingerprint: \"{}\"\n", escape_str(fp)));
        }
        if !t.alpn.is_empty() {
            let alpns: Vec<String> = t
                .alpn
                .iter()
                .map(|a| format!("\"{}\"", escape_str(a)))
                .collect();
            out.push_str(&format!("    alpn: [{}]\n", alpns.join(", ")));
        }
    }

    if let Some(ws) = &t.ws {
        out.push_str("    ws: {\n");
        out.push_str(&format!("        path: \"{}\"\n", escape_str(&ws.path)));
        if let Some(host) = ws.headers.get("Host").or_else(|| ws.headers.get("host")) {
            out.push_str(&format!(
                "        headers: {{ Host: \"{}\" }}\n",
                escape_str(host)
            ));
        }
        out.push_str("    }\n");
    }

    if let Some(grpc) = &t.grpc {
        out.push_str("    grpc: {\n");
        out.push_str(&format!(
            "        service_name: \"{}\"\n",
            escape_str(&grpc.service_name)
        ));
        out.push_str("    }\n");
    }

    if let Some(st) = &t.shadow_tls {
        out.push_str("    shadow_tls: {\n");
        out.push_str(&format!(
            "        password: \"{}\"\n",
            escape_str(&st.password)
        ));
        out.push_str(&format!("        sni: \"{}\"\n", escape_str(&st.sni)));
        out.push_str("    }\n");
    }
}

fn serialize_group(g: &GroupSpec, out: &mut String) {
    let ty_str = match g.ty {
        GroupType::Select => "select",
        GroupType::UrlTest => "url_test",
        GroupType::Fallback => "fallback",
        GroupType::LoadBalance => "load_balance",
        GroupType::Relay => "relay",
    };

    out.push_str(&format!(
        "group \"{}\" {} {{\n",
        escape_str(&g.name),
        ty_str
    ));

    if !g.members.is_empty() {
        let members: Vec<String> = g
            .members
            .iter()
            .map(|m| format!("\"{}\"", escape_str(m)))
            .collect();
        out.push_str(&format!("    members: [{}]\n", members.join(", ")));
    }

    if !g.providers.is_empty() {
        let providers: Vec<String> = g
            .providers
            .iter()
            .map(|p| format!("\"{}\"", escape_str(p)))
            .collect();
        out.push_str(&format!("    providers: [{}]\n", providers.join(", ")));
    }

    if let Some(url) = &g.test_url {
        out.push_str(&format!("    url: \"{}\"\n", escape_str(url)));
    }

    if g.interval != 300 && g.interval > 0 {
        out.push_str(&format!("    interval: {}s\n", g.interval));
    }

    if g.tolerance != 50 && g.tolerance > 0 {
        out.push_str(&format!("    tolerance: {}ms\n", g.tolerance));
    }

    if let Some(f) = &g.filter {
        out.push_str(&format!("    filter: \"{}\"\n", escape_str(f)));
    }

    if let Some(ef) = &g.exclude_filter {
        out.push_str(&format!("    exclude_filter: \"{}\"\n", escape_str(ef)));
    }

    if let Some(fb) = &g.fallback {
        out.push_str(&format!("    fallback: \"{}\"\n", escape_str(fb)));
    }

    out.push_str("}\n\n");
}

fn serialize_dns(dns: &DnsSpec, out: &mut String) {
    out.push_str("dns {\n");
    if !dns.nameserver.is_empty() {
        let ns: Vec<String> = dns
            .nameserver
            .iter()
            .map(|s| format!("\"{}\"", escape_str(s)))
            .collect();
        out.push_str(&format!("    nameservers: [{}]\n", ns.join(", ")));
    }
    if !dns.default_nameserver.is_empty() {
        let dns_list: Vec<String> = dns
            .default_nameserver
            .iter()
            .map(|s| format!("\"{}\"", escape_str(s)))
            .collect();
        out.push_str(&format!(
            "    default_nameserver: [{}]\n",
            dns_list.join(", ")
        ));
    }
    if !dns.fallback.is_empty() {
        let fb: Vec<String> = dns
            .fallback
            .iter()
            .map(|s| format!("\"{}\"", escape_str(s)))
            .collect();
        out.push_str(&format!("    fallback: [{}]\n", fb.join(", ")));
    }
    if let Some(f) = &dns.fake_ip {
        if f.enabled {
            out.push_str(&format!("    fake_ip: \"{}\"\n", escape_str(&f.ip_range)));
        }
    }
    if let Some(l) = &dns.listen {
        out.push_str(&format!("    listen: \"{}\"\n", escape_str(l)));
    }
    out.push_str("}\n\n");
}

fn serialize_services(s: &ServiceSpec, out: &mut String) {
    out.push_str("services {\n");
    let mode_str = match s.mode {
        RoutingMode::Rule => "rule",
        RoutingMode::Global => "global",
        RoutingMode::Direct => "direct",
    };
    out.push_str(&format!("    mode: \"{mode_str}\"\n"));
    if !s.log_level.is_empty() && s.log_level != "info" {
        out.push_str(&format!(
            "    log_level: \"{}\"\n",
            escape_str(&s.log_level)
        ));
    }
    if let Some(c) = &s.external_controller {
        out.push_str(&format!("    external_controller: \"{}\"\n", escape_str(c)));
    }
    if let Some(sec) = &s.secret {
        out.push_str(&format!("    secret: \"{}\"\n", escape_str(sec)));
    }
    out.push_str("}\n\n");
}

fn serialize_security(sec: &SecuritySpec, out: &mut String) {
    out.push_str("security {\n");
    if !sec.allow_geoip.is_empty() {
        let list: Vec<String> = sec
            .allow_geoip
            .iter()
            .map(|c| format!("\"{}\"", escape_str(c)))
            .collect();
        out.push_str(&format!("    allow_geoip: [{}]\n", list.join(", ")));
    }
    if !sec.block_geoip.is_empty() {
        let list: Vec<String> = sec
            .block_geoip
            .iter()
            .map(|c| format!("\"{}\"", escape_str(c)))
            .collect();
        out.push_str(&format!("    block_geoip: [{}]\n", list.join(", ")));
    }
    out.push_str("}\n\n");
}

fn format_route_rule(r: &RouteRuleSpec) -> String {
    let cond = match &r.payload {
        RulePayload::MatchAll => "_".to_string(),
        RulePayload::Cel(expr) => expr.clone(),
        RulePayload::GeoIp(g) => format!("geoip == \"{}\"", escape_str(g)),
        RulePayload::GeoSite(s) => format!("geosite == \"{}\"", escape_str(s)),
        RulePayload::IpCidr { cidr, src: false } => {
            format!("dst.ip in \"{}\"", escape_str(cidr))
        }
        RulePayload::IpCidr { cidr, src: true } => {
            format!("src.ip in \"{}\"", escape_str(cidr))
        }
        RulePayload::Domain(d) => format!("host == \"{}\"", escape_str(d)),
        RulePayload::DomainSuffix(d) => format!("host.endsWith(\"{}\")", escape_str(d)),
        RulePayload::DomainKeyword(d) => format!("host.contains(\"{}\")", escape_str(d)),
        RulePayload::DomainRegex(reg) => format!("host.matches(\"{}\")", escape_str(reg)),
        RulePayload::ProcessName(p) => format!("process.name == \"{}\"", escape_str(p)),
        RulePayload::ProcessPath(p) => format!("process.path == \"{}\"", escape_str(p)),
        RulePayload::Network(n) => format!("net == \"{}\"", escape_str(n)),
        RulePayload::Inbound(i) => format!("inbound == \"{}\"", escape_str(i)),
        RulePayload::InUser(u) => format!("in_user == \"{}\"", escape_str(u)),
        RulePayload::SubRule(sub) => format!("sub_rule == \"{}\"", escape_str(sub)),
        RulePayload::RuleSet(rs) => format!("rule_set == \"{}\"", escape_str(rs)),
        RulePayload::Port { ranges, src: false } => {
            if ranges.len() == 1 && ranges[0].0 == ranges[0].1 {
                format!("dst.port == {}", ranges[0].0)
            } else {
                let list: Vec<String> = ranges
                    .iter()
                    .map(|(a, b)| {
                        if a == b {
                            a.to_string()
                        } else {
                            format!("{a}-{b}")
                        }
                    })
                    .collect();
                format!("dst.port in [{}]", list.join(", "))
            }
        }
        RulePayload::Port { ranges, src: true } => {
            if ranges.len() == 1 && ranges[0].0 == ranges[0].1 {
                format!("src.port == {}", ranges[0].0)
            } else {
                let list: Vec<String> = ranges
                    .iter()
                    .map(|(a, b)| {
                        if a == b {
                            a.to_string()
                        } else {
                            format!("{a}-{b}")
                        }
                    })
                    .collect();
                format!("src.port in [{}]", list.join(", "))
            }
        }
        RulePayload::InPort(ranges) => {
            if ranges.len() == 1 && ranges[0].0 == ranges[0].1 {
                format!("in_port == {}", ranges[0].0)
            } else {
                let list: Vec<String> = ranges
                    .iter()
                    .map(|(a, b)| {
                        if a == b {
                            a.to_string()
                        } else {
                            format!("{a}-{b}")
                        }
                    })
                    .collect();
                format!("in_port in [{}]", list.join(", "))
            }
        }
        RulePayload::IpAsn { asn, src: false } => format!("dst.asn == {asn}"),
        RulePayload::IpAsn { asn, src: true } => format!("src.asn == {asn}"),
    };

    let mut res = format!("{} => \"{}\"", cond, escape_str(&r.target));
    if r.no_resolve {
        res.push_str(" no-resolve");
    }
    res
}

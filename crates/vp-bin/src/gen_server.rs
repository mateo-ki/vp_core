//! vpcore gen-server 一键开服与节点配置生成器。
//!
//! - 自动探测公网 IP
//! - 自动生成高强度安全密钥 (x25519 REALITY, SS-2022 Blake3, UUID v4)
//! - 自动签发长效自签名 TLS 证书 (rcgen, 供 Hysteria 2 / Trojan 使用)
//! - 自动注入 UDP RRL 防反射放大防御机制
//! - 一键写入最佳实践服务端 YAML 配置文件
//! - 终端直观输出标准客户端一键导入链接 (vless://, hysteria2://, ss://) 与 Clash 配置

use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD};

pub struct GenServerArgs {
    pub protocols: String,
    pub ip: Option<String>,
    pub domain: Option<String>,
    pub sni: String,
    pub reality_port: u16,
    pub hy2_port: u16,
    pub ss_port: u16,
    pub sub_port: u16,
    pub sub_token: Option<String>,
    pub output: Option<PathBuf>,
    pub cert_dir: Option<PathBuf>,
}

pub struct GenSubArgs {
    pub config: Option<PathBuf>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub token: Option<String>,
    pub format: String,
}

/// 执行一键开服生成逻辑
pub fn run(args: GenServerArgs) -> Result<(), Box<dyn std::error::Error>> {
    println!("\x1b[1;36m========================================================\x1b[0m");
    println!("\x1b[1;36m     VP_Core 一键开服 & 客户端节点生成向导 (gen-server)    \x1b[0m");
    println!("\x1b[1;36m========================================================\x1b[0m\n");

    // 1. 获取公网 IP 与域名
    let domain_opt = args
        .domain
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if let Some(ref dom) = domain_opt {
        println!(
            "[\x1b[32m+\x1b[0m] 绑定 CDN / 反向代理穿透域名: \x1b[1;32m{}\x1b[0m",
            dom
        );
    }

    let ip = match args.ip {
        Some(custom) if !custom.trim().is_empty() => {
            println!(
                "[\x1b[32m+\x1b[0m] 使用指定公网 IP/地址: \x1b[1;32m{}\x1b[0m",
                custom
            );
            custom.trim().to_string()
        }
        _ => {
            print!("[\x1b[34m*\x1b[0m] 正在自动检测本机公网 IP... ");
            let detected = detect_public_ip();
            match detected {
                Some(pub_ip) => {
                    println!("\x1b[1;32m{}\x1b[0m", pub_ip);
                    pub_ip
                }
                None => {
                    println!("\x1b[33m未检测到 (将使用 127.0.0.1 占位，请后续手动替换)\x1b[0m");
                    "127.0.0.1".to_string()
                }
            }
        }
    };

    // 2. 决定配置文件输出路径
    let output_path = match args.output {
        Some(p) => p,
        None => pick_default_config_path(),
    };

    // 确保证书目录与配置目录存在
    let config_dir = output_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let cert_dir = args.cert_dir.unwrap_or_else(|| config_dir.clone());
    fs::create_dir_all(&cert_dir)?;
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    // 3. 解析协议选项
    let proto_lower = args.protocols.to_lowercase();
    let gen_all = proto_lower == "all" || proto_lower.is_empty();
    let gen_reality = gen_all || proto_lower.contains("reality") || proto_lower.contains("vless");
    let gen_hy2 = gen_all || proto_lower.contains("hy2") || proto_lower.contains("hysteria");
    let gen_ss2022 = gen_all || proto_lower.contains("ss2022") || proto_lower.contains("ss");

    // 4. 生成各种凭据
    // VLESS-REALITY
    let uuid = generate_uuid_v4();
    let (reality_priv, reality_pub) = generate_x25519_keypair();
    let short_id = generate_hex(8);
    let sni = if args.sni.trim().is_empty() {
        "www.amazon.com".to_string()
    } else {
        args.sni.trim().to_string()
    };

    // Hysteria 2
    let hy2_pass = generate_hex(16);
    let cert_file = cert_dir.join("hy2_cert.pem");
    let key_file = cert_dir.join("hy2_key.pem");
    let (cert_pem, key_pem) = generate_self_signed_cert(&ip)?;
    fs::write(&cert_file, cert_pem)?;
    fs::write(&key_file, key_pem)?;

    // Shadowsocks-2022
    let mut ss_key_raw = [0u8; 16];
    vp_common::rand_bytes(&mut ss_key_raw);
    let ss2022_key = BASE64_STD.encode(ss_key_raw);

    let sub_port = if args.sub_port == 0 {
        2080
    } else {
        args.sub_port
    };
    let sub_token = args.sub_token.clone().unwrap_or_else(|| generate_hex(16));

    // 5. 组装服务端 YAML 配置
    let mut yaml = String::new();
    yaml.push_str("log-level: info\n");
    yaml.push_str("allow-lan: false\n");
    yaml.push_str("mode: rule\n\n");

    yaml.push_str(&format!(
        "# 外部控制器与客户端动态订阅端点 (/sub)\nexternal-controller: 0.0.0.0:{sub_port}\nsecret: \"{sub_token}\"\n\n"
    ));

    yaml.push_str(
        "# UDP 响应速率限制与反射放大攻击防护 (RRL: 认证用户自动进入 1 小时免限频白名单)\n",
    );
    yaml.push_str("rrl:\n");
    yaml.push_str("  max-qps: 20\n");
    yaml.push_str("  burst: 40\n");
    yaml.push_str("  slip: 2\n\n");

    yaml.push_str("listeners:\n");

    if gen_reality {
        yaml.push_str(&format!(
            "  # 1. VLESS + REALITY 原生监听 (端口 {} / 借用大厂证书伪装与透明探测回落)\n",
            args.reality_port
        ));
        yaml.push_str("  - name: reality-in\n");
        yaml.push_str("    type: mux\n");
        yaml.push_str("    listen: 0.0.0.0\n");
        yaml.push_str(&format!("    port: {}\n", args.reality_port));
        yaml.push_str("    reality:\n");
        yaml.push_str(&format!("      private-key: \"{reality_priv}\"\n"));
        yaml.push_str(&format!("      short-ids: [\"{short_id}\"]\n"));
        yaml.push_str(&format!("      dest: \"{sni}:443\"\n"));
        yaml.push_str(&format!("      server-names: [\"{sni}\"]\n"));
        yaml.push_str("    users:\n");
        yaml.push_str(&format!("      - \"{uuid}\"\n\n"));
    }

    if gen_hy2 {
        let cert_str = cert_file.to_string_lossy().replace('\\', "/");
        let key_str = key_file.to_string_lossy().replace('\\', "/");
        yaml.push_str(&format!(
            "  # 2. Hysteria 2 高速传输 (QUIC UDP / 端口 {} / 内置自签证书与极速流控)\n",
            args.hy2_port
        ));
        yaml.push_str("  - name: hy2-in\n");
        yaml.push_str("    type: hysteria2\n");
        yaml.push_str("    listen: 0.0.0.0\n");
        yaml.push_str(&format!("    port: {}\n", args.hy2_port));
        yaml.push_str(&format!("    cert: \"{cert_str}\"\n"));
        yaml.push_str(&format!("    key: \"{key_str}\"\n"));
        yaml.push_str("    users:\n");
        yaml.push_str(&format!("      - \"{hy2_pass}\"\n\n"));
    }

    if gen_ss2022 {
        yaml.push_str(&format!(
            "  # 3. Shadowsocks-2022 (2022-blake3-aes-128-gcm / 端口 {} / 抗主动探测与重放)\n",
            args.ss_port
        ));
        yaml.push_str("  - name: ss2022-in\n");
        yaml.push_str("    type: ss\n");
        yaml.push_str("    listen: 0.0.0.0\n");
        yaml.push_str(&format!("    port: {}\n", args.ss_port));
        yaml.push_str("    cipher: 2022-blake3-aes-128-gcm\n");
        yaml.push_str("    users:\n");
        yaml.push_str(&format!("      - \"{ss2022_key}\"\n\n"));
    }

    yaml.push_str("rules:\n");
    yaml.push_str("  - MATCH,DIRECT\n");

    // 写入配置文件
    fs::write(&output_path, &yaml)?;
    println!(
        "[\x1b[32m✓\x1b[0m] 服务端配置文件已生成: \x1b[1m{}\x1b[0m",
        output_path.display()
    );
    if gen_hy2 {
        println!(
            "[\x1b[32m✓\x1b[0m] 自签 TLS 证书已就绪: \x1b[1m{}\x1b[0m",
            cert_file.display()
        );
    }
    println!();

    // 6. 收集节点分享链接与 Clash 节点定义
    let mut all_links = Vec::new();
    let mut clash_proxies = String::new();
    let mut proxy_names = Vec::new();

    if let Some(ref dom) = domain_opt {
        let cf_link = format!(
            "vless://{uuid}@{dom}:443?type=ws&security=tls&path=%2Fvpcore-tunnel&sni={dom}#vpcore-Cloudflare-WS"
        );
        all_links.push(cf_link);
        proxy_names.push("vpcore-Cloudflare-WS".to_string());
        clash_proxies.push_str(&format!(
            "  - name: \"vpcore-Cloudflare-WS\"\n    type: vless\n    server: \"{dom}\"\n    port: 443\n    uuid: \"{uuid}\"\n    cipher: auto\n    tls: true\n    udp: true\n    servername: \"{dom}\"\n    network: ws\n    ws-opts:\n      path: /vpcore-tunnel\n      headers:\n        Host: \"{dom}\"\n"
        ));
    }

    if gen_reality {
        let reality_link = format!(
            "vless://{uuid}@{ip}:{}?security=reality&encryption=none&pbk={reality_pub}&sid={short_id}&sni={sni}&fp=chrome&type=tcp#vpcore-reality",
            args.reality_port
        );
        all_links.push(reality_link);
        proxy_names.push("vpcore-reality".to_string());
        clash_proxies.push_str(&format!(
            "  - name: \"vpcore-reality\"\n    type: vless\n    server: \"{ip}\"\n    port: {}\n    uuid: \"{uuid}\"\n    cipher: auto\n    tls: true\n    udp: true\n    servername: \"{sni}\"\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: \"{reality_pub}\"\n      short-id: \"{short_id}\"\n",
            args.reality_port
        ));
    }

    if gen_hy2 {
        let hy2_link = format!(
            "hysteria2://{hy2_pass}@{ip}:{}/?insecure=1&sni=hy2.vpcore.internal#vpcore-hy2",
            args.hy2_port
        );
        all_links.push(hy2_link);
        proxy_names.push("vpcore-hy2".to_string());
        clash_proxies.push_str(&format!(
            "  - name: \"vpcore-hy2\"\n    type: hysteria2\n    server: \"{ip}\"\n    port: {}\n    password: \"{hy2_pass}\"\n    sni: hy2.vpcore.internal\n    skip-cert-verify: true\n",
            args.hy2_port
        ));
    }

    if gen_ss2022 {
        let raw_cred = format!("2022-blake3-aes-128-gcm:{ss2022_key}");
        let ss_base64 = BASE64_STD.encode(raw_cred);
        let ss_link = format!("ss://{ss_base64}@{ip}:{}#vpcore-ss2022", args.ss_port);
        all_links.push(ss_link);
        proxy_names.push("vpcore-ss2022".to_string());
        clash_proxies.push_str(&format!(
            "  - name: \"vpcore-ss2022\"\n    type: ss\n    server: \"{ip}\"\n    port: {}\n    cipher: 2022-blake3-aes-128-gcm\n    password: \"{ss2022_key}\"\n    udp: true\n",
            args.ss_port
        ));
    }

    // 7. 生成静态订阅文件 sub.txt 与 sub-clash.yaml
    let raw_sub = all_links.join("\n");
    let base64_sub = BASE64_STD.encode(raw_sub.as_bytes());
    let sub_txt_path = config_dir.join("sub.txt");
    let _ = fs::write(&sub_txt_path, &base64_sub);

    let mut full_clash = String::from(
        "port: 7890\nsocks-port: 7891\nmode: rule\nlog-level: info\nallow-lan: true\n\nproxies:\n",
    );
    full_clash.push_str(&clash_proxies);
    full_clash.push_str(
        "\nproxy-groups:\n  - name: PROXY\n    type: select\n    proxies:\n      - 自动测速\n",
    );
    for n in &proxy_names {
        full_clash.push_str(&format!("      - \"{n}\"\n"));
    }
    full_clash.push_str("  - name: 自动测速\n    type: url-test\n    url: http://www.gstatic.com/generate_204\n    interval: 300\n    proxies:\n");
    for n in &proxy_names {
        full_clash.push_str(&format!("      - \"{n}\"\n"));
    }
    full_clash.push_str("\nrules:\n  - MATCH,PROXY\n");
    let sub_clash_path = config_dir.join("sub-clash.yaml");
    let _ = fs::write(&sub_clash_path, &full_clash);

    let sub_host = domain_opt.as_deref().unwrap_or(&ip);
    let sub_url = format!("http://{sub_host}:{sub_port}/sub?token={sub_token}");
    let clash_url = format!("http://{sub_host}:{sub_port}/sub?token={sub_token}&format=clash");

    // 8. 终端高亮输出订阅链接
    println!("\x1b[1;36m========================================================\x1b[0m");
    println!("\x1b[1;36m          🎉 客户端一键订阅链接 (Subscription)          \x1b[0m");
    println!("\x1b[1;36m========================================================\x1b[0m\n");

    println!(
        "[\x1b[1;32m★\x1b[0m] \x1b[1;32m通用订阅链接\x1b[0m (适用于 v2rayN / Shadowrocket / Sing-box / NekoBox 等):"
    );
    println!("  \x1b[1;32m{}\x1b[0m\n", sub_url);

    println!(
        "[\x1b[1;36m★\x1b[0m] \x1b[1;36mClash 专用订阅链接\x1b[0m (适用于 Clash / Clash Verge / Mihomo 等):"
    );
    println!("  \x1b[1;36m{}\x1b[0m\n", clash_url);

    println!(
        "[\x1b[1;33m★\x1b[0m] \x1b[1;33m免 HTTP 极速导入 Base64 订阅码\x1b[0m (复制后直接在客户端从剪贴板导入):"
    );
    println!("  \x1b[1m{}\x1b[0m\n", base64_sub);

    println!("[\x1b[34m*\x1b[0m] 离线订阅文件已生成于:");
    println!(
        "    - 通用 Base64 订阅: \x1b[1m{}\x1b[0m",
        sub_txt_path.display()
    );
    println!(
        "    - 完整 Clash 订阅:   \x1b[1m{}\x1b[0m\n",
        sub_clash_path.display()
    );

    // 9. 单节点链接输出（供备选）
    println!("\x1b[1;33m>>> 单节点一键导入链接 (如需单独添加指定节点): \x1b[0m\n");
    for link in &all_links {
        println!("\x1b[32m{}\x1b[0m\n", link);
    }

    // 10. Clash proxies 片段输出
    println!("\x1b[1;33m>>> Clash / Clash Verge 客户端配置片段 (proxies 段): \x1b[0m");
    println!("```yaml\nproxies:\n{}```\n", clash_proxies);

    println!("\x1b[1;32m>>> 启动服务命令: \x1b[0m");
    println!(
        "  \x1b[1m/usr/local/bin/vpcore run -c {}\x1b[0m",
        output_path.display()
    );
    println!("  或者若已配置 systemd 服务：\x1b[1msystemctl restart vpcore\x1b[0m\n");

    Ok(())
}

/// 导出或展示当前服务端的客户端订阅链接与配置
pub fn run_sub(args: GenSubArgs) -> Result<(), Box<dyn std::error::Error>> {
    let cfg_path = args.config.unwrap_or_else(|| {
        let default_etc = PathBuf::from("/etc/vpcore/config.yaml");
        if default_etc.exists() {
            default_etc
        } else if PathBuf::from("config.yaml").exists() {
            PathBuf::from("config.yaml")
        } else {
            PathBuf::from("vpcore-server.yaml")
        }
    });

    let config_dir = cfg_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let cfg_text = fs::read_to_string(&cfg_path).unwrap_or_default();

    // 尝试提取 external-controller 端口与 secret
    let mut ctl_port = args.port.unwrap_or(2080);
    let mut ctl_token = args.token.clone().unwrap_or_default();
    let detected_host = args.host.clone();

    for line in cfg_text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("external-controller:")
            || trimmed.starts_with("external_controller:")
        {
            if let Some(val) = trimmed.split(':').nth(2) {
                if let Ok(p) = val.trim().parse::<u16>() {
                    if args.port.is_none() {
                        ctl_port = p;
                    }
                }
            }
        } else if trimmed.starts_with("secret:") {
            if let Some(val) = trimmed.split_once(':') {
                let s = val.1.trim().trim_matches('"').trim_matches('\'');
                if !s.is_empty() && args.token.is_none() {
                    ctl_token = s.to_string();
                }
            }
        }
    }

    let host = match detected_host {
        Some(h) if !h.trim().is_empty() => h.trim().to_string(),
        _ => detect_public_ip().unwrap_or_else(|| "127.0.0.1".to_string()),
    };

    // 读取或动态生成 base64_sub 与 clash_sub
    let base64_sub = if let Ok(s) = fs::read_to_string(config_dir.join("sub.txt")) {
        s.trim().to_string()
    } else {
        generate_base64_from_config_text(&cfg_text, &host)
    };

    let clash_sub = if let Ok(s) = fs::read_to_string(config_dir.join("sub-clash.yaml")) {
        s
    } else if let Ok(s) = fs::read_to_string(config_dir.join("clash.yaml")) {
        s
    } else {
        generate_clash_from_config_text(&cfg_text, &host)
    };

    let sub_url = if ctl_token.is_empty() {
        format!("http://{host}:{ctl_port}/sub")
    } else {
        format!("http://{host}:{ctl_port}/sub?token={ctl_token}")
    };

    let clash_url = if ctl_token.is_empty() {
        format!("http://{host}:{ctl_port}/sub?format=clash")
    } else {
        format!("http://{host}:{ctl_port}/sub?token={ctl_token}&format=clash")
    };

    match args.format.to_lowercase().as_str() {
        "base64" => {
            println!("{base64_sub}");
        }
        "clash" => {
            print!("{clash_sub}");
        }
        "url" => {
            println!("{sub_url}");
        }
        "clash-url" => {
            println!("{clash_url}");
        }
        _ => {
            println!("\x1b[1;36m========================================================\x1b[0m");
            println!("\x1b[1;36m           VP_Core 客户端订阅向导 (gen-sub)              \x1b[0m");
            println!("\x1b[1;36m========================================================\x1b[0m\n");

            println!(
                "[\x1b[32m+\x1b[0m] 配置文件: \x1b[1m{}\x1b[0m",
                cfg_path.display()
            );
            println!("[\x1b[32m+\x1b[0m] 服务地址: \x1b[1m{}\x1b[0m", host);
            println!("[\x1b[32m+\x1b[0m] 订阅端口: \x1b[1m{}\x1b[0m\n", ctl_port);

            println!(
                "[\x1b[1;32m★\x1b[0m] \x1b[1;32m通用订阅链接\x1b[0m (适用于 v2rayN / Shadowrocket / Sing-box / NekoBox 等):"
            );
            println!("  \x1b[1;32m{}\x1b[0m\n", sub_url);

            println!(
                "[\x1b[1;36m★\x1b[0m] \x1b[1;36mClash 专用订阅链接\x1b[0m (适用于 Clash / Clash Verge / Mihomo 等):"
            );
            println!("  \x1b[1;36m{}\x1b[0m\n", clash_url);

            println!(
                "[\x1b[1;33m★\x1b[0m] \x1b[1;33m免 HTTP 极速导入 Base64 订阅码\x1b[0m (客户端复制后直接从剪贴板导入):"
            );
            println!("  \x1b[1m{}\x1b[0m\n", base64_sub);
        }
    }

    Ok(())
}

fn generate_base64_from_config_text(cfg_text: &str, clean_host: &str) -> String {
    let Ok(cfg) = vp_config::parse(cfg_text, vp_config::Format::Yaml) else {
        return String::new();
    };

    let mut links = Vec::new();
    for l in &cfg.listeners {
        match l.kind.as_str() {
            "mux" | "reality" => {
                let uuid = l
                    .users
                    .first()
                    .map(|s| s.as_str())
                    .unwrap_or("00000000-0000-0000-0000-000000000000");
                let reality = l.reality.as_ref();
                let sid = reality
                    .and_then(|r| r.short_ids.first().map(|s| s.as_str()))
                    .unwrap_or("");
                let sni = reality
                    .and_then(|r| r.server_names.first().map(|s| s.as_str()))
                    .unwrap_or("www.amazon.com");
                links.push(format!(
                    "vless://{uuid}@{clean_host}:{}?security=reality&encryption=none&pbk=&sid={sid}&sni={sni}&fp=chrome&type=tcp#vpcore-reality",
                    l.port
                ));
            }
            "hysteria2" => {
                let pass = l.users.first().map(|s| s.as_str()).unwrap_or("");
                links.push(format!(
                    "hysteria2://{pass}@{clean_host}:{}/?insecure=1&sni=hy2.vpcore.internal#vpcore-hy2",
                    l.port
                ));
            }
            "ss" => {
                let cipher = l.cipher.as_deref().unwrap_or("2022-blake3-aes-128-gcm");
                let key = l.users.first().map(|s| s.as_str()).unwrap_or("");
                let userinfo = BASE64_STD.encode(format!("{cipher}:{key}"));
                links.push(format!("ss://{userinfo}@{clean_host}:{}#vpcore-ss", l.port));
            }
            "trojan" => {
                let pass = l.users.first().map(|s| s.as_str()).unwrap_or("");
                links.push(format!(
                    "trojan://{pass}@{clean_host}:{}?security=tls&sni={clean_host}#vpcore-trojan",
                    l.port
                ));
            }
            "vless" => {
                let uuid = l.users.first().map(|s| s.as_str()).unwrap_or("");
                links.push(format!(
                    "vless://{uuid}@{clean_host}:{}?security=tls&sni={clean_host}#vpcore-vless",
                    l.port
                ));
            }
            _ => {}
        }
    }
    let joined = links.join("\n");
    BASE64_STD.encode(joined.as_bytes())
}

fn generate_clash_from_config_text(cfg_text: &str, clean_host: &str) -> String {
    let Ok(cfg) = vp_config::parse(cfg_text, vp_config::Format::Yaml) else {
        return String::new();
    };

    let mut proxies_yaml = String::new();
    let mut names = Vec::new();

    for l in &cfg.listeners {
        match l.kind.as_str() {
            "mux" | "reality" => {
                let uuid = l
                    .users
                    .first()
                    .map(|s| s.as_str())
                    .unwrap_or("00000000-0000-0000-0000-000000000000");
                let reality = l.reality.as_ref();
                let sid = reality
                    .and_then(|r| r.short_ids.first().map(|s| s.as_str()))
                    .unwrap_or("");
                let sni = reality
                    .and_then(|r| r.server_names.first().map(|s| s.as_str()))
                    .unwrap_or("www.amazon.com");
                names.push("vpcore-reality".to_string());
                proxies_yaml.push_str(&format!(
                    "  - name: \"vpcore-reality\"\n    type: vless\n    server: \"{clean_host}\"\n    port: {}\n    uuid: \"{uuid}\"\n    cipher: auto\n    tls: true\n    udp: true\n    servername: \"{sni}\"\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: \"\"\n      short-id: \"{sid}\"\n",
                    l.port
                ));
            }
            "hysteria2" => {
                let pass = l.users.first().map(|s| s.as_str()).unwrap_or("");
                names.push("vpcore-hy2".to_string());
                proxies_yaml.push_str(&format!(
                    "  - name: \"vpcore-hy2\"\n    type: hysteria2\n    server: \"{clean_host}\"\n    port: {}\n    password: \"{pass}\"\n    sni: hy2.vpcore.internal\n    skip-cert-verify: true\n",
                    l.port
                ));
            }
            "ss" => {
                let cipher = l.cipher.as_deref().unwrap_or("2022-blake3-aes-128-gcm");
                let key = l.users.first().map(|s| s.as_str()).unwrap_or("");
                names.push("vpcore-ss".to_string());
                proxies_yaml.push_str(&format!(
                    "  - name: \"vpcore-ss\"\n    type: ss\n    server: \"{clean_host}\"\n    port: {}\n    cipher: {cipher}\n    password: \"{key}\"\n    udp: true\n",
                    l.port
                ));
            }
            "trojan" => {
                let pass = l.users.first().map(|s| s.as_str()).unwrap_or("");
                names.push("vpcore-trojan".to_string());
                proxies_yaml.push_str(&format!(
                    "  - name: \"vpcore-trojan\"\n    type: trojan\n    server: \"{clean_host}\"\n    port: {}\n    password: \"{pass}\"\n    udp: true\n    sni: \"{clean_host}\"\n    skip-cert-verify: true\n",
                    l.port
                ));
            }
            "vless" => {
                let uuid = l.users.first().map(|s| s.as_str()).unwrap_or("");
                names.push("vpcore-vless".to_string());
                proxies_yaml.push_str(&format!(
                    "  - name: \"vpcore-vless\"\n    type: vless\n    server: \"{clean_host}\"\n    port: {}\n    uuid: \"{uuid}\"\n    cipher: auto\n    tls: true\n    udp: true\n",
                    l.port
                ));
            }
            _ => {}
        }
    }

    let mut out =
        String::from("port: 7890\nsocks-port: 7891\nmode: rule\nlog-level: info\n\nproxies:\n");
    out.push_str(&proxies_yaml);
    out.push_str(
        "\nproxy-groups:\n  - name: PROXY\n    type: select\n    proxies:\n      - 自动测速\n",
    );
    for n in &names {
        out.push_str(&format!("      - \"{n}\"\n"));
    }
    out.push_str("  - name: 自动测速\n    type: url-test\n    url: http://www.gstatic.com/generate_204\n    interval: 300\n    proxies:\n");
    for n in &names {
        out.push_str(&format!("      - \"{n}\"\n"));
    }
    out.push_str("\nrules:\n  - MATCH,PROXY\n");
    out
}

/// 自动探测本机公网 IPv4 / IPv6
fn detect_public_ip() -> Option<String> {
    const APIS: &[&str] = &[
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ];

    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_millis(2500))
        .timeout_read(Duration::from_millis(2500))
        .build();

    for url in APIS {
        if let Ok(resp) = agent.get(url).call() {
            if let Ok(body) = resp.into_string() {
                let trimmed = body.trim();
                if let Ok(ip) = trimmed.parse::<IpAddr>() {
                    return Some(ip.to_string());
                }
            }
        }
    }
    None
}

/// 选择默认配置文件路径（Linux 优先 /etc/vpcore/config.yaml，Windows 或无权限退回当前目录）
fn pick_default_config_path() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        use std::path::Path;
        let etc_vpcore = Path::new("/etc/vpcore");
        // 尝试测试 /etc/vpcore 是否可写，或 /etc 是否可写
        if etc_vpcore.exists() || Path::new("/etc").exists() {
            if fs::create_dir_all(etc_vpcore).is_ok() {
                return etc_vpcore.join("config.yaml");
            }
        }
    }

    PathBuf::from("vpcore-server.yaml")
}

/// 生成标准 UUID v4
fn generate_uuid_v4() -> String {
    let mut b = [0u8; 16];
    vp_common::rand_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 1
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

/// 生成 n 字节长度的十六进制字符串（如 short_id、随机口令）
fn generate_hex(bytes_len: usize) -> String {
    let mut b = vec![0u8; bytes_len];
    vp_common::rand_bytes(&mut b);
    b.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// 生成 x25519 密钥对并编码为 URL_SAFE_NO_PAD base64
fn generate_x25519_keypair() -> (String, String) {
    let mut priv_bytes = [0u8; 32];
    vp_common::rand_bytes(&mut priv_bytes);
    let secret = x25519_dalek::StaticSecret::from(priv_bytes);
    let pub_key = x25519_dalek::PublicKey::from(&secret);

    let priv_b64 = URL_SAFE_NO_PAD.encode(priv_bytes);
    let pub_b64 = URL_SAFE_NO_PAD.encode(pub_key.as_bytes());
    (priv_b64, pub_b64)
}

/// 生成包含指定 IP 与域名的自签证书 (PEM 格式)
fn generate_self_signed_cert(
    ip_or_domain: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let mut sans = vec!["localhost".to_string(), "hy2.vpcore.internal".to_string()];
    if !ip_or_domain.is_empty() && ip_or_domain != "127.0.0.1" {
        sans.push(ip_or_domain.to_string());
    }

    let cert =
        rcgen::generate_simple_self_signed(sans).map_err(|e| format!("自签证书生成失败: {e}"))?;
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    Ok((cert_pem, key_pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_credentials_format() {
        let uuid = generate_uuid_v4();
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid.chars().filter(|&c| c == '-').count(), 4);

        let (priv_k, pub_k) = generate_x25519_keypair();
        assert_eq!(priv_k.len(), 43); // 32 bytes in URL_SAFE_NO_PAD
        assert_eq!(pub_k.len(), 43);

        let (cert, key) = generate_self_signed_cert("1.2.3.4").unwrap();
        assert!(cert.contains("BEGIN CERTIFICATE"));
        assert!(key.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_gen_server_output_validates() {
        let temp_dir = std::env::temp_dir().join(format!("vpcore-test-{}", generate_hex(4)));
        let out_file = temp_dir.join("test-config.yaml");

        let args = GenServerArgs {
            protocols: "all".to_string(),
            ip: Some("1.2.3.4".to_string()),
            domain: Some("test.example.com".to_string()),
            sni: "www.amazon.com".to_string(),
            reality_port: 443,
            hy2_port: 31889,
            ss_port: 31888,
            sub_port: 2080,
            sub_token: Some("testtoken123".to_string()),
            output: Some(out_file.clone()),
            cert_dir: Some(temp_dir.clone()),
        };

        run(args).expect("run gen-server 应当成功");
        assert!(out_file.exists());
        assert!(temp_dir.join("sub.txt").exists());
        assert!(temp_dir.join("sub-clash.yaml").exists());

        let yaml = fs::read_to_string(&out_file).unwrap();
        let cfg = vp_config::parse_and_validate(&yaml, vp_config::Format::Yaml)
            .expect("生成的服务端 YAML 应当通过格式与逻辑校验");
        assert_eq!(cfg.listeners.len(), 3);
        assert_eq!(cfg.external_controller.as_deref(), Some("0.0.0.0:2080"));
        assert_eq!(cfg.secret.as_deref(), Some("testtoken123"));

        // 测试 run_sub
        let sub_args = GenSubArgs {
            config: Some(out_file.clone()),
            host: Some("test.example.com".to_string()),
            port: Some(2080),
            token: None,
            format: "base64".to_string(),
        };
        run_sub(sub_args).expect("run_sub 应当成功");

        // 清理临时文件
        let _ = fs::remove_dir_all(temp_dir);
    }
}

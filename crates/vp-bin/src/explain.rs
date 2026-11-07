use std::io::IsTerminal;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use clap::Args;
use vp_app::api::explain::parse_target;
use vp_core::{RouteTrace, Router, Session};

#[derive(Args, Debug)]
pub struct ExplainArgs {
    /// 诊断目标（URL、域名或 IP[:PORT]，如 https://github.com、google.com、1.1.1.1:53）
    pub target: String,

    /// 目标端口覆盖（缺省时 URL 解析出端口或默认 443/80）
    #[arg(short, long)]
    pub port: Option<u16>,

    /// 传输层协议（tcp 或 udp，默认 tcp）
    #[arg(short, long, default_value = "tcp")]
    pub network: String,

    /// 入站标签名称（默认 mixed）
    #[arg(short, long, default_value = "mixed")]
    pub inbound: String,

    /// 模拟进程名称（例如 curl, git, chrome.exe）
    #[arg(short = 'P', long)]
    pub process: Option<String>,

    /// 模拟源 IP 地址（例如 192.168.1.100）
    #[arg(long)]
    pub src_ip: Option<String>,

    /// 配置文件路径（离线分析用，缺省自动探测 ./config.yaml 等）
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// 工作目录 / 规则库目录（支持 -d / -D / --directory）
    #[arg(short = 'd', short_alias = 'D', long, alias = "dir")]
    pub directory: Option<PathBuf>,

    /// 外部控制器 API 地址（在线实时诊断已运行的内核实例，如 http://127.0.0.1:9090）
    #[arg(long)]
    pub api: Option<String>,

    /// 外部控制器鉴权 Secret / Token
    #[arg(long)]
    pub secret: Option<String>,

    /// 以结构化 JSON 格式输出原始追踪数据
    #[arg(long)]
    pub json: bool,
}

pub async fn run(args: ExplainArgs) -> Result<(), String> {
    // 1. 若显式指定了 --api，执行在线远程诊断
    if let Some(ref api_base) = args.api {
        let trace = fetch_remote_explain(api_base, &args)?;
        output_trace(&trace, args.json);
        return Ok(());
    }

    // 2. 探寻配置文件（优先 --config，次选默认路径）
    let config_path = args.config.clone().or_else(detect_default_config);

    if let Some(cfg_path) = config_path {
        let text = std::fs::read_to_string(&cfg_path)
            .map_err(|e| format!("读取配置文件 {} 失败: {e}", cfg_path.display()))?;
        let fmt = vp_config::Format::from_path(&cfg_path.to_string_lossy());
        let dir = args.directory.clone().unwrap_or_else(|| {
            cfg_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf()
        });

        // 离线启动独立实例（listen_ports=false，不占用系统端口，免 Root）
        let app = vp_app::App::start(&text, fmt, &dir, false)
            .await
            .map_err(|e| format!("解析并装载配置失败: {e}"))?;

        let dst = parse_target(&args.target, args.port)
            .ok_or_else(|| format!("无效的诊断目标: {:?}", args.target))?;

        let network = match args.network.to_ascii_lowercase().as_str() {
            "udp" => vp_core::Network::Udp,
            _ => vp_core::Network::Tcp,
        };

        let src = args
            .src_ip
            .as_deref()
            .and_then(|s| s.parse::<IpAddr>().ok())
            .map(|ip| SocketAddr::new(ip, 0));

        let mut sess = match network {
            vp_core::Network::Tcp => Session::new_tcp(args.inbound.as_str().into(), src, dst),
            vp_core::Network::Udp => Session::new_udp(args.inbound.as_str().into(), src, dst),
        };
        sess.process = args.process.as_deref().map(|p| p.into());

        let trace = app.router.explain(&sess).await;
        output_trace(&trace, args.json);
        Ok(())
    } else {
        // 无配置文件时，尝试探活本地正在运行的 daemon (9090 / 2080)
        let probed = probe_local_daemon(&args);
        if let Ok(trace) = probed {
            output_trace(&trace, args.json);
            return Ok(());
        }

        Err("未找到配置文件，且未检测到正在运行的本地内核服务。\n请通过 -c <config.yaml> 指定配置文件，或通过 --api <http://127.0.0.1:9090> 连接在线内核。".into())
    }
}

fn detect_default_config() -> Option<PathBuf> {
    let candidates = [
        PathBuf::from("config.vp"),
        PathBuf::from("config.yaml"),
        PathBuf::from("config.yml"),
        PathBuf::from("config.json"),
        PathBuf::from("vpcore-sub.yaml"),
        PathBuf::from("/etc/vpcore/config.vp"),
        PathBuf::from("/etc/vpcore/config.yaml"),
    ];
    candidates.into_iter().find(|p| p.exists())
}

fn fetch_remote_explain(api_base: &str, args: &ExplainArgs) -> Result<RouteTrace, String> {
    let base = api_base.trim_end_matches('/');
    let target_encoded = urlencoding(&args.target);
    let mut url = format!(
        "{base}/routes/explain?url={target_encoded}&network={}&inbound={}",
        args.network, args.inbound
    );
    if let Some(p) = args.port {
        url.push_str(&format!("&port={p}"));
    }
    if let Some(ref pr) = args.process {
        url.push_str(&format!("&process={}", urlencoding(pr)));
    }
    if let Some(ref s) = args.src_ip {
        url.push_str(&format!("&src_ip={s}"));
    }

    let mut req = ureq::get(&url).timeout(std::time::Duration::from_secs(10));
    if let Some(ref secret) = args.secret {
        req = req.set("Authorization", &format!("Bearer {secret}"));
    }

    let resp = req
        .call()
        .map_err(|e| format!("请求外部控制器 {url} 失败: {e}"))?;
    let trace: RouteTrace = serde_json::from_reader(resp.into_reader())
        .map_err(|e| format!("解析控制器诊断响应失败: {e}"))?;
    Ok(trace)
}

fn probe_local_daemon(args: &ExplainArgs) -> Result<RouteTrace, String> {
    let ports = [9090, 2080];
    for p in ports {
        let base = format!("http://127.0.0.1:{p}");
        if let Ok(trace) = fetch_remote_explain(&base, args) {
            return Ok(trace);
        }
    }
    Err("本地探测无响应".into())
}

fn urlencoding(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

fn output_trace(trace: &RouteTrace, json_format: bool) {
    if json_format {
        println!(
            "{}",
            serde_json::to_string_pretty(trace).unwrap_or_default()
        );
        return;
    }

    let use_color = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let (c_cyan, c_green, c_yellow, c_magenta, c_red, c_bold, c_dim, c_reset) = if use_color {
        (
            "\x1b[36m", "\x1b[32m", "\x1b[33m", "\x1b[35m", "\x1b[31m", "\x1b[1m", "\x1b[2m",
            "\x1b[0m",
        )
    } else {
        ("", "", "", "", "", "", "", "")
    };

    println!(
        "{c_cyan}================================================================================{c_reset}"
    );
    println!("{c_bold}                    VP_Core 路由链路诊断追踪 (explain){c_reset}");
    println!(
        "{c_cyan}================================================================================{c_reset}"
    );
    println!(
        "{c_bold}[*] 诊断目标:{c_reset} {c_green}{}:{}{c_reset} ({})",
        trace.destination.host,
        trace.destination.port,
        if trace.destination.is_domain {
            "Domain"
        } else {
            "IP"
        }
    );
    println!(
        "{c_bold}[*] 会话环境:{c_reset} Network: {c_yellow}{}{c_reset} | Inbound: {c_yellow}{}{c_reset} | Process: {}",
        trace.session.network.to_uppercase(),
        trace.session.inbound,
        trace.session.process.as_deref().unwrap_or("None")
    );
    println!();

    // [1] 路由模式
    println!("{c_cyan}┌── [1] 分流运行模式{c_reset}");
    let mode_desc = match trace.mode.as_str() {
        "rule" => "rule (规则优先分流)",
        "global" => "global (全局代理模式)",
        "direct" => "direct (全局直连模式)",
        m => m,
    };
    println!("│   └── Mode: {c_bold}{mode_desc}{c_reset}");
    println!("│");

    // [2] 目标信息
    println!("{c_cyan}├── [2] 目标地址与嗅探{c_reset}");
    println!("│   ├── Host: {c_green}{}{c_reset}", trace.destination.host);
    println!("│   ├── Port: {c_green}{}{c_reset}", trace.destination.port);
    println!(
        "│   └── Type: {}",
        if trace.destination.is_domain {
            "Domain (域名)"
        } else {
            "IP Address (纯 IP)"
        }
    );
    println!("│");

    // [3] 惰性 DNS 解析
    println!("{c_cyan}├── [3] 惰性 DNS 解析{c_reset}");
    if let Some(ref dns) = trace.dns {
        if dns.triggered {
            println!(
                "│   ├── 触发状态: {c_yellow}已触发{c_reset} (触发规则: {:?})",
                dns.trigger_rule.as_deref().unwrap_or("-")
            );
            println!("│   ├── 解析耗时: {c_green}{}ms{c_reset}", dns.duration_ms);
            println!(
                "│   └── 解析结果: {c_cyan}{}{c_reset}",
                dns.resolved_ips.join(", ")
            );
        } else {
            println!("│   └── 触发状态: 未触发 (前置域名/通用规则已提前命中，避免了 DNS 耗时)");
        }
    } else {
        println!("│   └── 触发状态: 未触发 (未涉及需目标 IP 的规则评估)");
    }
    println!("│");

    // [4] 自适应抗阻断
    if trace.adaptive_blocked {
        println!("{c_cyan}├── [!] 自适应阻断状态{c_reset}");
        println!("│   └── {c_red}⚡ 命中自适应临时阻断 LRU 缓存，直连自动短路切至代理{c_reset}");
        println!("│");
    }

    // [5] 规则匹配决策
    println!("{c_cyan}├── [4] 规则匹配决策{c_reset}");
    let rule_time_str = if trace.rule_match.elapsed_us >= 1000 {
        format!("{:.2} ms", trace.rule_match.elapsed_us as f64 / 1000.0)
    } else {
        format!("{} µs", trace.rule_match.elapsed_us)
    };
    println!(
        "│   ├── 评估进度: 评估至第 {c_bold}{}{c_reset} 条 (总数: {} 条，规则匹配耗时: {c_green}{rule_time_str}{c_reset})",
        trace.rule_match.evaluated_count, trace.rule_match.total_rules
    );
    if let Some(ref m) = trace.rule_match.matched {
        println!(
            "│   ├── 命中规则: #{c_bold}{}{c_reset} {c_green}{}{c_reset}",
            m.index, m.raw
        );
        println!("│   ├── 规则类型: {c_magenta}{}{c_reset}", m.rule_type);
        println!("│   └── 分流目标: {c_bold}{c_yellow}{}{c_reset}", m.target);
    } else {
        println!("│   └── 命中状态: {c_dim}无规则命中，回落默认策略 (DIRECT){c_reset}");
    }
    println!("│");

    // [6] 策略组穿透链
    println!("{c_cyan}├── [5] 策略组穿透决策链{c_reset}");
    if trace.group_chain.is_empty() {
        println!("│   └── 无策略组跳转（直达出站节点）");
    } else {
        for (i, step) in trace.group_chain.iter().enumerate() {
            let is_last_step = i + 1 == trace.group_chain.len();
            let prefix_step = if is_last_step {
                "│   └──"
            } else {
                "│   ├──"
            };
            let sub_indent = if is_last_step {
                "│       "
            } else {
                "│   │   "
            };

            println!(
                "{prefix_step} [{}] 组名: {c_bold}{c_yellow}{}{c_reset} ({})",
                i + 1,
                step.group_name,
                step.group_type
            );
            println!("{sub_indent}├── 决策依据: {c_cyan}{}{c_reset}", step.reason);
            println!(
                "{sub_indent}├── 选中成员: {c_bold}{c_green}{}{c_reset}",
                step.picked_member
            );
            if step.udp_adjusted {
                println!(
                    "{sub_indent}├── UDP 调度: {c_yellow}原选中节点不支持 UDP，已平滑切换为支持 UDP 的存活节点{c_reset}"
                );
            }

            println!("{sub_indent}└── 组内成员快照 ({} 个):", step.members.len());
            for (m_idx, m) in step.members.iter().enumerate() {
                let is_last_m = m_idx + 1 == step.members.len();
                let m_prefix = if is_last_m { "└──" } else { "├──" };
                let is_picked = m.name == step.picked_member;
                let picked_mark = if is_picked {
                    format!(" {c_green}[* 选中]{c_reset}")
                } else {
                    String::new()
                };
                let delay_str = match m.delay_ms {
                    Some(d) => format!("{d}ms"),
                    None => "-".into(),
                };
                let alive_str = if m.alive {
                    format!("{c_green}存活{c_reset}")
                } else {
                    format!("{c_red}异常{c_reset}")
                };
                let udp_str = if m.support_udp {
                    "UDP:支持"
                } else {
                    "UDP:不支持"
                };

                println!(
                    "{sub_indent}    {} {} ({}, 延迟: {}, {}){}",
                    m_prefix, m.name, alive_str, delay_str, udp_str, picked_mark
                );
            }
            if !is_last_step {
                println!("│   │");
            }
        }
    }
    println!("│");

    // [7] 终结出站节点
    println!("{c_cyan}└── [6] 终结出站节点 (Leaf Outbound){c_reset}");
    println!(
        "    ├── 节点名称: {c_bold}{c_green}{}{c_reset}",
        trace.final_outbound.name
    );
    println!(
        "    ├── 出站类型: {c_magenta}{}{c_reset}",
        trace.final_outbound.outbound_type
    );
    if let Some(ref r) = trace.final_outbound.remote_addr {
        println!("    ├── 远程地址: {c_cyan}{r}{c_reset}");
    }
    println!(
        "    ├── UDP 支持: {}",
        if trace.final_outbound.support_udp {
            format!("{c_green}支持{c_reset}")
        } else {
            format!("{c_red}不支持{c_reset}")
        }
    );
    let total_time_str = if trace.elapsed_us >= 1000 {
        format!("{:.2} ms", trace.elapsed_us as f64 / 1000.0)
    } else {
        format!("{} µs", trace.elapsed_us)
    };
    println!("    ├── 决策总耗时: {c_green}{total_time_str}{c_reset}");
    println!(
        "    └── 决策全路径: {c_bold}{}{c_reset}",
        trace.decision_chain
    );
    println!(
        "{c_cyan}================================================================================{c_reset}"
    );
}

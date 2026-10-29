//! vpcore CLI。

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "vpcore",
    version,
    about = "VP_Core —— 小而快的全协议代理/VPN 内核"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 启动内核
    Run {
        /// GUI 托管模式：stdin 收到 stop 或管道关闭时正常退出
        #[arg(long)]
        managed_stdin: bool,
        /// 配置文件（.yaml / .yml / .json）
        #[arg(short, long)]
        config: PathBuf,
        /// 工作目录 / 规则库目录（支持 -d / -D / --directory）
        #[arg(short = 'd', short_alias = 'D', long, alias = "dir")]
        directory: Option<PathBuf>,
        /// 日志级别覆盖（trace/debug/info/warn/error）
        #[arg(short, long)]
        log_level: Option<String>,
    },
    /// 校验配置
    #[command(alias = "check")]
    Validate {
        /// 配置文件（.yaml / .yml / .json）
        #[arg(short, long)]
        config: PathBuf,
        /// 工作目录 / 规则库目录（支持 -d / -D / --directory）
        #[arg(short = 'd', short_alias = 'D', long, alias = "dir")]
        directory: Option<PathBuf>,
    },
    /// 将本地分享链接列表转换为 proxies YAML（不发起网络请求）
    ImportLinks {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// 全组测速
    Test {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// 拉取订阅并生成配置
    Sub {
        /// 订阅 URL
        url: String,
        /// 输出配置文件路径
        #[arg(short, long, default_value = "vpcore-sub.yaml")]
        output: PathBuf,
        /// 本地 mixed 监听端口
        #[arg(short, long, default_value_t = 7890)]
        port: u16,
        /// 代理地址（例如 http://127.0.0.1:7890 或 socks5://127.0.0.1:7890，缺省自动读取 HTTP_PROXY/ALL_PROXY 环境变量）
        #[arg(short = 'x', long)]
        proxy: Option<String>,
        /// 自定义 User-Agent（缺省使用 Clash.Meta 标头以兼容各机场面板）
        #[arg(long)]
        user_agent: Option<String>,
    },
    /// 应急清理所有系统 TUN 历史残留路由（恢复网络）
    CleanRoutes,
}

/// HTTP GET 拉取（ureq 默认跟随重定向，支持代理与标准客户端 User-Agent）
fn fetch(url: String, proxy: Option<String>, user_agent: Option<String>) -> Result<String, String> {
    let mut builder = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(30));

    // 优先使用 CLI 指定的代理，否则检查环境变量 HTTP_PROXY / HTTPS_PROXY / ALL_PROXY
    let proxy_str = proxy.or_else(|| {
        std::env::var("HTTPS_PROXY")
            .or_else(|_| std::env::var("https_proxy"))
            .or_else(|_| std::env::var("HTTP_PROXY"))
            .or_else(|_| std::env::var("http_proxy"))
            .or_else(|_| std::env::var("ALL_PROXY"))
            .or_else(|_| std::env::var("all_proxy"))
            .ok()
    });

    if let Some(ref p) = proxy_str {
        if let Ok(proxy_obj) = ureq::Proxy::new(p) {
            builder = builder.proxy(proxy_obj);
        }
    }

    let agent = builder.build();
    let ua = user_agent.unwrap_or_else(|| "clash.meta/v1.18.10".into());

    let resp = agent
        .get(&url)
        .set("User-Agent", &ua)
        .set("Accept", "*/*")
        .call()
        .map_err(|e| format!("{e}"))?;
    let mut body = String::new();
    use std::io::Read;
    resp.into_reader()
        .take(16 << 20)
        .read_to_string(&mut body)
        .map_err(|e| format!("{e}"))?;
    Ok(body)
}

fn init_logging(level: &str) {
    use std::io::IsTerminal;
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let ansi = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(ansi)
        .init();
    // panic 不退出（任务级隔离），但记录到日志
    std::panic::set_hook(Box::new(|info| {
        tracing::error!("panic（已隔离）: {info}");
    }));
}

#[cfg(windows)]
fn trim_working_set() {
    unsafe {
        windows_sys::Win32::System::ProcessStatus::K32EmptyWorkingSet(
            windows_sys::Win32::System::Threading::GetCurrentProcess(),
        );
    }
}

#[cfg(not(windows))]
fn trim_working_set() {}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::ImportLinks { input, output } => {
            let result = (|| -> Result<(), String> {
                let text = std::fs::read_to_string(&input).map_err(|e| e.to_string())?;
                if text.len() > 4 * 1024 * 1024 {
                    return Err("导入内容超过 4 MB".into());
                }
                let mut yaml = String::from("proxies:\n");
                let mut count = 0;
                for (i, line) in text.lines().enumerate() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let node = vp_protocol::sub::parse_uri(line)
                        .map_err(|_| format!("第 {} 行链接无效或格式不支持", i + 1))?;
                    yaml.push_str(&node.to_yaml());
                    count += 1;
                }
                if count == 0 {
                    return Err("没有可导入的链接".into());
                }
                std::fs::write(&output, yaml).map_err(|e| e.to_string())?;
                println!("已解析 {count} 个节点");
                Ok(())
            })();
            if let Err(e) = result {
                eprintln!("{e}");
                std::process::exit(2);
            }
        }
        Cmd::Validate {
            config,
            directory: _,
        } => {
            let text = match std::fs::read_to_string(&config) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("读取 {} 失败: {e}", config.display());
                    std::process::exit(2);
                }
            };
            let fmt = vp_config::Format::from_path(&config.to_string_lossy());
            match vp_config::parse_and_validate(&text, fmt) {
                Ok(cfg) => {
                    println!(
                        "✓ 配置有效：{} 个节点，{} 个组，{} 条规则，模式 {:?}",
                        cfg.proxies.len(),
                        cfg.proxy_groups.len(),
                        cfg.rules.len(),
                        cfg.mode
                    );
                }
                Err(errs) => {
                    eprintln!("✗ 配置无效：");
                    for e in errs {
                        eprintln!("  - {e}");
                    }
                    std::process::exit(1);
                }
            }
        }
        Cmd::Sub {
            url,
            output,
            port,
            proxy,
            user_agent,
        } => {
            init_logging("warn");
            // 拉取（跟随重定向的最小 HTTP GET）
            let body = tokio::task::spawn_blocking(move || fetch(url, proxy, user_agent))
                .await
                .unwrap()
                .unwrap_or_else(|e| {
                    eprintln!("拉取订阅失败: {e}");
                    std::process::exit(2);
                });
            let nodes = vp_protocol::sub::parse_subscription(&body);
            let (cfg, count, sample_names) = if !nodes.is_empty() {
                let count = nodes.len();
                let sample_names: Vec<String> =
                    nodes.iter().take(5).map(|n| n.name().to_string()).collect();
                (
                    vp_protocol::sub::build_config(&nodes, port),
                    count,
                    sample_names,
                )
            } else if let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&body) {
                // 支持直接返回 Clash YAML 订阅的情况
                let list_val = doc
                    .as_mapping()
                    .and_then(|m| m.get("proxies").or_else(|| m.get("payload")));
                if let Some(serde_yaml::Value::Sequence(seq)) = list_val {
                    if seq.is_empty() {
                        eprintln!("订阅中没有可识别的节点");
                        std::process::exit(1);
                    }
                    let count = seq.len();
                    let mut sample_names = Vec::new();
                    for item in seq.iter().take(5) {
                        if let Some(name) = item.get("name").and_then(|v| v.as_str()) {
                            sample_names.push(name.to_string());
                        }
                    }
                    // 若原始文档包含 proxy-groups，则直接使用原文档并注入 mixed-port
                    let has_groups = doc
                        .as_mapping()
                        .and_then(|m| m.get("proxy-groups"))
                        .is_some();
                    let final_cfg = if has_groups {
                        format!("mixed-port: {port}\n{body}")
                    } else {
                        let mut names = Vec::new();
                        for item in seq {
                            if let Some(name) = item.get("name").and_then(|v| v.as_str()) {
                                names.push(name.to_string());
                            }
                        }
                        let proxies_yaml = serde_yaml::to_string(seq).unwrap_or_default();
                        let mut out = format!(
                            "mixed-port: {port}\nmode: rule\nlog-level: info\n\nproxies:\n"
                        );
                        for line in proxies_yaml.lines() {
                            out.push_str("  ");
                            out.push_str(line);
                            out.push('\n');
                        }
                        out.push_str("\nproxy-groups:\n");
                        out.push_str("  - name: PROXY\n    type: select\n    proxies: [自动选择");
                        for n in &names {
                            out.push_str(&format!(", \"{}\"", n));
                        }
                        out.push_str("]\n");
                        out.push_str("  - name: 自动选择\n    type: url-test\n    url: http://www.gstatic.com/generate_204\n    interval: 300\n    proxies: [");
                        out.push_str(
                            &names
                                .iter()
                                .map(|n| format!("\"{n}\""))
                                .collect::<Vec<_>>()
                                .join(", "),
                        );
                        out.push_str("]\n");
                        out.push_str("\nrules:\n  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve\n  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve\n  - MATCH,PROXY\n");
                        out
                    };
                    (final_cfg, count, sample_names)
                } else {
                    eprintln!("订阅中没有可识别的节点");
                    std::process::exit(1);
                }
            } else {
                eprintln!("订阅中没有可识别的节点");
                std::process::exit(1);
            };

            std::fs::write(&output, cfg).unwrap_or_else(|e| {
                eprintln!("写入 {} 失败: {e}", output.display());
                std::process::exit(2);
            });
            println!(
                "✓ {} 个节点 → {}（mixed-port {port}）",
                count,
                output.display()
            );
            for n in sample_names {
                println!("  - {n}");
            }
            if count > 5 {
                println!("  ... 共 {count} 个");
            }
        }
        Cmd::Test { config } => {
            init_logging("warn");
            let text = std::fs::read_to_string(&config).unwrap_or_else(|e| {
                eprintln!("读取 {} 失败: {e}", config.display());
                std::process::exit(2);
            });
            let fmt = vp_config::Format::from_path(&config.to_string_lossy());
            let dir = config
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .to_path_buf();
            match vp_app::App::start(&text, fmt, &dir, false).await {
                Ok(app) => app.url_test_all_groups().await,
                Err(e) => {
                    eprintln!("启动失败: {e}");
                    std::process::exit(1);
                }
            }
        }
        Cmd::Run {
            managed_stdin,
            config,
            directory,
            log_level,
        } => {
            let text = std::fs::read_to_string(&config).unwrap_or_else(|e| {
                eprintln!("读取 {} 失败: {e}", config.display());
                std::process::exit(2);
            });
            // 极速提取日志级别，避免启动时对数万行配置进行多余的重复全量解析
            let level = log_level.clone().unwrap_or_else(|| {
                text.lines()
                    .find_map(|l| {
                        let l = l.trim();
                        let rest = l
                            .strip_prefix("log-level:")
                            .or_else(|| l.strip_prefix("log_level:"))?;
                        Some(
                            rest.trim()
                                .trim_matches(|c| c == '\'' || c == '"')
                                .to_string(),
                        )
                    })
                    .unwrap_or_else(|| "info".into())
            });
            init_logging(&level);
            let app =
                match vp_app::App::start_from_file_with_dir(&config, directory.as_deref(), true)
                    .await
                {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!("启动失败: {e}");
                        std::process::exit(1);
                    }
                };
            println!("vpcore {} 已启动", env!("CARGO_PKG_VERSION"));
            for (tag, port) in &app.listen_ports {
                println!("  {tag}: 127.0.0.1:{port}");
            }
            if let Some(c) = &app.controller {
                println!("  controller: http://{c}");
            }
            // 启动初始化完成后立即修剪工作集，归还解析配置产生的临时内存页
            trim_working_set();

            let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
            if managed_stdin {
                std::thread::spawn(move || {
                    use std::io::BufRead;
                    for line in std::io::stdin().lock().lines() {
                        match line {
                            Ok(line) if line.trim() != "stop" => continue,
                            _ => break,
                        }
                    }
                    let _ = stop_tx.send(());
                });
            } else {
                std::mem::forget(stop_tx);
            }

            // 跨平台文件变动检测（每秒检查一次 mtime）+ Unix SIGHUP / SIGINT·SIGTERM
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
            ticker.tick().await; // 消耗初始即刻 tick
            let mut last_mtime = std::fs::metadata(&config)
                .ok()
                .and_then(|m| m.modified().ok());
            let mut trim_ticks = 0u32;

            #[cfg(unix)]
            {
                let mut term =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .unwrap();
                let mut hup =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).unwrap();
                loop {
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => break,
                        _ = &mut stop_rx => break,
                        _ = term.recv() => break,
                        Some(_) = hup.recv() => {
                            match app.reload().await {
                                Ok(()) => {
                                    println!("✓ SIGHUP：配置已平滑热重载");
                                    trim_working_set();
                                }
                                Err(e) => eprintln!("✗ SIGHUP：热重载失败（保留旧配置）: {e}"),
                            }
                        }
                        _ = ticker.tick() => {
                            trim_ticks += 1;
                            if trim_ticks >= 300 {
                                trim_ticks = 0;
                                trim_working_set();
                            }
                            if let Ok(m) = std::fs::metadata(&config).and_then(|m| m.modified()) {
                                if last_mtime.is_some_and(|last| m > last) {
                                    last_mtime = Some(m);
                                    match app.reload().await {
                                        Ok(()) => {
                                            println!("✓ 配置文件变动，已平滑热重载");
                                            trim_working_set();
                                        }
                                        Err(e) => eprintln!("✗ 配置文件变动，热重载失败（保留旧配置）: {e}"),
                                    }
                                } else if last_mtime.is_none() {
                                    last_mtime = Some(m);
                                }
                            }
                        }
                    }
                }
            }

            #[cfg(not(unix))]
            {
                loop {
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => break,
                        _ = &mut stop_rx => break,
                        _ = ticker.tick() => {
                            trim_ticks += 1;
                            if trim_ticks >= 300 {
                                trim_ticks = 0;
                                trim_working_set();
                            }
                            if let Ok(m) = std::fs::metadata(&config).and_then(|m| m.modified()) {
                                if last_mtime.is_some_and(|last| m > last) {
                                    last_mtime = Some(m);
                                    match app.reload().await {
                                        Ok(()) => {
                                            println!("✓ 配置文件变动，已平滑热重载");
                                            trim_working_set();
                                        }
                                        Err(e) => eprintln!("✗ 配置文件变动，热重载失败（保留旧配置）: {e}"),
                                    }
                                } else if last_mtime.is_none() {
                                    last_mtime = Some(m);
                                }
                            }
                        }
                    }
                }
            }
            // 正常退出清理：确保所有动态添加的 TUN 路由被完整移除，防止机器断网
            let _ = vp_tun::auto_route::clean_all_routes();
            println!("bye");
        }
        Cmd::CleanRoutes => match vp_tun::auto_route::clean_all_routes() {
            Ok(()) => println!("✓ 已清理所有系统 TUN 历史残留路由，网络已自愈恢复"),
            Err(e) => eprintln!("✗ 清理路由失败: {e}"),
        },
    }
}

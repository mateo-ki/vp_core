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
    },
    /// 应急清理所有系统 TUN 历史残留路由（恢复网络）
    CleanRoutes,
}

/// HTTP GET 拉取（ureq 默认跟随重定向）
fn fetch(url: String) -> Result<String, String> {
    let resp = ureq::get(&url)
        .timeout(std::time::Duration::from_secs(30))
        .set("User-Agent", "vpcore/sub")
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
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    tracing_subscriber::fmt().with_env_filter(filter).init();
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
        Cmd::Sub { url, output, port } => {
            init_logging("warn");
            // 拉取（跟随重定向的最小 HTTP GET）
            let body = tokio::task::spawn_blocking(move || fetch(url))
                .await
                .unwrap()
                .unwrap_or_else(|e| {
                    eprintln!("拉取订阅失败: {e}");
                    std::process::exit(2);
                });
            let nodes = vp_protocol::sub::parse_subscription(&body);
            if nodes.is_empty() {
                eprintln!("订阅中没有可识别的节点");
                std::process::exit(1);
            }
            let cfg = vp_protocol::sub::build_config(&nodes, port);
            std::fs::write(&output, cfg).unwrap_or_else(|e| {
                eprintln!("写入 {} 失败: {e}", output.display());
                std::process::exit(2);
            });
            println!(
                "✓ {} 个节点 → {}（mixed-port {port}）",
                nodes.len(),
                output.display()
            );
            for n in nodes.iter().take(5) {
                println!("  - {}", n.name());
            }
            if nodes.len() > 5 {
                println!("  ... 共 {} 个", nodes.len());
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
            config,
            directory,
            log_level,
        } => {
            let text = std::fs::read_to_string(&config).unwrap_or_else(|e| {
                eprintln!("读取 {} 失败: {e}", config.display());
                std::process::exit(2);
            });
            // 先探明日志级别（配置或覆盖）
            let fmt = vp_config::Format::from_path(&config.to_string_lossy());
            let level = log_level.clone().unwrap_or_else(|| {
                vp_config::parse(&text, fmt)
                    .ok()
                    .map(|c| c.log_level)
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

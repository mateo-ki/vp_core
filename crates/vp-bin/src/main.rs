//! vpcore CLI。

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "vpcore", version, about = "VP_Core —— 小而快的全协议代理/VPN 内核")]
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
        /// 日志级别覆盖（trace/debug/info/warn/error）
        #[arg(short, long)]
        log_level: Option<String>,
    },
    /// 校验配置
    Validate {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// 全组测速
    Test {
        #[arg(short, long)]
        config: PathBuf,
    },
}

fn init_logging(level: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Validate { config } => {
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
        Cmd::Test { config } => {
            init_logging("warn");
            let text = std::fs::read_to_string(&config).unwrap_or_else(|e| {
                eprintln!("读取 {} 失败: {e}", config.display());
                std::process::exit(2);
            });
            let fmt = vp_config::Format::from_path(&config.to_string_lossy());
            let dir = config.parent().unwrap_or(std::path::Path::new(".")).to_path_buf();
            match vp_app::App::start(&text, fmt, &dir, false).await {
                Ok(app) => app.url_test_all_groups().await,
                Err(e) => {
                    eprintln!("启动失败: {e}");
                    std::process::exit(1);
                }
            }
        }
        Cmd::Run { config, log_level } => {
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
            let dir = config.parent().unwrap_or(std::path::Path::new(".")).to_path_buf();
            let app = match vp_app::App::start(&text, fmt, &dir, true).await {
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
            // 等待退出信号
            #[cfg(unix)]
            {
                let mut sig =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = sig.recv() => {}
                }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
            println!("bye");
        }
    }
}

//! vpcore CLI。

#[cfg(windows)]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod explain;
mod gen_server;
mod update;

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
        /// 配置文件（.yaml / .yml / .json / .vp）
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
        /// 配置文件（.yaml / .yml / .json / .vp）
        #[arg(short, long)]
        config: PathBuf,
        /// 工作目录 / 规则库目录（支持 -d / -D / --directory）
        #[arg(short = 'd', short_alias = 'D', long, alias = "dir")]
        directory: Option<PathBuf>,
    },
    /// 配置文件格式无损转换（YAML / JSON / .vp DSL 互转）
    Convert {
        /// 输入配置文件路径（支持 .yaml / .yml / .json / .vp）
        #[arg(short, long)]
        input: PathBuf,

        /// 输出配置文件路径（缺省直接输出至标准输出 stdout）
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// 强制指定输入格式（yaml / json / vp / dsl，缺省根据扩展名推断）
        #[arg(long)]
        from: Option<String>,

        /// 强制指定输出格式（yaml / json / vp / dsl，缺省根据输出文件名扩展名推断，否则为 vp）
        #[arg(short = 't', long)]
        to: Option<String>,
    },
    /// 格式化 .vp DSL 配置文件
    Fmt {
        /// 目标配置文件（.vp）
        #[arg(required = true)]
        files: Vec<PathBuf>,

        /// 原地写回格式化后的内容
        #[arg(short = 'w', long)]
        write: bool,

        /// 仅检查文件是否已规范化格式（未格式化时退出码 1）
        #[arg(short = 'c', long)]
        check: bool,
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
        /// 输出配置文件路径（支持 .yaml / .vp）
        #[arg(short, long, default_value = "vpcore-sub.yaml")]
        output: PathBuf,
        /// 输出格式覆盖（yaml / vp / dsl，缺省根据 output 后缀自动推断）
        #[arg(short = 'f', long)]
        format: Option<String>,
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
    /// 应急清理所有系统 TUN 历史残留路由与 iptables 端口重定向（恢复网络）
    CleanRoutes,
    /// 一键生成服务端配置及客户端分享链接
    #[command(name = "gen-server", alias = "init-server")]
    GenServer {
        /// 生成协议组合（可选：all, reality, hy2, ss2022, ss，默认 all）
        #[arg(short = 'p', long, default_value = "all")]
        protocols: String,

        /// 服务器公网 IP 或域名（缺省自动请求公共 API 探测本机 IP）
        #[arg(long)]
        ip: Option<String>,

        /// 绑定 CDN/反向代理穿透域名（例如 your-domain.com）
        #[arg(short, long, alias = "host")]
        domain: Option<String>,

        /// 伪装域名（用于 REALITY，默认 www.amazon.com）
        #[arg(long, default_value = "www.amazon.com")]
        sni: String,

        /// REALITY 监听端口（默认 443）
        #[arg(long, default_value_t = 443)]
        reality_port: u16,

        /// Hysteria 2 监听端口（默认 31889）
        #[arg(long, default_value_t = 31889)]
        hy2_port: u16,

        /// Shadowsocks-2022 监听端口（默认 31888）
        #[arg(long, default_value_t = 31888)]
        ss_port: u16,

        /// 订阅服务 / 外部控制器监听端口（默认 2080）
        #[arg(long, default_value_t = 2080)]
        sub_port: u16,

        /// 订阅访问 Token / Secret（缺省自动生成高强度随机 Token）
        #[arg(long)]
        sub_token: Option<String>,

        /// 配置文件输出路径（默认优先 /etc/vpcore/config.yaml，无权限或不存在时自动使用 ./vpcore-server.yaml）
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// 证书与私钥保存目录（默认与输出配置文件同目录）
        #[arg(long)]
        cert_dir: Option<PathBuf>,
    },
    /// 导出或生成客户端订阅链接与配置
    #[command(name = "gen-sub", alias = "export-sub")]
    GenSub {
        /// 配置文件路径（默认优先 /etc/vpcore/config.yaml 或 ./config.yaml）
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// 覆盖公网 IP 或域名
        #[arg(long)]
        host: Option<String>,

        /// 订阅端口（默认读取配置中的 external-controller 端口，或 2080）
        #[arg(long)]
        port: Option<u16>,

        /// 订阅访问 Token
        #[arg(long)]
        token: Option<String>,

        /// 输出格式：all (终端向导展示), base64 (仅输出 Base64 订阅文本), clash (仅输出 Clash YAML), url (仅输出通用订阅链接), clash-url (仅输出 Clash 订阅链接)
        #[arg(short, long, default_value = "all")]
        format: String,
    },
    /// 自动检查并更新 vpcore 至最新版本
    #[command(name = "update", alias = "upgrade", alias = "self-update")]
    Update {
        /// 强制重新安装/更新（即使已是最新版本）
        #[arg(short, long)]
        force: bool,

        /// 仅检查更新信息，不实际下载替换
        #[arg(short, long)]
        check: bool,

        /// 自定义更新源或直接指定二进制下载 URL
        #[arg(short, long)]
        url: Option<String>,
    },
    /// 诊断路由分流决策链路 (explain)
    #[command(name = "explain", alias = "trace")]
    Explain(explain::ExplainArgs),
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

struct LocalTimer;

impl tracing_subscriber::fmt::time::FormatTime for LocalTimer {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        let now = chrono::Local::now();
        write!(w, "{}", now.format("%Y-%m-%d %H:%M:%S"))
    }
}

#[cfg(unix)]
#[allow(clippy::manual_c_str_literals)]
fn redirect_broken_std_to_devnull() {
    unsafe {
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
        if devnull >= 0 {
            libc::dup2(devnull, libc::STDOUT_FILENO);
            libc::dup2(devnull, libc::STDERR_FILENO);
            libc::close(devnull);
        }
    }
}

fn is_broken_pipe_panic(info: &std::panic::PanicHookInfo<'_>) -> bool {
    let payload_str = if let Some(s) = info.payload().downcast_ref::<&str>() {
        *s
    } else if let Some(s) = info.payload().downcast_ref::<String>() {
        s.as_str()
    } else {
        ""
    };
    if payload_str.contains("Broken pipe")
        || payload_str.contains("os error 32")
        || payload_str.contains("failed printing to stderr")
        || payload_str.contains("failed printing to stdout")
    {
        return true;
    }
    let display_str = info.to_string();
    display_str.contains("Broken pipe")
        || display_str.contains("os error 32")
        || display_str.contains("failed printing to stderr")
        || display_str.contains("failed printing to stdout")
}

fn setup_panic_hook(with_tracing: bool) {
    std::panic::set_hook(Box::new(move |info| {
        if is_broken_pipe_panic(info) {
            #[cfg(unix)]
            redirect_broken_std_to_devnull();
            return;
        }
        // 对于其他 panic，防范写入破损流时发生二次递归 panic 导致系统 SIGABRT 强杀
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if with_tracing {
                tracing::error!("panic（已隔离）: {info}");
            } else {
                use std::io::Write;
                let _ = writeln!(std::io::stderr(), "panic（已隔离）: {info}");
            }
        }));
    }));
}

fn init_logging(level: &str) {
    use std::io::IsTerminal;
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let ansi = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_timer(LocalTimer)
        .with_target(false)
        .with_ansi(ansi)
        .init();
    // 切换为 tracing 记录 panic，保持 Broken pipe 防御与 catch_unwind 隔离
    setup_panic_hook(true);
}

#[cfg(windows)]
fn trim_working_set() {
    unsafe {
        windows_sys::Win32::System::ProcessStatus::K32EmptyWorkingSet(
            windows_sys::Win32::System::Threading::GetCurrentProcess(),
        );
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn trim_working_set() {
    unsafe {
        unsafe extern "C" {
            fn malloc_trim(pad: usize) -> std::ffi::c_int;
        }
        malloc_trim(0);
    }
}

#[cfg(not(any(windows, all(target_os = "linux", target_env = "gnu"))))]
fn trim_working_set() {}

fn main() {
    #[cfg(unix)]
    unsafe {
        // 忽略 SIGPIPE 信号，防止往关闭的 socket 或 pipe 写入时被系统信号强杀
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    setup_panic_hook(false);

    let threads = std::env::var("TOKIO_WORKER_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            let cpus = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(2);
            cpus.clamp(2, 4)
        });
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
        .expect("初始化 tokio 运行时失败")
        .block_on(async_main());
}

async fn async_main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::GenServer {
            protocols,
            ip,
            domain,
            sni,
            reality_port,
            hy2_port,
            ss_port,
            sub_port,
            sub_token,
            output,
            cert_dir,
        } => {
            if let Err(e) = gen_server::run(gen_server::GenServerArgs {
                protocols,
                ip,
                domain,
                sni,
                reality_port,
                hy2_port,
                ss_port,
                sub_port,
                sub_token,
                output,
                cert_dir,
            }) {
                eprintln!("\x1b[31m[!] 生成失败: {e}\x1b[0m");
                std::process::exit(1);
            }
        }
        Cmd::GenSub {
            config,
            host,
            port,
            token,
            format,
        } => {
            if let Err(e) = gen_server::run_sub(gen_server::GenSubArgs {
                config,
                host,
                port,
                token,
                format,
            }) {
                eprintln!("\x1b[31m[!] 导出订阅失败: {e}\x1b[0m");
                std::process::exit(1);
            }
        }
        Cmd::Update { force, check, url } => {
            if let Err(e) = update::run(update::UpdateArgs { force, check, url }) {
                eprintln!("\x1b[31m[!] 更新失败: {e}\x1b[0m");
                std::process::exit(1);
            }
        }
        Cmd::Explain(args) => {
            init_logging("warn");
            if let Err(e) = explain::run(args).await {
                eprintln!("\x1b[31m[!] 诊断失败: {e}\x1b[0m");
                std::process::exit(1);
            }
        }
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
            if fmt == vp_config::Format::Dsl {
                match vp_dsl::parse(&text) {
                    Ok(ir) => {
                        let cfg = vp_config::Config::from(ir);
                        match vp_config::validate::validate(&cfg) {
                            Ok(()) => {
                                println!(
                                    "✓ 配置有效（VP DSL）：{} 个节点，{} 个组，{} 条规则，模式 {:?}",
                                    cfg.proxies.len(),
                                    cfg.proxy_groups.len(),
                                    cfg.rules.len(),
                                    cfg.mode
                                );
                            }
                            Err(errs) => {
                                eprintln!("✗ 配置语义无效：");
                                for e in errs {
                                    eprintln!("  - {e}");
                                }
                                std::process::exit(1);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("✗ VP DSL 语法解析失败：\n  - {e}");
                        std::process::exit(1);
                    }
                }
            } else {
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
        }
        Cmd::Convert {
            input,
            output,
            from,
            to,
        } => {
            let text = match std::fs::read_to_string(&input) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("读取 {} 失败: {e}", input.display());
                    std::process::exit(2);
                }
            };

            // 1. 判断输入格式并转换为统一 IR
            let src_fmt = from.as_deref().map(|s| s.to_ascii_lowercase());
            let is_src_dsl = match src_fmt.as_deref() {
                Some("vp") | Some("dsl") => true,
                Some("yaml") | Some("yml") => false,
                Some("json") => false,
                _ => {
                    vp_config::Format::from_path(&input.to_string_lossy()) == vp_config::Format::Dsl
                }
            };

            let ir = if is_src_dsl {
                match vp_dsl::parse(&text) {
                    Ok(ir) => ir,
                    Err(e) => {
                        eprintln!("解析 VP DSL 失败: {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                let fmt = match src_fmt.as_deref() {
                    Some("json") => vp_config::Format::Json,
                    Some("yaml") | Some("yml") => vp_config::Format::Yaml,
                    _ => vp_config::Format::from_path(&input.to_string_lossy()),
                };
                match vp_config::parse(&text, fmt).and_then(|c| {
                    c.into_ir()
                        .map_err(|errs| vp_common::Error::Config(errs.join("; ")))
                }) {
                    Ok(ir) => ir,
                    Err(e) => {
                        eprintln!("解析输入配置并转换为统一 IR 失败: {e}");
                        std::process::exit(1);
                    }
                }
            };

            // 2. 判断目标格式并生成目标文本
            let dst_fmt = to
                .as_deref()
                .map(|s| s.to_ascii_lowercase())
                .or_else(|| {
                    output.as_ref().map(|o| {
                        let s = o.to_string_lossy().to_ascii_lowercase();
                        if s.ends_with(".yaml") || s.ends_with(".yml") {
                            "yaml".into()
                        } else if s.ends_with(".json") {
                            "json".into()
                        } else {
                            "vp".into()
                        }
                    })
                })
                .unwrap_or_else(|| {
                    if is_src_dsl {
                        "yaml".into()
                    } else {
                        "vp".into()
                    }
                });

            let out_str = match dst_fmt.as_str() {
                "vp" | "dsl" => vp_dsl::ir_to_dsl(&ir),
                "yaml" | "yml" => serde_yaml::to_string(&ir).unwrap_or_else(|e| {
                    eprintln!("序列化为 YAML 失败: {e}");
                    std::process::exit(1);
                }),
                "json" => serde_json::to_string_pretty(&ir).unwrap_or_else(|e| {
                    eprintln!("序列化为 JSON 失败: {e}");
                    std::process::exit(1);
                }),
                other => {
                    eprintln!("不支持的目标格式: '{other}' (可选: vp, yaml, json)");
                    std::process::exit(1);
                }
            };

            if let Some(ref out_path) = output {
                if let Err(e) = std::fs::write(out_path, &out_str) {
                    eprintln!("写入 {} 失败: {e}", out_path.display());
                    std::process::exit(2);
                }
                println!(
                    "✓ 转换成功: {} -> {} (目标格式: {})",
                    input.display(),
                    out_path.display(),
                    dst_fmt.to_uppercase()
                );
            } else {
                print!("{out_str}");
            }
        }
        Cmd::Fmt {
            files,
            write,
            check,
        } => {
            let mut has_unformatted = false;
            let mut failed = false;

            for file in &files {
                let text = match std::fs::read_to_string(file) {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("读取 {} 失败: {e}", file.display());
                        failed = true;
                        continue;
                    }
                };

                let formatted = match vp_dsl::format_dsl(&text) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("格式化 {} 失败 (语法错误): {e}", file.display());
                        failed = true;
                        continue;
                    }
                };

                // 行尾无关比较：Windows 下 git autocrlf 会将文件检出为 CRLF，
                // 内容等价即视为已格式化，避免与 git 行尾转换互相打架。
                let normalized = text.replace("\r\n", "\n");

                if check {
                    if normalized.trim() != formatted.trim() {
                        eprintln!("✗ 未格式化: {}", file.display());
                        has_unformatted = true;
                    }
                } else if write {
                    if normalized.trim() != formatted.trim() {
                        if let Err(e) = std::fs::write(file, &formatted) {
                            eprintln!("写入 {} 失败: {e}", file.display());
                            failed = true;
                        } else {
                            println!("✓ 已格式化: {}", file.display());
                        }
                    }
                } else {
                    print!("{formatted}");
                }
            }

            if failed || (check && has_unformatted) {
                std::process::exit(1);
            }
        }
        Cmd::Sub {
            url,
            output,
            format,
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

            let is_dsl = match format.as_deref() {
                Some(f) if f.eq_ignore_ascii_case("vp") || f.eq_ignore_ascii_case("dsl") => true,
                Some(f) if f.eq_ignore_ascii_case("yaml") || f.eq_ignore_ascii_case("yml") => false,
                _ => output
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .ends_with(".vp"),
            };

            let final_content = if is_dsl {
                match vp_config::parse(&cfg, vp_config::Format::Yaml).and_then(|c| {
                    c.into_ir()
                        .map_err(|errs| vp_common::Error::Config(errs.join("; ")))
                }) {
                    Ok(ir) => vp_dsl::ir_to_dsl(&ir),
                    Err(e) => {
                        eprintln!("转换订阅配置为 VP DSL 失败: {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                cfg
            };

            std::fs::write(&output, final_content).unwrap_or_else(|e| {
                eprintln!("写入 {} 失败: {e}", output.display());
                std::process::exit(2);
            });
            let format_label = if is_dsl { "，格式: VP DSL" } else { "" };
            println!(
                "✓ {} 个节点 → {}（mixed-port {port}{format_label}）",
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
                            .or_else(|| l.strip_prefix("log_level:"))
                            .or_else(|| l.strip_prefix("log-level ="))
                            .or_else(|| l.strip_prefix("log_level ="))?;
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
            tracing::info!("vpcore {} 已启动", env!("CARGO_PKG_VERSION"));
            for (tag, port) in &app.listen_ports {
                tracing::info!("监听服务: {tag}=127.0.0.1:{port}");
            }
            if let Some(c) = &app.controller {
                tracing::info!("外部控制: http://{c}");
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
                                    tracing::info!("✓ SIGHUP：配置已平滑热重载");
                                    trim_working_set();
                                }
                                Err(e) => tracing::error!("✗ SIGHUP：热重载失败（保留旧配置）: {e}"),
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
                                            tracing::info!("✓ 配置文件变动，已平滑热重载");
                                            trim_working_set();
                                        }
                                        Err(e) => tracing::error!("✗ 配置文件变动，热重载失败（保留旧配置）: {e}"),
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
                                            tracing::info!("✓ 配置文件变动，已平滑热重载");
                                            trim_working_set();
                                        }
                                        Err(e) => tracing::error!("✗ 配置文件变动，热重载失败（保留旧配置）: {e}"),
                                    }
                                } else if last_mtime.is_none() {
                                    last_mtime = Some(m);
                                }
                            }
                        }
                    }
                }
            }
            // 正常退出清理：确保本进程动态添加的 TUN 路由被完整移除，防止机器断网。
            // 只在本进程装过 auto-route 路由时执行：clean_all_routes 删的是通用的 /1 分半默认路由，
            // 没开 TUN 也执行会误删其他 VPN（如 OpenVPN redirect-gateway def1）装的同名路由，
            // 让其流量绕过 VPN 或直接断网
            let installed_routes = app
                .tun_runtime
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .is_some_and(|rt| rt.route_guard.is_some());
            if installed_routes {
                let _ = vp_tun::auto_route::clean_all_routes();
            }
            if app.has_port_redirects() {
                let _ = vp_tun::port_redirect::clean_all_port_redirects();
            }
            println!("bye");
        }
        Cmd::CleanRoutes => {
            let r1 = vp_tun::auto_route::clean_all_routes();
            let r2 = vp_tun::port_redirect::clean_all_port_redirects();
            match (r1, r2) {
                (Ok(()), Ok(())) => {
                    println!(
                        "✓ 已清理所有系统 TUN 历史残留路由与 iptables 端口重定向，网络已自愈恢复"
                    );
                }
                (Err(e), _) => eprintln!("✗ 清理路由失败: {e}"),
                (_, Err(e)) => eprintln!("✗ 清理 iptables 端口重定向失败: {e}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broken_pipe_panic_detection() {
        setup_panic_hook(false);

        // 验证针对标准流 Broken pipe，catch_unwind 能够正常拦截，且不会引发二次 panic
        let res = std::panic::catch_unwind(|| {
            panic!("failed printing to stderr: Broken pipe (os error 32)");
        });
        assert!(res.is_err(), "panic 应被正常捕获");

        let res2 = std::panic::catch_unwind(|| {
            panic!("failed printing to stdout: Broken pipe (os error 32)");
        });
        assert!(res2.is_err(), "stdout panic 应被正常捕获");
    }
}

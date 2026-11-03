//! vpcore 自我更新 (self-update) 引擎。
//!
//! - 自动检测当前操作系统与 CPU 架构
//! - 支持从指定 URL 或官方 Release 源下载最新二进制
//! - 替换前新二进制自我健康检查 (--version 验证)，防止损坏导致服务瘫痪
//! - 跨平台原子热替换 (Linux inode rename / Windows .old 重命名热替换)
//! - systemd 托管服务自动平滑重载

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

pub struct UpdateArgs {
    pub force: bool,
    pub check: bool,
    pub url: Option<String>,
}

/// 获取当前构建的目标架构三元组
pub fn get_target_triple() -> &'static str {
    if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        "x86_64-unknown-linux-musl"
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "aarch64") {
        "aarch64-unknown-linux-musl"
    } else if cfg!(target_os = "windows") && cfg!(target_arch = "x86_64") {
        "x86_64-pc-windows-msvc"
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "x86_64") {
        "x86_64-apple-darwin"
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        "aarch64-apple-darwin"
    } else {
        "unknown"
    }
}

/// 解析或探测最新 Release 下载链接
pub fn resolve_download_url(target: &str) -> String {
    let ext = if target.contains("windows") {
        "zip"
    } else {
        "tar.gz"
    };

    // 优先尝试通过 GitHub API 动态匹配最新的 Release Asset 真实名称与直链
    let api_url = "https://api.github.com/repos/mateo-ki/vp_core/releases/latest";
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(4))
        .timeout_read(Duration::from_secs(6))
        .build();

    if let Ok(resp) = agent
        .get(api_url)
        .set("User-Agent", "vpcore-updater")
        .call()
    {
        if let Ok(val) = serde_json::from_reader::<_, serde_json::Value>(resp.into_reader()) {
            if let Some(assets) = val.get("assets").and_then(|a| a.as_array()) {
                // 1. 精确匹配包含目标架构三元组的资源文件
                for asset in assets {
                    if let (Some(name), Some(url)) = (
                        asset.get("name").and_then(|n| n.as_str()),
                        asset.get("browser_download_url").and_then(|u| u.as_str()),
                    ) {
                        if name.contains(target) {
                            return url.to_string();
                        }
                    }
                }
                // 2. 跨 glibc / musl 模糊匹配（Linux 通用可执行文件）
                if target.contains("linux") {
                    let arch_key = if target.contains("aarch64") {
                        "aarch64"
                    } else {
                        "x86_64"
                    };
                    for asset in assets {
                        if let (Some(name), Some(url)) = (
                            asset.get("name").and_then(|n| n.as_str()),
                            asset.get("browser_download_url").and_then(|u| u.as_str()),
                        ) {
                            if name.contains("linux")
                                && name.contains(arch_key)
                                && name.ends_with(".tar.gz")
                            {
                                return url.to_string();
                            }
                        }
                    }
                }
            }
        }
    }

    // API 降级后直接使用最新下载重定向
    format!("https://github.com/mateo-ki/vp_core/releases/latest/download/vpcore-{target}.{ext}")
}

/// 执行自我更新主逻辑
pub fn run(args: UpdateArgs) -> Result<(), Box<dyn std::error::Error>> {
    let current_version = env!("CARGO_PKG_VERSION");
    let current_exe = std::env::current_exe()?;
    let target = get_target_triple();

    println!("\x1b[1;36m========================================================\x1b[0m");
    println!("\x1b[1;36m          VP_Core 内核自我更新向导 (update)             \x1b[0m");
    println!("\x1b[1;36m========================================================\x1b[0m\n");

    println!(
        "[\x1b[32m+\x1b[0m] 当前运行版本: \x1b[1;32mv{}\x1b[0m",
        current_version
    );
    println!(
        "[\x1b[32m+\x1b[0m] 运行程序路径: \x1b[1m{}\x1b[0m",
        current_exe.display()
    );
    println!(
        "[\x1b[32m+\x1b[0m] 系统目标架构: \x1b[1m{}\x1b[0m\n",
        target
    );

    if target == "unknown" {
        return Err("当前操作系统架构不受直接自动更新支持，请手动编译或替换".into());
    }

    // 确定下载 URL
    let download_url = if let Some(ref u) = args.url {
        u.clone()
    } else if let Ok(env_url) = std::env::var("VPCORE_UPDATE_URL") {
        env_url
    } else {
        resolve_download_url(target)
    };

    if args.check {
        println!(
            "[\x1b[34m*\x1b[0m] 检查模式：更新下载源为: \x1b[1m{}\x1b[0m",
            download_url
        );
        return Ok(());
    }

    println!(
        "[\x1b[34m*\x1b[0m] 正在从更新源拉取最新二进制: \x1b[1;34m{}\x1b[0m",
        download_url
    );

    let temp_dir = std::env::temp_dir().join(format!("vpcore-update-{}", std::process::id()));
    fs::create_dir_all(&temp_dir)?;
    let downloaded_file = temp_dir.join("downloaded.bin");

    // 下载文件
    download_to_file(&download_url, &downloaded_file)?;

    // 提取新可执行程序
    let new_binary_path = extract_binary(&downloaded_file, &temp_dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&new_binary_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&new_binary_path, perms)?;
    }

    // 运行新二进制自检健康度验证
    print!("[\x1b[34m*\x1b[0m] 正在对新版本执行自检完整性验证... ");
    let version_output = Command::new(&new_binary_path)
        .arg("--version")
        .output()
        .map_err(|e| format!("新二进制自检启动失败，取消更新避免损坏系统: {e}"))?;

    if !version_output.status.success() {
        return Err("新下载的二进制自检未能成功执行，已终止更新".into());
    }
    let new_ver_str = String::from_utf8_lossy(&version_output.stdout)
        .trim()
        .to_string();
    println!("\x1b[1;32m通过! ({})\x1b[0m", new_ver_str);

    if new_ver_str.contains(current_version) && !args.force {
        println!(
            "\n\x1b[1;33m[!] 当前已是最新版本 ({})，无需重复更新。使用 --force 可强制重新安装。\x1b[0m",
            current_version
        );
        let _ = fs::remove_dir_all(&temp_dir);
        return Ok(());
    }

    // 执行跨平台原子安全替换
    replace_current_exe(&new_binary_path, &current_exe)?;

    // 清理临时文件
    let _ = fs::remove_dir_all(&temp_dir);

    println!(
        "\n\x1b[1;32m[✓] 升级成功！当前二进制已更新为: {}\x1b[0m",
        new_ver_str
    );

    // 若运行在 Linux systemd 托管环境中，自动平滑重启服务
    #[cfg(target_os = "linux")]
    {
        if is_systemd_service_active("vpcore") {
            println!(
                "[\x1b[34m*\x1b[0m] 检测到 systemd 托管的 vpcore 服务正在运行，正在平滑重启服务..."
            );
            let res = Command::new("systemctl")
                .arg("restart")
                .arg("vpcore")
                .status();
            match res {
                Ok(st) if st.success() => {
                    println!("\x1b[1;32m[✓] vpcore systemd 服务已自动重启并生效最新版本！\x1b[0m");
                }
                _ => {
                    println!(
                        "\x1b[33m[!] 请手动执行 systemctl restart vpcore 使新版本立即生效\x1b[0m"
                    );
                }
            }
        }
    }

    Ok(())
}

/// 下载指定 URL 内容到本地文件
fn download_to_file(url: &str, output: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .timeout_read(Duration::from_secs(60))
        .build();

    let resp = agent
        .get(url)
        .call()
        .map_err(|e| format!("下载更新失败: {e}"))?;
    let mut reader = resp.into_reader();
    let mut file = fs::File::create(output)?;
    std::io::copy(&mut reader, &mut file)?;
    Ok(())
}

/// 提取解压二进制：支持 tar.gz、zip、以及直接的可执行二进制文件
fn extract_binary(
    archive_path: &Path,
    extract_to: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let bin_name = if cfg!(windows) {
        "vpcore.exe"
    } else {
        "vpcore"
    };
    let target_bin = extract_to.join(bin_name);

    // 检查是否为 tar.gz 或 zip
    let (is_tar, is_zip) = (|| -> Option<(bool, bool)> {
        let mut f = fs::File::open(archive_path).ok()?;
        let mut magic = [0u8; 2];
        use std::io::Read;
        f.read_exact(&mut magic).ok()?;
        // Gzip magic number 0x1f, 0x8b; Zip magic 0x50, 0x4b ('PK')
        Some((magic == [0x1f, 0x8b], magic == [0x50, 0x4b]))
    })()
    .unwrap_or((false, false));

    if is_tar || is_zip {
        #[cfg(unix)]
        {
            if is_tar {
                let status = Command::new("tar")
                    .arg("-xzf")
                    .arg(archive_path)
                    .arg("-C")
                    .arg(extract_to)
                    .status()
                    .map_err(|e| format!("调用系统 tar 解压失败: {e}"))?;
                if !status.success() {
                    return Err("系统 tar 解压返回失败代码".into());
                }
            } else if is_zip {
                let status = Command::new("unzip")
                    .arg("-q")
                    .arg("-o")
                    .arg(archive_path)
                    .arg("-d")
                    .arg(extract_to)
                    .status()
                    .map_err(|e| format!("调用系统 unzip 解压失败: {e}"))?;
                if !status.success() {
                    return Err("系统 unzip 解压返回失败代码".into());
                }
            }
        }
        #[cfg(windows)]
        {
            // Windows 10/11 内置 bsdtar (tar.exe)，支持 .zip 与 .tar.gz
            let status = Command::new("tar")
                .arg("-xf")
                .arg(archive_path)
                .arg("-C")
                .arg(extract_to)
                .status()
                .map_err(|e| format!("解压压缩包失败: {e}"))?;
            if !status.success() {
                return Err("解压更新包返回错误".into());
            }
        }
        if target_bin.exists() {
            return Ok(target_bin);
        }
        // 若压缩包内包含一级子目录（如 vpcore-v1.5.3-.../vpcore），递归扫描匹配
        if let Ok(entries) = fs::read_dir(extract_to) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    let sub_bin = p.join(bin_name);
                    if sub_bin.exists() {
                        return Ok(sub_bin);
                    }
                }
            }
        }
    }

    // 若不是压缩包或解压后未在目录找到，则将下载的文件直接视作二进制
    Ok(archive_path.to_path_buf())
}

/// 跨平台安全热替换当前运行程序
fn replace_current_exe(
    new_bin: &Path,
    current_exe: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        // Linux 支持 unlink/rename 运行中文件的 inode
        let temp_dest = current_exe.with_extension("tmp_new");
        fs::copy(new_bin, &temp_dest)?;
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&temp_dest)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&temp_dest, perms)?;
        fs::rename(&temp_dest, current_exe)?;
    }

    #[cfg(windows)]
    {
        // Windows 锁定运行中的 exe，但支持 rename
        let old_exe = current_exe.with_extension("exe.old");
        let _ = fs::remove_file(&old_exe); // 清理上次残留
        fs::rename(current_exe, &old_exe)?;
        fs::copy(new_bin, current_exe)?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn is_systemd_service_active(service_name: &str) -> bool {
    let out = Command::new("systemctl")
        .arg("is-active")
        .arg("--quiet")
        .arg(service_name)
        .status();
    matches!(out, Ok(st) if st.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_triple_not_unknown() {
        let triple = get_target_triple();
        assert_ne!(triple, "unknown");
    }

    #[test]
    fn test_resolve_download_url() {
        let url = resolve_download_url("x86_64-unknown-linux-musl");
        assert!(url.contains("vpcore"));
        assert!(url.contains("x86_64"));
    }

    #[test]
    fn test_extract_direct_binary() {
        let temp = std::env::temp_dir().join("vpcore-test-extract");
        let _ = fs::create_dir_all(&temp);
        let dummy = temp.join("test_bin");
        fs::write(&dummy, b"dummy-binary").unwrap();

        let extracted = extract_binary(&dummy, &temp).unwrap();
        assert!(extracted.exists());
        let _ = fs::remove_dir_all(temp);
    }
}

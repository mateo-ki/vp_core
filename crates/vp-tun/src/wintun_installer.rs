//! Windows Wintun 驱动按需外部动态装载管理。
//!
//! 不内嵌驱动二进制文件（降低核心二进制体积），按需在外部目录中探测并装载官方 wintun.dll。

#[cfg(windows)]
pub mod windows {
    use std::path::{Path, PathBuf};
    use tracing::debug;

    /// 依据 CPU 架构获取标准的 wintun 解压包内部相对路径
    fn arch_relative_path() -> &'static str {
        #[cfg(target_arch = "x86_64")]
        {
            "wintun/bin/amd64/wintun.dll"
        }
        #[cfg(target_arch = "aarch64")]
        {
            "wintun/bin/arm64/wintun.dll"
        }
        #[cfg(target_arch = "x86")]
        {
            "wintun/bin/x86/wintun.dll"
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "x86")))]
        {
            "wintun.dll"
        }
    }

    /// 探测外部存在的可用 wintun.dll 路径
    pub fn ensure_wintun_dll() -> Result<PathBuf, vp_common::Error> {
        let arch_rel = arch_relative_path();

        // 1. 检查环境变量指定的自定义路径
        if let Ok(env_path) = std::env::var("WINTUN_DLL_PATH") {
            let p = PathBuf::from(env_path);
            if p.exists() {
                debug!("从 WINTUN_DLL_PATH 环境变量指定路径加载 wintun: {}", p.display());
                return Ok(p);
            }
        }

        // 2. 检查程序同级目录及其解压子目录
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                let candidate = parent.join("wintun.dll");
                if candidate.exists() {
                    debug!("从可执行文件所在目录加载 wintun: {}", candidate.display());
                    return Ok(candidate);
                }
                let candidate_rel = parent.join(arch_rel);
                if candidate_rel.exists() {
                    debug!("从可执行文件架构子目录加载 wintun: {}", candidate_rel.display());
                    return Ok(candidate_rel);
                }
            }
        }

        // 3. 检查当前工作目录及其解压子目录
        if let Ok(cwd) = std::env::current_dir() {
            let candidate = cwd.join("wintun.dll");
            if candidate.exists() {
                debug!("从当前工作目录加载 wintun: {}", candidate.display());
                return Ok(candidate);
            }
            let candidate_rel = cwd.join(arch_rel);
            if candidate_rel.exists() {
                debug!("从当前工作目录架构子目录加载 wintun: {}", candidate_rel.display());
                return Ok(candidate_rel);
            }
        }

        // 4. 检查用户/系统级数据目录 (%LOCALAPPDATA%\vpcore\wintun.dll 或 %TEMP%\vpcore\wintun.dll)
        if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
            let candidate = Path::new(&local_appdata).join("vpcore").join("wintun.dll");
            if candidate.exists() {
                debug!("从 LOCALAPPDATA 目录加载 wintun: {}", candidate.display());
                return Ok(candidate);
            }
        }
        let temp_candidate = std::env::temp_dir().join("vpcore").join("wintun.dll");
        if temp_candidate.exists() {
            debug!("从临时缓存目录加载 wintun: {}", temp_candidate.display());
            return Ok(temp_candidate);
        }

        // 5. 检查系统目录 (C:\Windows\System32\wintun.dll)
        if let Ok(sys_root) = std::env::var("SystemRoot") {
            let candidate = Path::new(&sys_root).join("System32").join("wintun.dll");
            if candidate.exists() {
                debug!("从系统 System32 目录加载 wintun: {}", candidate.display());
                return Ok(candidate);
            }
        }

        // 若均未找到，抛出清晰直观的操作指引
        Err(vp_common::Error::Config(
            "未检测到 Wintun 驱动文件 (wintun.dll)。\n\
            请从官方下载驱动 (https://www.wintun.net/) 并执行以下任一操作：\n\
              1. 将对应架构的 wintun.dll 放置在 vpcore.exe 同级目录\n\
              2. 或设置环境变量 WINTUN_DLL_PATH 指向该文件绝对路径\n\
              3. 或将 wintun.dll 复制到 C:\\Windows\\System32 目录下".into(),
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_wintun_search_or_friendly_error() {
            // 在未设置非法路径的情况下，测试探测机制不 panic
            match ensure_wintun_dll() {
                Ok(path) => {
                    assert!(path.exists(), "查找到的外部 Wintun 路径必须存在: {}", path.display());
                }
                Err(err) => {
                    let msg = err.to_string();
                    assert!(msg.contains("wintun.dll"), "未找到时应给出包含 wintun.dll 说明的指引: {msg}");
                }
            }
        }
    }
}

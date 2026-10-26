//! VP_Core C-ABI FFI bridge.
//!
//! 提供供 Android (JNI)、iOS (Swift / Objective-C) 以及嵌入式系统调用的 C 语言标准 ABI 动态/静态库接口。

use std::ffi::{c_char, c_int, CStr, CString};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use vp_app::App;
use vp_config::Format;

// 状态码常量定义
pub const VP_OK: c_int = 0;
pub const VP_ERR_ALREADY_RUNNING: c_int = -1;
pub const VP_ERR_INVALID_PARAM: c_int = -2;
pub const VP_ERR_CONFIG: c_int = -3;
pub const VP_ERR_RUNTIME: c_int = -4;
pub const VP_ERR_NOT_RUNNING: c_int = -5;

struct CoreInstance {
    app: Arc<App>,
    runtime: tokio::runtime::Runtime,
}

static GLOBAL_CORE: Mutex<Option<CoreInstance>> = Mutex::new(None);
static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);
static INIT_LOGGER_ONCE: Once = Once::new();

fn set_last_error(err: impl Into<String>) {
    let mut guard = LAST_ERROR.lock().unwrap();
    *guard = Some(err.into());
}

fn clear_last_error() {
    let mut guard = LAST_ERROR.lock().unwrap();
    *guard = None;
}

/// 初始化全局日志输出（支持 trace/debug/info/warn/error），多次调用幂等
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vp_init_logger(log_level: *const c_char) -> c_int {
    let level_str = if log_level.is_null() {
        "info".to_string()
    } else {
        match unsafe { CStr::from_ptr(log_level) }.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return VP_ERR_INVALID_PARAM,
        }
    };

    INIT_LOGGER_ONCE.call_once(|| {
        use tracing_subscriber::EnvFilter;
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(&level_str));
        let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
    });

    VP_OK
}

/// 校验配置文本语法与语义完整性
///
/// 若合法，返回 NULL 指针；若非法，返回由堆分配的错误信息 C 字符串（使用完毕后必须调用 vp_free_string 释放）。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vp_validate_config(config_str: *const c_char) -> *mut c_char {
    clear_last_error();
    if config_str.is_null() {
        let err = CString::new("配置指针为 NULL").unwrap();
        return err.into_raw();
    }

    let cfg_slice = match unsafe { CStr::from_ptr(config_str) }.to_str() {
        Ok(s) => s,
        Err(e) => {
            let err = CString::new(format!("配置非有效 UTF-8: {e}")).unwrap();
            return err.into_raw();
        }
    };

    let fmt = if cfg_slice.trim_start().starts_with('{') {
        Format::Json
    } else {
        Format::Yaml
    };

    match vp_config::parse_and_validate(cfg_slice, fmt) {
        Ok(_) => std::ptr::null_mut(),
        Err(errs) => {
            let msg = format!("配置校验未通过:\n  - {}", errs.join("\n  - "));
            CString::new(msg).unwrap().into_raw()
        }
    }
}

/// 启动 VP_Core 运行时
///
/// - config_str: UTF-8 编码的 YAML / JSON 格式配置文本
/// - tun_fd: 外部注入的 TUN 文件描述符（如 Android VpnService.Builder 建立的文件句柄）。
///           传入 < 0（例如 -1）表示不注入外部 fd（桌面或普通入站模式）。
///
/// 返回值：0 (VP_OK) 成功，负数表示错误码。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vp_start(config_str: *const c_char, tun_fd: c_int) -> c_int {
    clear_last_error();
    if config_str.is_null() {
        set_last_error("配置指针为 NULL");
        return VP_ERR_INVALID_PARAM;
    }

    let cfg_slice = match unsafe { CStr::from_ptr(config_str) }.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("配置不是合法的 UTF-8 字符串: {e}"));
            return VP_ERR_INVALID_PARAM;
        }
    };

    let mut guard = match GLOBAL_CORE.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    if guard.is_some() {
        set_last_error("内核实例已在运行中，请先调用 vp_stop 停止旧实例");
        return VP_ERR_ALREADY_RUNNING;
    }

    let fmt = if cfg_slice.trim_start().starts_with('{') {
        Format::Json
    } else {
        Format::Yaml
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("vpcore-worker")
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            set_last_error(format!("创建 Tokio 运行时失败: {e}"));
            return VP_ERR_RUNTIME;
        }
    };

    let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let injected_fd = if tun_fd >= 0 { Some(tun_fd) } else { None };

    let app = match runtime.block_on(App::start_with_tun_fd(
        cfg_slice,
        fmt,
        &current_dir,
        true,
        injected_fd,
    )) {
        Ok(a) => a,
        Err(e) => {
            set_last_error(format!("内核装配与启动失败: {e}"));
            return VP_ERR_CONFIG;
        }
    };

    *guard = Some(CoreInstance { app, runtime });
    VP_OK
}

/// 停止当前正在运行的 VP_Core 运行时并释放全部资源
///
/// 返回值：0 (VP_OK) 成功，负数表示错误码。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vp_stop() -> c_int {
    clear_last_error();
    let mut guard = match GLOBAL_CORE.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    let instance = match guard.take() {
        Some(inst) => inst,
        None => {
            set_last_error("当前没有运行中的内核实例");
            return VP_ERR_NOT_RUNNING;
        }
    };

    // 终止活动连接记录并关闭运行时
    instance.runtime.shutdown_timeout(Duration::from_millis(600));
    VP_OK
}

/// 平滑热重载内核路由规则与节点配置
///
/// - config_str: UTF-8 编码的 YAML / JSON 格式新配置文本
///
/// 返回值：0 (VP_OK) 成功，负数表示错误码。重载期间现有连接不中断。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vp_reload(config_str: *const c_char) -> c_int {
    clear_last_error();
    if config_str.is_null() {
        set_last_error("重载配置指针为 NULL");
        return VP_ERR_INVALID_PARAM;
    }

    let cfg_slice = match unsafe { CStr::from_ptr(config_str) }.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("重载配置不是合法的 UTF-8 字符串: {e}"));
            return VP_ERR_INVALID_PARAM;
        }
    };

    let guard = match GLOBAL_CORE.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    let instance = match guard.as_ref() {
        Some(inst) => inst,
        None => {
            set_last_error("当前没有运行中的内核实例，无法重载");
            return VP_ERR_NOT_RUNNING;
        }
    };

    match instance.runtime.block_on(instance.app.reload_with_text(cfg_slice)) {
        Ok(_) => VP_OK,
        Err(e) => {
            set_last_error(format!("平滑热重载失败: {e}"));
            VP_ERR_CONFIG
        }
    }
}

/// 查询内核当前是否正在运行
///
/// 返回值：1 表示正在运行，0 表示未运行。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vp_is_running() -> c_int {
    let guard = match GLOBAL_CORE.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if guard.is_some() {
        1
    } else {
        0
    }
}

/// 获取全局累计流量统计（上传字节数与下载字节数）
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vp_get_stats(upload: *mut u64, download: *mut u64) {
    let guard = match GLOBAL_CORE.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    if let Some(inst) = guard.as_ref() {
        unsafe {
            if !upload.is_null() {
                *upload = inst.app.stats.upload.load(Ordering::Relaxed);
            }
            if !download.is_null() {
                *download = inst.app.stats.download.load(Ordering::Relaxed);
            }
        }
    } else {
        unsafe {
            if !upload.is_null() {
                *upload = 0;
            }
            if !download.is_null() {
                *download = 0;
            }
        }
    }
}

/// 获取最近一次发生的错误描述信息
///
/// 返回值：堆分配的 C 字符串指针（由调用方使用 vp_free_string 释放），若无错误返回 NULL。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vp_last_error() -> *mut c_char {
    let guard = LAST_ERROR.lock().unwrap();
    match guard.as_ref() {
        Some(err) => match CString::new(err.as_bytes()) {
            Ok(c) => c.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

/// 释放由 VP_Core FFI 分配的 C 字符串指针
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vp_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

/// 获取当前内核版本号字符串（例如 "0.1.0"）
///
/// 返回值：堆分配的 C 字符串指针（由调用方使用 vp_free_string 释放）。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vp_version() -> *mut c_char {
    let ver = env!("CARGO_PKG_VERSION");
    CString::new(ver).unwrap().into_raw()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn test_version_and_string_free() {
        unsafe {
            let ver_ptr = vp_version();
            assert!(!ver_ptr.is_null());
            let ver = CStr::from_ptr(ver_ptr).to_str().unwrap();
            assert_eq!(ver, env!("CARGO_PKG_VERSION"));
            vp_free_string(ver_ptr);
        }
    }

    #[test]
    fn test_validate_config_ffi() {
        unsafe {
            let bad_cfg = CString::new("invalid: [").unwrap();
            let err_ptr = vp_validate_config(bad_cfg.as_ptr());
            assert!(!err_ptr.is_null());
            let err_str = CStr::from_ptr(err_ptr).to_str().unwrap();
            assert!(err_str.contains("配置校验未通过") || err_str.contains("failed"));
            vp_free_string(err_ptr);

            let good_cfg = CString::new(r#"
mixed-port: 17890
mode: direct
"#).unwrap();
            let ok_ptr = vp_validate_config(good_cfg.as_ptr());
            assert!(ok_ptr.is_null());
        }
    }

    #[test]
    fn test_lifecycle_start_stop_stats_reload() {
        unsafe {
            assert_eq!(vp_is_running(), 0);

            let cfg = CString::new(r#"
mixed-port: 27891
mode: direct
"#).unwrap();

            let ret = vp_start(cfg.as_ptr(), -1);
            assert_eq!(ret, VP_OK);
            assert_eq!(vp_is_running(), 1);

            // 重复启动返回 VP_ERR_ALREADY_RUNNING
            let ret_dup = vp_start(cfg.as_ptr(), -1);
            assert_eq!(ret_dup, VP_ERR_ALREADY_RUNNING);

            // 获取统计
            let mut up = 999;
            let mut down = 999;
            vp_get_stats(&mut up, &mut down);
            assert_eq!(up, 0);
            assert_eq!(down, 0);

            // 热重载
            let reload_cfg = CString::new(r#"
mixed-port: 27891
mode: rule
rules:
  - MATCH,DIRECT
"#).unwrap();
            let reload_ret = vp_reload(reload_cfg.as_ptr());
            assert_eq!(reload_ret, VP_OK);

            // 正常停止
            let stop_ret = vp_stop();
            assert_eq!(stop_ret, VP_OK);
            assert_eq!(vp_is_running(), 0);

            // 再次停止返回 VP_ERR_NOT_RUNNING
            assert_eq!(vp_stop(), VP_ERR_NOT_RUNNING);
        }
    }
}

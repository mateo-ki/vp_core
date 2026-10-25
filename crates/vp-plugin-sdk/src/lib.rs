//! vp-plugin-sdk：插件作者使用的 C-ABI 绑定（冻结 ABI）。
//!
//! 插件为 `.dll` / `.so` / `.dylib`，导出 `vp_transform_abi` 返回下述函数表。
//! ABI 一经发布不可变更，只能新增版本。

use std::os::raw::{c_char, c_void};

pub const ABI_VERSION: u32 = 1;

/// 流量方向
pub const DIR_UPSTREAM: u32 = 0; // 客户端 → 服务器
pub const DIR_DOWNSTREAM: u32 = 1; // 服务器 → 客户端

/// transform 插件函数表
#[repr(C)]
pub struct VpTransformVt {
    /// 返回插件支持的 ABI 版本（宿主校验）
    pub abi_version: unsafe extern "C" fn() -> u32,
    /// 由 JSON 配置创建实例句柄；失败返回 null
    pub create: unsafe extern "C" fn(cfg_json: *const c_char, cfg_len: usize) -> *mut c_void,
    pub destroy: unsafe extern "C" fn(handle: *mut c_void),
    /// 缓冲区变换；输出缓冲由插件分配。
    /// 返回 0 成功；*out 为 null 时表示透传原缓冲。
    pub transform: unsafe extern "C" fn(
        handle: *mut c_void,
        dir: u32,
        in_ptr: *const u8,
        in_len: usize,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,
    /// 释放 transform 分配的缓冲
    pub free_buf: unsafe extern "C" fn(handle: *mut c_void, ptr: *mut u8, len: usize),
}

/// 宿主侧约定的导出符号名
pub const EXPORT_SYMBOL: &str = "vp_transform_abi";

/// 声明式导出宏：实现 TransformImpl 的结构体一键导出
#[macro_export]
macro_rules! vp_transform_plugin {
    ($ty:ty) => {
        extern "C" fn vp_abi_version() -> u32 {
            $crate::ABI_VERSION
        }

        static VT: $crate::VpTransformVt = $crate::VpTransformVt {
            abi_version: vp_abi_version,
            create: vp_create,
            destroy: vp_destroy,
            transform: vp_transform,
            free_buf: vp_free_buf,
        };

        unsafe extern "C" fn vp_create(
            cfg_json: *const ::std::os::raw::c_char,
            cfg_len: usize,
        ) -> *mut ::std::os::raw::c_void {
            let cfg = if cfg_json.is_null() || cfg_len == 0 {
                "{}"
            } else {
                ::std::str::from_utf8(::std::slice::from_raw_parts(
                    cfg_json as *const u8,
                    cfg_len,
                ))
                .unwrap_or("{}")
            };
            match <$ty>::create(cfg) {
                Ok(h) => Box::into_raw(Box::new(h)) as *mut ::std::os::raw::c_void,
                Err(_) => ::std::ptr::null_mut(),
            }
        }

        unsafe extern "C" fn vp_destroy(handle: *mut ::std::os::raw::c_void) {
            if !handle.is_null() {
                drop(Box::from_raw(handle as *mut $ty));
            }
        }

        unsafe extern "C" fn vp_transform(
            handle: *mut ::std::os::raw::c_void,
            dir: u32,
            in_ptr: *const u8,
            in_len: usize,
            out_ptr: *mut *mut u8,
            out_len: *mut usize,
        ) -> i32 {
            if handle.is_null() {
                return -1;
            }
            let h = &mut *(handle as *mut $ty);
            let input = if in_ptr.is_null() || in_len == 0 {
                &[][..]
            } else {
                ::std::slice::from_raw_parts(in_ptr, in_len)
            };
            match h.transform(dir, input) {
                Ok(out) => {
                    if out.is_empty() {
                        *out_ptr = ::std::ptr::null_mut();
                        *out_len = 0;
                    } else {
                        let mut b = out.into_boxed_slice();
                        *out_len = b.len();
                        *out_ptr = b.as_mut_ptr();
                        ::std::mem::forget(b);
                    }
                    0
                }
                Err(_) => -2,
            }
        }

        unsafe extern "C" fn vp_free_buf(
            _handle: *mut ::std::os::raw::c_void,
            ptr: *mut u8,
            len: usize,
        ) {
            if !ptr.is_null() && len > 0 {
                drop(Vec::from_raw_parts(ptr, len, len));
            }
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn vp_transform_abi() -> *const $crate::VpTransformVt {
            &VT
        }
    };
}

/// 插件实现 trait
pub trait TransformImpl {
    fn create(cfg_json: &str) -> Result<Self, String>
    where
        Self: Sized;
    fn transform(&mut self, dir: u32, input: &[u8]) -> Result<Vec<u8>, String>;
}

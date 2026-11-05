//! Android JNI entrypoints for `com.vpcore.VPCore`

use jni::sys::{JNI_FALSE, JNI_TRUE, JNIEnv, jboolean, jclass, jint, jlong, jlongArray, jstring};
use std::ptr;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_vpcore_VPCore_initLogger(
    env: *mut JNIEnv,
    _class: jclass,
    log_level: jstring,
) -> jint {
    if log_level.is_null() {
        return unsafe { crate::vp_init_logger(ptr::null()) };
    }
    let get_fn = unsafe { (**env).v1_1.GetStringUTFChars };
    let release_fn = unsafe { (**env).v1_1.ReleaseStringUTFChars };
    let chars = unsafe { get_fn(env, log_level, ptr::null_mut()) };
    if chars.is_null() {
        return -2;
    }
    let res = unsafe { crate::vp_init_logger(chars) };
    unsafe { release_fn(env, log_level, chars) };
    res
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_vpcore_VPCore_validateConfig(
    env: *mut JNIEnv,
    _class: jclass,
    config_str: jstring,
) -> jstring {
    if config_str.is_null() {
        return ptr::null_mut();
    }
    let get_fn = unsafe { (**env).v1_1.GetStringUTFChars };
    let release_fn = unsafe { (**env).v1_1.ReleaseStringUTFChars };
    let new_string_fn = unsafe { (**env).v1_1.NewStringUTF };

    let chars = unsafe { get_fn(env, config_str, ptr::null_mut()) };
    if chars.is_null() {
        return ptr::null_mut();
    }
    let err_ptr = unsafe { crate::vp_validate_config(chars) };
    unsafe { release_fn(env, config_str, chars) };

    if err_ptr.is_null() {
        return ptr::null_mut();
    }
    let res = unsafe { new_string_fn(env, err_ptr) };
    unsafe { crate::vp_free_string(err_ptr) };
    res
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_vpcore_VPCore_start(
    env: *mut JNIEnv,
    _class: jclass,
    config_str: jstring,
    tun_fd: jint,
) -> jint {
    if config_str.is_null() {
        return -2;
    }
    let get_fn = unsafe { (**env).v1_1.GetStringUTFChars };
    let release_fn = unsafe { (**env).v1_1.ReleaseStringUTFChars };

    let chars = unsafe { get_fn(env, config_str, ptr::null_mut()) };
    if chars.is_null() {
        return -2;
    }
    let res = unsafe { crate::vp_start(chars, tun_fd) };
    unsafe { release_fn(env, config_str, chars) };
    res
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_vpcore_VPCore_stop(_env: *mut JNIEnv, _class: jclass) -> jint {
    unsafe { crate::vp_stop() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_vpcore_VPCore_reload(
    env: *mut JNIEnv,
    _class: jclass,
    config_str: jstring,
) -> jint {
    if config_str.is_null() {
        return -2;
    }
    let get_fn = unsafe { (**env).v1_1.GetStringUTFChars };
    let release_fn = unsafe { (**env).v1_1.ReleaseStringUTFChars };

    let chars = unsafe { get_fn(env, config_str, ptr::null_mut()) };
    if chars.is_null() {
        return -2;
    }
    let res = unsafe { crate::vp_reload(chars) };
    unsafe { release_fn(env, config_str, chars) };
    res
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_vpcore_VPCore_isRunning(
    _env: *mut JNIEnv,
    _class: jclass,
) -> jboolean {
    if unsafe { crate::vp_is_running() } == 1 {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_vpcore_VPCore_getStats(
    env: *mut JNIEnv,
    _class: jclass,
) -> jlongArray {
    let mut upload = 0u64;
    let mut download = 0u64;
    unsafe { crate::vp_get_stats(&mut upload, &mut download) };

    let new_arr_fn = unsafe { (**env).v1_1.NewLongArray };
    let set_region_fn = unsafe { (**env).v1_1.SetLongArrayRegion };

    let arr = unsafe { new_arr_fn(env, 2) };
    if arr.is_null() {
        return ptr::null_mut();
    }
    let buf = [upload as jlong, download as jlong];
    unsafe { set_region_fn(env, arr, 0, 2, buf.as_ptr()) };
    arr
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_vpcore_VPCore_lastError(
    env: *mut JNIEnv,
    _class: jclass,
) -> jstring {
    let err_ptr = unsafe { crate::vp_last_error() };
    if err_ptr.is_null() {
        return ptr::null_mut();
    }
    let new_string_fn = unsafe { (**env).v1_1.NewStringUTF };
    let res = unsafe { new_string_fn(env, err_ptr) };
    unsafe { crate::vp_free_string(err_ptr) };
    res
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_vpcore_VPCore_version(
    env: *mut JNIEnv,
    _class: jclass,
) -> jstring {
    let ver_ptr = unsafe { crate::vp_version() };
    if ver_ptr.is_null() {
        return ptr::null_mut();
    }
    let new_string_fn = unsafe { (**env).v1_1.NewStringUTF };
    let res = unsafe { new_string_fn(env, ver_ptr) };
    unsafe { crate::vp_free_string(ver_ptr) };
    res
}

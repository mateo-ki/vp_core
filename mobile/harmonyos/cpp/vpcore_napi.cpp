/**
 * @file vpcore_napi.cpp
 * @brief OpenHarmony / HarmonyOS NEXT Node-API C++ 桥接模块
 */

#include "napi/native_api.h"
#include <cstring>
#include <string>
#include "vpcore.h"

static napi_value NapiInitLogger(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1] = {nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    char level_buf[32] = {0};
    const char *level_ptr = nullptr;
    if (argc >= 1 && args[0] != nullptr) {
        size_t len = 0;
        if (napi_get_value_string_utf8(env, args[0], level_buf, sizeof(level_buf) - 1, &len) == napi_ok) {
            level_ptr = level_buf;
        }
    }

    int ret = vp_init_logger(level_ptr);
    napi_value result;
    napi_create_int32(env, ret, &result);
    return result;
}

static napi_value NapiValidateConfig(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1] = {nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    if (argc < 1 || args[0] == nullptr) {
        napi_value res;
        napi_get_null(env, &res);
        return res;
    }

    size_t str_len = 0;
    napi_get_value_string_utf8(env, args[0], nullptr, 0, &str_len);
    std::string config_str(str_len + 1, '\0');
    napi_get_value_string_utf8(env, args[0], &config_str[0], config_str.size(), &str_len);

    char *err_ptr = vp_validate_config(config_str.c_str());
    if (err_ptr == nullptr) {
        napi_value res;
        napi_get_null(env, &res);
        return res;
    }

    napi_value res;
    napi_create_string_utf8(env, err_ptr, NAPI_AUTO_LENGTH, &res);
    vp_free_string(err_ptr);
    return res;
}

static napi_value NapiStart(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2] = {nullptr, nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    if (argc < 1 || args[0] == nullptr) {
        napi_value res;
        napi_create_int32(env, -2, &res);
        return res;
    }

    size_t str_len = 0;
    napi_get_value_string_utf8(env, args[0], nullptr, 0, &str_len);
    std::string config_str(str_len + 1, '\0');
    napi_get_value_string_utf8(env, args[0], &config_str[0], config_str.size(), &str_len);

    int tun_fd = -1;
    if (argc >= 2 && args[1] != nullptr) {
        napi_get_value_int32(env, args[1], &tun_fd);
    }

    int ret = vp_start(config_str.c_str(), tun_fd);
    napi_value res;
    napi_create_int32(env, ret, &res);
    return res;
}

static napi_value NapiStop(napi_env env, napi_callback_info) {
    int ret = vp_stop();
    napi_value res;
    napi_create_int32(env, ret, &res);
    return res;
}

static napi_value NapiReload(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1] = {nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    if (argc < 1 || args[0] == nullptr) {
        napi_value res;
        napi_create_int32(env, -2, &res);
        return res;
    }

    size_t str_len = 0;
    napi_get_value_string_utf8(env, args[0], nullptr, 0, &str_len);
    std::string config_str(str_len + 1, '\0');
    napi_get_value_string_utf8(env, args[0], &config_str[0], config_str.size(), &str_len);

    int ret = vp_reload(config_str.c_str());
    napi_value res;
    napi_create_int32(env, ret, &res);
    return res;
}

static napi_value NapiIsRunning(napi_env env, napi_callback_info) {
    int running = vp_is_running();
    napi_value res;
    napi_get_boolean(env, running == 1, &res);
    return res;
}

static napi_value NapiGetStats(napi_env env, napi_callback_info) {
    uint64_t up = 0, down = 0;
    vp_get_stats(&up, &down);

    napi_value obj;
    napi_create_object(env, &obj);

    napi_value val_up, val_down;
    napi_create_int64(env, static_cast<int64_t>(up), &val_up);
    napi_create_int64(env, static_cast<int64_t>(down), &val_down);

    napi_set_named_property(env, obj, "uploadBytes", val_up);
    napi_set_named_property(env, obj, "downloadBytes", val_down);
    return obj;
}

static napi_value NapiLastError(napi_env env, napi_callback_info) {
    char *err_ptr = vp_last_error();
    if (err_ptr == nullptr) {
        napi_value res;
        napi_get_null(env, &res);
        return res;
    }

    napi_value res;
    napi_create_string_utf8(env, err_ptr, NAPI_AUTO_LENGTH, &res);
    vp_free_string(err_ptr);
    return res;
}

static napi_value NapiVersion(napi_env env, napi_callback_info) {
    char *ver_ptr = vp_version();
    napi_value res;
    if (ver_ptr != nullptr) {
        napi_create_string_utf8(env, ver_ptr, NAPI_AUTO_LENGTH, &res);
        vp_free_string(ver_ptr);
    } else {
        napi_create_string_utf8(env, "unknown", NAPI_AUTO_LENGTH, &res);
    }
    return res;
}

EXTERN_C_START
static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {
        {"initLogger", nullptr, NapiInitLogger, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"validateConfig", nullptr, NapiValidateConfig, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"start", nullptr, NapiStart, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"stop", nullptr, NapiStop, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"reload", nullptr, NapiReload, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"isRunning", nullptr, NapiIsRunning, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"getStats", nullptr, NapiGetStats, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"lastError", nullptr, NapiLastError, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"version", nullptr, NapiVersion, nullptr, nullptr, nullptr, napi_default, nullptr},
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}
EXTERN_C_END

static napi_module _vpcore_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "vpcore_napi",
    .nm_priv = nullptr,
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterVpCoreModule(void) {
    napi_module_register(&_vpcore_module);
}

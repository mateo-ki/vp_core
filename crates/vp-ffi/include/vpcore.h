/**
 * @file vpcore.h
 * @brief VP_Core C-ABI Interface Header
 *
 * Designed for Android JNI, iOS Swift / Objective-C bridging, and embedded systems.
 */

#ifndef VPCORE_H
#define VPCORE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status and Error Codes */
#define VP_OK                     0
#define VP_ERR_ALREADY_RUNNING   -1
#define VP_ERR_INVALID_PARAM     -2
#define VP_ERR_CONFIG            -3
#define VP_ERR_RUNTIME           -4
#define VP_ERR_NOT_RUNNING       -5

/**
 * @brief Initialize global logging level.
 *
 * @param log_level C string: "trace", "debug", "info", "warn", or "error". Passing NULL defaults to "info".
 * @return 0 on success, or a negative error code.
 */
int vp_init_logger(const char *log_level);

/**
 * @brief Validate configuration text syntax and semantics.
 *
 * @param config_str UTF-8 encoded YAML or JSON configuration text.
 * @return NULL if valid. If invalid, returns a pointer to an error message string
 *         which MUST be freed with vp_free_string().
 */
char *vp_validate_config(const char *config_str);

/**
 * @brief Start the VP_Core runtime.
 *
 * @param config_str UTF-8 encoded YAML or JSON configuration text.
 * @param tun_fd External TUN file descriptor (e.g. Android VpnService.Builder fd,
 *               or iOS PacketTunnelProvider fd). Pass -1 if not injecting an external TUN device.
 * @return 0 (VP_OK) on success, or a negative error code:
 *         VP_ERR_ALREADY_RUNNING (-1) if already running,
 *         VP_ERR_INVALID_PARAM (-2) if parameters are null or invalid UTF-8,
 *         VP_ERR_CONFIG (-3) if configuration failed validation or assembly,
 *         VP_ERR_RUNTIME (-4) if Tokio runtime creation failed.
 */
int vp_start(const char *config_str, int tun_fd);

/**
 * @brief Stop the running VP_Core runtime and release all resources.
 *
 * @return 0 (VP_OK) on success, or VP_ERR_NOT_RUNNING (-5) if not currently running.
 */
int vp_stop(void);

/**
 * @brief Smoothly hot-reload configuration (routing rules, proxy nodes, etc.) without dropping connections.
 *
 * @param config_str UTF-8 encoded YAML or JSON new configuration text.
 * @return 0 (VP_OK) on success, or a negative error code.
 */
int vp_reload(const char *config_str);

/**
 * @brief Check if VP_Core is currently running.
 *
 * @return 1 if running, 0 if not running.
 */
int vp_is_running(void);

/**
 * @brief Query cumulative traffic statistics.
 *
 * @param upload Pointer to store cumulative bytes uploaded (can be NULL).
 * @param download Pointer to store cumulative bytes downloaded (can be NULL).
 */
void vp_get_stats(uint64_t *upload, uint64_t *download);

/**
 * @brief Retrieve the most recent error message.
 *
 * @return Pointer to a newly allocated error string, or NULL if no error occurred.
 *         The returned string MUST be freed using vp_free_string().
 */
char *vp_last_error(void);

/**
 * @brief Free a string allocated by VP_Core FFI (such as from vp_version or vp_last_error).
 *
 * @param s Pointer to string to free. Passing NULL is a safe no-op.
 */
void vp_free_string(char *s);

/**
 * @brief Get the VP_Core version string (e.g. "0.1.0").
 *
 * @return Pointer to newly allocated version string. MUST be freed with vp_free_string().
 */
char *vp_version(void);

#ifdef __cplusplus
}
#endif

#endif /* VPCORE_H */

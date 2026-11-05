package com.vpcore

import android.os.ParcelFileDescriptor

/**
 * VP_Core Android Kotlin Native Wrapper.
 *
 * 适用于 Android 平台（支持 Android 5.0+ / API 21+）。
 * 深度集成 Android VpnService，支持无缝透传 ParcelFileDescriptor fd。
 */
object VPCore {

    // 状态码常量定义
    const val OK: Int = 0
    const val ERR_ALREADY_RUNNING: Int = -1
    const val ERR_INVALID_PARAM: Int = -2
    const val ERR_CONFIG: Int = -3
    const val ERR_RUNTIME: Int = -4
    const val ERR_NOT_RUNNING: Int = -5

    data class TrafficStats(
        val uploadBytes: Long,
        val downloadBytes: Long
    ) {
        val totalBytes: Long get() = uploadBytes + downloadBytes
    }

    init {
        try {
            System.loadLibrary("vpcore")
        } catch (e: UnsatisfiedLinkError) {
            System.err.println("[VPCore] 加载 libvpcore.so 失败，请检查 jniLibs 路径配置: ${e.message}")
            throw e
        }
    }

    // ==========================================
    // 底层 JNI 声明 (对齐 crates/vp-ffi/android_jni.rs)
    // ==========================================
    @JvmStatic
    private external fun initLogger(logLevel: String?): Int

    @JvmStatic
    private external fun validateConfig(configStr: String): String?

    @JvmStatic
    private external fun start(configStr: String, tunFd: Int): Int

    @JvmStatic
    private external fun stop(): Int

    @JvmStatic
    private external fun reload(configStr: String): Int

    @JvmStatic
    private external fun isRunning(): Boolean

    @JvmStatic
    private external fun getStats(): LongArray

    @JvmStatic
    private external fun lastError(): String?

    @JvmStatic
    private external fun version(): String

    // ==========================================
    // 高级面向对象与 Kotlin 友好封装
    // ==========================================

    /**
     * 初始化内核全局日志输出级别
     * @param logLevel "trace", "debug", "info", "warn", 或 "error"（默认 "info"）
     */
    fun setupLogger(logLevel: String = "info"): Boolean {
        return initLogger(logLevel) == OK
    }

    /**
     * 获取内核核心版本号（例如 "1.6.0"）
     */
    val coreVersion: String
        get() = version()

    /**
     * 查询内核是否正在运行中
     */
    val active: Boolean
        get() = isRunning()

    /**
     * 获取最后一次发生的错误描述信息（若无错误则为 null）
     */
    val coreLastError: String?
        get() = lastError()

    /**
     * 校验配置文本（YAML / JSON）合法性
     * @return 成功返回 Result.success，失败返回附带错误信息的 Result.failure
     */
    fun checkConfig(configStr: String): Result<Unit> {
        val err = validateConfig(configStr)
        return if (err == null) {
            Result.success(Unit)
        } else {
            Result.failure(IllegalArgumentException(err))
        }
    }

    /**
     * 启动内核运行时并托管流量
     * @param configStr YAML 或 JSON 格式的完整配置
     * @param vpnInterface 由 VpnService.Builder().establish() 生成的 ParcelFileDescriptor 文件描述符
     */
    @Synchronized
    fun startCore(configStr: String, vpnInterface: ParcelFileDescriptor? = null): Result<Unit> {
        val fd = vpnInterface?.detachFd() ?: -1
        val code = start(configStr, fd)
        return if (code == OK) {
            Result.success(Unit)
        } else {
            val msg = coreLastError ?: "启动失败，错误码: $code"
            Result.failure(IllegalStateException(msg))
        }
    }

    /**
     * 停止内核并释放所有连接与内存资源
     */
    @Synchronized
    fun stopCore(): Result<Unit> {
        val code = stop()
        return if (code == OK) {
            Result.success(Unit)
        } else {
            val msg = coreLastError ?: "停止失败，错误码: $code"
            Result.failure(IllegalStateException(msg))
        }
    }

    /**
     * 平滑热重载内核路由规则与节点配置（不中断已有网络流）
     */
    @Synchronized
    fun reloadConfig(configStr: String): Result<Unit> {
        val code = reload(configStr)
        return if (code == OK) {
            Result.success(Unit)
        } else {
            val msg = coreLastError ?: "热重载失败，错误码: $code"
            Result.failure(IllegalStateException(msg))
        }
    }

    /**
     * 获取当前内核累计统计流量
     */
    fun queryTraffic(): TrafficStats {
        val arr = getStats()
        return if (arr.size >= 2) {
            TrafficStats(uploadBytes = arr[0], downloadBytes = arr[1])
        } else {
            TrafficStats(0L, 0L)
        }
    }
}

//
//  VPCore.swift
//  VP_Core iOS / macOS Swift Native Wrapper
//

import Foundation
import NetworkExtension

#if canImport(VPCoreC)
import VPCoreC
#elseif canImport(VPCore)
import VPCore
#endif

public enum VPCoreError: LocalizedError {
    case alreadyRunning
    case invalidParam(String)
    case configError(String)
    case runtimeError(String)
    case notRunning
    case unknown(Int32, String?)

    public var errorDescription: String? {
        switch self {
        case .alreadyRunning:
            return "VP_Core 内核实例已在运行中"
        case .invalidParam(let msg):
            return "参数无效: \(msg)"
        case .configError(let msg):
            return "配置错误: \(msg)"
        case .runtimeError(let msg):
            return "运行时错误: \(msg)"
        case .notRunning:
            return "当前内核未处于运行状态"
        case .unknown(let code, let msg):
            return "内核错误 (代码: \(code)): \(msg ?? "未知原因")"
        }
    }
}

public struct VPCoreTrafficStats {
    public let uploadBytes: UInt64
    public let downloadBytes: UInt64
    public var totalBytes: UInt64 { uploadBytes + downloadBytes }

    public init(uploadBytes: UInt64, downloadBytes: UInt64) {
        self.uploadBytes = uploadBytes
        self.downloadBytes = downloadBytes
    }
}

public final class VPCoreManager: @unchecked Sendable {
    public static let shared = VPCoreManager()

    private init() {}

    /// 初始化日志级别 ("trace", "debug", "info", "warn", "error")
    @discardableResult
    public func initLogger(level: String = "info") -> Bool {
        return level.withCString { cStr in
            return vp_init_logger(cStr) == 0
        }
    }

    /// 获取内核版本号
    public var version: String {
        guard let cStr = vp_version() else { return "unknown" }
        defer { vp_free_string(cStr) }
        return String(cString: cStr)
    }

    /// 查询内核当前是否正在运行
    public var isRunning: Bool {
        return vp_is_running() == 1
    }

    /// 获取最近一次发生的错误描述信息
    public var lastError: String? {
        guard let cStr = vp_last_error() else { return nil }
        defer { vp_free_string(cStr) }
        return String(cString: cStr)
    }

    /// 校验 YAML / JSON 格式配置文本
    public func validateConfig(_ configText: String) throws {
        try configText.withCString { cStr in
            if let errPtr = vp_validate_config(cStr) {
                defer { vp_free_string(errPtr) }
                let errMsg = String(cString: errPtr)
                throw VPCoreError.configError(errMsg)
            }
        }
    }

    /// 启动内核
    /// - Parameters:
    ///   - configText: YAML / JSON 完整配置
    ///   - tunFd: PacketTunnelProvider 注入的 TUN 文件描述符（未注入则传 -1）
    public func start(configText: String, tunFd: Int32 = -1) throws {
        let ret = configText.withCString { cStr in
            return vp_start(cStr, tunFd)
        }

        if ret != 0 {
            let msg = lastError
            switch ret {
            case -1: throw VPCoreError.alreadyRunning
            case -2: throw VPCoreError.invalidParam(msg ?? "")
            case -3: throw VPCoreError.configError(msg ?? "")
            case -4: throw VPCoreError.runtimeError(msg ?? "")
            default: throw VPCoreError.unknown(ret, msg)
            }
        }
    }

    /// 停止运行中的内核并释放资源
    public func stop() throws {
        let ret = vp_stop()
        if ret != 0 {
            throw VPCoreError.notRunning
        }
    }

    /// 平滑热重载配置
    public func reload(configText: String) throws {
        let ret = configText.withCString { cStr in
            return vp_reload(cStr)
        }
        if ret != 0 {
            let msg = lastError ?? "热重载配置失败"
            throw VPCoreError.configError(msg)
        }
    }

    /// 获取当前上传与下载统计
    public func queryTraffic() -> VPCoreTrafficStats {
        var up: UInt64 = 0
        var down: UInt64 = 0
        vp_get_stats(&up, &down)
        return VPCoreTrafficStats(uploadBytes: up, downloadBytes: down)
    }
}

# VP_Core iOS / macOS SDK 集成指南

VP_Core iOS 专属包包含了符合 Apple 官方规范的通用二进制框架（`VPCore.xcframework`）以及原生 Swift 封装类（`VPCore.swift`）。

---

## 📦 目录结构

```text
vpcore-ios-v1.6.0.zip
├── VPCore.xcframework/           # 包含真机 (arm64) 与模拟器 (arm64-sim) 通用框架
├── include/
│   ├── vpcore.h                  # C-ABI 头文件
│   └── module.modulemap          # Clang Module 映射
├── Swift/
│   └── VPCore.swift              # 原生 Swift 封装类
├── Package.swift                 # Swift Package Manager 支持
└── README.md
```

---

## 🚀 极速集成步骤

### 方式一：Swift Package Manager (推荐)
直接在 Xcode 项目中：
1. 点击 `File` -> `Add Package Dependencies...`；
2. 在右上角搜索框中输入本项目 GitHub 仓库地址：
   ```text
   https://github.com/mateo-ki/vp_core
   ```
3. 选择版本规则（如 `Exact Version: 1.6.0`），点击 `Add Package` 即可一键完成依赖注入！

### 方式二：手动导入 XCFramework
1. 将 `VPCore.xcframework` 拖入你的 Xcode 工程的 `Frameworks, Libraries, and Embedded Content`；
2. 选择 **"Do Not Embed"**（因为是静态库架构封装）；
3. 将 `Swift/VPCore.swift` 源码加入你的目标 Target（通常是 `PacketTunnel` Extension）。

---

## 💡 在 PacketTunnelProvider 中使用示例

```swift
import NetworkExtension
import VPCore

class PacketTunnelProvider: NEPacketTunnelProvider {

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        // 1. 初始化日志
        VPCoreManager.shared.initLogger(level: "info")

        // 2. 准备配置文本
        let configYaml = """
        mixed-port: 7890
        mode: rule
        tun:
          enable: true
          stack: gvisor
        rules:
          - MATCH,DIRECT
        """

        // 3. 配置网络设置并启动系统隧道
        let tunnelNetworkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        tunnelNetworkSettings.ipv4Settings = NEIPv4Settings(addresses: ["172.19.0.1"], subnetMasks: ["255.255.255.252"])
        tunnelNetworkSettings.dnsSettings = NEDNSSettings(servers: ["172.19.0.2"])

        setTunnelNetworkSettings(tunnelNetworkSettings) { [weak self] error in
            if let error = error {
                completionHandler(error)
                return
            }

            // 4. 获取系统 tunnel 文件描述符或直接启动 VP_Core
            do {
                try VPCoreManager.shared.start(configText: configYaml, tunFd: -1)
                NSLog("[VP_Core] 核心启动成功, 版本: \(VPCoreManager.shared.version)")
                completionHandler(nil)
            } catch {
                NSLog("[VP_Core] 启动失败: \(error.localizedDescription)")
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        do {
            try VPCoreManager.shared.stop()
        } catch {
            NSLog("[VP_Core] 停止核心异常: \(error)")
        }
        completionHandler()
    }
}
```

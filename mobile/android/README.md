# VP_Core Android SDK 集成指南

VP_Core Android 专属包包含了预编译好的全架构动态库（`libvpcore.so`）及开箱即用的 Kotlin 原生封装类（`VPCore.kt`）。

---

## 📦 目录结构

```text
vpcore-android-v1.6.0.zip
├── jniLibs/
│   ├── arm64-v8a/libvpcore.so      # 现代 Android 64 位主力真机
│   ├── armeabi-v7a/libvpcore.so    # 32 位老旧设备兼容
│   └── x86_64/libvpcore.so         # Android Studio 官方 x86_64 模拟器
├── include/
│   └── vpcore.h                    # C-ABI 头文件
├── kotlin/
│   └── com/vpcore/VPCore.kt        # 开箱即用的 Kotlin 高层封装
└── README.md
```

---

## 🚀 极速集成步骤

### 1. 拷贝动态库与 Kotlin 源码
1. 将 `jniLibs/` 目录中的内容复制到你 Android 项目的 `app/src/main/jniLibs/` 下；
2. 将 `kotlin/com/vpcore/VPCore.kt` 复制到你 Android 项目的 `app/src/main/java/com/vpcore/` 下。

### 2. 声明 VPN 权限 (`AndroidManifest.xml`)
在你的应用清单文件中声明网络与 VPN 服务权限：
```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />

<application ...>
    <service
        android:name=".MyVpnService"
        android:permission="android.permission.BIND_VPN_SERVICE"
        android:exported="false">
        <intent-filter>
            <action android:name="android.net.VpnService" />
        </intent-filter>
    </service>
</application>
```

### 3. 在 `VpnService` 中一键拉起内核
```kotlin
import android.net.VpnService
import com.vpcore.VPCore

class MyVpnService : VpnService() {

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // 1. 初始化日志
        VPCore.setupLogger("info")

        // 2. 配置 YAML / JSON 规则文本
        val configYaml = """
            mixed-port: 7890
            mode: rule
            tun:
              enable: true
              stack: gvisor
            rules:
              - MATCH,DIRECT
        """.trimIndent()

        // 3. 构建 Android 虚拟网卡
        val vpnInterface = Builder()
            .setSession("VP_Core")
            .addAddress("172.19.0.1", 30)
            .addDnsServer("172.19.0.2")
            .addRoute("0.0.0.0", 0)
            .setMtu(1500)
            .establish() ?: return START_NOT_STICKY

        // 4. 将网卡 fd 注入内核启动
        VPCore.startCore(configYaml, vpnInterface).onSuccess {
            println("VP_Core 内核启动成功，版本: ${VPCore.coreVersion}")
        }.onFailure { err ->
            System.err.println("内核启动失败: ${err.message}")
        }

        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        // 停止内核并释放资源
        VPCore.stopCore()
    }
}
```

### 4. 运行时操作
```kotlin
// 平滑重载配置（不掉线）
VPCore.reloadConfig(newYaml).onSuccess { /* 重载成功 */ }

// 查询流量统计
val stats = VPCore.queryTraffic()
println("上传: ${stats.uploadBytes} B, 下载: ${stats.downloadBytes} B")
```

# VP_Core 纯血鸿蒙 (HarmonyOS NEXT) SDK 集成指南

VP_Core 鸿蒙专属包专为华为纯血鸿蒙（HarmonyOS NEXT / OpenHarmony 4.0+）设计，采用官方标准 **Node-API (N-API)** 规范与 ArkTS 原生封装。

---

## 📦 目录结构

```text
vpcore-harmonyos-v1.6.0.zip
├── libs/
│   ├── arm64-v8a/libvpcore.so      # 纯血鸿蒙真机（Mate 60 / Pura 70 / MatePad / 智选车机）
│   └── x86_64/libvpcore.so         # DevEco Studio 官方鸿蒙模拟器
├── include/
│   └── vpcore.h                    # C-ABI 头文件
├── arkts/
│   ├── VPCore.ets                  # ArkTS 面向对象高层封装
│   └── index.d.ts                  # ArkTS 类型定义文件
├── cpp/
│   └── vpcore_napi.cpp             # OpenHarmony N-API 桥接层
├── CMakeLists.txt                  # DevEco C++ 模块构建脚本
└── README.md
```

---

## 🚀 DevEco Studio 集成步骤

### 1. 导入 Native 模块与 C++ 源码
1. 将 `libs/` 中的动态库复制到工程模块下的 `src/main/cpp/libs/`；
2. 将 `cpp/vpcore_napi.cpp` 与 `include/vpcore.h` 复制到 `src/main/cpp/` 目录下；
3. 将 `CMakeLists.txt` 放入 `src/main/cpp/`，并在模块的 `build-profile.json5` 中声明 externalNativeOpt；
4. 将 `arkts/VPCore.ets` 与 `arkts/index.d.ts` 复制到 `src/main/ets/vpcore/`。

### 2. 声明 VPN 权限 (`module.json5`)
在你的 UIAbility 或 ExtensionAbility 的 `module.json5` 中配置：
```json5
{
  "module": {
    "requestPermissions": [
      {
        "name": "ohos.permission.INTERNET"
      },
      {
        "name": "ohos.permission.MANAGE_VPN"
      }
    ]
  }
}
```

### 3. 在 ArkTS 中通过 `@ohos.net.vpn` 调起 VP_Core
```typescript
import vpn from '@ohos.net.vpn';
import { VPCore } from '../vpcore/VPCore';

export default class VpnAbilityStage {

  async startVpCore() {
    // 1. 初始化日志
    VPCore.initLogger('info');

    // 2. 配置 YAML
    const configYaml = `
mixed-port: 7890
mode: rule
tun:
  enable: true
rules:
  - MATCH,DIRECT
`;

    // 3. 通过鸿蒙系统 VPN 框架建立虚拟网卡
    const vpnConfig: vpn.VpnConfig = {
      addresses: [{ address: "172.19.0.1", family: 1 }],
      routes: [{ interface: "tun0", destination: { address: "0.0.0.0", family: 1 }, prefixLength: 0 }],
      dnsAddresses: ["172.19.0.2"],
      mtu: 1500
    };

    const vpnConnection = vpn.createVpnConnection(getContext(this));
    await vpnConnection.create(vpnConfig);
    const tunFd = await vpnConnection.getTunFd();

    // 4. 将系统 tunFd 注入 VP_Core 内核启动
    const ret = VPCore.start(configYaml, tunFd);
    if (ret === 0) {
      console.info(`[VP_Core] 纯血鸿蒙内核启动成功, 版本: ${VPCore.version}`);
    } else {
      console.error(`[VP_Core] 启动失败: ${VPCore.lastError}`);
    }
  }

  stopVpCore() {
    VPCore.stop();
  }
}
```

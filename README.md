# VP_Core

**小而快、零运行时开销的全协议代理 / VPN 内核（Rust 实现）。**

全面对标 **sing-box** 与 **mihomo (Clash.Meta)**，具备极致轻量、高吞吐、超低内存与开箱即用的服务端/客户端一体化能力。

---

## ✨ 核心优势

- ⚡ **极致轻量**：Linux Musl 单文件仅 **4.3 MB**，空载常驻内存 (RSS) 仅 **10~20 MB**（零 GC 停顿），512MB 低配 VPS 轻松拉满。
- 🚀 **极高吞吐**：基于 Rust + Tokio 异步运行时，全链路池化零拷贝，千兆线速轻松跑满。
- 🛡️ **生产级服务端**：原生支持 VLESS (REALITY/WS CDN穿透)、SS-2022、Hysteria 2、Trojan、TUIC v5，内置内核级 iptables 端口跳跃重定向、UDP RRL 防反射与端口敲门隐身防御。
- 🌐 **一键开服与订阅**：内置开服引擎与动态 HTTP 订阅端点（`/sub`），自动输出 Clash 规则配置与通用节点链接。
- 🔌 **全协议原生 UDP**：原生支持 VLESS/VMess/Trojan UDP、XUDP (Mux.Cool) 及 packetaddr 编码，支持单连接多目标 (Full-Cone)。
- 📱 **全平台覆盖**：Windows (Wintun)、Linux (Musl/OpenWrt)、macOS、Android 与 iOS。

---

## 🚀 极速上手

### 1. VPS 一键开服部署

在全新的 Linux VPS 上一键自动安装、配置 systemd 并生成节点与订阅：

```bash
# 自动探测公网 IP 开服（输出全协议节点与一键订阅）
curl -fsSL https://raw.githubusercontent.com/mateo-ki/vp_core/main/install.sh | bash

# 绑定域名开服（支持 Cloudflare CDN 穿透）
curl -fsSL https://raw.githubusercontent.com/mateo-ki/vp_core/main/install.sh | bash -s -- --domain your-domain.com
```

### 2. 常用命令

```bash
# 服务端管理
vpcore gen-server        # 一键生成服务端配置、节点链接及订阅
vpcore gen-sub           # 导出当前服务端订阅 (支持 clash / base64)
vpcore update            # 内核跨平台平滑自我更新 (带健康校验)

# 客户端运行
vpcore sub "<URL>" -o config.yaml   # 拉取远程订阅生成客户端配置
vpcore validate -c config.yaml      # 校验配置文件语法与端口
vpcore run -c config.yaml           # 启动代理 / VPN 服务
vpcore test -c config.yaml          # 全节点延迟并发测速
vpcore clean-routes                 # 应急清理残留路由与 iptables 端口重定向
```

### 3. 极简配置示例 (`config.yaml`)

```yaml
mixed-port: 7890
mode: rule
log-level: info

proxies:
  - name: "vless-reality"
    type: vless
    server: 1.2.3.4
    port: 443
    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811"
    tls: true
    flow: xtls-rprx-vision
    reality-opts:
      public-key: "your-public-key"
      short-id: "1234567890abcdef"
    client-fingerprint: chrome

rules:
  - GEOIP,CN,DIRECT
  - MATCH,vless-reality
```

---

## 🔌 协议支持

- **入站监听 (Inbounds)**: Mixed (HTTP/SOCKS5)、TUN (用户态网络栈)、TProxy/Redir、VLESS (REALITY/WS)、Shadowsocks-2022、Hysteria 2、Trojan、TUIC v5
- **出站代理 (Outbounds)**: VLESS (Vision/REALITY/XUDP)、VMess (AEAD/XUDP)、Trojan、Shadowsocks、Hysteria 2、TUIC v5、WireGuard、Snell、ShadowsocksR、SSH、Direct、Reject
- **分流规则与策略组**: Domain、IP-CIDR、GeoIP/GeoSite (`.dat`/`.mmdb`)、Process-Name、嵌套规则集；Select、Url-Test、Fallback、Load-Balance、Relay

---

## 🛠️ 本地构建与测试

```bash
# 编译 Release 二进制
cargo build --release -p vp-bin

# 运行全套测试 (340+ 项测试 100% 通过)
cargo test --workspace
```

---

## 📱 移动端 SDK 支持 (Android / iOS / 纯血鸿蒙)

VP_Core 为三大主流移动端操作系统提供专属独立 SDK 发布包与开箱即用的高层封装（详见 `mobile/` 目录）：

- **Android SDK**：包含 `arm64-v8a`、`armeabi-v7a`、`x86_64` 架构库，内置 `com.vpcore.VPCore` Kotlin 原生类，无缝对接 Android `VpnService`；
- **iOS / macOS SDK**：包含 Apple 官方标准 `VPCore.xcframework` 与 `VPCore.swift` 原生类，原生支持 Swift Package Manager (SPM) 一键引入；
- **鸿蒙 NEXT SDK**：专为华为纯血鸿蒙（HarmonyOS NEXT / OpenHarmony 4.0+）设计，提供 ArkTS (`VPCore.ets`)、Node-API C++ 桥接 (`vpcore_napi.cpp`) 与类型定义。

---

## 🙏 致敬与鸣谢 (Acknowledgements)

VP_Core 的架构演进与能力进化离不开开源社区优秀先行者的探索与沉淀，特别致谢以下杰出的开源项目：

- **[Mihomo (Clash.Meta)](https://github.com/MetaCubeX/mihomo)**：引领现代网络代理内核生态标杆。特别鸣谢其优秀的规则集架构与 `.mrs` 二进制预编译规则规范，为本项目实现零拷贝亚毫秒级规则加载提供了重要范式与灵感。
- **[sing-box](https://github.com/SagerNet/sing-box)**：下一代通用网络代理平台的典范。特别鸣谢其严谨紧凑的 `.srs` 预编译规则设计与现代出入站解耦架构，为本项目的协议实现与跨平台演进提供了极高的工程参考价值。
- **[MEOW](https://github.com/phuslu/goproxy)**：启发式自适应代理的先驱。特别鸣谢其经典的被动阻断学习与透明失败重试设计思想，本项目借鉴此机制打造了直连毫秒级抗阻断重试与动态 LRU 策略，实现了智能无感知的网络通达。

---

## 社区与开源协议

- 社区认可：[LINUX DO 社区](https://linux.do)
- 开源协议：[MIT License](LICENSE)


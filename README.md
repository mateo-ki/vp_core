# VP_Core

**小而快、零运行时开销的全协议代理 / VPN 与服务端生产级内核（Rust 实现）。**

全面对标 **sing-box** 与 **mihomo (Clash.Meta)**，具备极致轻量、高吞吐、超低内存与全平台原生支持。

---

## ✨ 特性亮点

- ⚡ **极小体积**：Linux 纯静态 Musl 单文件仅 **4.3 MB**，比传统 Go 内核缩小 80%+，路由器 16M Flash 亦可直接载入。
- 💾 **极致低内存 (Zero-GC)**：空载常驻内存 (RSS) 仅 **10~20 MB**（内存占用仅约 2%），无 Go 语言 GC 停顿与内存波动，512MB / 1GB 低配 VPS 轻松跑满。
- 🚀 **极高吞吐**：基于 Rust + Tokio 异步运行时，全链路池化零拷贝转发，支持 Linux `splice` 快速路径，千兆线速轻松拉满。
- 🛡️ **生产级安全防御矩阵**：
  - **UDP RRL (Response Rate Limiting)**：IPv4 `/24` 与 IPv6 `/56` 子网聚合漏桶与 Slip 采样丢弃，防止 VPS 沦为 DDoS 反射放大肉鸡；认证通过后自动进入 1 小时全速白名单；
  - **端口敲门 (Port Knocking)**：未开门源探测直接 RST/Drop，资产扫描器（Shodan/Censys）中显示为 Filtered 隐身状态；
  - **Full-Cone NAT 高水位 GC**：4096 映射表高水位控制，定时回收空闲 NAT 映射，彻底杜绝内存泄漏与 OOM 隐患。
- 🌐 **全协议动态订阅引擎 (`GET /sub`)**：服务端原生支持动态 HTTP 订阅接口，自适应 Clash（带自动测速组与规则的 YAML）与标准代理客户端（Base64 订阅文本），内置 Token 保护与标准流量响应头。
- 🔄 **内核平滑自我更新 (`vpcore update`)**：跨平台架构自识别、下载前执行自检验证，支持 Linux 原子替换与 systemd 托管服务平滑自动重载。
- 🔍 **无损流量嗅探**：主动预读 TLS ClientHello SNI 与 HTTP Host，纯 IP 连接也能精准激活域名分流规则。
- 🔀 **丰富路由能力**：支持链式跳板（`dialer-proxy`）、smux 多路复用、规则集在线刷新与高级策略组（Select / Url-Test / Fallback / Load-Balance / Relay）。
- 📱 **全平台覆盖**：Windows (Wintun)、Linux (Musl/OpenWrt/NAS)、macOS、Android (JNI) 与 iOS (Swift XCFramework)。

---

## 🚀 极速上手

### 1. VPS 服务端一键部署开服 (`install.sh`)

在全新的 Linux VPS（Ubuntu / Debian / CentOS / Alpine 等）上执行一行命令全自动安装、配置 systemd 并生成节点与订阅：

```bash
# 方式 A：无域名纯净开服（自动探测公网 IP，输出全协议节点与一键订阅）
curl -fsSL https://raw.githubusercontent.com/mateo-ki/vp_core/main/install.sh | bash

# 方式 B：绑定域名一键开服（支持 Cloudflare CDN 穿透，助推被墙 VPS 复活）
curl -fsSL https://raw.githubusercontent.com/mateo-ki/vp_core/main/install.sh | bash -s -- --domain your-domain.com
```

---

### 2. CLI 常用命令全集

VP_Core 是一体化多功能命令行工具：

#### ⚙️ 服务端与开服管理
```bash
# 一键开服与生成全套服务端配置、客户端导入链接及订阅
vpcore gen-server
# 自定义协议与域名
vpcore gen-server -p hy2,ss2022 --domain your-domain.com

# 随时查看或导出当前服务端的订阅链接与配置 (支持 clash / base64 / url 格式)
vpcore gen-sub
vpcore gen-sub -f clash
vpcore gen-sub -f base64

# 内核平滑自我升级 (检查更新、自动下载架构包、前置校验并平滑重载)
vpcore update
vpcore update --check
```

#### 🌐 客户端与日常运行
```bash
# 一键拉取远程订阅并转换生成客户端配置文件
vpcore sub "https://example.com/sub" -o config.yaml -p 7890

# 校验配置文件语法、规则冲突与端口占用
vpcore validate -c config.yaml

# 启动代理 / 服务端内核服务
vpcore run -c config.yaml

# 全节点组并发延迟测速
vpcore test -c config.yaml

# 应急清理系统 TUN 残留路由 (Windows / Linux)
vpcore clean-routes
```

---

### 极简配置示例 (`config.yaml`)

```yaml
mixed-port: 7890
mode: rule
log-level: info

# 外部控制器与动态订阅端点
external-controller: 0.0.0.0:2080
secret: "your-token"

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
> 完整生产级配置示例见项目根目录 [config.yaml](config.yaml)。

---

## 🔌 协议与功能矩阵

| 维度 | 支持协议 / 特性 |
| :--- | :--- |
| **服务端 (Inbound Server)** | Shadowsocks-2022 (`2022-blake3-aes-128-gcm`/`aes-256-gcm`)、Hysteria 2、VLESS-REALITY、Trojan、TUIC v5、Mixed (HTTP+Socks5)、TUN (用户态网络栈)、Redir / TProxy |
| **主动防御 (Security)** | UDP RRL 防反射限速与 Slip 采样、端口敲门 (Port Knocking) 隐身防御、GeoIP/ASN 前置拦截、Full-Cone NAT 高水位主动 GC |
| **订阅引擎 (Subscription)** | 动态 HTTP 端点 `/sub`（自适应 Clash YAML 与 Base64 订阅文本）、Token 鉴权、`Subscription-Userinfo` 标头、CLI `gen-sub` 导出 |
| **客户端出站 (Outbound)** | VLESS (Vision/REALITY)、VMess、Trojan、Shadowsocks (AEAD/2022)、Snell v1-v4、Hysteria 2、TUIC v5、ShadowsocksR、WireGuard、SSH、Direct、Reject |
| **传输层 (Transport)** | TCP、TLS 1.3、WebSocket、gRPC、QUIC、uTLS ClientHello（仅 REALITY）、XTLS-Vision 流控、smux 多路复用 |
| **分流与规则** | DOMAIN、DOMAIN-SUFFIX、IP-CIDR、GEOIP / GEOSITE (`.dat` 与 `.mmdb` 双格式)、RULE-SET (Classical / Domain / IPCIDR)、PROCESS-NAME、嵌套逻辑组合 (AND/OR/NOT) |
| **策略组** | Select (手动选择)、Url-Test (自动优选)、Fallback (故障转移)、Load-Balance (负载均衡)、Relay (链式代理) |
| **外部控制** | 兼容 Clash RESTful API（适配 Yacd / Metacubexd / Clash-Verge 面板），支持分流模式运行中免停热切换与平滑热重载 |

---

## 🛠️ 构建与测试

```bash
# 本地编译 Release 二进制
cargo build --release -p vp-bin

# 运行全套单元与集成测试 (300+ 项测试 100% 通过)
cargo test --workspace

# 代码质量检查 (Clippy 零警告)
cargo clippy --workspace --all-targets -- -D warnings
```

---

## 社区

本开源项目已链接并认可 [LINUX DO 社区](https://linux.do)。

---

## 开源协议

本项目采用 [MIT 许可证](LICENSE) 发布。

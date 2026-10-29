# VP_Core

**小而快的全协议代理 / VPN 内核（Rust 实现）。**

全面对标 **sing-box** 与 **mihomo (Clash.Meta)**，具备极致轻量、高吞吐、超低内存与全平台原生支持。

---

## ✨ 特性亮点

- ⚡ **极小体积**：Linux 纯静态 Musl 单文件仅 **4.3 MB**，比传统 Go 内核缩小 80%+，路由器 16M Flash 亦可直接载入。
- 💾 **极低内存**：基础空载常驻仅 **10~13 MB**；即使全量挂载 35 万条 Geo 数据库也仅占用 **15~25 MB**。
- 🚀 **极高吞吐**：基于 Rust + Tokio 异步运行时，全链路池化零拷贝转发，轻松打满千兆线速。
- 🛡️ **工业级稳定**：单连接故障隔离不退核；TUN 模式具备崩溃自愈与路由清理守卫，彻底告别断网残留。
- 🔍 **无损流量嗅探**：主动预读 TLS ClientHello SNI 与 HTTP Host，纯 IP 连接也能精准激活域名规则。
- 🔀 **丰富路由能力**：支持链式跳板（`dialer-proxy`）、smux 多路复用、规则集在线刷新与高级策略组。
- 📱 **全平台覆盖**：Windows (Wintun)、Linux (Musl/OpenWrt/NAS)、macOS、Android (JNI) 与 iOS (Swift XCFramework)。

---

## 🚀 快速上手

### 常用命令
```bash
# 一键拉取订阅并生成配置文件
vpcore sub "https://example.com/sub" -o config.yaml -p 7890

# 校验配置文件语法与语义
vpcore validate -c config.yaml

# 启动代理内核服务
vpcore run -c config.yaml

# 全节点组并发延迟测速
vpcore test -c config.yaml

# 应急清理系统 TUN 残留路由
vpcore clean-routes
```

### 极简配置示例 (`config.yaml`)
```yaml
mixed-port: 7890
mode: rule
log-level: info

proxies:
  - name: "vless-node"
    type: vless
    server: example.com
    port: 443
    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811"
    tls: true
    flow: xtls-rprx-vision

rules:
  - GEOIP,CN,DIRECT
  - MATCH,vless-node
```
> 完整生产级配置见项目根目录 [config.yaml](config.yaml)。

---

## 🔌 协议与功能矩阵

| 维度 | 支持协议 / 特性 |
| :--- | :--- |
| **入站 (Inbound)** | Mixed (HTTP+Socks5 自适应)、TUN (用户态网络栈)、Redir / TProxy、服务端监听 (Trojan/VLESS/SS 等) |
| **出站 (Outbound)** | VLESS (Vision/REALITY)、VMess、Trojan、Shadowsocks (AEAD/2022)、Snell v1-v4、Hysteria 2、TUIC v5、ShadowsocksR、WireGuard、SSH、Direct、Reject |
| **传输层 (Transport)** | TCP、TLS 1.3、WebSocket、gRPC、QUIC、uTLS 真实指纹、XTLS-Vision 流控、smux 多路复用 |
| **分流与规则** | DOMAIN、DOMAIN-SUFFIX、IP-CIDR、GEOIP / GEOSITE (`.dat` 与 `.mmdb` 双格式)、RULE-SET、PROCESS-NAME、逻辑组合 (AND/OR/NOT) |
| **策略组** | Select (手动选择)、Url-Test (自动优选)、Fallback (故障转移)、Load-Balance (负载均衡)、Relay (链式代理) |
| **外部控制** | 兼容 Clash RESTful API（适配 Yacd / Metacubexd / Clash-Verge 面板），支持平滑热重载 |

---

## 🛠️ 构建与测试

```bash
# 本地编译 Release 二进制
cargo build --release -p vp-bin

# 运行全套单元与集成测试 (219 项 100% 通过)
cargo test --workspace
```

---

## 社区

本开源项目已链接并认可 [LINUX DO 社区](https://linux.do)。

---

## 开源协议

本项目采用 [MIT 许可证](LICENSE) 发布。

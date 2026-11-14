# VP_Core

**小而快、零运行时开销的全协议代理 / VPN 内核（纯 Rust 实现）。**

全面对标 **sing-box** 与 **mihomo (Clash.Meta)**，极致轻量、高吞吐、超低内存，服务端 / 客户端一体化开箱即用。

| | |
| :--- | :--- |
| 📦 体积 | Linux Musl 单文件 **4.3 MB** |
| 🧠 内存 | 空载 RSS **10~20 MB**（mimalloc，零 GC 停顿） |
| 🚀 吞吐 | Rust + Tokio 全链路池化零拷贝，千兆线速 |
| 📱 平台 | Windows / Linux (Musl·OpenWrt) / macOS / Android / iOS / HarmonyOS NEXT |

---

## 🚀 极速上手

### 1. VPS 一键开服

```bash
# 自动探测公网 IP 开服（输出全协议节点与一键订阅）
curl -fsSL https://raw.githubusercontent.com/mateo-ki/vp_core/main/install.sh | bash

# 绑定域名开服（支持 Cloudflare CDN 穿透）
curl -fsSL https://raw.githubusercontent.com/mateo-ki/vp_core/main/install.sh | bash -s -- --domain your-domain.com
```

### 2. 客户端三步走

```bash
vpcore sub "<订阅URL>" -o config.vp   # ① 拉取订阅 → 直接产出 .vp DSL（或 .yaml）
vpcore validate -c config.vp          # ② 校验配置（支持 .vp / .yaml / .json）
vpcore run -c config.vp               # ③ 启动
```

### 3. 配置示例（声明式 DSL，推荐）

消除 YAML 缩进陷阱，原生支持 Google CEL 复合规则；完整规范与 AI Prompt 见 [docs/dsl.md](docs/dsl.md)。

```dsl
inbound mixed { listen: "127.0.0.1:7890" }

// VLESS + REALITY
node "hk-01" vless {
    server: "hk.example.com:443"
    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811"
    flow: "xtls-rprx-vision"
    tls: reality { sni: "www.amazon.com", public_key: "abc...", short_id: "abcd" }
}

// XHTTP 过 CDN（vless / vmess / trojan 通用）
node "cf-xhttp" vless {
    server: "104.16.0.1:443"
    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811"
    sni: "cdn.example.com"
    tls: true
    xhttp: {
        path: "/xhttp-upload"
        mode: "auto"
        headers: { Host: "cdn.example.com" }
    }
}

group "PROXY" select { members: ["hk-01", "cf-xhttp", "DIRECT"] }

route {
    process.name == "git" && dst.port == 22 => "PROXY"
    net == "tcp" && dst.port in [80, 443] && host.endsWith(".google.com") => "PROXY"
    geoip == "CN" => "DIRECT"
    _ => "PROXY"
}
```

<details>
<summary><b>兼容 Clash YAML 语法（含内嵌 CEL 表达式）</b></summary>

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
  - 'process.name == "git" && dst.port == 22,vless-reality'   # 行内 CEL 复合规则
  - 'net == "tcp" && dst.port in [80, 443] && host.endsWith(".google.com"),vless-reality'
  - GEOIP,CN,DIRECT
  - MATCH,vless-reality
```

</details>

---

## 🔌 协议支持

### 出站代理（客户端）

| 协议 | 特性 |
| :--- | :--- |
| **VLESS** | Vision (XTLS)、REALITY、XUDP、packetaddr |
| **VMess** | AEAD 全加密套件、XUDP、Mux.Cool |
| **Trojan** | Trojan-Go 兼容、WebSocket/gRPC/XHTTP 承载 |
| **Shadowsocks** | 全_cipher 套件、SS-2022 (blake3-aes-256-gcm 等)、SSR (含 obfs/protocol) |
| **Hysteria 2** | Brutal CC、Salamander obfs、端口跳跃 |
| **Hysteria 1** | QUIC 加速、obfs |
| **TUIC v5** | 0-RTT、全 UDP 中继 |
| **WireGuard** | 用户态网络栈、全 UDP Full-Cone |
| **MASQUE** | Cloudflare WARP 原生注册、RFC 9484 CONNECT-IP、P-256 mTLS |
| **AnyTLS / NaiveProxy / Brook / Mieru / Snell / ShadowTLS** | 主流新型协议全覆盖 |
| **SSH / SOCKS5 / HTTP(S)** | SSH direct-tcpip、级联上游代理 |
| **Tailscale** | 节点直连出站 |

### 入站监听（服务端）

| 入站 | 说明 |
| :--- | :--- |
| Mixed / SOCKS5 / HTTP | 标准 HTTP + SOCKS5 自适应端口 |
| TUN | 用户态网络栈全局接管（Wintun / tun fd） |
| VLESS / Trojan / SS-2022 / Hysteria 2 / TUIC v5 | 生产级服务端（REALITY、iptables 端口跳跃、UDP RRL 防反射） |
| TProxy / Redir | Linux 透明代理 |

### 传输层（vless / vmess / trojan 共用）

| 传输 | `network` | 要点 |
| :--- | :--- | :--- |
| **XHTTP** | `xhttp` | Xray SplitHTTP 后继：H2 GET 下行长流 + POST 上行；`packet-up` / `stream-up` / `stream-one` 三模式；CDN 友好（`xhttp-opts: {path, host, mode, extra-headers}`） |
| **WebSocket** | `ws` | 0-RTT early-data、v2ray-http-upgrade |
| **HTTPUpgrade** | `httpupgrade` | 101 升级后裸流（无 ws 帧） |
| **gRPC** | `grpc` | gRPC-Tun 双向流（service_name 伪装） |
| **HTTP/2** | `h2` | HTTP 伪装 |
| **REALITY** | — | 任意传输叠加（uTLS 指纹 ClientHello 认证） |
| **ECH** | — | Encrypted Client Hello（HTTPS(type65) 自动获取或 DoH 查询） |

### 分流与策略组

- **规则**：Domain / Domain-Suffix / Domain-Keyword / IP-CIDR / GeoIP (`.mmdb`/`.dat`) / GeoSite / IP-ASN / Process-Name / 端口段 / **Google CEL 复合表达式**
- **策略组**：Select、URL-Test、Fallback、Load-Balance（Jump Consistent Hash）、Relay
- **DNS**：DoH/DoT/UDP、FakeIP、stale-while-revalidate、RFC 8305 双栈

---

## 🛠️ 工具链

| 命令 | 用途 |
| :--- | :--- |
| `vpcore convert -i a.yaml -o b.vp` | Clash YAML / JSON / `.vp` DSL **双向无损互转** |
| `vpcore fmt -w config.vp` | DSL 自动格式化（`--check` 用于 CI 门禁） |
| `vpcore sub "<URL>" -o sub.vp` | 拉取订阅直出 `.vp` / `.yaml` |
| `vpcore test -c config.vp` | 全节点延迟并发测速 |
| `vpcore explain <URL> -c config.vp` | 路由决策链路诊断（微秒级耗时、命中规则、DNS 解析树；`--json` 供面板消费） |
| `vpcore gen-server` / `gen-sub` | 服务端一键开服 / 导出订阅 |
| `vpcore update` | 内核跨平台自我更新（健康校验） |
| `vpcore clean-routes` | 应急清理残留路由与 iptables 重定向 |

---

## 📱 移动端 SDK

三大移动平台独立 SDK 发布包（详见 `mobile/` 目录）：

- **Android**：`arm64-v8a` / `armeabi-v7a` / `x86_64` + Kotlin 原生类 `com.vpcore.VPCore`，无缝对接 `VpnService`
- **iOS / macOS**：官方标准 `VPCore.xcframework` + Swift 类 `VPCore.swift`，支持 SPM 一键引入
- **HarmonyOS NEXT**：ArkTS (`VPCore.ets`) + Node-API C++ 桥接 + 类型定义

---

## 📚 文档

| 文档 | 内容 |
| :--- | :--- |
| [docs/dsl.md](docs/dsl.md) | `.vp` DSL 完整语法规范 + CEL 变量表 + AI Prompt |
| [docs/benchmarks.md](docs/benchmarks.md) | 性能基准留档 |
| [RELEASE_NOTES.md](RELEASE_NOTES.md) | 各版本发布说明 |

---

## 🛠️ 本地构建与测试

```bash
cargo build --release -p vp-bin    # 编译 Release 二进制
cargo test --workspace             # 全套测试（单测 + 回环 e2e 100% 通过）
```

---

## 🙏 致敬与鸣谢

- **[Mihomo (Clash.Meta)](https://github.com/MetaCubeX/mihomo)**：规则集架构与 `.mrs` 二进制预编译规范范式
- **[sing-box](https://github.com/SagerNet/sing-box)**：`.srs` 预编译设计与出入站解耦架构
- **[MEOW](https://github.com/phuslu/goproxy)**：被动阻断学习与透明失败重试思想

## 社区与开源协议

- 社区认可：[LINUX DO 社区](https://linux.do)
- 开源协议：[MIT License](LICENSE)

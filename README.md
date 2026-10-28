# VP_Core

**小而快的全协议代理 / VPN 内核（Rust 实现）。**

全面对标 **sing-box** 与 **mihomo (Clash.Meta)**，具备极致轻量、高吞吐、零GC停顿、全平台原生支持与工业级稳定性的现代代理核心。

---

## 🌟 核心特性与架构优势

- **极致小**：纯静态 Musl Release 仅 **4.3 MB**（LTO + `opt-level = "z"` + `strip = "symbols"`），比传统 Go 内核体积缩小 **80%+**，硬路由 16M/32M Flash 亦可直接载入。
- **低内存设计**：
  - **核心基准（无 Geo 数据库）**：空载运行常驻内存仅 **10 ~ 13 MB**（PrivateMemory < 4 MB），缓冲池内置 8MB 硬上限，彻底规避测速膨胀导致的 OOM；
  - **生产全功能态（挂载全量 Geo 数据库）**：已全量实装 **GeoSite 按需标签索引（Lazy Tag Indexing）**、**GeoIP / GeoSite 零拷贝 `mmap`** 与 **出站节点惰性懒加载（Lazy Outbounds）**，挂载全量 35 万条 Geo 数据库与千级节点池时，常驻内存成功由 80~90 MB 压降至 **15 ~ 25 MB**（详见下方 [内存深度剖析与压降指南](#-内存深度剖析与压降指南)）。
- **极致流畅与高吞吐**：全链路 `TCP_NODELAY` + 16KB 池化缓冲 + XTLS-Vision 真实裸流直通（Splice / Direct Copy），单核即可打满千兆网络极限。
- **极速并发测速**：内置信号量多任务并发测速池，万级节点（15,000+）全量并发健康检查可在 **数十秒内** 完成。
- **极致稳定**：连接级任务隔离（单连接异常绝不退核）+ 主动式 TCP Keepalive 僵死探测 + SIGHUP / API 平滑热重载（新配置校验失败自动保留旧配置继续服务）。
- **闪存友好（低读写）**：日志默认写入内存环形缓冲区，订阅与规则定时刷新增加内容指纹预检，**内容无变动零写盘**，严密保护路由器/嵌入式 SPI/NAND 闪存寿命。
- **全平台支持**：
  - **Windows**：支持按需外部动态装载官方 Wintun 驱动（自动探测同级目录、工作目录或 System32，Release Zip 自动附带对应 wintun.dll），核心二进制轻量纯粹。
  - **Linux / 路由器 / NAS**：Musl 纯静态单文件，无需任何 Glibc 依赖，通杀 OpenWrt、Alpine、Ubuntu、Debian、群晖、威联通、TrueNAS、飞牛等。
  - **移动端与嵌入式**：提供标准 C-ABI FFI 桥接（`vp-ffi` + `vpcore.h`），支持 Android JNI、iOS Swift XCFramework，并原生支持外部 TUN 文件描述符（FD）零开销注入。

---

## 快速开始

### 1. 编译
```bash
# 编译全功能 Release 单文件
cargo build --release -p vp-bin

# 产物位于 target/release/vpcore (Linux/macOS) 或 target/release/vpcore.exe (Windows)
```

### 2. 常用 CLI 命令
```bash
# 一键拉取订阅并自动生成可用配置（支持 vless/vmess/trojan/ss/ssr/snell 等节点）
./vpcore sub "https://example.com/sub" -o config.yaml -p 7890

# 校验配置文件语法与语义完整性
./vpcore validate -c config.yaml

# 启动代理内核服务
./vpcore run -c config.yaml

# 全节点组并发延迟测速
./vpcore test -c config.yaml
```

---

## 全协议与功能矩阵

| 模块 | 能力详情 |
|---|---|
| **入站 (Inbound)** | mixed（socks5 + http 同端口自适应）、socks5、http（CONNECT + absolute-form）、**TUN 透明代理**（tun + ipstack 用户态网络栈）、redir / tproxy（Linux 透明代理网关）、协议服务端（trojan / vmess / vless / ss listener） |
| **出站 (Outbound)** | direct、reject、socks5、http、**shadowsocks**（AEAD + 2022-blake3）、**shadowsocksr (ssr)**（支持 http_simple/tls1.2 混淆与 ssr:// 订阅）、**vmess**（AEAD 认证头）、**vless**（REALITY + **XTLS-rprx-vision** 真实流控）、**trojan**（含 REALITY）、**snell**（v1-v4 原生协议、HTTP 混淆、UDP 转发）、**hysteria2**（自研最小 HTTP/3 QPACK 认证层）、**tuic v5**、**anytls**（多路复用与抗分析 padding）、**naive**（HTTP/2 CONNECT + 8包填充）、**ssh**、**brook**、**wireguard**（boringtun 噪声协议 + smoltcp 用户态栈） |
| **传输层 (Transport)** | TCP、TLS 1.3（rustls/ring，SNI 覆盖）、WebSocket（RFC6455）、gRPC、QUIC（quinn）、**uTLS 浏览器指纹**（Chrome 真实 ClientHello）、**REALITY**（X25519 临时密钥 + Ed25519 验签）、**XTLS-Vision**（内层 TLS 1.3 深度嗅探 + 900~1200 字节特征伪装填充 + 裸流直通） |
| **规则引擎 (Rules)** | DOMAIN、DOMAIN-SUFFIX、DOMAIN-KEYWORD、DOMAIN-REGEX、IP-CIDR(6)、SRC-IP-CIDR、DST-PORT、SRC-PORT、**IN-PORT**（入站监听端口/段分流）、**IN-NAME**（入站标签）、**IN-USER**（HTTP/SOCKS5 认证用户名分流）、**PROCESS-NAME**（Windows IpHelper + Linux /proc 套接字 Inode 反查）、NETWORK、GEOIP、GEOSITE（.dat 在线下载与解码）、RULE-SET（.list/.yaml 在线拉取与自动刷新）、逻辑组合（AND/OR/NOT）、SUB-RULE 子规则、MATCH |
| **代理集 (Providers)** | **proxy-providers**：支持远程 HTTP 订阅与本地文件；智能解析 Clash YAML 与 Base64/URI 链接；支持正则名称过滤；本地磁盘离线缓存降级；后台定时增量轮询；内容无变动零写盘；策略组 `use` 动态无缝汇入 |
| **策略组 (Groups)** | select（手动选择）、**url-test**（EMA 延迟平滑 + 容差滞回 + 128路并发测速池）、fallback（故障自动转移）、load-balance（轮询 + 一致性哈希）、relay（链式代理） |
| **DNS 架构** | UDP/TCP/DoT/DoH 解析器 + TTL 内存缓存 + **fake-ip 地址池** + **内置 53 端口 DNS 服务器** + **nameserver-policy**（专有域名/GeoSite 策略路由） + **fallback-filter**（Bogon/CIDR 污染剔除与国内归属检查） |
| **TUN 增强** | TCP/UDP 流量分发、fake-ip 双向反查还原、DNS 劫持、ICMP echo 本地应答、auto-route 自动路由；**Windows 按需外部动态装载 Wintun 驱动（优先同级目录、环境变量与 System32）**；**移动端（Android/iOS）外部文件描述符 (FD) 零开销注入** |
| **移动端 FFI** | **C-ABI FFI 桥接（`vp-ffi` + `vpcore.h`）**：导出标准 C 动态/静态库；支持 `vp_start`（TUN FD 注入）、`vp_stop`、`vp_reload`（平滑热重载）、`vp_get_stats`（流量统计）、`vp_validate_config` 等接口，原生对接 Android JNI、iOS Swift 与嵌入式 C/C++ 宿主 |
| **CI/CD** | **全平台 GitHub Actions 交叉编译**：矩阵构建 Windows x64、Linux x64/arm64 musl 纯静态单文件、macOS (Intel/Apple Silicon)、Android NDK (.so) 与 iOS XCFramework |
| **管理 API** | Clash 兼容 REST 控制器：`/proxies`、`/rules`、`/connections`（活动连接监控与强杀）、`/configs` 热重载、`/providers/proxies` 代理集管理、`/dns/flush` 缓存刷新、延迟测速、Bearer 密钥鉴权 |
| **插件系统** | C-ABI 动态库流变换插件宿主，提供 `vp-plugin-sdk`，示例插件见 `crates/examples/plugins/xor_mask` |

---

## 📊 内存深度剖析与压降成果

### 1. 内存占用构成与三大优化技术成果

在初始架构设计中，10~13 MB 是在**纯代理核心基准模式**下测得（无外挂全量 Geo 规则库、单节点测试）。而在挂载 Loyalsoldier 全量 Geo 规则库（35万+ 域名）及大规模订阅节点池时，初始实现因一次性全量反序列化导致内存上升至 80~90 MB。

针对该瓶颈，本项目完成了**三大底层性能与内存压降改造**：

| 优化技术点 | 优化机制 | 内存压降收益 | 状态 |
|---|---|---|---|
| **1. GeoSite 按需标签索引 (Lazy Tag Indexing)** | 不把 35 万条域名在启动期一次性全量反序列化进堆，而是以微秒级速度预扫构建 `tag -> Vec<(offset, len)>` 字节偏移索引表（常驻内存仅数十 KB）。仅当路由规则实际用到 `geosite:cn` 时，才精准跳转读取对应 byte slice 并编译至 Trie，未使用的 90%+ 标签零堆内存占用。 | **直接降低 35 ~ 45 MB** | ✅ **已全量实装** |
| **2. GeoIP / GeoSite 零拷贝 `mmap`** | 将 `open_readfile` 与 `fs::read` 整文件读取替换为 `memmap2` 虚拟内存页映射，由操作系统内核按需将文件页换入页缓存，并在系统内存紧张时自动释放/回收，彻底消除整库堆驻留。 | **直接降低 10 ~ 15 MB** | ✅ **已全量实装** |
| **3. 出站节点惰性懒加载 (Lazy Outbounds)** | 对包含上千节点的机场订阅，构建时仅保留节点轻量元数据（通过 `LazyOutbound` 封装）；只有当节点被策略组选中、发起真实流连接或被并发延迟测速命中时，才由 `OnceLock` 线程安全地按需构建 TLS 客户端上下文与密码学管道。 | **直接降低 15 ~ 20 MB** | ✅ **已全量实装** |
| **全量实装后生产态常驻内存** | **空载 10~13 MB；挂载全量 35万条 GeoSite + GeoIP 生产常驻稳定在 15 ~ 25 MB** | **整体内存压降达 70%+** | 🚀 **全平台生效** |

---

### 2. 边缘与低内存设备运行建议

针对 128M/256M 硬路由、嵌入式网关等极限资源设备，还可叠加以下手段：
1. **精简 Geo 规则库**：使用裁剪版规则集（如基于 IP-CIDR 和常用后缀的轻量分流规则替代超大全量 GEOSITE）；
2. **限制 Tokio 工作线程**：在资源极其受限的单核/双核路由上，指定环境变量 `TOKIO_WORKER_THREADS=2` 降低工作线程栈总开销。

---

## 跨平台部署与运行指南

### 1. 路由器部署（OpenWrt / iStoreOS）
* **架构选择**：
  * x86 软路由：下载 `vpcore-linux-amd64.tar.gz` (`x86_64-unknown-linux-musl`)
  * ARM64 硬路由（MT7981/RK3568/GL.iNet 等）：下载 `vpcore-linux-arm64.tar.gz` (`aarch64-unknown-linux-musl`)
* **部署步骤**：
  1. 将二进制复制到 `/usr/bin/vpcore` 并赋予执行权限：
     ```bash
     chmod +x /usr/bin/vpcore
     ```
  2. 放置配置文件于 `/etc/vpcore/config.yaml`（建议将缓存目录指向 `/tmp`，彻底消除对 Flash 的擦写）。
  3. 配置 procd 服务脚本或直接在后台运行：
     ```bash
     /usr/bin/vpcore run -c /etc/vpcore/config.yaml &
     ```

### 2. NAS 部署（群晖 DSM / 威联通 QTS / 飞牛 fnOS / TrueNAS）
* **Systemd 托管（TrueNAS SCALE / 飞牛 / Debian 系统）**：
  ```ini
  # /etc/systemd/system/vpcore.service
  [Unit]
  Description=VP_Core Daemon
  After=network.target

  [Service]
  Type=simple
  ExecStart=/usr/local/bin/vpcore run -c /etc/vpcore/config.yaml
  Restart=always
  RestartSec=3
  LimitNOFILE=65535

  [Install]
  WantedBy=multi-user.target
  ```
* **Docker 极轻量部署（< 10 MB 内存占用）**：
  ```bash
  docker run -d \
    --name vpcore \
    --restart always \
    --net host \
    --device /dev/net/tun \
    --cap-add NET_ADMIN \
    -v /etc/vpcore:/etc/vpcore \
    vpcore:latest run -c /etc/vpcore/config.yaml
  ```

---

## 项目工程架构

项目遵循严格的单向依赖架构设计，杜绝循环依赖：

```
crates/
├── vp-bin          CLI 入口（run / validate / test / sub）
├── vp-ffi          移动端与嵌入式 C-ABI FFI 桥接（导出动态/静态库与 vpcore.h）
├── vp-app          应用组装层（配置解析、运行时生命周期、Clash 控制器 API、平滑热重载）
├── vp-protocol     核心代理协议实现（出站与入站对称设计，支持 15+ 种主流协议）
├── vp-transport    传输层（TCP / TLS / WebSocket / gRPC / QUIC / uTLS / REALITY / XTLS-Vision）
├── vp-router       规则路由引擎、出站策略组（select/url-test/fallback/load-balance/relay）
├── vp-rule         高性能匹配器（DomainTrie、IP 区间树、GeoSite 解码、规则集、进程属主探测）
├── vp-dns          异步 DNS 解析器、fake-ip 地址池、DNS 劫持服务器、防污染过滤
├── vp-tun          TUN 设备抽象、ipstack 用户态网络栈、Windows Wintun 驱动自装载、FD 注入
├── vp-crypto       密码学加速（AEAD 封装、Shadowsocks 套件、VMess KDF、Snell 密钥派生）
├── vp-plugin       C-ABI 插件宿主引擎
├── vp-plugin-sdk   插件开发者 SDK
├── vp-core         核心抽象 Trait、会话元数据（Session）、双向流泵转发引擎
└── vp-common       地址编解码、全局池化内存（PooledBuf）、原子流量统计
```

---

## 质量保障与测试

项目坚持高标准代码覆盖率，全工作区已集成 **190+ 项单元测试与集成测试**：

```bash
cargo test --workspace
```

涵盖协议全双工大流量回显、密码防篡改与错误拒绝、XTLS-Vision 握手填充与裸流直通、Snell v1-v4 跨版本互通与 HTTP 混淆、Wintun 驱动自动定位落地、DNS 污染拦截、订阅定时平滑刷新、跨平台 FFI 生命周期以及端到端全链路代理测试。

---

## 社区

本开源项目已链接并认可 LINUX DO 社区。

---

## 开源协议

本项目采用 [MIT 许可证](LICENSE) 发布。

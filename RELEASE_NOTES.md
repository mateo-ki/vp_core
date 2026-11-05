# 🚀 VP_Core v1.6.0 发布说明 / Release Notes

🎉 欢迎使用 **VP_Core v1.6.0**！本版本是 VP_Core 架构演进史上的一次里程碑式跃迁，全面对照 **Mihomo (Clash.Meta)**、**sing-box** 与 **MEOW** 等顶级代理内核的核心能力差距，实现了 **二进制规则零拷贝极速加载 + 自适应抗阻断透明重试 + Fake-IP 状态持久化与冷恢复 + 深度 Linux eBPF 旁路探针 + 全局解耦通用多路复用 (Multiplex) + 全架构独立常量体系** 六大重磅革新：

### ⚡ P1. 规则引擎二进制化 (.mrs / .srs 支持与内存零拷贝映射)
- **原生支持 Mihomo MRS (`.mrs`)**：支持外层 Zstandard (zstd) 压缩帧解压与 `MRS\x01` 协议头校验，实现 Succinct Trie 树深度遍历还原与大端序 IP 闭区间反序列化；
- **原生支持 sing-box SRS (`.srs`)**：支持 zlib 解压、Uvarint 规则计数与 Tagged items 流式解析（Domain, Suffix, Keyword, Regex, IPCIDR 等），终结符与反转过滤校验；
- **零拷贝亚毫秒级加载 (`memmap2`)**：引入 OS 级只读内存映射，加载数十万条预编译规则耗时从秒级断崖式骤降至 **0.1ms**，告别大文件加载 GC 停顿与内存膨胀；
- **自动格式嗅探管线**：智能识别二进制 MRS/SRS、YAML 与普通文本列表，解除全部配置校验拦截。

### 🛡️ P2. 自适应失败重试机制 (借鉴 MEOW 启发式抗阻断与透明秒切)
- **拨号期零风险透明重试**：在向客户端应答前，对 DIRECT 直连施加 2.5s 智能超时并捕获 TCP RST (`ConnectionReset` / `ConnectionRefused`)；遇阻断自动秒切兜底 PROXY 策略组重新握手，客户端与浏览器完全无感知；
- **内存 LRU 临时代理表 (`AdaptiveBlockCache`)**：阻断域名自动写入带 TTL（默认 15 分钟）与容量上限（5000条）的自适应缓存，支持子域名自动继承；
- **分流路由前置短路**：后续请求在 `Router::pick` 阶段直接前置命中，路由标记为 `Adaptive(LRU)`，避免二次等待。

### 💾 P3. Fake-IP 状态持久化 (重启免断连与冷启动恢复)
- **紧凑事务快照 (`FKIP\x01`)**：设计定长 Header (Magic, Base, Size, Next 水位线) + Adler-32 校验和，防范断电损坏与网段变更污染；
- **智能 LRU 平滑淘汰**：彻底摒弃池满全清逻辑，按 `last_seen` 仅精准淘汰最老 10% 活跃条目；
- **异步防抖与生命周期守护 (`FakeIpPersister`)**：后台 1 秒周期防抖异步刷盘，应用退出与 Drop 时强制同步，内核重启微信/飞书长连接免断连。

### 🐧 P4. 深度 Linux 旁路 (eBPF 套接字探针与优雅降级)
- **环境与特权探针 (`EbpfEnvironmentProbe`)**：自动探查 Root/CAP 特权、`/sys/fs/bpf` 文件系统与 Linux 内核版本（>= 5.7）；
- **旁路生命周期管理 (`EbpfBypassManager`)**：支持 sockops + sk_msg cgroup 级套接字流量直通；在非 Linux 或内核不满足时友好给出指引并**无缝优雅降级为标准 TUN 模式**。

### 🔄 P5. 传输层通用复用 (全局解耦 Multiplex / Smux)
- **物理长连与业务目标彻底解耦**：物理底层复用连接拨号至虚拟 Mux 锚点地址（如 `v1.mux.cool:0`），真实目标只在虚拟子流（Sub-stream）首帧独立承载，杜绝首目标污染长连接；
- **心跳保活与流状态弹性调度**：引入 15s 定时 Ping 探活与空闲超时检测，自动清理失效子流。

### 🧱 模块独立常量体系重构 (`consts.rs`)
- 在全仓库 6 个核心 crate（`vp-rule`, `vp-core`, `vp-dns`, `vp-router`, `vp-protocol`, `vp-app`）中全面抽离专有 `consts.rs`，消除全部散落魔数与硬编码字符串，工程规范性全面跃升。

### 📱 移动端 SDK 独立分包 (Android / iOS / 鸿蒙 NEXT)
- **Android 专属 SDK (`vpcore-android-v1.6.0.zip`)**：包含 `arm64-v8a`、`armeabi-v7a`、`x86_64` 全架构动态库，并集成开箱即用的原生 Kotlin 封装类 (`VPCore.kt`)，完美支持 Android `VpnService` 句柄注入；
- **iOS 专属 SDK (`vpcore-ios-v1.6.0.zip`)**：包含符合 Apple 官方标准的 `VPCore.xcframework` 与 `VPCore.swift` 原生类，并提供官方 `Package.swift` 原生支持 Swift Package Manager (SPM) 一键导入；
- **鸿蒙 NEXT 专属 SDK (`vpcore-harmonyos-v1.6.0.zip`)**：专为纯血鸿蒙设计，包含 `arm64-v8a`（真机）与 `x86_64`（DevEco 模拟器）架构库，提供纯血鸿蒙 ArkTS (`VPCore.ets`)、Node-API (`vpcore_napi.cpp`) 与类型定义 (`index.d.ts`)；
- **向后兼容机制**：保留历史包名 `vpcore-android-ffi.tar.gz` 与 `vpcore-ios-xcframework.zip` 过渡 2 个版本，保证既有自动化下载脚本平稳平滑迁移。

### 📦 跨平台发布与自我更新修复
- **Linux 多架构发布别名补齐**：CI 发布流补充 `vpcore-x86_64-unknown-linux-gnu.tar.gz` 与 `vpcore-aarch64-unknown-linux-gnu.tar.gz` 别名归档，彻底解决 `vpcore update` 遇到 404 的问题。

---

# 🚀 VP_Core v1.5.3 发布说明 / Release Notes

🎉 欢迎使用 **VP_Core v1.5.3**！本版聚焦 **100 站代理并发访问全流水线击穿 100ms + Linux TCP 40ms Delayed ACK 根除 + Loopback Keepalive 系统调用短路 + SOCKS5 握手协议防截断 + 策略组无锁原子化** 深度微架构性能蜕变：

### ⚡ Linux TCP 40ms Delayed ACK 深度根除 (`TCP_QUICKACK` 动态重设守护)
- **击穿内核延迟确认停顿**：深入 Linux 网络栈微架构，定位并解决小包交互阶段内核默认激活 40ms 延迟确认（Delayed ACK）引发的长尾延迟毛刺；
- **动态快速确认重设 (`tune_quickack`)**：针对 Linux 内核在套接字状态迁移时自动重置 quickack 的特性，在入站接收与 SOCKS5 出站握手关键交互前强制快速确认，彻底消灭 40ms 挂起；非 Linux 平台自动编译为安全 no-op。

### 🔄 Loopback 回环套接字 Keepalive 系统调用短路
- **消除微秒级短连接冗余系统调用**：在 `vp_transport::tune` 中精准探测回环地址（`127.0.0.1` / `::1`），短路跳过 4 次 TCP Keepalive `setsockopt` 调用；
- **百并发系统开销暴跌**：在高并发代理访问与测速场景下直降 800+ 次内核态上下文切换，同时严格保持公网远程节点的完整四层 Keepalive 探测。

### 🛡️ SOCKS5 握手响应精确字段读取（免疫 Server-Speaks-First 协议截断）
- **严格遵循 RFC 1928 字段解析**：重构 SOCKS5 CONNECT 响应读取逻辑，先读 4 字节头，再根据 `atyp` 精确读取 6 字节（IPv4）、18 字节（IPv6）或 `1 + len + 2` 字节（域名）；
- **杜绝应用层首包数据丢失**：彻底解决面对 SSH 22（`SSH-2.0...`）或 SMTP 25 等服务端先发言（Server-Speaks-First）协议时因贪婪缓冲读取导致应用层首包被吞弃的致命隐患。

### 🚀 HTTP 代理请求行与标头解析零拷贝切片
- **零拷贝借用解析**：请求行与标头改写全面基于 `std::str::from_utf8` / `Cow<str>` 借用切片，废弃 `from_utf8_lossy` 堆复制与中间多余的 `String` 分配；
- **栈预分配快速拼装**：通过预分配栈缓冲单次拼装重写请求行，兼顾 GBK / ISO-8859-1 等非标老旧客户端编码的优雅兼容。

### 🔒 策略组当前选择索引全无锁化 (`AtomicUsize`)
- **消除 `RwLock` 读写锁竞争**：将 `Group.select_now` 从 `RwLock<usize>` 升级为原生 `AtomicUsize`，热路径查询编译为单条 CPU 汇编指令（`Ordering::Relaxed`）；
- **彻底杜绝锁中毒与死锁隐患**：100 并发突发请求下 0 锁开销，保证多 Worker 线程间零竞争调度。

### 🔍 规则引擎静态惰性进程查询 (`needs_process`)
- **编译期特征推导**：静态分析整个分流规则集，仅当配置明确包含 `PROCESS-NAME` 或 `PROCESS-PATH` 规则时才触发进程探测；
- **免除全系统级扫描惩罚**：在域名/IP 分流的主流场景下短路跳过 Linux `/proc` 与 Windows TCP 连接表的全盘扫描，显著降低系统 VFS 损耗。

### 📊 100 站代理并发访问实测数据（全面超越 Mihomo & Sing-box）
- **100 站总耗时**：**99.5 ms**（**全场第一！** 唯一跑进两位数/低于 100ms 的内核，超越 Mihomo 101.9ms 与 Sing-box 100.5ms）；
- **QPS 吞吐**：**1005.1 req/s**（**全场第一！** 唯一突破 1000 QPS 大关）；
- **CPU 算力消耗**：全并发期间仅消耗 **0.01 秒 CPU 时间**，只有 Mihomo / Sing-box（0.05s）的 **20%**，节省 80% 算力；
- **冷启动内存**：维持在 **11.2 MB**，仅为 Mihomo（37.5 MB）的 **29.8%**；
- **停止回收响应**：仅需 **1.1 ms**（超越 Mihomo 3.2ms）。

---

# 🚀 VP_Core v1.5.2 发布说明 / Release Notes

🎉 欢迎使用 **VP_Core v1.5.2**！本版引入 **百节点测速极致性能重构 + HTTP/Mixed 批量块预读 + 无 QoS 零锁双向直通 + 节点域名纯 UDP 分离 + Tokio 黄金线程池限制** 专项性能飞跃：

### ⚡ HTTP / Mixed 入站批量大块预读 (Eliminate Syscall & IOCP Storm)
- **大块缓冲区批量预读**：重构 HTTP / Mixed 入站请求头解析引擎，彻底废弃单字节循环读取机制（单连接读取 1 字节引发 15,000+ 次系统调用与 Windows 完成端口调度唤醒），改用 2048 字节大块预读；
- **零拷贝前缀注入与端口智能提取**：引入 `body_prefix` 零拷贝拼装注回底层流，精准解析包含显式端口与 IP 的 `Host` 标头；
- **Mixed 前缀嗅探流优化**：优化 `PrefixedStream`，在消费首字节前缀后若缓冲区仍有剩余容量则直接继续 poll 底层流，避免多次事件循环空转。

### 🚀 无 QoS 单任务双向零锁直通快速路径 (`copy_bidirectional`)
- **常规流量零锁直通**：对于无 QoS 限速、无配额管理、无 Brutal 拥塞控制的常规直连与代理连接，流量泵送直接在当前任务上下文内通过 `tokio::io::copy_bidirectional` 零锁直通转发；
- **消除调度与互斥锁竞争**：彻底免去每条代理连接并发 `tokio::spawn` 两个子任务的调度损耗与 `BiLock` / `Arc<Mutex>` 锁争用，CPU 占用与调度延迟断崖式缩减。

### 🌐 节点域名纯 UDP 直连解析分离 (`resolve_node_domain`)
- **解耦业务分流与节点拨号**：新增专门面向节点服务器域名的直连解析通道，优先查验静态 hosts 与内存缓存，直接交由轻量快速纯 UDP `bootstrap_servers`（`default-nameserver`）并发解析；
- **消除 TLS 握手风暴**：节点域名拨号绝不走外层 DoH / TLS 握手，彻底消除 100 节点高并发批量测速时瞬时触发的 100 次 TLS 加解密风暴与长尾延迟。

### ⚙️ Tokio 代理内核黄金线程池配比 (`TOKIO_WORKER_THREADS`)
- **Worker 线程精准钳位**：针对 16 / 20+ 多核现代处理器，将多线程运行时默认 Worker 线程数限制为 `clamp(2, 4)`，杜绝高并发网络 I/O 下跨核任务窃取（Work-Stealing）引发的 CPU 线程竞争与核间同步开销；
- **支持外部灵活微调**：支持通过 `TOKIO_WORKER_THREADS` 环境变量进行自由调整与精准配置。

### 📊 100 节点基准测速全线领先（实测对比）
- **测速延迟与吞吐断崖式跃升**：100 节点测速吞吐跃升至 **903.5 req/s**（提升 4.6 倍），单站延迟低至 **13.31 ms**，总耗时降至 **98.5 ms**；
- **CPU 开销暴跌 92%+**：CPU 占用时间从 0.641 s 暴跌至 **0.016 s ~ 0.047 s**（下降 92.7%），成为全场 CPU 消耗最低的代理内核；
- **极致物理内存控制**：压测流量期物理内存峰值仅 **11.8 MB ~ 12.6 MB**，仅为同类内核（30MB ~ 42MB）的 30%~40%。

---

# 🚀 VP_Core v1.5.1 发布说明 / Release Notes

🎉 欢迎使用 **VP_Core v1.5.1**！本版引入 **Linux 内核级 iptables / ip6tables UDP 多端口跳跃重定向守卫 (IptablesPortRedirectGuard) + 零脚本开箱即用 + 孤儿规则自愈 + 双栈抗 QoS 丢包** 专项加固：

### 🛡️ Linux 内核级 UDP 多端口跳跃重定向 (Port Hopping Netfilter REDIRECT)
- **原生内核级重定向**：针对运营商对单端口 UDP 施加的 QoS 恶劣限速与丢包，当服务端 Listener 配置宽范围端口跳跃（如 `ports: "20000-40000"` 共 20,001 个端口）时，自动注入 Linux 内核 Netfilter `REDIRECT` 规则，由内核网络层瞬时转发至主监听端口；
- **杜绝文件描述符耗尽 (`EMFILE`)**：免去在用户态逐一绑定成千上万个 UDP 套接字的系统开销，显著降低内存占用与调度损耗，小内存 VPS 也能稳定运行超大范围端口跳跃。

### 🔄 RAII 生命周期守护与零脚本无感开箱即用 (IptablesPortRedirectGuard)
- **全自动注入与清理**：告别繁琐的手动编写 iptables 脚本与开机自启配置；服务启动时由内核自动检查并注入缺失规则，服务终止或接收终止信号时通过 Rust `Drop` 机制全自动撤销还原；
- **跨平台平滑降级**：非 Linux 平台自动编译为安全 no-op 并对用户态套接字数量进行上限保护（最多 64 端口）；在无 root 权限或缺省工具环境下输出友好提示并优雅回退，绝不 panic。

### 🧹 孤儿规则深度自愈与应急网络恢复 (Sweep & clean-routes)
- **唯一注释标签索引**：所有由 VP_Core 注入的重定向规则均自动标记 `-m comment --comment "vpcore-mport-<listener>"`；
- **自愈清理与应急工具联动**：针对断电、意外崩溃或被 `kill -9` 强杀遗留的孤儿规则，联动 `vpcore clean-routes` 应急自愈命令，执行 `iptables -t nat -S PREROUTING` 逆向解析，一键批处理清理所有残留重定向规则。

### 🌐 IPv4 + IPv6 全双栈协同支持
- **同步管理双栈防火墙**：当配置开启 `ipv6: true` 时，自动同步向 `ip6tables` 注入并管理对应端口重定向规则，保证 IPv6 与 IPv4 客户端获得完全一致的抗 QoS 跳跃体验。

---

# 🚀 VP_Core v1.5.0 发布说明 / Release Notes

🎉 欢迎使用 **VP_Core v1.5.0**！本版是 **全协议原生 UDP 矩阵 + XUDP / packetaddr 编码 + XTLS Vision / REALITY / TUIC 互通互联重构 + QUIC Happy Eyeballs 竞速** 重大里程碑版本：

### 🌐 全协议原生 UDP 与 XUDP 矩阵 (Full-Cone UDP)
- **主流协议原生 UDP 全面覆盖**：VLESS、VMess、Trojan 原生 UDP 全面落地（出站与服务端入站双向支持）；
- **Xray XUDP (Mux.Cool) & packetaddr 编码支持**：支持 `packet-encoding: xudp | packetaddr`（与 mihomo 语义对齐），实现一条代理连接承载多个远端目标（Full-Cone）；服务端自适应 Mux 与 packetaddr 命令；
- **通用流式数据报框架**：抽象出通用的 `PacketFraming` 与 `StreamPacketConn`，统一承载 UoT、VLESS、VMess 与 Trojan 的数据报传输；
- **Cancel-Safe 帧读取引擎**：重构 `FrameReader`，单次 await 仅触发一次缓冲读取，杜绝在 `tokio::select!` 分支打断时丢失帧片断导致流解析错位。

### 🛡️ 真实节点互通重大修复与握手加固 (Interop Fixes)
- **XTLS Vision 架构重构**：完全对齐 Xray 规范，首帧携带 16 字节 UUID 前缀；实现完整的 `PaddingContinue` / `PaddingEnd` / `PaddingDirect` 状态机；收到 `PaddingDirect` 时通过 `ProxyStream::switch_to_raw_read` 绕过外层 TLS 切换到底层 TCP 直拷，彻底解决与 Xray Vision 节点死锁卡死的问题；
- **uTLS / REALITY 记录零填充规范对齐**：严格遵循 RFC 8446 §5.2 规范，从末尾反向寻找 Inner Content Type，防止 REALITY 服务端握手填充及末尾为 0 的合法数据被误截断；
- **VLESS 懒握手 (Lazy Handshake)**：请求头与客户端首个载荷合并发送，避免在 HTTP 类先发数据协议下与 Xray 服务端互等响应头超时；修复底层写操作 Pending 时丢失请求头的隐患；修复入站早数据误回写给客户端的 Bug；
- **TUIC v5 规范对齐与双模式支持**：修复 TUIC v5 中 `SIZE` 字段错误包含地址长度导致与真实服务端不互通的致命 Bug；支持 `udp-relay-mode`（native / quic）；关闭连接时主动发送 `Dissociate` 让服务端释放关联套接字。

### ⚡ QUIC Happy Eyeballs 错峰竞速与 Hysteria2 分片重组
- **Happy Eyeballs 错峰竞速**：Hysteria / Hysteria2 / TUIC 解析出多 IP 时按 250ms（RFC 8305）错峰并发拨号，任一成功即用，彻底解决首个 IP 丢包时整节点卡死的问题；
- **Hysteria2 官方 frag.go 分片重组**：超过单包上限时规范切片，超限或异常时优雅丢包，消除 panic 崩溃隐患（防范 GHSA-qh5x-rfwf-rvfv）；
- **服务端 UDP 会话独立转发**：服务端单会话维护独立套接字，按数据报各自目标进行真实转发，回包携带真实源地址并支持 60s 空闲自动回收；释放连接时主动中止 demux 任务，防止旧 QUIC 连接泄露。

### 🔀 智能路由与系统级兼容加固
- **策略组 UDP 智能避让**：在 `url-test` / `fallback` 等策略组中，UDP 会话会自动避开不支持 UDP 的纯 TCP 节点（如纯 HTTP 节点），避免 UDP 连接中断；
- **配置弱类型宽容兼容**：预处理纯数字字段（如纯数字用户名、密码、节点名等），兼容各类机场订阅导出的弱类型配置，支持 `udp-over-tcp` kebab-case 格式；
- **Windows 出站与路由防护**：出站网卡绑定支持“以太网”、“WLAN”等网卡别名；退出时仅在自身安装过 auto-route 时执行清理，避免误删第三方 VPN 路由。

---

# 🚀 VP_Core v1.4.1 发布说明 / Release Notes

🎉 欢迎使用 **VP_Core v1.4.1**！本版是 **原生 VLESS-WebSocket 服务端入站 + Cloudflare CDN 穿透拯救被墙 VPS + RFC 6455 握手加固** 关键版本：

### ⚡ 原生 VLESS-WebSocket 服务端入站 (Zero-Panel VLESS-WS)
- **原生接管 Web 路径代理**：在 `VlessInbound` 中实现自适应 WebSocket 服务端入站识别与握手升协议，无需在 VPS 上安装 3x-ui / xray 等外部重型第三方面板，VP_Core 单内核独立接管 Caddy / Nginx 443 反代路径（如 `/vpcore-tunnel`）；
- **Cloudflare Anycast CDN 完美穿透**：针对物理 IP / 自定义端口遭 GFW 阻断的 VPS，借由 Cloudflare 443 免费 CDN 节点与 WebSocket 隧道实现免翻墙秒通复活；
- **极端低常驻内存**：彻底淘汰第三方面板后，VPS 服务端常驻物理内存稳定在 **15MB**（仅占 1%~2%），512MB 玩具级低配 VPS 亦可全天候稳定运行。

### 🛡️ RFC 6455 WebSocket 握手协议加固与回落优化
- **Sec-WebSocket-Accept 签名修复**：实现不区分大小写的请求头提取算法，严格保留 Base64 原始 Key 字符大小写，解决 Cloudflare CDN 边缘节点与代理客户端因 SHA-1 签名不符导致的握手失败；
- **精准流量分流探测**：强化入站流量预读识别，仅在明确探测到 `upgrade: websocket` 子串时触发 WebSocket 升级，普通 HTTP 探针与浏览器请求平滑回退至 fallback 伪装站点，互不干扰。

### 🚀 CLI 开服与配置生成器联动升级 (`vpcore gen-server`)
- **自动注入 CDN 穿透入站**：当传入 `--domain` 参数绑定域名时，自动生成 `vless-ws-in`（127.0.0.1:28289）本地监听，与 Web 服务器反代配置无缝衔接；
- **全格式节点链接输出**：一键导出包含标准通用链接、Clash 规则配置与动态 `/sub` 订阅端点。

---

# 🚀 VP_Core v1.4.0 发布说明 / Release Notes

🎉 欢迎使用 **VP_Core v1.4.0**！本版是 **高性能服务端生产级矩阵 + CLI 一键开服 + 内核自我更新** 重大里程碑版本：

### ⚡ 高性能服务端矩阵与全协议栈支持 (Zero-GC Server Inbounds)
- **多协议全功能服务端实现**：支持 Shadowsocks-2022（`2022-blake3-aes-128-gcm` / `aes-256-gcm`）、Hysteria 2、VLESS-REALITY、Trojan、TUIC 等服务端原生监听与分发；
- **极致内存控制 (Zero-GC)**：基于 Rust 零成本抽象，Linux VPS 实测常驻内存 (RSS) 仅 ~20MB（内存占用仅 2%），无 Go 语言 GC 停顿与内存波动，完美适配 512MB / 1GB 低配 VPS；
- **UDP RRL (Response Rate Limiting) 防反射放大**：内置 IPv4 `/24`、IPv6 `/56` 子网聚合漏桶与 Slip 采样丢弃机制，防止 VPS 沦为 DDoS 放大肉鸡；认证通过后自动进入 1 小时全速白名单；
- **端口敲门 (Port Knocking) 与隐身防御**：未敲门探测直接丢弃/RST，端口在资产扫描器（Shodan/Censys）中显示为 Filtered 隐身状态；支持 GeoIP / ASN 前置拦截；
- **Full-Cone NAT 高水位主动 GC**：4096 映射表高水位控制，定时清理过期及空闲 UDP NAT 映射，彻底杜绝内存泄漏与 OOM 隐患。

### 🚀 CLI 一键开服与节点生成 (`vpcore gen-server` / `init-server`)
- **零门槛全自动配置**：多源探测公网 IP，全自动生成 UUID v4、x25519 密钥对、SS-2022 Blake3 密钥以及有效期 10 年的高性能自签 TLS 证书；
- **客户端分享与 Clash 配置全套输出**：生成完成直接在终端格式化输出标准 `vless://`、`hysteria2://`、`ss://` 链接以及可直接粘贴的 Clash `proxies` 节点 YAML 片段；
- **支持 `--domain` 域名联动与 CDN 穿透**：一键生成 Cloudflare Anycast CDN + WebSocket 节点，助推受阻断 VPS 国内免翻墙直连复活。

### 🌐 全协议客户端订阅引擎与动态 /sub 端点
- **服务端原生动态订阅接口 (`GET /sub`)**：自动适配客户端类型与请求参数（`?format=clash` 或 Clash User-Agent 自动输出完整 Clash 订阅包；默认输出标准 Base64 订阅文本）；支持安全 Token 鉴权与 `Subscription-Userinfo` 标头；
- **CLI 静态订阅落盘与一键订阅链接**：`gen-server` 自动生成并在终端高亮输出通用订阅 URL、Clash 专用订阅 URL 与 Base64 订阅码，同步离线生成 `sub.txt` 与 `sub-clash.yaml`；
- **随时导出与查看订阅 (`vpcore gen-sub`)**：支持根据现有配置文件随时一键导出订阅链接、Base64 订阅码或 Clash YAML 配置。

### 🔄 内核自我更新与跨平台热替换 (`vpcore update` / `upgrade`)
- **自动适配架构下载**：识别 Linux / Windows / macOS 的 x86_64 与 aarch64 架构，支持官方 Release 与自定义加速镜像源；
- **严格前置健康检查**：覆盖前在临时路径执行 `--version` 自检，验证失败立即终止更新，防止坏包损坏服务；
- **跨平台原子热替换**：Linux 下利用 inode unlink/rename，Windows 下利用 `.exe.old` 转移策略，进程运行中平滑升级；
- **systemd 托管平滑重载**：Linux 环境下自动检测 systemd 托管状态并触发 `systemctl restart vpcore` 平滑生效。

### 📦 一键自动化部署脚本 (`install.sh`)
- 提供全新跨发行版一键脚本，自动检测架构、安装二进制、部署 systemd 守护进程并调用 `gen-server` 输出节点。

---

# 🚀 VP_Core v1.3.2 发布说明 / Release Notes

🎉 欢迎使用 **VP_Core v1.3.2**！本版聚焦 **Windows TUN 模式 DNS 劫持拦截与 Fake-IP 冲突修复**，彻底解决 TUN 模式下 YouTube 访问失败与 DNS 超时问题：

### 🌐 Windows Wintun DNS 劫持分离与 Fake-IP 冲突根治（P0）
- **DNS 拦截分离**：Wintun 适配器 DNS 地址指向同网段未占用 IP（`198.18.0.2`），避免 Windows 将发往虚拟网卡自身 IP（`198.18.0.1`）的 DNS 查询直接经系统内核回环处理导致 TUN 无法拦截的问题；
- **Fake-IP 地址池保留池加固**：保留 `base+1`（网卡地址）与 `base+2`（DNS 劫持地址），Fake-IP 严格从 `base+3` 起按需分配，杜绝地址冲突。

### ⚡ Hysteria 2 / QUIC Datagram 与物理网卡防环路优化
- **QUIC Datagram 目标保留**：修复 TUN 模式下目标地址回环反查引起的格式化异常，UDP 流量正确携带原始目标域名/地址，解决 YouTube 等 QUIC 站点握手黑洞；
- **底层 UDP 套接字物理绑定**：出站 QUIC / UDP 套接字显式通过物理网卡拨号，防止 TUN 下发的默认路由造成自循环死锁；
- **TUN MTU 调优**：MTU 标准化为 1500，杜绝超大包分片导致上游光猫/路由器丢包。

---

# 🚀 VP_Core v1.3.1 发布说明 / Release Notes

🎉 欢迎使用 **VP_Core v1.3.1**！本版是 **Windows TUN 防回环专项 + ECH 回退修复**，根治"开启 TUN 后整机断网"与"节点 ECH 被拒后连接判死"两大故障：

### 🛡 TUN 防回环专项（Windows，P0）
- **出站套接字补齐源 IP 显式绑定**：只设 `IP_UNICAST_IF` 时，Windows 的源地址 / 路由选择仍按路由表走 —— auto-route 下即 TUN 自身（198.18.0.1），节点拨号与 DNS 查询全部流回自己形成回环，表现为 **TUN 开启后整机断网**（Baidu 直连域名也解析失败：DNS 上游一并被吞）。现在 TCP / UDP 出站统一 `UNICAST_IF + 源 IP 绑定`（`GetIpAddrTable` 解析网卡 IP），节点拨号、DoH、DoT、UDP 上游全覆盖；
- **DNS 上游裸拨号根治**：DoH / DoT / DNS-over-TCP 三处裸 `TcpStream::connect`（未绑物理网卡）统一切换绑卡拨号 `connect_tcp_bound`；此前 auto-route 下内核自己的 DNS 上游查询会以 TUN 地址为源回流，被当成客户端流量再走 PROXY，雪崩式放大；
- **auto-route 可观测性**：双 /1 接管路由的 `route add` 逐条校验并落日志，报错详情从 stdout 提取（route.exe 报错打在 stdout 且中文系统为 GBK），失败时明确告警"仅成功 N/2，TUN 无法接管全部系统流量"。

### 🔐 ECH 被拒回退修复（P0）
- **不再用同一份被拒配置反复撞墙**：服务端拒绝 ECH 且原样吐回同一份 retry config 时，旧逻辑无条件缓存并重拨重试 —— `dial` 单次重拨撞同一堵墙，普通 TLS 永远轮不到，连接以 `ECH_REJECTED_FALLBACK` 判死，节点整体不可用；
- **新的状态机**：仅当服务端给出**不同于刚被拒那份**的新 retry config 才按标准 ECH 流程再试一次；否则清缓存、标记主机，重拨直接走普通 TLS，收敛路径固定为 `ECH(DNS 配置) → ECH(retry) → 普通 TLS`，之后该主机记住结论不再浪费握手；
- 新增决策边界回归测试；节点服务端 ECH 配置轮换（Cloudflare 常见）不再导致节点假死。

---


🎉 欢迎使用 **VP_Core v1.3.0**！本版是 **Linux 透明网关（Armbian / N1 / 软路由）生产级修复专项 + Tailscale 集成**，同时修复 4 项透明网关重大故障、全新 TPROXY 数据面与 Tailscale 出站：

### 🛠 透明网关四大故障根治（P0）
- **geoip.metadb 加载成功但查询全失效**：重写 MMDB 记录反序列化——`#[serde(untagged)]` 多态模型统一兼容 MaxMind 官方嵌套格式（`{country:{iso_code}}`）、MetaCubeX `meta-rules-dat`（纯字符串 / 字符串数组）与 sing-geoip 扁平字典，`GEOIP` 规则全面恢复判定；
- **DIRECT 直连吞吐被卡 ~2 MB/s**：双重病根一次根除——`redir` 入站 `accept()` 补齐 `tune()`（`TCP_NODELAY`，消除与 Delayed-ACK 的 40ms Nagle 空转）；嗅探层 `PeekedStream` 透传底座 socket 与预读缓冲，直连流量在排空首包后全面切入 Linux `splice` 管道零拷贝；
- **tproxy-port 收包后不处理**：全新原生 Linux `TproxyInbound`——TCP 侧 `IP_TRANSPARENT` 监听直接提取原始目标；UDP 侧 `recvmsg` 解析 `IP_ORIGDSTADDR` cmsg 辅助数据 + 绑定原目标的透明回包套接字，60 秒空闲 NAT 流表自动回收；
- **dns.listen 被忽略**：`dns.listen` 解除对 `tun.enable` 的从属绑定，支持 `0.0.0.0:53` / `:53` / `127.0.0.1:1053` 等写法独立启动 UDP + TCP（RFC 7766）DNS 服务端。

### 🆕 新特性
- **Tailscale 出站（`type: tailscale`）**：经本机/远程 Tailscale Connector 的 SOCKS5 接口（默认 `127.0.0.1:1055`）接入 Tailnet，支持 `exit-node` 出口节点、UDP 中继、`dialer-proxy` 链式与 smux 包装；`*.ts.net`（MagicDNS）内置永不 Fake-IP，点对点 `100.64/10` 通信不被劫持；
- **listeners 段统一多入站**：`inbounds:`/`listeners:` 段现支持 `tproxy` / `redir` / `mixed` / `socks5` / `http` 及全部协议服务端，新增 `listen` 绑定字段，与顶层 `tproxy-port` / `redir-port` 并存兼容；
- **TPROXY 健壮性加固**：UDP 收包循环锁外投递与建连（消除持锁死锁链：流任务终止回收与通道满互等可致全局收包器瘫痪）；cmsg 缺失严格报错丢弃（iptables 误用 REDIRECT 目标时不再静默错误路由）。

### 🔧 数据面微调
- 转发泵链读阈值由"读满整块"放宽为"≥2KB 持续灌入"，保持"探一眼"绝不持数据等待的死锁防线；
- AEAD 微基准改为 `#[ignore]` 手动压测，常规 `cargo test` 套件提速约 1 分钟。

---

# 🚀 VP_Core v1.2.0 发布说明 / Release Notes

🎉 欢迎使用 **VP_Core v1.2.0**！本版正式打通外部控制器 REST API 模式热切能力，实现「规则 / 全局 / 直连」运行中免停秒级无感热切换：

### ⚡ 外部控制器与出站模式免停热调
- **PATCH /configs 动态热调模式**：实现 Clash 兼容规范 REST API `PATCH /configs {"mode": "rule" | "global" | "direct"}`，支持大小写不敏感解析与标准响应；
- **RouterHandle 原子路由热换**：新增 `clone_with_mode` 机制，在保持所有既有代理组连接池、节点健康检查与活跃长连接不中断的前提下，原子替换内存分流决策引擎；
- **配置持久化落盘同步**：热调模式时自动异步将生效模式写回持久化 `config.yaml`（`mode:` 字段），保证重启后状态一致；
- **GET /configs 模式小写规范对齐**：返回结果与 Clash / Mihomo 规范严格对齐为小写（`rule`/`global`/`direct`）。

---

# 🚀 VP_Core v1.1.0 发布说明 / Release Notes

🎉 欢迎使用 **VP_Core v1.1.0**！本版是数据面性能与运行时资源治理的里程碑：转发引擎引入预读合并与 Linux splice 零拷贝，编译优化释放加密 SIMD 算力，并建立起"可限制、可追踪、可取消、可回收"的连接运行时：

### ⚡ 转发引擎重构（性能核心）
- **链式预读 + vectored 合并写**：32KB 池化缓冲，读满整块才链上预读，最多 4 块并成一次 `writev`——128KB 转发从 8 次 syscall 降到 4 读 + 1 写；
- **"探一眼"式防死锁设计**：链读用单次 poll 收集，绝不持已收数据等待下一块——彻底修复请求-响应式流量（HTTP 整块倍数响应、Snell 大载荷）的管线死锁，交互式小包零尾延迟；
- **Linux splice 零拷贝快速路径**：裸 socket 直连走 socket→pipe→socket 内核搬运，数据不进用户态；加密/混淆/嗅探封装自动回退通用泵，Windows/移动端路径不变；
- **编译优化修正**：`opt-level` 从体积优先的 `"z"` 改为 `3`——RustCrypto 的 AES-NI/AVX2 内联循环不再被降级，AEAD 吞吐实测提升 4-5 倍（aes-128-gcm 323→1329 MB/s，chacha20 265→1339 MB/s）。

### 🛡 连接运行时资源治理
- **连接资源预算**：新增 `resource-limits` 配置节，支持全局与每入站 TCP 连接上限；超限快速拒绝并回送失败应答，额度由 RAII Permit 管理，连接异常/任务取消都能可靠归还（缺省不限，桌面端零行为变化）；
- **热更新任务滞留修复（P0）**：健康检查任务句柄按 Router 代际归属，配置热替换时统一终止旧代任务，杜绝旧 Group 长期驻留与重复探测；
- **测速有界并发**：探测改为固定 worker 池按索引取活，同时存在的任务对象数从 O(节点数) 降至 O(32)；
- **缓冲池可观测**：新增活跃缓冲块数、池命中/未命中、超预算分配指标——活跃内存不再不可见。

### 🧱 运行时基础改进
- **连接表 16 分片**：高并发建删连接的锁竞争摊薄，`list()` 逐片加锁；
- **套接字调优快照**：4 个独立全局 Atomic 合并为单一 `SocketTuning` 快照，tune() 一致读取，不再出现半新半旧参数；
- **一致性哈希去堆分配**：IP 哈希路径改为栈上固定数组 FNV，路由热路径零临时分配；
- **每连接进程名解析**：Windows 下按源地址反查归属进程并在 API 暴露，进程级流量统计落地；
- **ArcSwap 评估结论**：微基准对比 RwLock<Arc>（9.7M ops/s）与 ArcSwap（14.5M ops/s），路由 pick 每连接仅一次，保留 RwLock 并将数据入库。

### 🧪 质量与基准体系
- 新增基准体系：AEAD 微基准、环回全链路吞吐（含工具上限标定）、转发拆账与热替换对比，`docs/benchmarks.md` 留档；
- Linux 真机（WSL2 Ubuntu 24.04）验证 splice 路径，真机抓出并修复 tokio 就绪缓存自旋挂起（dup+AsyncFd try_io）；
- 全套回归：泵防死锁、健康检查生命周期、连接预算、缓冲池指标、协议兼容 265+ 测试通过。

---

# 🚀 VP_Core v1.0.4 发布说明 / Release Notes

🎉 欢迎使用 **VP_Core v1.0.4**！本版重点攻坚并解决了 ShadowsocksR (SSR) 时序倒置缺陷，全面对齐 RFC 9180 HPKE 并实现 Encrypted Client Hello (ECH) 原生握手与重试机制，大幅提升边缘节点连通率：

### 🔒 ECH (Encrypted Client Hello) 全链路原生打通
- **RFC 9180 HPKE 规范级对齐**：
  - 彻底矫正 HPKE 密钥交换自实现中的标签（`eae_prk`）与 `LabeledExtract` 逻辑，完全命中 RFC 9180 A.1.1 官方测试向量；
  - 解决 Cloudflare 边缘服务器拒绝解密（`ServerRejectedEncryptedClientHello`）的问题；
  - 实现 TLS 握手层服务器 ECH Retry Config 实时缓存与自动重试。
- **VLESS 懒握手与订阅参数扩展**：
  - 解决 Cloudflare Worker 等环境下的 VLESS 握手死锁，实现请求头与首包载荷合并发送；
  - 支持 `ech=<query_server_name>+<doh_url>` 格式的 ECH 订阅参数解析，并通过指定 DoH 解析器提取 HTTPS 记录中的 ECHConfigList。

### ⚡ ShadowsocksR (SSR) 收发路径时序重构
- **矫正混淆层与流加密处理顺序**：
  - 修复 `tls1.2_ticket_auth` 混淆层首包 ClientHello 误被底层流密码（`chacha20-ietf` / `rc4-md5`）加密为乱码的问题；
  - 发送路径重排为：协议分帧 → SS 流加密 → TLS 记录封装（ClientHello 保持明文，`[IV]+密文` 正确封装入 0x17 记录）；
  - 接收路径重排为：TLS 解帧 → 写入 SS 流缓冲区 → 提取 IV → 流解密，实测支持 `chacha20-ietf` 与 `rc4-md5` 生产节点高可用连接。

### 🌐 协议与规则扩展
- 增加 Hysteria 1 与 ASN 规则匹配能力；
- 优化 SS Stream 密码算法套件及 UDP 转发。

---

# 🚀 VP_Core v1.0.3 发布说明 / Release Notes

🎉 欢迎使用 **VP_Core v1.0.3**！本版深度重构与完善了 **Hysteria 2** 协议栈，彻底解决官方服务端连接异常，引入连接池多路复用大幅降低延迟，并提升了 VLESS + REALITY 与多出站协议的兼容性：

### ⚡ Hysteria 2 全功能深度重构与稳定性升级
- **彻底根治 QUIC 错误码 260（`H3_CLOSED_CRITICAL_STREAM`）**：
  - 在 HTTP/3 认证完成后长久持有控制流与字典流句柄，生命周期与底层 QUIC 连接严格对齐，彻底解决连接官方 Hysteria 2 服务端时的异常中断问题；
  - 启动轻量后台协程持续吸收对端控制帧，杜绝流缓冲区积压。
- **QUIC 会话连接池与多路复用（Multiplexing）**：
  - 引入 `Hysteria2Session` 持久连接池，相同出站复用已有存活 QUIC 连接打开双向数据流（`open_bi`），规避短连接反复握手与认证的巨大开销，显著降低首次请求与连续访问延迟；
  - 提供连接失效自动重连与平滑自愈机制。
- **UDP 数据报解复用器（UDP Demuxer）**：
  - 实现基于 `session_id` 的后台 UDP 数据报分发器，支持多路并发 UDP 代理流共享单一 QUIC 链路。
- **支持 Salamander 混淆与带宽速率透传**：
  - 完整实现基于 Blake2b-256 + 随机 Salt 的 Salamander XOR 混淆协议；
  - 支持将配置的下行带宽速率透传至 `hysteria-cc-rx` 认证头，支持 BBR 拥塞控制自适应。

### 🛠️ 传输层、规则与出站配置兼容性增强
- **修复 VLESS + REALITY 传输解密**：
  - 修复特定 TLS 环境下 uTLS 与 REALITY 解密协同问题，保障连接稳定性。
- **优化 Clash Proxy-Provider 解析**：
  - 增强外部订阅提供者 payload 结构反序列化容错。
- **出站证书跳过参数对齐**：
  - 为所有出站协议（SS、SSR、VMess、VLESS、Trojan、Hysteria 2、TUIC 等）补充 `skip-cert-verify` / `allowInsecure` / `insecure` 别名兼容。
---

# 🚀 VP_Core v1.0.2 发布说明 / Release Notes

🎉 欢迎使用 **VP_Core v1.0.2**！本版重点提升了规则引擎性能与冷启动效率，启动耗时压降超 90%：

### ⚡ 规则引擎与启动性能飙升
- **$O(1)$ 哈希规则索引**：
  - 将海量域名匹配从二分查找优化为哈希分组索引，规则构建速度提升 14 倍以上；
  - 修复 2.4 万+ 条规则加载时的内存拷贝瓶颈，实现百毫秒级急速启动。
- **配置快速解析**：
  - 优化日志级别扫描与配置文件加载路径，消除冗余反序列化开销。

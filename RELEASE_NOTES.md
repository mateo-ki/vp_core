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

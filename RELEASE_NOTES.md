# 🚀 VP_Core v1.7.4 发布说明 / Release Notes：支持 MASQUE (Cloudflare WARP) 协议与纯 Rust 用户态网络栈

> **“RFC 9484 CONNECT-IP 胶囊通道、P-256 双向 mTLS、解耦独立的纯 Rust 用户态 smoltcp 驱动器——现代代理协议版图再下一城。”**
>
> 🎉 欢迎使用 **VP_Core v1.7.4**！本版本正式引入了对 **MASQUE 协议（Cloudflare WARP MASQUE 模式，RFC 9297 / 9298 / 9484）** 的原生支持。从协议握手、P-256 自签名客户端证书动态签发、服务端公钥 Pinning 校验，到 HTTP/3 控制流与 Extended CONNECT 路由宣告，再到下沉的纯 Rust 用户态网络栈，全链路实现 100% 内存安全闭环，并经过全部 57 个真实订阅 WARP 节点以及四项数据面生命周期深度审计加固。

### 🌟 核心更新全览 (Highlights)

| 类别 | 内容 | 收益 |
| :--- | :--- | :--- |
| **MASQUE 协议原生支持** | 完整实现 RFC 9297/9298 HTTP Datagram + RFC 9484 CONNECT-IP (`:protocol = cf-connect-ip`) | 无缝支持 Cloudflare WARP 官方与第三方 MASQUE 出站代理节点 |
| **P-256 双向 mTLS 认证** | 支持 SEC1/PKCS#8 私钥解析、动态签发客户端 X.509 自签名证书与 SPKI 证书公钥比对校验 | 完美对齐 Cloudflare WARP 身份认证规范与 Mihomo/Clash MASQUE 格式 |
| **纯 Rust 用户态协议栈 (`ip_stack`)** | 基于 `smoltcp` 解耦出独立的虚拟 IP 驱动栈（支持 `172.16.0.2` 及 IPv6），事件驱动注入与读取 | 免操作系统 TUN 网卡权限即可在用户态完成四层 TCP/UDP 代理转换，统一赋能 WireGuard 与 MASQUE |
| **配置、IR 与 DSL 100% 往返** | `vp-config` / `vp-ir` / `vp-dsl` 全链路支持 `masque` 类型，支持短横线与下划线别名及驼峰字段 | 25821 节点全量订阅库中的全部 57 个真实 MASQUE 节点反序列化与 DSL 往返编译 100% 通过 |
| **数据面生命周期深度加固** | 持有 Quinn Endpoint 与关键单向/双向流句柄，彻底根除提前 Drop 导致的 `H3_CLOSED_CRITICAL_STREAM` (0x0104) 强断 | 解决长期连接被对端主动发送重置的致命生命周期 Bug |
| **异步 DNS 动态解析** | 网关连接自动兼容纯 IP 与域名（支持 `engage.cloudflareclient.com` 等） | 用户无需预先解析 IP，支持官方域名与优选 IP 混合配置 |
| **事件驱动收发包引擎** | 引入 `Notify` 同步信号替代 1ms 定时器空转轮询，配合 50ms 兜底防竞态 | 数据面待发报文即时唤醒转发，CPU 空转能耗降至趋零 |
| **双向流保活与排空** | 持续异步读取 Stream 0 响应数据并捕获远端 Capsule 宣告与正常断流信号 | 杜绝流控窗口枯竭与悬挂连接 |

---

# 🚀 VP_Core v1.7.3 发布说明 / Release Notes：决策面优化与大规模测试加固

> **"分流决策的每一微秒、LB 会话的每一次漂移、规则引擎的每一次分配——这次都用大规模测试砸出来了真问题。"**
>
> 🎉 欢迎使用 **VP_Core v1.7.3**！本版本聚焦**决策面**（分流规则引擎与策略组）的精准优化，并由五类大规模测试（规模化规则回归、并发线程安全、e2e 并发压测、混沌复跑、真实数据幂等）护航——测试还顺带抓出 2 个真实热点并当场修复。

### 🌟 核心更新全览 (Highlights)

| 类别 | 内容 | 收益 |
| :--- | :--- | :--- |
| **GEOIP/IP-ASN 查询复用** | `MatchCtxCache` 惰性缓存（OnceLock 按 IP 记录首查） | 机场常见 10+ 条 GEOIP/IP-ASN 规则的 mmdb 树遍历 **N 次 → 1 次** |
| **DOMAIN-KEYWORD 分配消除** | host 小写转换惰性化并跨规则共享 | 50-200 条关键词规则每连接 50-200 次堆分配 → **1 次** |
| **LB 一致性哈希修正** | FNV 取模 → **Jump Consistent Hash**（Google 论文原式） | 成员增减时每会话仅 ~1/n 概率迁移；旧方案全量洗牌导致 LB 组 UDP NAT 会话大面积漂移（游戏/QUIC 断流）——正确性修复 |
| **规则 trie 哈希提速** | `DomainTrie` 子节点 SipHash → **FNV-1a 64** | 单条 trie 查询 ~800ns → ~400ns（40% 提速）；大规模测试分段微基准定位 |
| **域名小写化零分配** | 每查询一次的 `to_ascii_lowercase` 堆分配 → **Cow 零分配快速路径** | 数万条规则线性扫描下每条一次的分配归零 |
| **大规模测试落库** | 2 万条混合规则规模化回归（保序语义 + 分段计时基线）+ 8 线程并发安全测试 | 防退化守护进 CI |

### 🧪 大规模测试矩阵（全部通过）

- **规模化**：20k 混合规则编译 29ms、保序语义全对、分段计时基线锁定
- **并发安全**：8 线程 × 5000 次并发匹配结果零漂移
- **e2e 压测**：100 TCP（512KB 往返）+ 30 UDP 会话并发穿 mixed 全链路，0.1 秒完成 0 错误
- **混沌复跑**：workspace 全量 × 3 轮，398×3 = 1194 全过零 flaky
- **真实数据**：25821 真实节点 convert → fmt 幂等回归 0 差异

### 📝 审计修正（工程透明）

立项时的"域名层/IP-CIDR 层聚合索引"在深读 compile 后放弃：引擎已有相邻同 target 规则批量合并（`PendingDomainBatch`），数万条订阅规则实际编译为几十条批量规则，聚合收益降至微秒级，不值得保序重构风险。策略组 pick 路径审计确认已 O(1)。

---

# 🚀 VP_Core v1.7.2 发布说明 / Release Notes：全链路性能优化与真实订阅兼容性大考

> **“25821 个真实订阅节点全量压测、双平台互为盲区的事故互查、真实节点穿透验证——性能与兼容性这次都见真章。”**
>
> 🎉 欢迎使用 **VP_Core v1.7.2**！本版本包含两批入站→出站全链路优化（12 项方案落地 9 项）、25821 个真实订阅节点的全量兼容性压测修复（15 种协议）与真实节点端到端穿透验证。所有优化均经基准留档（`docs/benchmarks.md`），所有修过的坑都有回归测试或事故复盘锁死。

### 🌟 核心更新全览 (Highlights)

| 类别 | 内容 | 收益 |
| :--- | :--- | :--- |
| **入站性能** | Linux `TCP_DEFER_ACCEPT`(3s) + 多核 `SO_REUSEPORT` 多监听器（mixed/socks5/http，`min(cpus,8)` 槽） | 空握手零唤醒、端口扫描免疫；万级并发接入打散 accept 互斥与 epoll 惊群 |
| **路由性能** | 确定性路由决策缓存（`uses_session_state` 静态内省，进程/源地址/入站标识依赖自动禁用） | 日常浏览 98%+ 连接 O(1) 决策，热重载自然失效 |
| **DNS 性能** | RFC 8305 双栈地址交叉编排 + RFC 8767 stale-while-revalidate（60s 窗口+在途去重） | v6 黑洞首包延迟 -200ms+；高频域名 DNS 感知延迟恒为 0 |
| **中继性能** | 非对称缓冲 上行 32K / 下行 128K | 单连接缓冲内存 -37.5%，同内存多承载 ~60% 并发 |
| **UDP 性能** | `PacketSend` 直发句柄绕过 mpsc（DIRECT/SOCKS5/SS 三出站）+ quinn-udp recvmmsg 批量收包 | 游戏/QUIC 上行 Jitter 显著下降，高 PPS 收包 syscall -90%+ |
| **真实订阅兼容** | 25821 节点全量压测：alpn 字符串（40% 节点）、V2Ray 平铺字段（vless 74%）、字符串布尔/数字、双键并存、null 占位、DSL 往返 8 处破坏 | 真实机场订阅"拿来即用"，convert/fmt 全链路幂等无损 |

### 🧯 事故与修复（工程透明）

- **socks5 UDP 中继活锁**（Windows 必现）：`readable()` + 裸 quinn-udp `recv` 绕过 `try_io` → tokio 就绪标志永不清除 → 100% CPU 空转。包进 `try_io` 修复，并防御 GRO `stride==0` 死循环（§3.6 splice 自旋之后第二次同类教训）。
- **REUSEPORT 上线即翻车**（Linux 多核必现）：多监听器跟随全局 tuning 默认 `reuse_port=false` → 第 2+ listener `EADDRINUSE` 整个入站起不来。强制开启修复。**结论：cfg(linux) 差异 Windows 测不出，WSL 兜底测试升级为固定门禁。**
- **UDP 直发会话 GC 误删**（纯逻辑）：直发分支 drop rx → GC 以 `tx.is_closed()` 判活误删会话 → NAT 失效每包重连。rx 恒持有修复 + 回归测试锁死。

### ✅ 质量门禁

Windows 393 测试 0 失败 + `cargo fmt --check`；WSL Linux `clippy -D warnings` 0 告警 + 全量测试；25821 真实节点 `validate ✓ → convert → fmt --check` 幂等 0 差异；真实 vless/trojan 节点端到端穿透（HTTP 204 + 出口 IP 落地正确）。

---

# 🚀 VP_Core v1.7.1 发布说明 / Release Notes：一键无损转换与 DSL 格式化工具链 (`convert` & `fmt`)

> **“配置迁移不该是手工苦力活，格式规范更不该靠肉眼自觉。”**
>
> 🎉 欢迎使用 **VP_Core v1.7.1**！本版本为 v1.7.0 推出的统一中间表示 (VP IR) 与 `.vp` DSL 补全了完整的**生态工具链闭环**：新增 `vpcore convert` 实现 Clash YAML / JSON / `.vp` DSL **任意双向无损互转**；新增 `vpcore fmt` 提供 `cargo fmt` 风格的 DSL 自动对齐与 CI/CD 格式门禁；`vpcore sub` 订阅拉取现已支持**直出规范 `.vp` DSL 配置**。从此存量配置一键无痛迁移，DSL 代码风格全局统一。

### 🌟 核心更新全览 (Highlights)

| 新特性 | 解决的传统痛点 | 带来突破性价值 |
| :--- | :--- | :--- |
| **一键无损互转 (`convert`)** | 手头积压大量 Clash YAML/JSON 配置，手工翻译成 DSL 费时费力且易丢字段 | 基于 VP IR 的三格式任意互转（YAML ⇄ JSON ⇄ `.vp`），格式自动推断，语义 100% 保真 |
| **DSL 格式化引擎 (`fmt`)** | 团队协作与 AI 生成的 `.vp` 代码风格混乱，缩进与对齐全凭自觉 | `parse -> IR -> ir_to_dsl` 确定性规范化排版；`-w` 原地写回，`--check` 非零退出码门禁 |
| **订阅直出 DSL (`sub`)** | 拉取机场订阅只能得到 YAML，仍需手工二次转换 | `vpcore sub <URL> -o sub.vp` 一步到位产出规范 DSL 配置文件 |
| **协议覆盖全面补齐** | DSL 对部分冷门协议与链式代理支持不全 | 新增 Snell、SSH、AnyTLS、SSR、Hysteria (v1) 支持与 `dialer_proxy` / `routing_mark` / `interface` 出站字段 |
| **CI 门禁与鲁棒性加固** | 混乱输入可能导致工具链 panic 崩溃，格式规范无强制保障 | 仓库内置 `example/config.vp` 并纳入 CI `fmt --check` + `validate` 双门禁；混沌模糊测试确保畸形输入优雅报错绝不 panic |

### 🔄 P1. 一键无损互转 (`vpcore convert`)
存量配置的迁移成本直接降为零：
```bash
# Clash YAML 一键转为极简 .vp DSL
vpcore convert -i config.yaml -o config.vp

# .vp DSL 逆向导出标准 YAML / JSON
vpcore convert -i config.vp -o exported.yaml
vpcore convert -i config.vp -o exported.json

# 直接在终端打印转换结果；支持 --from / --to 强制指定格式
vpcore convert -i config.yaml
```
- **全自动格式推断**：依据扩展名（`.yaml` / `.yml` / `.json` / `.vp`）自动识别输入输出格式，`--from` / `--to` 可显式覆盖；
- **统一 IR 枢纽架构**：所有转换均经由强类型 `VpIr` 中转，杜绝“字符串拼装”反模式，语义零丢失；
- **闭环可验证**：转换产物可直接通过 `vpcore validate` 校验，测试覆盖 `YAML -> .vp -> validate -> fmt --check -> YAML` 全生命周期。

### 🎨 P2. DSL 自动格式化与 CI/CD 门禁 (`vpcore fmt`)
```bash
# 原地格式化并对齐 .vp 文件
vpcore fmt -w config.vp

# CI/CD 门禁检查（未规范格式化时以退出码 1 失败）
vpcore fmt --check config.vp

# 预览格式化结果（输出至标准输出）
vpcore fmt config.vp
```
- **确定性规范化**：基于统一 IR 重新生成，天然完成语法校验——无法格式化的文件即非法配置；
- **仓库级门禁范例**：本仓库 `example/config.vp` 已纳入 GitHub Actions，每次 PR 强制执行 `validate` + `fmt --check` 双重门禁。

### 📥 P3. 订阅直出 DSL (`vpcore sub`)
```bash
# 拉取订阅并直接保存为规范 .vp DSL 配置
vpcore sub "https://subscribe.example.com/api/v1/client/subscribe?token=xxx" -o sub.vp
```
- 按 `-o` 输出文件扩展名自动识别格式，亦可通过 `-f vp` 显式指定；
- 终端回显明确标注输出格式（`格式: VP DSL`）。

### 🧪 P4. 工程质量与鲁棒性加固
- **混沌模糊测试**：空文件、二进制垃圾、截断 YAML/JSON、非法 DSL 语法等 10 类畸形输入全部优雅报错退出，绝不 panic；
- **Mock 订阅端到端测试**：本地 HTTP 订阅服务器 -> `sub` 拉取 -> 直出 DSL -> `validate` + `fmt --check` 双门禁全链路自动化验证；
- **全套质量门禁**：全工作区 390+ 项测试 100% 通过，`clippy -D warnings` 零警告，`cargo fmt --check` 全对齐。

### ⚡ 极速体验与升级指南
- **客户端平滑自我更新**：
  ```bash
  vpcore update
  ```
- **存量配置一键迁移**：
  ```bash
  vpcore convert -i config.yaml -o config.vp
  vpcore fmt -w config.vp
  vpcore run -c config.vp
  ```

---

# 🚀 VP_Core v1.7.0 架构革新：统一中间表示 VP IR、声明式全量配置 DSL 与微秒级全景链路诊断

> **“性能早已不是瓶颈，真正的工业级代理内核应当全力优化路由模块，把易用性做到极致，并彻底消除破坏性更新。”**
>
> 🎉 欢迎使用 **VP_Core v1.7.0**！这是项目演进历程中极具里程碑意义的重大版本。我们彻底打破了传统代理内核在配置格式与规则表达上的陈旧桎梏：确立了纯净强类型的**统一中间表示层 (Unified VP IR)**；推出了专为人类直觉与大模型（LLM）打造的**声明式全量配置语言 (`.vp` DSL)**；实现了手写 Pratt 攀爬算法的 **Google CEL 表达式引擎**；并带来了精确至微秒（µs）的 **Chrome DevTools 风格全景链路诊断系统 (`vpcore explain`)**。

### 🌟 核心革新全览 (Highlights)

| 核心特性 | 解决的传统痛点 | 带来突破性价值 |
| :--- | :--- | :--- |
| **统一中间表示 (VP IR)** | Clash YAML 序列化别名污染运行时模型，版本变更极易引发破坏性更新 | 借鉴 LLVM IR/Envoy xDS 架构，构建纯净强类型契约，多前端零损耗降维 |
| **全量配置 DSL (`vp-dsl`)** | 传统 YAML 缩进脆弱、少个空格全盘报错、JSON 嵌套深如迷宫 | 类似 Terraform/HCL 的极简块声明语法，杜绝缩进陷阱，天然契合 AI 生成 |
| **Google CEL 表达式引擎** | 传统规则无法表达复合条件，无法书写 `&&`、`\|\|`、`in` 逻辑 | 手写 Pratt 算符攀爬解析器，支持 Wireshark 风格纳秒级短路规则分流 |
| **全景链路诊断 (`explain`)** | 节点连不上或首包卡顿如抓瞎排错，翻找千行调试日志耗时费力 | 终端高亮决策树，精确度量规则匹配、DNS、节点测速与全流程耗时（µs/ms） |
| **策略组容灾兜底 (fallback)** | 机场节点变动导致正则匹配为空、组内全灭时直接报错断网 | 正则动态过滤匹配 + 空成员自动平滑切换 fallback 兜底，网络永不中断 |
| **外部订阅零拷贝直转 IR** | 传统“拼装临时 YAML 字符串 -> 二次反序列化”的反模式损耗性能 | 订阅 URI 零中转直出强类型 `OutboundSpec`，解析吞吐翻倍提升 |

### 🔍 P1. 全景链路诊断与微秒级可观测性引擎 (`explain`)
告别黑盒盲猜！通过 `vpcore explain <target>` 即可获得毫秒/微秒级全景决策树：
```text
================================================================================
                    VP_Core 路由链路诊断追踪 (explain)
================================================================================
[*] 诊断目标: www.google.com:443 (Domain)
[*] 会话环境: Network: TCP | Inbound: mixed | Process: None

┌── [1] 分流运行模式
│   └── Mode: rule (规则优先分流)
│
├── [2] 目标地址与嗅探
│   ├── Host: www.google.com
│   ├── Port: 443
│   └── Type: Domain (域名)
│
├── [3] 惰性 DNS 解析
│   ├── 触发状态: 已触发 (触发规则: GEOIP,CN)
│   ├── 解析耗时: 38ms   (精确捕获 DNS 首包查询延迟)
│   └── 解析结果: 142.250.190.46
│
├── [4] 规则匹配决策
│   ├── 评估进度: 评估至第 1 条 (总数: 50 条，规则匹配耗时: 12 µs)
│   ├── 命中规则: #1 EXPR,(host.endsWith(".google.com")),PROXY
│   ├── 规则类型: EXPR
│   └── 分流目标: PROXY
│
├── [5] 策略组穿透决策链
│   └── [1] 组名: PROXY (url-test)
│       ├── 决策依据: 自动优选延迟最低存活节点
│       ├── 选中成员: 香港-01
│       └── 组内成员快照 (2 个):
│           ├── 香港-01 (存活, 延迟: 45ms, UDP:支持) [* 选中]
│           └── 日本-01 (存活, 延迟: 110ms, UDP:支持)
│
└── [6] 终结出站节点 (Leaf Outbound)
    ├── 节点名称: 香港-01
    ├── 出站类型: proxy
    ├── 远程地址: 1.2.3.4:443
    ├── UDP 支持: 支持
    ├── 决策总耗时: 70 µs (全流程瞬时完成)
    └── 决策全路径: [Rule 1: EXPR] -> PROXY > PROXY(url-test) -> 香港-01
================================================================================
```
- **CLI 原生 `--json` 格式化**：直接产出标准 JSON 数据，供脚本、前端面板、外部巡检与监控调用；
- **在线实时 REST API**：后台守护进程开放 `GET/POST /routes/explain` 端点，无需重启即可动态模拟任何目标与进程的分流路径。

### 📝 P2. 现代声明式配置 DSL (`.vp`) 与 Google CEL 表达式引擎
分流规则的本质是元编程逻辑！现在你可以用最直观的语法编写全量配置 (`config.vp`)：
```dsl
inbound mixed {
    listen: "127.0.0.1:7890"
}

node "香港-01" vless {
    server: "hk.example.com:443"
    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811"
    flow: "xtls-rprx-vision"
    tls: reality {
        sni: "www.amazon.com"
        public_key: "abc1234567890"
        short_id: "abcd"
    }
}

group "AUTO" url_test {
    members: ["香港-01", "日本-01"]
    interval: 300s
    tolerance: 50ms
    filter: "(?i)香港"
    fallback: "DIRECT"
}

group "PROXY" select {
    members: ["AUTO", "香港-01", "DIRECT"]
}

route {
    // 进程与端口精确比对（Cost 0 极速短路）
    process.name == "git" && dst.port == 22 => "PROXY"

    // 协议、端口与域名后缀复合匹配
    net == "tcp" && dst.port in [80, 443] && host.endsWith(".google.com") => "AUTO"

    // IP CIDR 与源 IP 网段判断
    dst.ip in "10.0.0.0/8" || src.ip in "192.168.1.0/24" => "DIRECT"
    dst.ip in "127.0.0.0/8" => "DIRECT"

    // GeoIP 国家代码
    geoip == "CN" => "DIRECT"

    // 通配兜底
    _ => "PROXY"
}
```
- **Pratt 算符优先级攀爬算法**：严格保证 `&&`、`||`、`!`、`in`、`==`、`!=` 优先级无歧义；
- **基于评估开销的自动重排序优化**：Cost 0 端口/协议整数比对优先执行，纳秒级快速短路跳出；
- **全格式 100% 向后兼容**：既支持独立的 `.vp` 脚本，也完全支持在传统 Clash YAML 的 `rules` 中直接嵌入单行 CEL 表达式。

### 🤖 P3. 面向 AI 的大模型专属 Prompt 与文档体系
为了方便用户让 **ChatGPT / Claude / DeepSeek** 根据自然语言一键生成零错误配置，配套推出了完善的文档：
- **语法规范与速查手册**：详见项目文档 [`docs/dsl.md`](docs/dsl.md)；
- **开箱即用 AI Prompt**：复制文档中第四章的专属 Prompt 丢给任何大语言模型，即可通过日常对话定制专属代理与分流方案。

### 🌐 P4. 统一中间表示层 (VP IR) 与底层解耦重构
- **独立纯数据结构层 (`crates/vp-ir`)**：解耦所有外部序列化细节与运行时协议栈；
- **多源汇聚前端**：Clash YAML、JSON5、外部订阅链接和 `.vp` DSL 统一无损降维至 `VpIr`；
- **运行时纯净装配**：`vp-app` 重构为直接消费 `VpIr` 的装配内核 `App::start_from_ir`。

### 📱 P5. 移动端与全平台发布包矩阵 (Desktop & Mobile SDKs)
全套桌面二进制与移动端 SDK 同步发布：
- **Desktop 桌面端**：Windows (`x86_64-pc-windows-msvc`)、Linux Musl (`x86_64` / `aarch64`)、macOS (`x86_64` / `aarch64 Apple Silicon`)；
- **Android SDK**：包含 `arm64-v8a`、`armeabi-v7a`、`x86_64` 预编译动态库与 Kotlin 原生封装；
- **iOS / macOS SDK**：包含 Apple 官方标准 `VPCore.xcframework` 与 Swift Package Manager 支持；
- **纯血鸿蒙 NEXT SDK**：专为 HarmonyOS NEXT / OpenHarmony 设计的 ArkTS + Node-API C++ 桥接包。

### ⚡ 极速体验与升级指南
- **客户端平滑自我更新**：
  ```bash
  vpcore update
  ```
- **体验全新链路诊断**：
  ```bash
  vpcore explain https://www.google.com -c config.yaml
  ```
- **校验配置有效性**：
  ```bash
  vpcore validate -c config.yaml
  ```

---

# 🚀 VP_Core v1.6.3 发布说明 / Release Notes

🎉 欢迎使用 **VP_Core v1.6.3**！本版本聚焦 **REALITY 客户端证书公钥校验对齐 Xray 行为（支持非 Ed25519 真实伪装站证书平滑回退 WebPKI） + Linux 守护进程 Broken Pipe 递归 Panic 引发 SIGABRT 崩溃根除 + 真实网络节点端到端校验**：

### ⚡ P1. REALITY 客户端证书公钥校验拦截修复（对齐 Xray 规范） (`vp-transport`)
- **取消强制 32 字节 Ed25519 断言**：彻底解决服务端下发目标伪装网站（如 `tesla.com` 等）真实证书（RSA-2048 270 字节 SPKI 或 ECDSA 证书）时，客户端报错 `protocol: utls reality: 证书公钥长度 270 != 32 字节 (非 Ed25519)` 并阻断连接的问题；
- **优雅回退 WebPKI 校验链**：在握手 `HS_CERT` 阶段，若对端返回定制 32 字节 Ed25519 证书则执行 HMAC-SHA512 签名防篡改校验并跳过 WebPKI；若为非 Ed25519 证书，保持 `reality_verified = false` 并平滑回退至后续标准 WebPKI 证书链与 SNI 校验，行为完全对齐 Xray；
- **动态适配 X.509 TBSCertificate 结构**：重构 `extract_spki`，支持根据首元素 tag 动态识别 X.509 v1 与 v3 规范，精准定位 SPKI 证书公钥；
- **真实订阅库与节点端到端实测验证**：在本地 2,828 个 REALITY 节点真实测试中全线通过，成功打通 Cloudflare 与 Microsoft 混合代理访问。

### 🛡️ P2. Linux 守护进程 Broken Pipe 递归 Panic 引发 SIGABRT 崩溃根除 (`vp-bin`)
- **系统层 SIGPIPE 信号主动忽略**：在 Unix 入口主动设置 `libc::signal(libc::SIGPIPE, libc::SIG_IGN)`，杜绝因对端 socket 或日志管道断开引发系统级强杀；
- **智能识别管道中断并重定向 `/dev/null`**：在全局 panic hook 中精准过滤 `Broken pipe`、`os error 32`、`failed printing to stderr` 等由标准流写入失败引起的 panic，自动调用 `libc::dup2` 将 stdout / stderr 重定向至 `/dev/null`，避免再次写入破损流；
- **`catch_unwind` 日志隔离机制**：针对非破损流 panic 使用 `std::panic::catch_unwind` 进行安全打印，彻底防止 panic 处理期间二次 panic 触发 Rust runtime `abort()` (SIGABRT)；
- **热重载事件循环日志改造**：将主循环与 SIGHUP 处理逻辑中的裸 `println!` / `eprintln!` 全面升级为结构化 `tracing::info!` 与 `tracing::error!`。

---

# 🚀 VP_Core v1.6.2 发布说明 / Release Notes

🎉 欢迎使用 **VP_Core v1.6.2**！本版本聚焦 **全协议传输层高并发稳定性根治 + 防火墙 ECH 静默丢包超时自愈 + REJECT 规则静默拦截与 502 告警根除 + DNS 容灾平滑降级**：

### ⚡ P1. 传输层稳定性重构：根除 WebSocket 分帧异步重发导致的数据损坏 (`vp-transport`)
- **异步分帧写入状态机严格对齐 Tokio 契约**：彻底重构 `WsStream::poll_write` 实现，当底层 TCP 发送缓冲区被打满导致 `flush_pending` 返回 `Pending` 时，前置拦截并保持未消费状态；排空缓冲区后严格按 16KB 单帧编码并仅返回已吸纳字节数；
- **根除重复发包与流解密校验失败**：杜绝因调用方重复重试触发同一数据块被二次编码发出的严重缺陷，彻底解决大流量传输（如 YouTube 4K 播放、大文件下载）与高并发场景下的突发断流与 TCP RST 掐线。

### 🛡️ P2. 防火墙 ECH 静默黑洞丢包超时自愈与自动回退 (`vp-transport`)
- **引入 ECH 2.5s 独立超时探测**：针对大陆防火墙（GFW）对含 ECH（Encrypted Client Hello）扩展的 TLS 握手包实施全网静默丢包（黑洞）策略，引入 2.5 秒快速熔断保护；
- **自愈式普通 TLS 快速重拨**：当检测到 ECH 握手超时或被服务端拒绝时，自动标记该主机屏蔽 ECH 并立即以普通 TLS 重新拨号，将原先 10~30 秒的死等超时降至 200ms 快速自愈秒连。

### 🚫 P3. 规则拦截规范化：REJECT 静默阻断与 502 Bad Gateway 根除 (`vp-protocol`)
- **HTTP 入站阻断行为对齐成熟内核**：彻底修复 `RejectOutbound` 向上抛出 `Error::Unsupported` 导致 HTTP 入站向客户端回写 `HTTP/1.1 502 Bad Gateway` 并疯狂打印 Warn 日志的问题；
- **标准 403 Forbidden 响应**：命中广告拦截或自定义 REJECT 规则时，降级为友好 Info 日志并回传轻量 `403 Forbidden` 立即关闭，杜绝系统后台上报触发的代理网关故障报警。

### 🌐 P4. DNS 直连解析查空平滑降级与 Windows 网络状态保障 (`vp-dns`, `vp-protocol`)
- **NODATA 查空自动降级系统解析**：针对微软 NCSI 网络探测域名（`ipv6.msftncsi.com` 等纯 AAAA 域名）在默认非 IPv6 模式下请求 A 记录返回空答案的情况，增加系统原生解析器二次兜底与自动 AAAA 探测；
- **彻底消除 Windows 误报“无 Internet 访问”**：解决系统因直连解析失败弹出黄色感叹号与无法上网的误判。

---

# 🚀 VP_Core v1.6.1 发布说明 / Release Notes

🎉 欢迎使用 **VP_Core v1.6.1**！本版本聚焦 **移动端 TUN 虚拟网卡 epoll 异步事件驱动架构重构 + Android/Unix 外部 FD 阻塞死锁根除 + 移动网络切换与高并发防断连稳定性提升**：

### ⚡ P1. 移动端 TUN 设备基于 epoll / AsyncFd 纯异步重构 (`vp-tun`)
- **彻底根除字符设备阻塞式 read 死锁**：废弃原先将 `/dev/tun` 包装为 `tokio::fs::File` 走 `spawn_blocking` 线程池的缺陷实现，避免后台阻塞读线程在 `tokio::select!` 超时或取消时无法中断导致的线程池耗尽与死锁；
- **原生 Linux / Android epoll 事件驱动**：采用 `tun::create_as_async` 封装外部 FD 注入模式，底层基于 Tokio `AsyncFd` 实现全事件驱动，零多余线程开销，实现微秒级网络包唤醒与极速转发；
- **无缝对接 Android VpnService 非阻塞模式**：完美支持 `VpnService.Builder.setBlocking(false)`，彻底消除在移动端 Android/Unix 环境下的网络假死与丢包。

### 🛡️ P2. 移动端网络生命周期与 DNS 稳定性增强
- **配合 Android 底层承载网络保活**：支持与 Android `setUnderlyingNetworks` 和 `NetworkCallback` 联动，杜绝 Android 30 秒 `handleLingerComplete` 引发的 `agentDisconnect` 异常断线；
- **Fake-IP 移动端极速劫持保障**：优化 TUN 私有网段 UDP 53 DNS 拦截与响应逻辑，杜绝移动端网络栈 TLS 853 / DoT 探测阻断。

---

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

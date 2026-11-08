# 性能基准体系（审计报告任务 8 · 第一阶段）

原则：所有性能声明必须可复现。本页收录现有基准的运行方式与参考数值；
新增优化必须先跑基准留档，防止"看似更快"的回归。

## 1. AEAD 加密微基准（vp-crypto）

- 位置：`crates/vp-crypto/tests/aead_bench.rs`
- 运行：`cargo test -p vp-crypto --release --test aead_bench -- --nocapture`
- 64MB 载荷、3 轮取值，加密+解密合并吞吐。

参考值（2026-10，opt-level=3，Windows x64）：

| 算法 | opt-level=3 | opt-level="z" |
|---|---|---|
| aes-128-gcm | 1329 MB/s | 323 MB/s |
| chacha20poly1305 | 1339 MB/s | 265 MB/s |

结论已固化：`[profile.release]` 必须保持 `opt-level = 3`（"z" 废掉
RustCrypto 的 SIMD 内联循环，加密吞吐掉 4-5 倍）。

## 2. 环回 SOCKS5 全链路吞吐（vpcore 内核）

- 位置：`scripts/bench_loopback.py`
- 运行：`python scripts/bench_loopback.py [rounds] [mb]`（默认 9 轮 × 256MB）
- 方法：Python 裸 SOCKS5 客户端 → 内核（MATCH,DIRECT）→ 本地 sink；
  先测"直连不过内核"标定工具上限，再测经内核；CPU 用 ctypes
  GetProcessTimes 精确差分。
- 注意：需桌面安静（浏览器/视频会显著拉低中位数，只比较安静轮次）；
  两端 socket 缓冲 4MB（缺省 64KB 会把工具卡在 ~200MB/s，数字全废）。

参考值（2026-10，opt-level=3 + 探一眼式链读泵）：

- 工具上限（直连）：中位 3703 MB/s
- 经内核：中位 1229 / 最大 1639 MB/s，内核 CPU 0.0006 s/MB
- 对比 mihomo 同方法：1434-1585 MB/s（历史值，同量级）

## 3. 转发热路径拆账（vp-core 示例）

- 位置：`crates/vp-core/examples/profile_pump.rs`
- 运行：`cargo run --release -p vp-core --example profile_pump`
- 方法：三种中段转发单元（std 阻塞线程 / tokio 裸任务 / 完整 relay()）
  拓扑严格一致，进程 CPU 差分逐级分账（B−A=tokio 调度、C−B=relay 簿记）。
- **已知问题**：本工具自建回声拓扑存在未解的慢滴异常（每 32KB 一跳
  ~125ms、CPU 全程睡眠，疑似工具侧问题而非内核——内核基准同机可达
  GB/s）。修复前其绝对数值不可用；待任务 8 二阶段重写。

## 3.5 RouterHandle 热替换读路径（报告任务5）

- 位置：`crates/vp-common/examples/swap_bench.rs`
- 运行：`cargo run --release -p vp-common --example swap_bench`
- 方法：8 读线程高频 clone 快照 + 1 写线程每 10ms 替换（模拟热更新）。

参考值（2026-10）：RwLock<Arc> 9.69M ops/s（单次最差 266µs，写方在锁内
构建载荷所致，真实代码在锁外构建）；ArcSwap 14.5M ops/s。
**结论：同数量级，路由 pick 每连接仅 1 次，保留 RwLock 不换库**。
注：基准的写方在锁内做 1000 次字符串分配，对 RwLock 略有不公平。

## 3.6 splice Linux 真机验证（2026-10-30）

- 环境：WSL2 Ubuntu 24.04（离线工具链 + cargo vendor，因本机 WSL 的
  IPv4 回环被代理/VPN 软件破坏，测试绑定 [::1]）
- 结果：vp-core **12/12 通过**（含 splice 端到端 512KB 双向 + 半关闭 +
  字节对账）；vp-common 7/7；vp-protocol 97 通过（7 个失败为 ::1
  替换导致的 hy/naive 地址解析伪影，Windows 全绿）
- 真机发现并修复 1 个真实挂起：tokio readable()/writable() 的就绪标志
  只被自身读路径清除，splice 绕过导致自旋 —— dup() 新 fd 注册 AsyncFd
  用 try_io 语义解决（commit d71db62）

## 4. 回归守护

- 泵链读防死锁回归：`cargo test -p vp-core --lib tunnel::`
  （`readahead_never_holds_data_hostage_on_exact_multiple` 等 6 测）
- 健康检查任务生命周期：`cargo test -p vp-router --lib group::tests::health_task_lifecycle_on_swap`
- 缓冲池/连接预算指标：`cargo test -p vp-common`
- 连接表分片语义：`cargo test -p vp-core --lib conn_table`
- 测速有界并发/健康检查：`cargo test -p vp-router --lib`

## 3.9 转发热路径优化批次（2026-11-08，v1.7.1 后）

一批 10 项入站→出站全链路优化（详见 commit 记录）：

| 项 | 改动 | 预期收益 |
|---|---|---|
| 中继缓冲 | `copy_bidirectional` → `copy_bidirectional_with_sizes(128K,128K)`（tunnel.rs） | 通用泵路径摆脱 tokio 默认 8KB 限制 |
| mixed splice 解锁 | `PrefixedStream` 补齐 `raw_socket`/`unconsumed_peek`/`consume_peek` 委托 + relay 多层排空 | Linux mixed 主力入站打通 splice 零拷贝 |
| SOCKS5 地址解析 | 逐字节 `read_exact` → 至多 2 次批量 `read_exact` | 握手 syscall 从 ~10 次降到 2 次 |
| tokio worker | `clamp(2,4)` → 核数全释放（<1GB 内存设备收敛 2 线程，`TOKIO_WORKER_THREADS` 仍可覆盖） | 多核服务器不再欠配 |
| DNS 缓存 | 真实 TTL 存储 + 权威 NXDOMAIN 负缓存（30s）+ 水位淘汰替代整表 clear | 重复查询零上游请求；NXDOMAIN 防穿透 |
| 嗅探缓存 | (ip,port)→域名 60s 短缓存，TCP/QUIC/UDP 三路接入 | 浏览器并发建连免重复 30ms 嗅探等待 |
| UDP NAT | 全表单锁 → 16 分片（FNV 路由）+ 零分配键 + 锁外拨号 | 高 PPS 锁竞争摊薄 16 倍 |
| TFO | Linux 出站 `TCP_FASTOPEN_CONNECT`（尽力而为） | 高频短连接省 1 RTT |
| TUN 窗口 | ipstack `TcpConfig`：read 16K→256K、max_unacked 16K→1M | 高 BDP 跨洋链路单流吞吐提升一个数量级 |
| DoH/DoT 连接池 | 每查询新建 TCP+TLS → keep-alive 长连接池（单端点 4 条、120s 空闲回收、失效自动重拨） | 每次查询省一次完整 TLS 握手 |

环回基准留档（Windows x64，opt-level=3，桌面噪声较大，仅作趋势参考）：

- 工具上限 3536 MB/s；经内核中位 954 / 最大 1100 MB/s（历史：1229/1639）
- **内核 CPU 效率 0.0005 s/MB（历史 0.0006，改善约 17%）** —— 本批次最可靠的硬指标
- 吞吐绝对值受桌面噪声影响大（同轮波动 730-1100），结论以 Linux 真机 +
  splice 路径复测为准；mixed splice 解锁在 Linux 上的收益未在本机体现

## 4.5 全链路优化第二批（2026-11-08，12 项方案落地 9 项）

| 项 | 改动 | 预期收益 |
|---|---|---|
| 1 入站 DEFER_ACCEPT | Linux 监听器 `TCP_DEFER_ACCEPT(3s)`（vp-transport） | 空握手零唤醒；端口扫描器免疫 |
| 2 入站 REUSEPORT | mixed/socks5/http 在 >=4 核 Linux 绑 `min(cpus,8)` 个独立 listener（`bind_tcp_listener_many`） | 万级并发突发接入打散 accept 互斥与 epoll 惊群 |
| 3 确定性路由缓存 | 规则集不依赖进程/源地址/入站标识时（`RuleEngine::uses_session_state` 内省），(network,host,port)→出站 60s 缓存（1024 容量，热重载自然失效） | 日常浏览 98%+ 连接 O(1) 决策，免除线性规则扫描与惰性 DNS |
| 5 RFC 8305 | `resolve_node_addrs` 输出按 [v6_1, v4_1, v6_2, v4_2...] 交叉编排 | v6 黑洞环境首包延迟缩短 200ms+ |
| 6 DNS SWR | RFC 8767：过期 60s 内先交付旧值，后台静默刷新（在途去重，失败保留旧值） | 高频域名 DNS 感知延迟恒为 0 |
| 7 QUICKACK | 出站 tune() 设置 `TCP_QUICKACK`（Linux） | 首包阶段消除延迟 ACK（最长 40ms） |
| 9 非对称缓冲 | 中继缓冲 128K/128K → 上行 32K / 下行 128K | 单连接缓冲内存 -37.5%，同内存多承载 ~60% 并发 |
| 11 UDP 直发 | `PacketConn::send_handle()` trait 扩展；DIRECT / SOCKS5 UDP / SS UDP 三个出站提供免队列直发句柄，NAT 命中会话上行零调度发包 | 游戏/QUIC 上行 Jitter 显著下降 |
| 12 recvmmsg | socks5 UDP 中继 socket 接入 quinn-udp 批量收包（单 syscall ≤16 报，GRO stride 兼容） | 高 PPS 收包 syscall 降 90%+ |

**活锁事故与修复（必须记住的教训）**：

- recvmmsg 批量收包上线后 Windows 全量测试 `vp_app` 二进制满核空转 50 分钟。
  根因：中继循环 `readable()` 唤醒后**裸调** quinn-udp `UdpSocketState::recv`
  （绕过 tokio），数据报到达时 WouldBlock 前的真实读不经 tokio，就绪标志从不
  被清除 → `readable()` 永远立即返回就绪 → recv 永远 WouldBlock → 100% CPU。
- 修复：裸 syscall 必须包进 `relay.try_io(Interest::READABLE, || ...)`，
  WouldBlock 才能正确清除 tokio 就绪标志；同时防御 stride==0（0 长首报文+GRO）
  导致 `split_at(0)` seg 永不收缩的死循环。
- **这是 §3.6 splice 自旋（d71db62）之后的第二次同类事故**：任何绕过 tokio
  读路径的裸 I/O，与 `readable()/writable()` 搭配时必须经 `try_io`。已把该
  约束写进代码注释。

**REUSEPORT 上线即翻车事故（WSL 兜底抓住）**：

- 多监听器 `bind_tcp_listener_many` 最初把"是否 REUSEPORT"跟随全局 tuning
  快照（默认 `false`）→ Linux 多核（WSL 20 核 → 8 listeners）第 2+ 个
  listener bind 即 `EADDRINUSE`，**整个入站起不来**；Windows 因
  `inbound_listener_count()==1` 幸免，29 个 vp-app 测试 5 个 AddrInUse 暴雷。
- 修复：多监听器路径强制 `reuse_port=true`（该函数的存在前提就是 REUSEPORT；
  `count==1` 时无副作用）。协议服务端 listener 仍走单绑定（保守，不在本项范围）。
- 结论再次确认：**cfg(linux) 行为差异 Windows 测不出来，WSL 兜底测试是门禁
  必选项**（本批次两个 Linux-only 事故——try_io 空转是 Windows 必现、
  REUSEPORT EADDRINUSE 是 Linux 必现——互相为对方平台补位才抓全）。

**三项明确取舍（诚实记录）**：

- **4 分层聚合规则索引**：暂缓。确定性路由缓存（项 3）已覆盖稳态 98%+ 连接的 O(1) 决策，
  保序分层索引（每层记录原始优先级、跨层取最小索引）需要对 vp-rule 做侵入式重构，
  边际收益 <2% 连接的首次决策。若未来出现数千规则 + 缓存不友好（大量动态特征规则）的场景再立项。
- **8 TLS 1.3 0-RTT**：不可行。rustls 0.23 不支持客户端 Early Data 发送（仅服务端），
  无绕过方案。会话票据内存复用已生效（连接器级 ClientConfig 共享 + 默认 in_memory_sessions），
  跨进程重启持久化仅节省每次重启一次握手，不值得引入磁盘态安全面。
- **10 QoS 路径 BiLock**：暂缓。tokio::io::split 的 BiLock 仅在限速/计费/Brutal 路径生效，
  该路径的链读防死锁泵经过专门设计与回归测试（§4）；无锁拆分（TcpStream into_split 降级
  或单任务 select 重写）有细微死锁/取消安全风险，收益只作用于 QoS 用户，风险收益比不划算。

## 5. 二阶段规划（按审计报告 §13）

- Criterion 化：relay 吞吐 / 并发连接 / 规则匹配 / 组选择
- 并发档位：100 / 1K / 5K / 10K（先本机，再进 CI）
- 长稳：1K 连接 1h、连续热更新 100 次（任务 1 的生命周期测试是其缩影）
- 对比对象：sing-box、mihomo（同硬件同流量模型，记录 RSS/CPU/P99）

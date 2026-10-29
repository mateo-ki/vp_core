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

## 5. 二阶段规划（按审计报告 §13）

- Criterion 化：relay 吞吐 / 并发连接 / 规则匹配 / 组选择
- 并发档位：100 / 1K / 5K / 10K（先本机，再进 CI）
- 长稳：1K 连接 1h、连续热更新 100 次（任务 1 的生命周期测试是其缩影）
- 对比对象：sing-box、mihomo（同硬件同流量模型，记录 RSS/CPU/P99）

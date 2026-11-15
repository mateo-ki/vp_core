# AGENTS.md

VP_Core（D:\project\rust\VP_Core）：纯 Rust 代理内核（vpcore）。workspace：vp-bin / vp-app / vp-core / vp-protocol / vp-config / vp-common / vp-crypto / vp-dns / vp-ir / vp-dsl / vp-plugin / vp-plugin-sdk / vp-router / vp-tun / vp-transport。未发布 crates.io。

## 硬规则：每次提交都要极致测试

pre-commit 钩子（core.hooksPath=scripts/githooks）机械强制。本地必须完整复现 CI（.github/workflows/ci.yml）每一步，全绿才允许 commit：

1. `mkdir -p target/debug/examples`（ipstack 构建脚本规避，CI 同款，勿删）
2. `cargo fmt --all -- --check`
3. `cargo clippy --workspace --all-targets -- -D warnings`
4. `cargo test --workspace`
5. DSL 门：`cargo run -q -p vp-bin -- validate -c example/config.vp` + `cargo run -q -p vp-bin -- fmt --check example/config.vp`（OS error 32 = vpcore.exe 被运行中的实例占用，先停再跑）
6. 改了 vp-protocol 的协议实现（监听器/出站）：必须加跨内核实测矩阵 —— target/matrix/ 的 vpcore_server + mihomo_client 配置，每个被改协议做 vpcore↔mihomo 双向（作为监听端 + 作为出站端）真测，curl 一律 `--noproxy ""`

白名单免测（钩子内置）：`*.md`、`*.txt`、`*.png`、`*.ico`、`.github/*`、`scripts/githooks/*`。`FORCE_FULL_GATE=1` 可无视白名单强制全门。

## 实测纪律（历史教训，违反过且付出过代价）

- loopback 测试 curl 必须 `--noproxy ""`：curl 对 127.0.0.1 默认绕过代理，不加就是直连，结果全假
- 起测试实例前先清点端口占用（`netstat -ano` / Get-CimInstance），杀净残留进程再跑 —— 残留实例曾反复污染测试结果
- 杀进程禁用过宽的 CommandLine 模糊匹配（曾误杀用户正在用的 mihomo，端口 17898）；按 netstat 的 PID 精确杀
- sing 系服务端懒应答：snell/hy2 握手同步等应答会死锁，解析必须延迟到流首读（sing clientConn.Read 语义）
- tokio `poll_read` 里用 `ready!` 前必须保证 Pending 返回前恢复已累积状态（cancel-safety）—— snell gate / hy2 resp_acc 各踩过一次
- H3 关键流（control / QPACK encoder / decoder）必须 drain 到 EOF 且持有到连接结束，RecvStream/SendStream 过早 drop 都会让 quic-go 报 H3_CLOSED_CRITICAL_STREAM
- QUIC varint 是 2-bit 长度前缀（00=1B/01=2B/10=4B/11=8B），不是 HPACK 风格的 continuation bit
- GitHub 源码 tarball 用 ghfast.top 镜像拉取（raw.githubusercontent 限流）；jsdelivr 数据 API 可用

## 提交纪律

- 一个主题一个提交；提交前 `git diff --stat` 自查，不改无关文件
- 提交信息用中文 + conventional 前缀（feat/fix/chore，与 git log 历史一致）
- push 需用户明确要求；push 走 127.0.0.1:9980 代理

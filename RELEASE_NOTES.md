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

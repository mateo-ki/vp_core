# VP_Core 功能增强实施方案：REALITY 协议、热重载完善、Rule-Provider 在线刷新

针对用户的“1、2、4 都做，3（插件市场装配）先放一放”的要求，本方案系统性设计并规划这三大特性的实现与测试。

---

## 一、特性 1：REALITY 协议扩展（VLESS / Trojan / 通用 TLS 客户端）

### 1.1 核心线格式与规范（对标 Xray-core / sing-box）
- **客户端密钥与参数**：
  - `public_key` / `pbk`：服务端静态 Curve25519 公钥（32 字节，Base64 URL-safe / Hex 解码）；
  - `short_id` / `sid`：服务端 short-id（0~8 字节 Hex，不足 8 字节补零）；
  - `server_name` / `sni`：目标伪装域名（如 `www.apple.com`）；
  - `spider_x` / `spx`：爬虫探测路径。
- **握手认证机制**：
  - 客户端生成临时 Curve25519 密钥对 `(client_eph_pri, client_eph_pub)`，将 `client_eph_pub` 写入 ClientHello `key_share`（group 0x001d）；
  - 计算协商秘密：$\text{auth\_secret} = \text{X25519}(\text{client\_eph\_pri}, \text{server\_static\_pub})$；
  - 派生认证密钥：$\text{aead\_key} = \text{HKDF-SHA256}(\text{auth\_secret}, \text{salt} = \text{random}[0..20], \text{info} = \text{"REALITY"}, \text{len} = 32)$；
  - 组装 16 字节明文载荷：`[1, 8, 1, 0, unix_secs_be(4), short_id(8)]`；
  - 使用 AES-256-GCM 加密载荷，`nonce = random[20..32]`，`AAD = ClientHello`（此时 `session_id` 填 32 个零字节）；
  - 密文 16B + Tag 16B = 32B，写入 `ClientHello.legacy_session_id`。
- **服务端响应与证书验签**：
  - 服务端回送 ServerHello（包含临时 `server_eph_pub` 并 echo `session_id`）；
  - 在后续 EncryptedHandshake 中，REALITY 服务端下发特殊 Ed25519 证书；
  - 客户端提取证书中 32B Ed25519 公钥，验证签名是否等于 $\text{HMAC-SHA512}(\text{aead\_key}, \text{ed25519\_pubkey})$；
  - 若匹配，则服务端通过认证，客户端跳过系统根证书 WebPKI 校验，完成 Finished 握手并进入应用数据流传输。

### 1.2 涉及文件与修改内容
1. `crates/vp-config/src/model.rs`：
   - 新增 `RealityOpts` 结构体（`public_key`, `short_id`, `spider_x`）；
   - 在 `VlessCfg` 与 `TrojanCfg` 中增加字段 `pub reality_opts: Option<RealityOpts>`（aliases: `reality-opts`, `reality_opts`）。
2. `crates/vp-transport/src/lib.rs` & `crates/vp-transport/src/utls.rs`：
   - 在 `TransportConfig` 中新增 `reality: Option<RealityConfig>`；
   - 在 `utls.rs` 中扩展握手引擎：当 `reality` 启用时，执行 REALITY 认证流程并在解析服务端证书时校验 `HMAC-SHA512`；
   - 密码学计算复用已有 `ring` 依赖（X25519 agreement、AES-256-GCM、HMAC-SHA512），零新增依赖。
3. `crates/vp-protocol/src/vless.rs` & `crates/vp-protocol/src/trojan.rs` & `crates/vp-protocol/src/lib.rs`：
   - 提取 `reality_opts` 并通过 `transport_of_full` 传入 `TransportConfig`；
   - 更新 `crates/vp-protocol/src/sub.rs`：`parse_vless` 与 `parse_trojan` 支持 `security=reality`、`pbk=...`、`sid=...`、`spx=...`。
4. **测试**：
   - 构造最小 REALITY 服务端握手与客户端自环测试：验证正确密钥/short_id 成功通信，错误密钥/篡改证书阻断。

---

## 二、特性 2：热重载（Hot-Reload）完善

### 2.1 现有问题
- 目前 `App::reload()` 仅使用内存中初次读取的配置字符串，修改磁盘文件后调用 reload 无法生效；
- Windows 平台没有 Unix `SIGHUP` 信号，在控制台运行无平滑重载触发入口；
- `api.rs` 的 `PUT /configs` 尚未解析 JSON 请求体中的 `{"path": "..."}`。

### 2.2 解决方案与涉及文件
1. `crates/vp-app/src/lib.rs`：
   - 将 `config_text: RwLock<Option<(String, Format, PathBuf)>>` 升级为保留配置文件真实路径 `config_path: Option<PathBuf>` 的共享结构 `Arc<RwLock<ConfigMeta>>`；
   - `App::reload(&self)`：若配置来源为文件，先从磁盘异步重读最新文本（`tokio::fs::read_to_string`）；
   - 重新执行 `assemble_for_reload`，若校验或解析失败，保留当前路由器并报错，保证服务零中断；
   - 若成功，调用 `router_handle.swap(...)` 平滑切换路由规则与出站表。
2. `crates/vp-bin/src/main.rs`：
   - 在 `Cmd::Run` 的主事件循环中，利用 `tokio::time::interval(1s)` 配合 `std::fs::metadata(&config).modified()` 监控配置文件修改时间（mtime）；
   - **跨平台通用**（Windows、macOS、Linux 一致支持）：保存配置文件立即自动触发平滑热重载，无需按快捷键或重启进程；
   - 同时保留 Unix 下的 `SIGHUP` 信号支持。
3. `crates/vp-app/src/api.rs`：
   - `PUT /configs` 增强：支持从请求体 JSON（`{"path": "..."}`）提取目标路径，若无参数则默认重新读取当前运行的配置文件磁盘内容。
4. **测试**：
   - 编写自动化测试：启动 App 后动态修改临时磁盘配置文件，断言 `app.reload()` 正确应用新增代理节点与路由规则。

---

## 三、特性 4：Rule-Provider 在线订阅拉取与定时刷新

### 3.1 现有问题
- 目前 `load_providers` 仅支持同步读取本地存在的文件（必须配置 `path`），若配置 `url` 或 `interval` 会被忽略；
- 如果每次更新 rule-provider 都完整重建 App，会导致已有的策略组、延时统计、Selector 手动选择被重置。

### 3.2 解决方案与涉及文件
1. `crates/vp-config/src/model.rs`：
   - `RuleProviderCfg` 增加 `#[serde(rename = "type", default)] pub kind: Option<String>`（兼容 `type: http` / `type: file`）；
   - 若配置了 `url` 且未提供 `path`，自动默认缓存路径为 `.cache/{name}.txt`。
2. `crates/vp-app/src/lib.rs`（在线拉取与离线降级）：
   - 在 `vp-app/Cargo.toml` 中引用已在 workspace 内声明的 `ureq.workspace = true`；
   - 启动加载时，若包含 `url`，先发起 HTTP GET 拉取内容（带超时），并尝试用 `vp_rule::provider::load_payload` 校验；
   - 校验成功后写入磁盘缓存文件，保证断网或重启离线时直接降级读取缓存；若拉取失败且缓存存在，打出 warn 日志并降级使用本地缓存。
3. `crates/vp-router/src/lib.rs`（原子平滑规则替换）：
   - 新增方法 `Router::clone_with_rules(&self, rules: RuleEngine) -> Arc<Router>`；
   - 保持所有的 `groups`、`outbounds`、`dns` 不变，仅更新规则引擎，彻底保留节点的历史延时记录与手动 Selector 选择状态。
4. `crates/vp-app/src/lib.rs`（后台定时刷新任务）：
   - 对所有配置了 `interval > 0` 的 HTTP rule-provider，在 `start` 时启动后台定时协程；
   - 定时从 `url` 拉取最新内容，若内容有变动且校验通过，写入磁盘缓存并重编译规则，调用 `router_handle.swap(...)` 实现零连接中断的规则热生效。
5. **测试**：
   - 模拟 HTTP 本地服务器返回 provider 内容，验证首次启动拉取、离线文件缓存降级、后台 interval 触发重编译和热替换生效。

---

## 四、实施顺序

1. **第 1 阶段（特性 2：热重载完善）**：
   - 改造 `App` / `ApiState` 配置元数据，实现从磁盘重读配置文本；
   - 在 `vp-bin` 中加入跨平台 mtime 文件轮询热重载与 Unix SIGHUP 统一；
   - 完善 `PUT /configs` 接口；
   - 运行测试并验证。
2. **第 2 阶段（特性 4：Rule-Provider 在线拉取与定时刷新）**：
   - `vp-config` 兼容字段与默认缓存路径；
   - `vp-router` 增加 `clone_with_rules`；
   - `vp-app` 实现 HTTP GET 拉取 + 离线缓存降级 + 后台 interval 自动热更新；
   - 编写单测并验证。
3. **第 3 阶段（特性 1：REALITY 协议扩展）**：
   - `vp-config` 增加 `RealityOpts`；
   - `vp-transport` / `utls.rs` 实现完整的 REALITY ClientHello 认证与 Ed25519 签名校验；
   - `vp-protocol` 中接线 VLESS / Trojan / sub 订阅解析；
   - 编写 REALITY 自环与认证拒绝测试。
4. **第 4 阶段（全 Workspace 回归与 README）**：
   - 运行全 workspace 单元测试与端到端测试；
   - 更新 README 协议矩阵与功能说明，完成代码提交。

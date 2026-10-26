# VP_Core 4项重大特性联合实施方案

本方案针对用户明确要求的 4 项重大特性进行系统性架构设计与分步实施规划：
1. **Proxy-Provider 代理集合订阅与后台自动刷新**（对标 Clash.Meta / mihomo）
2. **VLESS XTLS-rprx-vision 真实流控**（Vision 协议头、内层 TLS ClientHello 填充伪装与帧化直通）
3. **Snell 协议出+入站**（v1 / v2 / v3 / v4，PSK 鉴权、ChaCha20-Poly1305 / AES-128-GCM、0-RTT 复用与 HTTP/TLS 混淆）
4. **DNS 分流策略增强**（`nameserver-policy` 域名/GeoSite 专有分流 + `fallback-filter` GeoIP/CIDR 污染过滤）

---

## 一、特性 1：Proxy-Provider 代理集合订阅与后台自动刷新

### 1.1 架构与设计
- **配置模型**（`vp-config::model`）：
  - 新增 `ProxyProviderCfg`：
    ```rust
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct ProxyProviderCfg {
        #[serde(rename = "type", default)]
        pub kind: Option<String>,       // "http" 或 "file"
        pub url: Option<String>,
        pub path: Option<String>,       // 离线缓存路径或本地文件
        pub interval: Option<u64>,      // 刷新周期（秒）
        pub filter: Option<String>,     // 节点名正则表达式过滤
        #[serde(alias = "health-check", alias = "health_check", default)]
        pub health_check: Option<ProviderHealthCheckCfg>,
    }
    ```
  - `Config` 新增字段：`pub proxy_providers: HashMap<String, ProxyProviderCfg>`（别名 `proxy-providers`）。
  - `GroupCfg` 新增字段：`pub r#use: Vec<String>`（别名 `use`），支持通过引用 provider 名称动态汇入节点。
  - `vp-config::validate` 放宽校验：若策略组配置了 `use: [...]`，允许 `proxies: [...]` 为空；校验所引用的 provider 是否已在 `proxy_providers` 中声明。
- **订阅多格式解析与节点提取**（`vp-protocol::sub` / `vp-config`）：
  - 支持两类返回载荷：
    1. 标准 Clash YAML 文档（含 `proxies: [...]` 块）：由 `serde_yaml` 直接反序列化为 `Vec<ProxyCfg>`；
    2. Base64 编码或换行分隔的节点分享链接（`vless://`、`vmess://`、`trojan://`、`ss://`、`snell://` 等）：通过 `vp_protocol::sub::parse_subscription` 解析为 `Vec<SubNode>` 并转换为 `ProxyCfg`。
  - 支持 `filter` 正则过滤：仅保留匹配正则表达式的节点名称。
- **在线拉取、离线缓存降级与热装配**（`vp-app`）：
  - 启动时拉取远程 provider 文本（带 15s 超时与 `vpcore/proxy-provider` User-Agent）；
  - 成功则写入本地缓存路径（缺省为 `.cache/{name}.yaml`）；网络异常或断网时自动降级加载本地缓存；
  - 装配时将 provider 解析出的节点实例化为 `Arc<dyn Outbound>` 注册至全局 `outbounds` 表，并根据 `use: [...]` 将节点名称动态追加到对应策略组中；
- **后台增量定时刷新协程**：
  - 对配置了 `interval > 0` 的 HTTP provider，启动后台定时协程轮询拉取；
  - 当节点列表发生变动时，平滑重新构建策略组与路由器，调用 `router_handle.swap(...)` 实现连接零中断的动态热替换。

---

## 二、特性 2：VLESS XTLS-rprx-vision 真实流控（Vision）

### 2.1 架构与设计
- **VLESS Addons Protobuf 线格式**：
  - VLESS 握手请求头中包含 `addons` 字段：`[VERSION][UUID][Addons Len M][Addons Bytes...][CMD][Port][ATYP][Addr]`。
  - 当 `flow == "xtls-rprx-vision"` 时，构造标准的 protobuf 结构：
    `0x0A 0x10 0x78 0x74 0x6C 0x73 0x2D 0x72 0x70 0x72 0x78 0x2D 0x76 0x69 0x73 0x69 0x6F 0x6E`（Tag 1, String len 16, ASCII `"xtls-rprx-vision"`，共 18 字节）。
  - 服务端握手响应：读取 `[ver 0x00][addon_len]` 并正确消费服务端下发的响应 addons。
- **内层 TLS ClientHello 深度嗅探与长度填充伪装（Padding）**：
  - 连接建立后，客户端嗅探来自本地连接的首包数据：
    - 检查是否为 TLS 握手记录：`ContentType == 0x16`，版本 `0x03, 0x01..0x03`；
    - 检查 Handshake Type 是否为 `0x01`（ClientHello），且 `supported_versions` 扩展中声明了 TLS 1.3（`0x0304`）。
  - **Vision 握手帧化包装**：
    - 帧格式：`[Command: 1B][ContentLength: 2B be][PaddingLength: 2B be][Content Data][Padding Zeros]`；
    - `Command 0x00`（PaddingContinue）：对 ClientHello 添加伪随机填充（填充至 900~1200 字节特征区间），瓦解 DPI 对内层 ClientHello 长度指纹的识别；
    - 服务端回传 ServerHello / Certificate 时同样解包该帧结构并剥离尾部零填充；
    - 握手结束判定：当检测到客户端发送 Finished / ApplicationData（`0x17`）时，客户端发送带有 `Command 0x01`（PaddingEnd）的收尾帧。
- **直通流（Splice / Direct Copy）零开销传输**：
  - 双方完成 `PaddingEnd` 交换后，退出 Vision 帧化状态机，后续所有双向数据全部进入裸流直通（Direct Copy），消除任何重复分帧与封包损耗。
- **订阅与配置互通**：
  - `vp-protocol::sub` 中的 `parse_vless` 提取 `flow` 字段；
  - `vp-protocol::vless` 完整接入 `VlessCfg.flow`。

---

## 三、特性 3：Snell 协议出+入站（v4 / v3 / v2 / v1）

### 3.1 架构与设计
- **协议兼容性**：
  - 完整支持 Surge / Clash.Meta / mihomo 生态规范中的 Snell 协议（版本 v1、v2、v3、v4，缺省为 v4）。
  - 支持 TCP 流代理与 UDP 数据报转发（原生 Snell UDP 机制）。
- **密码学与密钥派生**（零新依赖，复用现有库）：
  - 凭据为 PSK 字符串；
  - v1/v2：HKDF-SHA256(psk, salt, "snell") / SHA256(psk)；
  - v3/v4：采用 16 字节随机 ClientNonce，使用 HKDF-SHA256 派生会话密钥，对称加密采用 `ChaCha20-Poly1305` 与 `AES-128-GCM`。
- **命令与地址格式**：
  - 命令：`0x00` PING，`0x01` CONNECT（TCP），`0x02` UDP；
  - 目标地址编码：`0x01` IPv4 (4B) + Port (2B be)，`0x03` Domain (1B 长度 + 域名) + Port (2B be)，`0x04` IPv6 (16B) + Port (2B be)。
- **混淆层（Obfuscation）**：
  - `obfs: http`：在底层 TCP 连接建立之初首发 HTTP GET/POST 伪装报头（带自定义 Host 与伪随机路径），服务端校验并回送 HTTP 响应头后切入 Snell 加密流；
  - `obfs: tls`：在首包包裹 TLS 1.3 ClientHello 伪装头。
- **组件实现**：
  - `crates/vp-protocol/src/snell.rs`：实现 `SnellOutbound` 与 `SnellInbound`（自建与自环互测）；
  - `crates/vp-config/src/model.rs`：新增 `SnellCfg` 与 `ProxyKind::Snell`；
  - `crates/vp-protocol/src/sub.rs`：支持 `snell://psk@host:port?version=4&obfs=http&host=...#name` 格式解析。

---

## 四、特性 4：DNS 分流策略增强（nameserver-policy / fallback-filter）

### 4.1 架构与设计
- **配置模型**（`vp-config::model`）：
  - `DnsConfig` 增加：
    ```rust
    #[serde(alias = "nameserver-policy", alias = "nameserver_policy", default)]
    pub nameserver_policy: HashMap<String, serde_yaml::Value>,
    #[serde(alias = "fallback-filter", alias = "fallback_filter", default)]
    pub fallback_filter: Option<FallbackFilterConfig>,
    ```
  - `FallbackFilterConfig`：
    ```rust
    pub struct FallbackFilterConfig {
        pub geoip: bool,             // 默认 true
        pub geoip_code: String,      // 默认 "CN"
        pub ipcidr: Vec<String>,     // 污染 IP / Bogon CIDR 列表
        pub domain: Vec<String>,     // 强制走 fallback 的域名
        pub geosite: Vec<String>,    // 强制走 fallback 的 geosite 标签（如 gfw）
    }
    ```
- **Policy 编译与路由匹配引擎**（`vp-dns` & `vp-rule`）：
  - 专有域名匹配器：利用 `vp-rule::DomainTrie` 编译 `*.google.com`、`domain:...` 前缀后缀与通配符，映射至专用 `Resolver` 实例；
  - GeoSite 标签匹配器：利用 `vp-rule::CompiledSite` 编译 `geosite:cn`、`geosite:category-ads-all` 等标签，映射至专用 `Resolver` 实例；
  - Upstream Bootstrap：利用 `default_nameserver`（纯 IP DNS）异步预解析 DoH / DoT 上游域名，消除原先调用系统阻塞 `ToSocketAddrs` 的隐患。
- **查询与过滤执行流程**：
  1. **Cache 检查**：命中且未过期直接返回；
  2. **Policy 专有分流优先**：若域名命中 `nameserver-policy` 中的域名规则或 `geosite` 规则，仅向该策略指定的上游解析器发起查询；
  3. **Fallback 强制分流**：若域名命中 `fallback-filter.domain` 或 `fallback-filter.geosite`，直接向 `fallback` 上游发起查询；
  4. **Primary 结果过滤与污染剔除**：
     - 若未命中上述特殊规则，向 `nameserver`（主解析器）发起查询；
     - 检查返回的 IP 列表：
       - 若任何 IP 落在 `fallback-filter.ipcidr`（如 `240.0.0.0/4`, `127.0.0.1/32` 等已知污染网段）；
       - 或启用了 `geoip: true` 且 IP 归属地不属于 `geoip_code`（如国外域名被国内 DNS 劫持投毒至非 CN IP）；
     - 则判定主解析器结果被污染，自动丢弃并降级使用 `fallback` 解析结果。

---

## 五、实施步骤规划

1. **第一阶段：特性 1（Proxy-Provider 代理集订阅）**
   - 在 `vp-config` 中增加 `ProxyProviderCfg` 与 `GroupCfg.r#use`，调整校验规则；
   - 在 `vp-app` 中实现 HTTP 拉取、磁盘缓存降级与 YAML/Base64/URI 混合解析；
   - 动态装配策略组成员，并启动后台周期定时刷新协程；
   - 编写单元与集成测试验证。

2. **第二阶段：特性 2（VLESS XTLS-rprx-vision 真实流控）**
   - 在 `vp-protocol::vless` 中实现 Protobuf Addons 组装与 `flow: xtls-rprx-vision` 识别；
   - 实现内层 TLS 1.3 ClientHello 嗅探、特征区间随机 Padding 填充、帧化封包与 `PaddingEnd` 直通状态机；
   - 编写 Vision 帧布局、填充解包与端到端传输自环测试。

3. **第三阶段：特性 3（Snell 协议出+入站 v1-v4）**
   - 在 `vp-config` 中增加 `SnellCfg`；
   - 在 `vp-protocol` 中实现 `snell.rs`（出站、入站、PSK 派生、AEAD 加解密、HTTP/TLS 混淆）；
   - 在 `sub.rs` 中支持 `snell://` 链接解析；
   - 编写大流量回显、错误密码拦截、混淆层互测等自环测试。

4. **第四阶段：特性 4（DNS nameserver-policy 分流与 fallback 过滤）**
   - 在 `vp-config` 中增加 `nameserver-policy` 与 `fallback-filter` 字段；
   - 在 `vp-dns` 中实现策略路由结构（Trie + GeoSite），在 `vp-app` 中提前初始化 GeoSite/GeoIP 并接入 DNS；
   - 实现主上游污染检测与 fallback 自动切换；
   - 编写专有分流与污染拦截单测。

5. **第五阶段：全工作区回归验证、README 更新与提交**
   - 运行 `cargo test --workspace` 全量测试；
   - 更新 README 说明文档；
   - 检查工作区敏感文件与测试凭据，完成干净提交。

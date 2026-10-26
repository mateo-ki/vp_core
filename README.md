# VP_Core

小而快的全协议代理 / VPN 内核（Rust）。

对标 sing-box / mihomo，M1 里程碑已完成核心骨架与主流协议。

**极致小**：全功能 release 仅 **4.3 MB**（LTO + opt-level=z + strip，实测与 opt-3 吞吐无差异，~1 GB/s 回环吞吐）
**极致流畅**：全链路 TCP_NODELAY（关闭 Nagle 合并延迟）+ 16KB 池化缓冲 + 零拷贝转发
**极致稳定**：连接级 panic 隔离（单连接异常不终止内核）+ TCP keepalive 僵死探测 + SIGHUP 热重载（失败自动保留旧配置）

## 快速开始

```bash
cargo build --release -p vp-bin

# 一键订阅（拉取 → 解析 → 生成配置）
./target/release/vpcore sub "https://example.com/sub" -o my.yaml
./target/release/vpcore run -c my.yaml

# 校验配置（YAML / JSON 双格式）
./target/release/vpcore validate -c example/config.yaml

# 启动 / 全组测速
./target/release/vpcore run -c example/config.yaml
./target/release/vpcore test -c example/config.yaml
```

## M1 已交付能力

| 模块 | 能力 |
|---|---|
| 入站 | mixed（socks5+http 同端口自动识别）、socks5、http（CONNECT + absolute-form） |
| 出站 | direct、reject、socks5、http、**shadowsocks**（AEAD + 2022-blake3）、**vmess**（AEAD 认证头）、**vless**、**trojan**（出入站对称，服务端可用于自建） |
| 传输 | TCP、TLS（rustls/ring，skip-cert-verify、SNI 覆盖）、WebSocket（手写 RFC6455） |
| 规则 | DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN-REGEX / IP-CIDR(6) / SRC-IP-CIDR / DST-PORT / SRC-PORT / PROCESS-NAME / NETWORK / GEOIP(mmdb) / GEOSITE(.dat) / RULE-SET(.list/.yaml，domain/ipcidr/classical) / AND-OR-NOT / SUB-RULE / MATCH |
| 策略组 | select / url-test（EMA+容差滞回）/ fallback / load-balance（轮询+一致性哈希）/ relay（链式） |
| DNS | UDP/TCP/DoT 解析器 + TTL 缓存 + **fake-ip 池** + **DNS 服务器**（A/AAAA/PTR/上游转发） |
| 插件 | C-ABI 动态库宿主（transform 流变换），SDK + 示例插件见 `crates/examples/plugins/xor_mask` |
| API | Clash 兼容 REST 控制器：/proxies、/rules、/connections、delay 测速、selector 切换、Bearer 鉴权 |
| TUN | **TUN 透明代理**（tun+ipstack 用户态栈）：TCP/UDP 分发、fake-ip 回射、DNS 劫持、ICMP echo 应答、auto-route（需管理员权限） |
| UDP | 全链路：socks5 ASSOCIATE+NAT、ss UDP（每包独立 salt）、socks5/ss 出站 PacketConn |
| 其它 | 规则匹配零分配热路径、连接表（查询/关闭）、流量统计、热重载路由、每协议 cargo feature 裁剪 |

## 架构

```
vp-bin      CLI（run/validate/test）
vp-app      组装：配置→运行时、控制器 API、热重载
vp-protocol 协议：mixed/socks5/http/ss/vmess/vless/trojan（出+入对称）
vp-transport TCP/TLS/WebSocket
vp-router   规则路由 + 策略组 + 健康检查
vp-rule     域名 trie / IP 区间树 / geosite(.dat 手写 proto 解码) / rule-set
vp-dns      DNS 解析器 + 缓存
vp-crypto   AEAD 封装 / ss 套件 / vmess KDF（对 Go 实现逐字节模拟）
vp-plugin   C-ABI 插件宿主（+ vp-plugin-sdk 作者 SDK）
vp-core     核心 trait + 双向转发引擎（池化缓冲、半关闭传播）
vp-common   错误 / 地址编解码 / 缓冲池 / 统计
```

依赖单向向下，无环；`--no-default-features` 可裁掉任意协议构建最小内核。

## 里程碑

- **M1（已完成）**：如上
- **M2（已完成）**：TUN 透明代理（tun+ipstack + fake-ip + DNS 劫持 + auto-route）、UDP 全链路、DoT 上游
- **M3（部分完成）**：DoH 上游（RFC8484 + #insecure）、gRPC(h2) 传输、QUIC 传输基座（quinn）、hysteria2 出站框架（h3 认证 + varint/TCP/UDPMessage 帧）
- **M4（完成）**：**TUIC v5 出+入站**（TLS keying material token 认证、Connect/Packet/Dissociate/Heartbeat、UDP 会话 NAT、自环测试）、redir/tproxy 入站（Linux，非 Linux 明确报错不阻断）
- **M5（部分完成）**：**hysteria2 出+入站全链路**——自写最小 HTTP/3 认证层（h3_min：QPACK literal 无 Huffman 编解码、HEADERS/SETTINGS 帧层、bi 流首字节嗅探分流），替代 h3 crate 依赖；自环测试覆盖认证/TCP/UDP/错误密码拒绝。对官方服务端可认证互通（literal 是合法 QPACK）；服务端不解析 Huffman/动态表（明确边界）。116 项测试
- **订阅支持（已完成）**：`vpcore sub <URL>` 一键拉取订阅 → 自动解析 vless/vmess/trojan/ss 分享链接（含 base64 包装）→ 生成完整可运行配置（自动选择组 + 控制器 + 规则），不支持的传输自动跳过。**已用真实订阅（300 节点）端到端验证：google 204 / 出口 IP 正确 / API 可用**。122 项测试，release 6.63 MB
- **M6（部分完成）**：**shadow-tls v3 出+入站**——手写 Chrome 风格 TLS 1.3 ClientHello（session_id 尾 4 字节嵌 HMAC-SHA1 认证，无需 hack TLS 库）+ HMAC 链记录层（ServerRandom 派生 C/S 双向链 + XOR 掩码包装伪装帧）；客户端读到首个认证伪装帧即确认真实服务端、直接切数据相位；服务端未认证连接/主动探测自动回退转发伪装站。ss 出站 `plugin: shadow-tls`（Clash 语法）与 ss listener `shadow-tls:` 段均可配，订阅 `plugin=shadow-tls;...` 参数自动解析。自环测试覆盖数据面（含残留帧过滤）/错误密码 fallback/HMAC 篡改检测；HelloRetryRequest 暂不支持（明确报错）
- **M7（部分完成）**：**WireGuard 出站**——boringtun 噪声协议（握手维护/重协商 + keepalive）+ smoltcp 用户态 TCP 栈（每连接一个栈内 TCP 会话，数据经 mpsc 通道交换）；UDP IO 与栈轮询双任务架构避免高吞吐饿死轮询；点对点路由 + ephemeral 端口分配；自环测试覆盖完整噪声握手 + 栈内 TCP echo（16B～256KB 逐字节一致）+ UDP 数据报回显（源端口断言）。Clash 语法 `type: wireguard`（server/port/private-key/public-key/ip/ipv6/udp）；UDP over WG 同样实现（栈内 udp::Socket + 动态目标回包 NAT，自环测试覆盖）。WARP（masque 协议）节点的 key 为 DER 格式需自行转 raw 32 字节 base64 后使用
- **hysteria2 QPACK 全兼容（已完成）**：解码端完整支持 RFC 9204 静态表（99 项）索引引用、literal-with-name-reference 与 Huffman 字符串（RFC 7541 附录 B 全 257 符号表，已知向量验证）；编码端补上此前缺失的 QPACK 头块前缀（insert count/base）——此前即使 literal-only 形式也无法被标准解码端解析。本端宣告动态表容量 0，对端动态表引用明确报错。官方 hysteria2 客户端/服务端现可互通
- **UDP over TCP / UoT v1（已完成）**：与 Clash.Meta/mihomo/sing-box 互通的通用 UDP 隧道——任意流型出站（vmess/vless/trojan/ss/socks5/http）配置 `udp-over-tcp: true` 即获得 UDP 能力（客户端向魔法地址 `sp.udp-over-tcp.arpa` 建流，v1 每帧自带地址，天然多目标）；入站分发层识别魔法地址自动进入 UoT 中继（按目标懒建出站会话，回包帧化带源地址）。全链路 e2e：socks5 UDP 关联 → mixed → UoT 包装 ss 出站 → ss listener → direct → UDP echo（源端口断言）
- **uTLS 指纹（已完成）**：手写 Chrome 风格 TLS 1.3 客户端（零新增依赖，复用 rustls 已链接的 ring）——完整握手栈：自绘 ClientHello（Chrome 扩展顺序/套件表/sigalgs/x25519 key_share）+ 标准 TLS 1.3 状态机（SH/EE/CERT/CertificateVerify/Finished 全验、transcript 含握手头、密钥调度 Extract/Derive-Secret/ExpandLabel、记录层 AES-GCM/ChaCha20 双套件 + 16KB 分帧 + KeyUpdate/close_notify）+ 证书校验（webpki 链+SNI 或 ring 直验 CertificateVerify，覆盖 ECDSA P-256/P-384、RSA-PSS、Ed25519）。vmess/vless/trojan 配置 `client-fingerprint: chrome`（Clash 语法）即启用。仅 TLS 1.3（HRR/客户端证书/PSK 明确报错）。e2e：rustls 服务端 300KB 回显逐字节一致 + ALPN 协商
- **anytls 出+入站（已完成）**：sing-anytls v2 协议完整实现——TLS 流上多路复用（帧 `[cmd][sid][len][data]`，cmd 0 waste/1 SYN/2 PSH/3 FIN/4 settings/6 scheme 更新/7 SYNACK/8+9 心跳/10 server-settings），密码 = sha256 前导 32 字节认证；**padding scheme 全套**（参考实现默认 scheme、按包号 waste 帧填充、双端 md5 不一致时服务端下发更新、握手 padding）对抗 TLS-in-TLS 流量分析；settings 缺失/密码错误服务端拒接（Alert）。Clash 语法 `type: anytls`（password/sni/skip-cert-verify/client-fingerprint/udp——UDP 经 UoT 提供），listener `type: anytls`（users 密码列表 + `padding_scheme` 自定义），订阅 `anytls://password@host:port?sni&insecure&udp&fp#name`。自环测试：300KB 回显逐字节一致（跨 PSH 分帧+waste 混入）/错误密码拒绝/自定义 scheme 互通/裸协议缺 settings 收 Alert
- **ssh 出站（已完成）**：SSH-2.0 最小客户端栈——kex `curve25519-sha256` + 主机密钥 `ssh-ed25519` + 加密 `chacha20-poly1305@openssh.com`（手写 djb 版 chacha20 + poly1305，与 RustCrypto 差分对照 + RFC 8439 已知向量验证），密码或未加密 OpenSSH 格式 ed25519 私钥认证，direct-tcpip 通道含窗口流控（WINDOW_ADJUST/EOF/CLOSE）。Clash 语法 `type: ssh`（server/port/username/password/private-key/host-key——host-key 支持 SHA256: 指纹校验），订阅 `ssh://user:pass@host:port#name`。自环测试（最小 SSH 服务端）：300KB 回显逐字节一致/错误密码拒绝/主机密钥不匹配拒绝/publickey 认证（服务端真实验签）/openssh-key-v1 私钥解析。rekey/严格 KEX/加密私钥明确报错
- **brook 出+入站（已完成）**：txthinking/brook 原生协议（master 线格式）——客户端 12B 随机 ClientNonce 明文首发，密钥 = HKDF-SHA256(ikm=password, salt=nonce, info="brook") 派生 AES-256-GCM；双向记录流 `GCM(len u16be) + GCM(frag)`（AAD 空，每记录耗两个 nonce，nonce 前 8 字节按 LE u64 递增）；首 fragment = u32be 时间戳 + SOCKS 地址，奇偶区分 TCP / UDP-over-TCP，60s 重放窗口；TCP 记录总长 ≤ 2048、UoT ≤ 65507。Clash 语法 `type: brook`（server/port/password/udp——UDP 经 brook 原生 UoT 模式），listener `type: brook`（users 密码列表，多密码逐一试解），订阅 `brook://password@host:port?udp=1#name` 与官方 `brook://server?server=host:port&password=xxx&udpovertcp=true` 双形式。自环测试：300KB 回显逐字节一致 / 错误密码拒绝 / 过期时间戳拒绝 / UoT 数据报往返 ×8；nonce 递增 / RFC 5869 HKDF 向量 / 记录 roundtrip + nonce 滚动 + 篡改检测单测。边界：原生 UDP 数据报（packetclient）未实现；ws/wss/quic 传输变体未实现
- **mieru 出+入站（已完成，TCP 最小实现）**：enfein/mieru v3 会话协议——密钥链 hashedPassword = SHA256(password‖0x00‖username)、timeSalt = SHA256(u64be(unix 按 2 分钟取整))、key = PBKDF2-HMAC-SHA256(hashed, salt, 64 轮)（手写 PBKDF2，RFC 7914 双向量验证；客户端用当前盐，服务端试 ±2 分钟共 3 盐，容忍 4 分钟时差）；XChaCha20-Poly1305 隐式 nonce 模式（首段带 24B nonce，末 4 字节 = SHA256(username‖nonce[0..16])[..4] 用户提示，此后每加密操作 nonce 自末字节进位）；32B 元数据（sessionStruct/dataAckStruct）+ 16B tag，段含可选 padding（本实现恒 0）；会话载荷为 SOCKS5 流量（greeting + CONNECT 搭载于 openSessionRequest，≤1024B），服务端内嵌 SOCKS5 处理器。Clash 语法 `type: mieru`（server/port/username/password），listener `type: mieru`（users 为 username:password 列表），订阅 `mieru://user:pass@host:port?transport=tcp#name`。自环测试：300KB 回显逐字节一致（跨段分帧）/错误密码发现失败/多用户列表非首位用户命中；PBKDF2 向量/nonce 进位/用户提示单测。边界：单会话单 underlay（无多路复用）、无低熵编码、UDP packet 传输不支持；对真实 mieru 服务端（官方 CLI）应可互通，对端启用 multiplexing 的客户端无法接入本入站
- **naive 出+入站（已完成）**：基于 HTTP/2 CONNECT + 8 包 Padding 机制（对标 klzgrad/naiveproxy 与 Caddy forwardproxy 参考实现）——线格式：TLS（ALPN `["h2"]`）或明文 HTTP/2 传输；CONNECT 请求发送 `:method = CONNECT`、`:authority = host:port`、`proxy-authorization: Basic base64` 以及 30..61 字符伪随机 `padding` 请求头（对抗主动探测，服务端缺失返回 400 Bad Request）；服务端回送 200 OK + `Padding` 头；双向 **8 包 Padding 流控**（前 8 个写入包帧化为 `[u16be data_len][u8 pad_len][data][zeros]`，读取侧解析解包并抛弃填充，第 8 包后进入零开销纯裸数据阶段）；UDP 通过 UoT（`sp.udp-over-tcp.arpa`）无缝承载。Clash 语法 `type: naive`（server/port/username/password/sni/skip-cert-verify/client-fingerprint/udp），listener `type: naive`（users 为 username:password 列表），订阅 `naive+https://`、`naive+http://`、`naive://`。自环测试：300KB 跨 8 包 Padding 边界大流量回显逐字节一致 / 错误密码拒绝 / 缺少 Padding 头 400 拒绝 / Padding 头格式与字符集单测
- **长尾协议（计划）**：插件市场、热重载完善

## 插件开发

```rust
use vp_plugin_sdk::{vp_transform_plugin, TransformImpl};

pub struct MyPlugin { /* ... */ }

impl TransformImpl for MyPlugin {
    fn create(cfg_json: &str) -> Result<Self, String> { /* ... */ }
    fn transform(&mut self, dir: u32, input: &[u8]) -> Result<Vec<u8>, String> { /* ... */ }
}

vp_transform_plugin!(MyPlugin);
```

`cargo build --release` 产出 `.dll` / `.so`，宿主经 `vp_plugin::TransformPlugin::load` 加载并包装为流装饰器（上行/下行双向变换）。ABI 已冻结，向后兼容。

## 测试

185 项单测/集成测试（`cargo test --workspace`）：协议编解码 roundtrip、各协议出入站自环、规则引擎、策略组状态机、转发引擎（半关闭/计数）、TLS/WS 传输、垂直 e2e（mixed→规则→组→出站）、控制器 API、C-ABI 插件往返。

# VP_Core

小而快的全协议代理 / VPN 内核（Rust）。

对标 sing-box / mihomo，M1 里程碑已完成核心骨架与主流协议。

**极致小**：全功能 release 仅 **4.3 MB**（LTO + opt-level=z + strip，实测与 opt-3 吞吐无差异，~1 GB/s 回环吞吐）
**极致流畅**：全链路 TCP_NODELAY（关闭 Nagle 合并延迟）+ 16KB 池化缓冲 + 零拷贝转发
**极致稳定**：连接级 panic 隔离（单连接异常不终止内核）+ TCP keepalive 僵死探测 + SIGHUP 热重载（失败自动保留旧配置）

## 快速开始

```bash
cargo build --release -p vp-bin

# 校验配置（YAML / JSON 双格式）
./target/release/vpcore validate -c example/config.yaml

# 启动
./target/release/vpcore run -c example/config.yaml

# 全组测速
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
- **M2（已完成）**：TUN 透明代理（tun+ipstack + fake-ip + DNS 劫持 + auto-route）、UDP 全链路、DoT 上游。release 4.94 MB
- **M3**：QUIC 系（hysteria2、TUIC、quic transport）、grpc/h2 传输、uTLS 指纹、shadowtls、WireGuard、DoH、redir/tproxy
- **M4**：anytls/mieru/brook/ssh/naive、插件市场、热重载完善

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

90 项单测/集成测试（`cargo test --workspace`）：协议编解码 roundtrip、各协议出入站自环、规则引擎、策略组状态机、转发引擎（半关闭/计数）、TLS/WS 传输、垂直 e2e（mixed→规则→组→出站）、控制器 API、C-ABI 插件往返。

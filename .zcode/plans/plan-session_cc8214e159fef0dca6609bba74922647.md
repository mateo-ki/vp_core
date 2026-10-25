# VP_Core — Rust 代理/VPN 内核总体实施计划

对标 sing-box / mihomo 的内核，Rust 实现。目标：全协议覆盖、极致体积与性能、C-ABI 插件体系、完整规则引擎与策略组、TUN 透明代理。

## 一、总体架构：Cargo Workspace 分层

```
VP_Core/
├── Cargo.toml                 # workspace；统一 release profile
├── crates/
│   ├── vp-common/     # 错误类型、缓冲池、地址解析、原子计数器、日志封装
│   ├── vp-core/       # 核心 trait（Outbound/Inbound/Router/Session）+ 双向转发引擎（性能核心）
│   ├── vp-config/     # 内部统一 IR + 双前端解析（Clash 兼容 YAML / JSON 含注释容忍）+ 校验
│   ├── vp-rule/       # 规则引擎：域名 trie、IP LPM 基数树、端口/进程/逻辑规则、rule-set、geosite
│   ├── vp-router/     # 路由决策 + 策略组（selector/url-test/fallback/load-balance/relay）+ 健康检查
│   ├── vp-dns/        # DNS：UDP/TCP/DoT（DoH M2），LRU+TTL 缓存；fake-ip 预留接口
│   ├── vp-transport/  # 传输层：tls(rustls/ring)、ws(手写 RFC6455)、grpc/h2/quic 后续
│   ├── vp-crypto/     # 密码套件聚合：aes-gcm、chacha20poly1305、blake3(ss2022)、md5/sha/hkdf
│   ├── vp-protocol/   # 出入站协议（每协议一个 cargo feature）
│   ├── vp-tun/        # TUN 设备抽象（M1 立接口，M2 完整实现：wintun/tokio-tun + smoltcp 用户态栈）
│   ├── vp-plugin/     # C-ABI 插件宿主（libloading）+ 版本化 vtable
│   ├── vp-plugin-sdk/ # 插件作者用的 Rust SDK（冻结 ABI 绑定）+ C 头文件
│   ├── vp-app/        # 组装：supervisor、热重载、Clash 兼容 RESTful 外部控制器
│   └── vp-bin/        # CLI 入口（clap）：run / validate / test / version
```

依赖方向单向向下：`bin → app → protocol/transport/dns → router → rule → core → common`，无环。

## 二、核心抽象（vp-core）

一切流量归约为字节流（TCP 型）与数据报（UDP 型）两类：

```rust
pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
pub struct Packet { src: SocketAddr, dst: SocketAddr, data: Bytes }

#[async_trait]
pub trait Outbound: Send + Sync {
    fn name(&self) -> &str;
    async fn connect(&self, dst: &DstAddr) -> Result<Box<dyn ProxyStream>>;
    async fn connect_packet(&self, dst: &DstAddr) -> Result<Box<dyn PacketConn>>;
    fn support_udp(&self) -> bool { false }
}
pub trait Inbound: Send + Sync { /* listen() 产出 Session 交给 Router */ }
pub trait Router: Send + Sync { /* route_stream / route_packet */ }
```

策略组自身也实现 `Outbound`，天然支持嵌套（DAG，构建期检测环）。

**转发引擎（性能核心）**：全程 `bytes::Bytes` 引用计数零拷贝；双向 2 task + 有界 channel；池化 64KiB buffer；批量读 + vectored write（writev）；连接表（供 API 查询/关闭）。Linux 后续升级 splice/io_uring。

## 三、规则引擎（vp-rule）

- 域名：反向标签压缩 trie，统一容纳 DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN-REGEX（regex 单独小集合）
- IP：前缀压缩 LPM 基数树（IPv4/IPv6 统一 128bit），支持 IP-CIDR / IP-CIDR6 / GEOIP（maxminddb mmap 零解析）
- GEOSITE / v2ray .dat：手写 protobuf wire 解码（~150 行，零依赖）
- RULE-SET：文本 .list 与二进制 .mrs（mihomo 生态）双支持，mmap 加载
- 端口、SRC-IP、SRC-PORT、PROCESS-NAME/PATH（Windows `GetExtendedTcpTable` / Linux `/proc/net/*`）、IN-TYPE
- 逻辑规则 AND/OR/NOT/SUB-RULE
- 全部规则**编译期**构建为紧凑结构，热路径零分配

## 四、策略组（vp-router）

- **Selector**（手动切换，可被 API 修改）/ **URLTest**（延迟测速，EMA 平滑 + tolerance 滞回，惰性触发）/ **Fallback**（按优先级故障转移）/ **LoadBalance**（一致性哈希 / 轮询）/ **Relay**（链式串联）
- 独立健康检查 task，指数退避；原子计数器记录每节点连接数/流量

## 五、配置（vp-config）

内部统一 IR，双前端：Clash 兼容 YAML（proxies / proxy-groups / rules / dns / port / external-controller 等，机场订阅零成本迁移）；JSON 前端为同一 schema 的 JSON/JSON5 表示（容忍注释）。校验阶段检测：组环引用、规则指向不存在的策略、端口冲突等，给出精确报错位置。

## 六、协议矩阵与里程碑

**M1（本次，完整骨架+主流协议跑通，出入站对称实现便于自环测试）**
- 入站：mixed（socks5+http 同端口自动识别）、socks5、http；协议服务端同套实现（ss/vmess/vless/trojan server）
- 出站：direct、reject、socks5、http、shadowsocks（AEAD + 2022-blake3）、vmess（aes-128-gcm/chacha20/zero）、vless（uuid + flow 基础）、trojan（sha224）
- 传输：tcp、tls（rustls+ring）、ws；DNS：UDP/TCP/DoT + 缓存
- CLI + Clash 兼容 REST API（GET /proxies、PUT 切换、GET /rules、GET /connections、延迟测试）
- **验收**：`vpcore validate` 双格式通过；curl 经 mixed 端口 → direct/各协议自环（本机协议 server）全部 2xx；规则+策略组生效

**M2（TUN 模式）**：wintun（Windows）/ tokio-tun，smoltcp 用户态栈，fake-ip DNS 劫持与回映射，auto-route；UDP 全链路（ss/vmess UDP、DNS 劫持）；redir/tproxy（Linux）；DoH
**M3（QUIC 系）**：quinn 基础上 hysteria2、TUIC v5、quic transport、grpc/h2 transport、uTLS 指纹、shadowtls、WireGuard（boringtun）
**M4（长尾+插件完善）**：anytls、mieru、brook、ssh；naive；插件市场机制、热重载完善

## 七、C-ABI 插件体系（vp-plugin + vp-plugin-sdk）

版本化稳定 ABI（`vp_plugin.h` + SDK crate），插件为 .dll/.so/.dylib，三类：
1. **transform**：纯缓冲区变换（输入/输出指针+len），无 IO，最快最安全——混淆/加解密类
2. **outbound**：`connect()` 返回已连接 socket fd 交还宿主，由宿主 tokio 接管
3. **provider**：节点/规则订阅扩展（M4）

宿主侧 libloading 动态加载，ABI 版本协商，插件崩溃不影响其它流量；SDK 提供 `#[vp_plugin]` 宏生成导出。M1 交付宿主 + transform/outbound 两类 + 官方示例插件（simple-obfs 风格 transform）。

## 八、体积与性能工程

- workspace release profile：`lto="fat"`、`codegen-units=1`、`panic="abort"`、`strip="symbols"`；opt-level 3 与 z 二选一以实测为准
- rustls 用 ring 后端（避免 aws-lc）；tokio 精确 features 不用 full；ws/http 解析手写（httparse + 自实现 RFC6455），不拉 hyper
- 每协议 cargo feature，`--no-default-features` 可出最小内核
- 目标：最小 feature Linux musl < 3MB；全功能 M1 < 12MB
- 基准：criterion（trie/LPM/转发吞吐）+ iperf 端到端，对比 mihomo 记录基线

## 九、测试

- 单元：trie/LPM、配置解析双格式、各协议编码 roundtrip、策略组状态机
- e2e：本机起内核 + 协议 server 自环 + curl --socks5 全协议矩阵
- 基准：criterion + 吞吐脚本

## 十、实施顺序（批准后立即开始）

1. `git init` + workspace + 全 crate 骨架 + profile
2. vp-common / vp-core（trait + 转发引擎 + 单测）
3. vp-config（IR + 双格式 + 校验）
4. vp-rule（trie + LPM + 逻辑规则 + geosite 解析）
5. vp-router（策略组 + 健康检查）
6. 垂直打通：mixed 入站 → direct/socks5 出站 → 本机 e2e
7. vp-transport（tls/ws）→ ss/vmess/vless/trojan 出入站 → 协议自环 e2e
8. vp-dns、vp-plugin 宿主 + 示例插件、vp-app API、vp-bin CLI
9. 基准与体积报告

每步含单测；M1 全部完成后输出验收报告。M2（TUN）作为下一阶段紧接推进。
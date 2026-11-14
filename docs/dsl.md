# VP_Core 全量配置 DSL 规范与 AI 提示词指南

本文档定义 VP_Core 声明式配置语言（`.vp` DSL）的完整语法规范，并提供专为**大语言模型（ChatGPT / Claude / DeepSeek 等）**设计的 System Prompt，让 AI 一键生成零错误配置。

> 💡 快速验证：`vpcore validate -c config.vp`　·　自动格式化：`vpcore fmt -w config.vp`

---

## 一、为什么引入 `.vp` DSL？

传统 YAML / JSON 是**静态数据格式**，表达分流逻辑存在天然弊端：

1. **零缩进陷阱** —— 大括号与空格无关，杜绝一个空格导致的解析崩溃；
2. **逻辑表达自然** —— 原生支持 Google CEL 表达式（`&&`、`||`、`in` 复合条件）；
3. **天然契合 AI** —— LLM 生成代码式 DSL 的结构合规率远高于严格缩进的 YAML。

---

## 二、语法全景速查

一份完整的 `.vp` 配置由**五个核心语块**组成：

```dsl
// ============================================================
// 1. 入站监听 (inbound)
// ============================================================
inbound mixed {
    listen: "127.0.0.1:7890"   // HTTP 与 SOCKS5 自适应
}

// 可选：TUN 虚拟网卡全局接管（免配系统代理）
// inbound tun {
//     address: "198.18.0.1/16"
//     auto_route: true
// }

// ============================================================
// 2. 出站节点 (node) —— 各协议与传输层写法见下方「节点速查」
// ============================================================
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

// ============================================================
// 3. 策略组 (group)
// ============================================================
group "AUTO" url_test {
    members: ["香港-01", "日本-01", "美国-01"]
    interval: 300s             // 测速周期（300s / 5m 等时间字面量）
    tolerance: 50ms            // 容差
    filter: "(?i)香港|日本"     // 正则过滤成员
    fallback: "DIRECT"         // 全灭时容灾兜底
}

group "PROXY" select {
    members: ["AUTO", "香港-01", "美国-01", "DIRECT"]
}

// ============================================================
// 4. DNS 引擎 (dns)
// ============================================================
dns {
    nameservers: ["https://doh.pub/dns-query", "223.5.5.5"]
    fake_ip: "198.18.0.0/15"
}

// ============================================================
// 5. 路由流向 (route —— Google CEL 表达式)
// ============================================================
route {
    process.name == "git" && dst.port == 22 => "PROXY"
    net == "tcp" && dst.port in [80, 443] && host.endsWith(".google.com") => "AUTO"
    dst.ip in "10.0.0.0/8" || dst.ip in "192.168.0.0/16" => "DIRECT"
    geoip == "CN" => "DIRECT"
    _ => "PROXY"               // 兜底规则
}
```

---

## 三、节点速查（协议 × 参数）

| 协议 | 必填参数 | 常用可选参数 |
| :--- | :--- | :--- |
| `vless` | `server` `uuid` | `flow`、`tls`（reality 块）、传输层子对象、`udp` |
| `vmess` | `server` `uuid` | `alter_id`、`cipher`、传输层子对象、`udp` |
| `trojan` | `server` `password` | `sni`、传输层子对象、`udp` |
| `ss` | `server` `cipher` `password` | `plugin` 相关 |
| `hysteria2` | `server` `password` | `sni`、`up` / `down`、`obfs_password` |
| `tuic` | `server` `uuid` `password` | `sni`、`alpn` |
| `wireguard` | `server` `private_key` `public_key` `ip` | `mtu`、`dns`、`allowed_ips` |
| `masque` | `server` `private_key` `public_key` `ip` | `ipv6`、`mtu`、`sni`、`uri` |
| `ssh` | `server` + `password` 或 `private_key` | `username`、`host_key` |
| `anytls` / `naive` / `brook` / `mieru` / `snell` / `ssr` | 参见各协议约定 | `password`、`sni` 等 |
| `http` / `socks5` | `server` | `username`、`password`（级联上游） |
| `direct` / `reject` | 无 | — |

所有节点通用：`name`（节点名）、`udp`（UDP 透传）、`skip_cert_verify`、`sni`。

---

## 四、传输层速查（vless / vmess / trojan 共用）

| 传输 | DSL 写法 | 说明 |
| :--- | :--- | :--- |
| REALITY | `tls: reality { sni: "...", public_key: "...", short_id: "..." }` | 任意传输叠加 |
| TLS | `tls: true` + `sni: "..."` | 普通 TLS |
| WebSocket | `ws: { path: "/path", headers: { Host: "cdn.com" } }` | CDN 穿透经典款 |
| gRPC | `grpc: { service_name: "mysvc" }` | gRPC-Tun 双向流 |
| **XHTTP** | `xhttp: { path: "/up", mode: "auto", headers: { Host: "cdn.com" } }` | Xray SplitHTTP 后继，H2 承载 |

### XHTTP 写法详解

XHTTP 是 Xray 生态的新一代 CDN 穿透传输（SplitHTTP 后继）：**GET 长响应承载下行、POST 承载上行**，单条 HTTP/2 连接复用全部请求，天生对 CDN / 反代友好。

```dsl
node "cf-xhttp" vless {
    server: "104.16.0.1:443"
    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811"
    sni: "cdn.example.com"
    tls: true
    udp: true
    xhttp: {
        path: "/xhttp-upload"                    // 伪装路径
        mode: "auto"                             // auto | packet-up | stream-up | stream-one
        headers: { Host: "cdn.example.com" }     // 伪装头（通常只需 Host）
    }
}
```

**mode 模式说明**：

| 模式 | 上行 | 下行 | 适用 |
| :--- | :--- | :--- | :--- |
| `auto`（默认） | 逐包 POST | GET 长响应流 | 通用推荐 |
| `packet-up` | 每包一条 POST `{path}/{session}/{seq}` | GET 长响应流 | 兼容性最好 |
| `stream-up` | 单条流式 POST | GET 长响应流 | 高吞吐上传 |
| `stream-one` | 单条双向 POST（请求体上行） | 同请求的响应体 | H3 友好场景 |

与 REALITY 叠加：在节点里同时写 `tls: reality { ... }` 与 `xhttp: { ... }` 即可。

---

## 五、CEL 路由表达式变量与函数一览

在 `route { ... }` 中以 `条件 => "出站目标"` 声明流向，**自上而下首个命中生效**：

| 属性 / 函数 | 类型 | 含义 | 示例 |
| :--- | :--- | :--- | :--- |
| `host` | String | 目标域名 | `host == "api.github.com"` |
| `host.endsWith("...")` | Bool | 域名后缀匹配 | `host.endsWith(".google.com")` |
| `host.contains("...")` | Bool | 包含子串 | `host.contains("twitter")` |
| `dst.port` | Int | 目标端口 | `dst.port == 443` / `dst.port in [80, 443]` |
| `dst.ip` | String | 目标 IP / 网段 | `dst.ip in "10.0.0.0/8"` |
| `src.ip` | String | 来源 IP / 网段 | `src.ip in "192.168.1.0/24"` |
| `net` | String | 协议（`"tcp"` / `"udp"`） | `net == "udp" && dst.port == 53` |
| `process.name` | String | 客户端进程名 | `process.name == "curl"` |
| `geoip` | String | IP 归属国家码 | `geoip == "CN"` |
| `&&` `\|\|` `!` | 算符 | 逻辑与 / 或 / 非 | `dst.port == 80 \|\| dst.port == 443` |
| `_` | 通配 | 默认兜底 | `_ => "PROXY"` |

---

## 六、🤖 丢给 AI 的专属 Prompt（复制即用）

```markdown
你现在是 VP_Core 代理内核的配置生成专家。请依据以下语法规范，根据我的需求输出合法的 `.vp` 配置文件。

### 语法规则：
1. 入站：inbound mixed { listen: "127.0.0.1:7890" }
2. 节点（协议 × 参数）：
   node "节点名" 协议名 {
       server: "host:port"
       // vless/vmess 用 uuid: "..."；trojan/ss 用 password: "..."
       // REALITY: tls: reality { sni: "...", public_key: "...", short_id: "..." }
       // 普通 TLS: tls: true 加 sni: "..."
       // WebSocket: ws: { path: "/path", headers: { Host: "cdn.com" } }
       // gRPC: grpc: { service_name: "mysvc" }
       // XHTTP: xhttp: { path: "/up", mode: "auto", headers: { Host: "cdn.com" } }
   }
3. 策略组：
   group "组名" select|url_test|fallback|load_balance|relay {
       members: ["节点1", "节点2", "DIRECT"]
       // url_test 可加 interval: 300s, tolerance: 50ms, filter: "正则", fallback: "DIRECT"
   }
4. DNS：dns { nameservers: ["https://doh.pub/dns-query", "223.5.5.5"]  fake_ip: "198.18.0.0/15" }
5. 路由（Google CEL）：
   route {
       process.name == "git" => "PROXY"
       net == "tcp" && dst.port in [80, 443] && host.endsWith(".google.com") => "PROXY"
       dst.ip in "10.0.0.0/8" => "DIRECT"
       geoip == "CN" => "DIRECT"
       _ => "PROXY"   // 兜底规则必须有
   }

要求：只输出合法的 .vp 配置代码块，不含寒暄；兜底规则 `_ =>` 不可省略。
我的需求是：[在此输入需求，例如：一个香港 VLESS-Reality 节点 + 一个过 CDN 的 XHTTP 节点，国内直连，GitHub/Google 走代理]
```

---

## 七、常用命令与生态工具链

| 命令 | 用途 |
| :--- | :--- |
| `vpcore validate -c config.vp` | 语法与语义校验 |
| `vpcore fmt -w config.vp` | 原地格式化对齐（`--check` 用于 CI 门禁；缺省输出到 stdout） |
| `vpcore convert -i config.yaml -o config.vp` | Clash YAML / JSON / `.vp` 双向无损互转（`-o exported.json` 可导出 JSON） |
| `vpcore sub "<URL>" -o sub.vp` | 拉取订阅直出 `.vp`（`-f vp` 显式指定格式） |
| `vpcore explain <URL> -c config.vp` | 路由决策诊断（命中规则、DNS 解析树、微秒级耗时；`--json` 结构化输出） |
| `vpcore run -c config.vp` | 启动内核 |

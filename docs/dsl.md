# VP_Core 全量配置 DSL 规范与 AI 提示词指南

本文档定义了 VP_Core 声明式配置语言（`.vp` DSL）的完整语法规范，并提供了专为 **大语言模型（ChatGPT / Claude / DeepSeek 等）** 设计的 System Prompt，方便用户通过自然语言让 AI 一键生成零错误配置文件。

---

## 一、 为什么引入 `.vp` DSL？

传统的 YAML / JSON 属于**静态数据格式**，用于表达分流规则等逻辑运算时存在严重弊端：
1. **零缩进陷阱**：大括号与空格无关，杜绝因一个空格导致的解析崩溃；
2. **逻辑表达自然**：原生支持 Google CEL 表达式，支持 `&&`、`||`、`!`、`in` 复合条件判断；
3. **天然契合 AI**：LLM 生成代码式 DSL 的结构合规率远高于严格缩进的 YAML。

---

## 二、 语法全景速查

一份完整的 `.vp` 配置文件由以下五个核心语块组成：

```dsl
// ==========================================
// 1. 入站监听语块 (inbound)
// ==========================================
inbound mixed {
    listen: "127.0.0.1:7890"  // 支持 HTTP 与 SOCKS5 自适应
}

// 可选：独立 TUN 虚拟网卡入站（免配置系统代理全局接管）
// inbound tun {
//     address: "198.18.0.1/16"
//     auto_route: true
// }

// ==========================================
// 2. 出站代理节点语块 (node)
// ==========================================
// VLESS + REALITY 节点
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

// Shadowsocks 节点
node "日本-01" ss {
    server: "jp.example.com:8388"
    cipher: "aes-128-gcm"
    password: "mypassword"
}

// Hysteria 2 节点
node "美国-01" hysteria2 {
    server: "us.example.com:443"
    password: "hy2password"
    sni: "my-domain.com"
}

// ==========================================
// 3. 策略组语块 (group)
// ==========================================
// 自动测速优选组 (url_test)
group "AUTO" url_test {
    members: ["香港-01", "日本-01", "美国-01"]
    interval: 300s          // 测速周期（支持 300s、5m 等字面量）
    tolerance: 50ms         // 容差
    filter: "(?i)香港|日本"    // 正则过滤成员
    fallback: "DIRECT"      // 全灭或无匹配时的容灾兜底
}

// 手动选择组 (select)
group "PROXY" select {
    members: ["AUTO", "香港-01", "日本-01", "美国-01", "DIRECT"]
}

// ==========================================
// 4. DNS 引擎语块 (dns)
// ==========================================
dns {
    nameservers: ["https://doh.pub/dns-query", "223.5.5.5"]
    fake_ip: "198.18.0.0/15"
}

// ==========================================
// 5. 路由流向语块 (route - Google CEL 表达式)
// ==========================================
route {
    // 进程与端口精确比对（Cost 0 极速短路）
    process.name == "git" && dst.port == 22 => "PROXY"

    // 协议、端口与域名后缀复合匹配
    net == "tcp" && dst.port in [80, 443] && host.endsWith(".google.com") => "AUTO"

    // 内网保留 IP 网段直连
    dst.ip in "10.0.0.0/8" || dst.ip in "192.168.0.0/16" => "DIRECT"
    dst.ip in "127.0.0.0/8" => "DIRECT"

    // GeoIP 国家代码匹配
    geoip == "CN" => "DIRECT"

    // 通配默认兜底（前序条件均未命中时触发）
    _ => "PROXY"
}
```

---

## 三、 CEL 路由表达式可用变量与函数一览

在 `route { ... }` 语块中，使用 `条件 => "出站目标"` 声明流向，支持的表达式属性如下：

| 属性 / 函数 | 类型 | 含义 | 示例 |
| :--- | :--- | :--- | :--- |
| `host` | String | 目标域名 / 主机名 | `host == "api.github.com"` |
| `host.endsWith("...")` | Bool | 域名后缀匹配 | `host.endsWith(".google.com")` |
| `host.contains("...")` | Bool | 域名包含子串 | `host.contains("twitter")` |
| `dst.port` | Int | 目标端口（数字） | `dst.port == 443` 或 `dst.port in [80, 443]` |
| `dst.ip` | String | 目标 IP / CIDR 网段 | `dst.ip in "10.0.0.0/8"` |
| `src.ip` | String | 来源 IP / 网段 | `src.ip in "192.168.1.0/24"` |
| `net` | String | 网络层协议 (`"tcp"` / `"udp"`) | `net == "udp" && dst.port == 53` |
| `process.name` | String | 发起请求的客户端进程名 | `process.name == "curl"` |
| `geoip` | String | 目标 IP 归属国家二字码 | `geoip == "CN"` |
| `&&` / `\|\|` / `!` | 算符 | 逻辑与 / 逻辑或 / 逻辑非 | `dst.port == 80 \|\| dst.port == 443` |
| `_` | 通配 | 默认兜底规则 | `_ => "PROXY"` |

---

## 四、 🤖 丢给 AI 的专属 Prompt（复制即可使用）

如果你想让 **ChatGPT / Claude / DeepSeek** 帮你自动生成或修改 `.vp` 配置文件，可直接将以下提示词完整复制并发给 AI：

```markdown
你现在是 VP_Core 代理内核的配置生成专家。请依据以下 VP_Core DSL 语法规范，根据我的需求输出合法的 `.vp` 配置文件。

### 语法规则：
1. 入站：
   inbound mixed { listen: "127.0.0.1:7890" }
2. 节点：
   node "节点名" 协议名 {
       server: "ip:port"
       // 针对 vless/vmess: uuid: "..."
       // 针对 ss: cipher: "aes-128-gcm", password: "..."
       // 针对 reality: tls: reality { sni: "...", public_key: "...", short_id: "..." }
   }
3. 策略组：
   group "组名" 组类型 {
       members: ["节点名1", "节点名2", "DIRECT"]
       // 若是 url_test，可指定 interval: 300s, tolerance: 50ms, filter: "正则", fallback: "DIRECT"
   }
4. DNS：
   dns {
       nameservers: ["https://doh.pub/dns-query", "223.5.5.5"]
       fake_ip: "198.18.0.0/15"
   }
5. 路由 (Google CEL 语法)：
   route {
       process.name == "git" => "PROXY"
       net == "tcp" && dst.port in [80, 443] && host.endsWith(".google.com") => "PROXY"
       dst.ip in "10.0.0.0/8" => "DIRECT"
       geoip == "CN" => "DIRECT"
       _ => "PROXY" // 兜底规则
   }

请只输出合法的 .vp 配置代码块，不包含与配置无关的寒暄。
我的需求是：[在此处输入你的分流需求，例如：配置 1 个香港节点和 1 个日本节点，国内直连，GitHub 和 Google 走代理]
```

---

## 五、 常用命令与生态工具链

### 1. 语法与语义校验
```bash
vpcore validate -c config.vp
```

### 2. 代码自动格式化与 CI 门禁 (`vpcore fmt`)
```bash
# 原地格式化并对齐 .vp 文件代码
vpcore fmt -w config.vp

# CI/CD 门禁检查（若未规范格式化则非零退出）
vpcore fmt --check config.vp

# 查看格式化结果（输出至标准输出）
vpcore fmt config.vp
```

### 3. 一键无损互转 (`vpcore convert`)
无缝将存量 Clash YAML / JSON 配置无损转为规范的 `.vp` DSL，或将 `.vp` 导出为标准格式：
```bash
# 将 Clash YAML 配置转换为极简 .vp DSL
vpcore convert -i config.yaml -o config.vp

# 将 .vp DSL 逆向导出为标准 YAML
vpcore convert -i config.vp -o exported.yaml

# 转换并导出为 JSON
vpcore convert -i config.vp -o exported.json

# 直接在终端标准输出打印转换结果
vpcore convert -i config.yaml
```

### 4. 远程机场订阅直接拉取并产出 `.vp` 配置 (`vpcore sub`)
```bash
# 拉取订阅并直接保存为 .vp DSL 配置
vpcore sub "https://subscribe.example.com/api/v1/client/subscribe?token=xxx" -o sub.vp

# 显式指定输出格式为 vp
vpcore sub "https://subscribe.example.com/api/v1/client/subscribe?token=xxx" -o myconfig -f vp
```

### 5. 路由决策链路诊断（查看命中哪条 CEL 规则及毫秒/微秒耗时）
```bash
# 交互式全景诊断
vpcore explain https://www.google.com -c config.vp

# 输出 JSON 格式（供 Web 面板或监控集成）
vpcore explain https://www.google.com -c config.vp --json
```

### 6. 启动内核运行
```bash
vpcore run -c config.vp
```

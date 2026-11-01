//! 443 端口多协议复用分发器 (TlsMuxInbound)
//!
//! 在单一端口（通常为 443）上终结标准 TLS 或 REALITY 握手，
//! 并依据首包前 58 字节指纹特征无损嗅探分发：
//! - 若首字节为 0x00 且匹配 UUID，分发至 VLESS 处理管道（支持 xtls-rprx-vision 流控）；
//! - 若前 56 字节为十六进制字符且后随 CRLF 并匹配哈希，分发至 Trojan 处理管道；
//! - 其余普通 HTTP/HTTPS 浏览器请求或未认证主动探测流量，通过 PeekedStream 原样零丢失回落至后置 Web 服务（如 Nginx/Caddy）。

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use vp_common::addr::decode_socks_addr;
use vp_common::{Error, Result};
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;
use vp_core::tunnel::{RelayHook, relay};
use vp_core::{ConnMeta, Inbound, Outbound, PeekedStream, ProxyStream, UserAccount, UserManager};
use vp_crypto::vmess_kdf::parse_uuid;
use vp_dns::Resolver;
use vp_transport::reality_server::{
    RealityHandshakeResult, RealityServerConfig, reality_server_handshake,
};
use vp_transport::tls::tls_acceptor;

use crate::direct::DirectOutbound;
use crate::trojan::password_hash;
use crate::vless::{VERSION as VLESS_VERSION, decode_request};
use crate::vless_vision::{VISION_FLOW_BYTES, VisionStream};

/// TlsMuxInbound 配置选项
#[derive(Clone, Default)]
pub struct TlsMuxOptions {
    /// 标准 TLS 证书 PEM 数据
    pub cert_pem: Option<Vec<u8>>,
    /// 标准 TLS 私钥 PEM 数据
    pub key_pem: Option<Vec<u8>>,
    /// REALITY 服务端配置
    pub reality: Option<Arc<RealityServerConfig>>,
    /// 动态多 SNI 分流路由表（SNI 域名 -> 转发目标或特定伪装站点）
    pub sni_routes: HashMap<String, String>,
    /// Web 回落目标（如 "127.0.0.1:8080"）
    pub fallback: Option<String>,
    /// 用户凭据列表（支持 Trojan 密码与 VLESS UUID）
    pub users: Vec<String>,
    /// 动态多用户管理器
    pub user_mgr: Option<Arc<UserManager>>,
    /// 入站安全门禁与限速器
    pub gate: Option<Arc<vp_core::InboundGate>>,
}

/// 443 端口多协议复用入站分发器
pub struct TlsMuxInbound {
    bind: String,
    port: u16,
    tag: Arc<str>,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    reality: Option<Arc<RealityServerConfig>>,
    sni_routes: HashMap<String, String>,
    fallback: Option<String>,
    trojan_hashes: Vec<[u8; 28]>,
    trojan_users_by_hex: HashMap<String, Arc<UserAccount>>,
    vless_uuids: HashSet<[u8; 16]>,
    vless_users_by_uuid: HashMap<[u8; 16], Arc<UserAccount>>,
    user_mgr: Option<Arc<UserManager>>,
    gate: Option<Arc<vp_core::InboundGate>>,
    direct: Arc<DirectOutbound>,
}

impl TlsMuxInbound {
    pub fn new(bind: &str, port: u16, tag: &str, options: TlsMuxOptions) -> Result<Self> {
        let tls_acceptor = match (&options.cert_pem, &options.key_pem) {
            (Some(cert), Some(key)) => Some(tls_acceptor(cert, key)?),
            _ => None,
        };

        let mut trojan_hashes = Vec::new();
        let mut trojan_users_by_hex = HashMap::new();
        let mut vless_uuids = HashSet::new();
        let mut vless_users_by_uuid = HashMap::new();

        for u in &options.users {
            // 尝试作为 VLESS UUID 解析
            if let Ok(uuid) = parse_uuid(u) {
                vless_uuids.insert(uuid);
                if let Some(mgr) = &options.user_mgr {
                    if let Some(account) = mgr.get_user(u) {
                        vless_users_by_uuid.insert(uuid, account);
                    }
                }
            }
            // 尝试作为 Trojan 密码哈希解析
            let h = password_hash(u);
            let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
            if !trojan_hashes.contains(&h) {
                trojan_hashes.push(h);
            }
            if let Some(mgr) = &options.user_mgr {
                if let Some(account) = mgr.get_user(u) {
                    trojan_users_by_hex.insert(hex, account);
                }
            }
        }

        // 导入 UserManager 中已存在的动态用户
        if let Some(mgr) = &options.user_mgr {
            for account in mgr.all_users() {
                if let Ok(uuid) = parse_uuid(&account.secret) {
                    vless_uuids.insert(uuid);
                    vless_users_by_uuid.insert(uuid, account.clone());
                }
                let h = password_hash(&account.secret);
                let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
                if !trojan_hashes.contains(&h) {
                    trojan_hashes.push(h);
                }
                trojan_users_by_hex.insert(hex, account);
            }
        }

        Ok(TlsMuxInbound {
            bind: bind.into(),
            port,
            tag: tag.into(),
            tls_acceptor,
            reality: options.reality,
            sni_routes: options.sni_routes,
            fallback: options.fallback,
            trojan_hashes,
            trojan_users_by_hex,
            vless_uuids,
            vless_users_by_uuid,
            user_mgr: options.user_mgr,
            gate: options.gate,
            direct: Arc::new(DirectOutbound::new(Arc::new(Resolver::system()), false)),
        })
    }

    /// 匹配 VLESS 用户
    fn match_vless_user(&self, uuid: &[u8; 16]) -> (bool, Option<Arc<UserAccount>>) {
        if let Some(mgr) = &self.user_mgr {
            if let Some(u) = mgr.get_user_by_uuid(uuid) {
                return (true, Some(u));
            }
        }
        if let Some(u) = self.vless_users_by_uuid.get(uuid) {
            return (true, Some(u.clone()));
        }
        (self.vless_uuids.contains(uuid), None)
    }

    /// 匹配 Trojan 用户
    fn match_trojan_user(&self, hex: &str) -> (bool, Option<Arc<UserAccount>>) {
        if let Some(mgr) = &self.user_mgr {
            if let Some(u) = mgr.get_user_by_trojan_hex(hex) {
                return (true, Some(u));
            }
        }
        if let Some(u) = self.trojan_users_by_hex.get(hex) {
            return (true, Some(u.clone()));
        }
        let matched = self.trojan_hashes.iter().any(|h| {
            let expect: String = h.iter().map(|b| format!("{b:02x}")).collect();
            expect.eq_ignore_ascii_case(hex)
        });
        (matched, None)
    }

    /// 派发并处理已经终结 TLS / REALITY 的明文双向数据流
    async fn serve_decrypted(
        self: &Arc<Self>,
        mut plain_stream: Box<dyn ProxyStream>,
        src: SocketAddr,
        ctx: &InboundCtx,
    ) -> Result<()> {
        let mut peek_buf = Vec::with_capacity(512);
        let mut chunk = [0u8; 128];

        // 读取首包首块数据（设置 2 秒等待超时）
        let n =
            match tokio::time::timeout(Duration::from_millis(2000), plain_stream.read(&mut chunk))
                .await
            {
                Ok(Ok(0)) => return Err(Error::Proto("tls-mux: 客户端过早关闭")),
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => return Err(Error::Proto("tls-mux: 读取首包超时")),
            };
        peek_buf.extend_from_slice(&chunk[..n]);

        // 1. 尝试识别 VLESS 协议特征：
        // VLESS 首字节版本固定为 0x00，随后 16 字节为 UUID
        if peek_buf[0] == VLESS_VERSION {
            // 补充读取到至少 17 字节以提取 UUID
            while peek_buf.len() < 17 {
                let n = plain_stream.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                peek_buf.extend_from_slice(&chunk[..n]);
            }

            if peek_buf.len() >= 17 {
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&peek_buf[1..17]);
                let (matched, user) = self.match_vless_user(&uuid);
                if matched {
                    // 校验用户流量配额熔断
                    if let Some(ref u) = user {
                        if u.is_quota_exceeded() {
                            return self
                                .handle_fallback_or_err(
                                    plain_stream,
                                    peek_buf,
                                    Error::Proto("vless: 用户配额已超限"),
                                )
                                .await;
                        }
                    }

                    // 循环读取完整 VLESS 请求头
                    let (dst, is_vision, used) = loop {
                        match decode_request(&peek_buf) {
                            Ok((_, dst, is_vision, used)) => break (dst, is_vision, used),
                            Err(Error::Proto(
                                "vless 请求头过短" | "vless 请求头截断" | "vless 地址截断",
                            )) => {
                                let n = plain_stream.read(&mut chunk).await?;
                                if n == 0 {
                                    return self
                                        .handle_fallback_or_err(
                                            plain_stream,
                                            peek_buf,
                                            Error::Proto("vless 请求头不完整"),
                                        )
                                        .await;
                                }
                                peek_buf.extend_from_slice(&chunk[..n]);
                                if peek_buf.len() > 1024 {
                                    return self
                                        .handle_fallback_or_err(
                                            plain_stream,
                                            peek_buf,
                                            Error::Proto("vless 请求头过长"),
                                        )
                                        .await;
                                }
                            }
                            Err(e) => {
                                return self
                                    .handle_fallback_or_err(plain_stream, peek_buf, e)
                                    .await;
                            }
                        }
                    };

                    // 回送 VLESS 响应头（若启用 vision 回送 18 字节流控标志）
                    if is_vision {
                        plain_stream
                            .write_all(&[VLESS_VERSION, VISION_FLOW_BYTES.len() as u8])
                            .await?;
                        plain_stream.write_all(VISION_FLOW_BYTES).await?;
                    } else {
                        plain_stream.write_all(&[VLESS_VERSION, 0]).await?;
                    }

                    if let Some(ref g) = self.gate {
                        g.mark_authenticated(src.ip());
                    }
                    let sess = Session::new_tcp(self.tag.clone(), Some(src), dst.clone());
                    let mut remote = self.direct.connect_stream(&sess, &dst).await?;
                    let extra = peek_buf.len() - used;
                    if extra > 0 {
                        remote.write_all(&peek_buf[used..]).await?;
                    }

                    let meta = ConnMeta {
                        id: sess.id,
                        inbound: self.tag.clone(),
                        network: "tcp",
                        host: dst.host.to_string(),
                        dst_port: dst.port,
                        src: Some(src.to_string()),
                        process: None,
                        user: user.as_ref().map(|u| u.username.clone()),
                        rule: None,
                        chain: Some("tls-mux-vless".into()),
                        start: vp_common::now_millis(),
                    };
                    let hook = RelayHook {
                        table: Some(ctx.conns.clone()),
                        meta: Some(meta),
                        stats: Some(ctx.stats.clone()),
                        user,
                        limiter: None,
                        brutal: None,
                    };
                    let client: Box<dyn ProxyStream> = if is_vision {
                        Box::new(VisionStream::new_server(plain_stream))
                    } else {
                        plain_stream
                    };
                    tokio::spawn(async move {
                        let _ = relay(client, remote, hook).await;
                    });
                    return Ok(());
                }
            }
        }

        // 2. 尝试识别 Trojan 协议特征：
        // Trojan 首部为 56 字符 ASCII 十六进制密码哈希 + 2 字节 CRLF（共 58 字节）
        if peek_buf[0].is_ascii_hexdigit() {
            while peek_buf.len() < 58 {
                let n = plain_stream.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                peek_buf.extend_from_slice(&chunk[..n]);
            }

            if peek_buf.len() >= 58
                && &peek_buf[56..58] == b"\r\n"
                && peek_buf[..56].iter().all(|b| b.is_ascii_hexdigit())
            {
                if let Ok(hex) = std::str::from_utf8(&peek_buf[..56]) {
                    let (matched, user) = self.match_trojan_user(hex);
                    if matched {
                        if let Some(ref u) = user {
                            if u.is_quota_exceeded() {
                                return self
                                    .handle_fallback_or_err(
                                        plain_stream,
                                        peek_buf,
                                        Error::Proto("trojan: 用户配额已超限"),
                                    )
                                    .await;
                            }
                        }

                        // 将 58 字节之后的多余预读字节无损封装进 PeekedStream
                        let mut client_stream =
                            PeekedStream::new(plain_stream, peek_buf[58..].to_vec());

                        // 读取 Trojan CMD（0x01 为 TCP）
                        let mut cmd = [0u8; 1];
                        client_stream.read_exact(&mut cmd).await?;
                        if cmd[0] != 0x01 {
                            return Err(Error::Unsupported("trojan 入站仅支持 TCP".into()));
                        }

                        // 读取 SOCKS5 目标地址
                        let mut addr_buf: Vec<u8> = Vec::with_capacity(300);
                        let (dst, _used) = loop {
                            match decode_socks_addr(&addr_buf) {
                                Ok(x) => break x,
                                Err(Error::Proto("address truncated"))
                                | Err(Error::Proto("empty domain")) => {
                                    let mut b = [0u8; 1];
                                    client_stream.read_exact(&mut b).await?;
                                    addr_buf.push(b[0]);
                                    if addr_buf.len() > 262 {
                                        return Err(Error::Proto("trojan 地址过长"));
                                    }
                                }
                                Err(e) => return Err(e),
                            }
                        };

                        // 读取结尾 CRLF
                        let mut crlf = [0u8; 2];
                        client_stream.read_exact(&mut crlf).await?;
                        if &crlf != b"\r\n" {
                            return Err(Error::Proto("trojan: 缺少结尾 CRLF"));
                        }

                        if let Some(ref g) = self.gate {
                            g.mark_authenticated(src.ip());
                        }
                        let sess = Session::new_tcp(self.tag.clone(), Some(src), dst.clone());
                        let remote = self.direct.connect_stream(&sess, &dst).await?;
                        let meta = ConnMeta {
                            id: sess.id,
                            inbound: self.tag.clone(),
                            network: "tcp",
                            host: dst.host.to_string(),
                            dst_port: dst.port,
                            src: Some(src.to_string()),
                            process: None,
                            user: user.as_ref().map(|u| u.username.clone()),
                            rule: None,
                            chain: Some("tls-mux-trojan".into()),
                            start: vp_common::now_millis(),
                        };
                        let hook = RelayHook {
                            table: Some(ctx.conns.clone()),
                            meta: Some(meta),
                            stats: Some(ctx.stats.clone()),
                            user,
                            limiter: None,
                            brutal: None,
                        };
                        let client: Box<dyn ProxyStream> = Box::new(client_stream);
                        tokio::spawn(async move {
                            let _ = relay(client, remote, hook).await;
                        });
                        return Ok(());
                    }
                }
            }
        }

        // 3. 未匹配到已知代理协议或凭据错误：透明零拷贝 Web Fallback 回落
        self.handle_fallback_or_err(
            plain_stream,
            peek_buf,
            Error::Proto("tls-mux: 协议特征未命中"),
        )
        .await
    }

    /// 处理回落逻辑或报错
    async fn handle_fallback_or_err(
        &self,
        stream: Box<dyn ProxyStream>,
        peeked: Vec<u8>,
        err: Error,
    ) -> Result<()> {
        if let Some(fb_target) = &self.fallback {
            tracing::debug!(
                fallback = %fb_target,
                "tls-mux 流量未认证或非代理请求，执行 Web Fallback 回落: {err}"
            );
            match tokio::net::TcpStream::connect(fb_target).await {
                Ok(fb_stream) => {
                    vp_transport::tune(&fb_stream);
                    let client: Box<dyn ProxyStream> = Box::new(PeekedStream::new(stream, peeked));
                    let remote: Box<dyn ProxyStream> = Box::new(fb_stream);
                    tokio::spawn(async move {
                        let _ = relay(client, remote, RelayHook::default()).await;
                    });
                    Ok(())
                }
                Err(conn_err) => {
                    tracing::warn!("tls-mux 连接回落目标 {fb_target} 失败: {conn_err}");
                    Err(err)
                }
            }
        } else {
            Err(err)
        }
    }

    /// 接入新连接并执行 SNI 嗅探与分流路由
    async fn handle_inbound_stream(
        self: &Arc<Self>,
        mut stream: tokio::net::TcpStream,
        src: SocketAddr,
        ctx: &InboundCtx,
    ) {
        // 安全门禁检查：未通过 GeoIP / ASN / 端口敲门过滤的源 IP 直接丢弃断开
        if let Some(ref g) = self.gate {
            if !g.check_accept(src.ip()) {
                return;
            }
        }

        // 1. 尝试预读前缀以嗅探 TLS SNI
        let mut peek_buf = Vec::with_capacity(512);
        let mut chunk = [0u8; 512];
        let n = match tokio::time::timeout(Duration::from_millis(2000), stream.read(&mut chunk))
            .await
        {
            Ok(Ok(0)) => return,
            Ok(Ok(n)) => n,
            _ => return,
        };
        peek_buf.extend_from_slice(&chunk[..n]);

        let is_tls = peek_buf.len() >= 5 && peek_buf[0] == 0x16 && peek_buf[1] == 0x03;
        let mut sniffed_sni = None;
        if is_tls {
            let record_len = u16::from_be_bytes([peek_buf[3], peek_buf[4]]) as usize;
            let target_read = (5 + record_len).min(1024);
            while peek_buf.len() < target_read {
                match stream.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => peek_buf.extend_from_slice(&chunk[..n]),
                    Err(_) => break,
                }
            }
            sniffed_sni = vp_core::sniff::parse_tls_sni(&peek_buf);
        }

        let peeked_stream = PeekedStream::new(stream, peek_buf);

        // 2. 若嗅探到了 SNI 且命中显式配置的动态伪装反代目标
        if let Some(ref sni) = sniffed_sni {
            let sni_lower = sni.to_ascii_lowercase();
            if let Some(target) = self.sni_routes.get(&sni_lower) {
                tracing::info!(sni = %sni, target = %target, "SNI 命中动态伪装路由，透明反代透传");
                if let Ok(remote) = tokio::net::TcpStream::connect(target).await {
                    vp_transport::tune(&remote);
                    let client: Box<dyn ProxyStream> = Box::new(peeked_stream);
                    let remote: Box<dyn ProxyStream> = Box::new(remote);
                    tokio::spawn(async move {
                        let _ = relay(client, remote, RelayHook::default()).await;
                    });
                    return;
                }
            }
        }

        // 3. 依据 SNI 匹配与配置分发握手模式：REALITY、标准 TLS 或明文
        let is_reality_candidate = if let Some(ref r) = self.reality {
            if let Some(ref sni) = sniffed_sni {
                r.server_names.is_empty()
                    || r.server_names.iter().any(|s| s.eq_ignore_ascii_case(sni))
            } else {
                self.tls_acceptor.is_none()
            }
        } else {
            false
        };

        if is_reality_candidate {
            if let Some(reality_cfg) = &self.reality {
                match reality_server_handshake(peeked_stream, reality_cfg.clone()).await {
                    Ok(RealityHandshakeResult::Success(plain)) => {
                        if let Err(e) = self.serve_decrypted(plain, src, ctx).await {
                            tracing::debug!("tls-mux (reality) 会话结束: {e}");
                        }
                    }
                    Ok(RealityHandshakeResult::Fellback) => {
                        tracing::debug!("tls-mux (reality) 探针已透明反代回落");
                    }
                    Err(e) => {
                        tracing::debug!("tls-mux (reality) 握手失败: {e}");
                    }
                }
                return;
            }
        }

        if let Some(acceptor) = &self.tls_acceptor {
            if is_tls {
                match acceptor.accept(peeked_stream).await {
                    Ok(tls_stream) => {
                        let plain: Box<dyn ProxyStream> =
                            Box::new(vp_core::stream::Opaque(tls_stream));
                        if let Err(e) = self.serve_decrypted(plain, src, ctx).await {
                            tracing::debug!("tls-mux (tls) 会话结束: {e}");
                        }
                    }
                    Err(e) => {
                        tracing::debug!("tls-mux TLS accept 失败: {e}");
                    }
                }
                return;
            }
        }

        // 4. 未开启 TLS/REALITY 或非 TLS 探测流量
        let plain: Box<dyn ProxyStream> = Box::new(peeked_stream);
        if let Err(e) = self.serve_decrypted(plain, src, ctx).await {
            tracing::debug!("tls-mux (plain) 会话结束: {e}");
        }
    }
}

#[async_trait]
impl Inbound for TlsMuxInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, ctx: InboundCtx) -> Result<u16> {
        use std::net::ToSocketAddrs;
        let addr = match (self.bind.as_str(), self.port).to_socket_addrs() {
            Ok(mut it) => it.next().ok_or_else(|| {
                Error::Config(format!("无法解析绑定地址 {}:{}", self.bind, self.port))
            })?,
            Err(e) => {
                return Err(Error::Config(format!(
                    "无法解析绑定地址 {}:{}: {e}",
                    self.bind, self.port
                )));
            }
        };

        let listener = vp_transport::bind_tcp_listener(addr)?;
        let bound = listener.local_addr()?.port();
        let this = self.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, src)) => {
                        vp_transport::tune(&stream);
                        let this = this.clone();
                        let ctx = ctx.clone();
                        tokio::spawn(async move {
                            this.handle_inbound_stream(stream, src, &ctx).await;
                        });
                    }
                    Err(e) => {
                        tracing::warn!("tls-mux 入站 accept 失败: {e}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        });

        Ok(bound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trojan::TrojanOutbound;
    use crate::vless::VlessOutbound;
    use vp_config::{TrojanCfg, VlessCfg};

    #[tokio::test]
    async fn test_tls_mux_multiplexing_and_fallback() {
        // 1. 启动回显目标服务器（模拟 Internet 目标服务）
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let mut b = [0u8; 1024];
                    loop {
                        let n = match s.read(&mut b).await {
                            Ok(0) => break,
                            Ok(n) => n,
                            Err(_) => break,
                        };
                        if s.write_all(&b[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        // 2. 启动后置 Web Fallback 站点（模拟本地 Nginx/Caddy）
        let web_server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let web_addr = web_server.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = web_server.accept().await {
                tokio::spawn(async move {
                    let mut b = [0u8; 1024];
                    let _ = s.read(&mut b).await;
                    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\nHello From Caddy!";
                    let _ = s.write_all(resp).await;
                });
            }
        });

        // 3. 构建并启动多协议复用入站分发器 TlsMuxInbound
        let ctx = InboundCtx {
            router: Arc::new(crate::test_support::NoopRouter()),
            stats: Arc::new(vp_common::Stats::default()),
            conns: Arc::new(vp_core::ConnTable::new()),
        };
        let user_mgr = Arc::new(UserManager::new());
        user_mgr.add_user(Arc::new(UserAccount::new(
            "trojan_user",
            "trojan_secret_password",
            None,
            None,
        )));
        let vless_uuid_str = "b831381d-6324-4d53-ad4f-8cda48b30811";
        user_mgr.add_user(Arc::new(UserAccount::new(
            "vless_user",
            vless_uuid_str,
            None,
            None,
        )));

        let options = TlsMuxOptions {
            cert_pem: None,
            key_pem: None,
            reality: None,
            sni_routes: HashMap::new(),
            fallback: Some(web_addr.to_string()),
            users: vec!["trojan_secret_password".into(), vless_uuid_str.into()],
            user_mgr: Some(user_mgr),
            gate: None,
        };

        let mux_server = Arc::new(TlsMuxInbound::new("127.0.0.1", 0, "mux-443", options).unwrap());
        let mux_port = mux_server.start(ctx).await.unwrap();

        // 场景 A: 验证 Trojan 流量经 mux 入站分发成功
        {
            let trojan_out = TrojanOutbound::new(&TrojanCfg {
                server: "127.0.0.1".into(),
                port: mux_port,
                password: "trojan_secret_password".into(),
                tls: false,
                server_name: None,
                skip_cert_verify: false,
                client_fingerprint: None,
                alpn: None,
                network: None,
                ws_opts: None,
                grpc_opts: None,
                http_opts: None,
                reality_opts: None,
                ech_opts: None,
                udp: false,
            })
            .unwrap();

            let sess = Session::new_tcp(
                "test-in".into(),
                None,
                vp_common::DstAddr {
                    host: vp_common::Host::Ip(echo_addr.ip()),
                    port: echo_addr.port(),
                },
            );
            let mut stream = trojan_out
                .connect_stream(&sess, &sess.dst)
                .await
                .expect("Trojan 出站拨号 Mux 失败");

            stream.write_all(b"PING_TROJAN_DATA").await.unwrap();
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"PING_TROJAN_DATA");
        }

        // 场景 B: 验证 VLESS 流量经 mux 入站分发成功
        {
            let vless_out = VlessOutbound::new(&VlessCfg {
                server: "127.0.0.1".into(),
                port: mux_port,
                uuid: vless_uuid_str.into(),
                flow: None,
                tls: false,
                server_name: None,
                skip_cert_verify: false,
                client_fingerprint: None,
                alpn: None,
                network: None,
                ws_opts: None,
                grpc_opts: None,
                reality_opts: None,
                ech_opts: None,
                http_opts: None,
                udp: false,
            })
            .unwrap();

            let sess = Session::new_tcp(
                "test-in".into(),
                None,
                vp_common::DstAddr {
                    host: vp_common::Host::Ip(echo_addr.ip()),
                    port: echo_addr.port(),
                },
            );
            let mut stream = vless_out
                .connect_stream(&sess, &sess.dst)
                .await
                .expect("VLESS 出站拨号 Mux 失败");

            stream.write_all(b"PING_VLESS_DATA").await.unwrap();
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"PING_VLESS_DATA");
        }

        // 场景 C: 验证未认证/普通 HTTP 请求通过 Web Fallback 原样零拷贝透传
        {
            let mut client = tokio::net::TcpStream::connect(("127.0.0.1", mux_port))
                .await
                .expect("连接 mux 端口失败");
            let http_req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
            client.write_all(http_req).await.unwrap();

            let mut resp = vec![0u8; 1024];
            let n = client.read(&mut resp).await.unwrap();
            let resp_str = String::from_utf8_lossy(&resp[..n]);
            assert!(
                resp_str.contains("Hello From Caddy!"),
                "应当收到后置 Web Fallback 站点响应: {resp_str}"
            );
        }
    }

    #[tokio::test]
    async fn test_tls_mux_reality_probe_fallback() {
        // 1. 模拟真实伪装目标（如 Apple 官网，收到探测返回伪装网页）
        let camo_dest = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let camo_addr = camo_dest.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = camo_dest.accept().await {
                let mut b = [0u8; 512];
                let _ = s.read(&mut b).await;
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 26\r\n\r\nHello From Apple Official!",
                    )
                    .await;
            }
        });

        // 2. 服务端 REALITY 密钥配置
        let srv_pri_bytes = [7u8; 32];
        let reality_cfg = Arc::new(RealityServerConfig::new(
            srv_pri_bytes,
            vec![[1, 2, 3, 4, 5, 6, 7, 8]],
            camo_addr.to_string(),
            vec!["www.apple.com".into()],
        ));

        let ctx = InboundCtx {
            router: Arc::new(crate::test_support::NoopRouter()),
            stats: Arc::new(vp_common::Stats::default()),
            conns: Arc::new(vp_core::ConnTable::new()),
        };

        let options = TlsMuxOptions {
            cert_pem: None,
            key_pem: None,
            reality: Some(reality_cfg),
            sni_routes: HashMap::new(),
            fallback: None,
            users: vec!["some_pass".into()],
            user_mgr: None,
            gate: None,
        };

        let mux_server =
            Arc::new(TlsMuxInbound::new("127.0.0.1", 0, "mux-reality", options).unwrap());
        let mux_port = mux_server.start(ctx).await.unwrap();

        // 3. 模拟主动探测/扫描器发送明文 HTTP 请求探测 443 REALITY 端口
        let mut scanner = tokio::net::TcpStream::connect(("127.0.0.1", mux_port))
            .await
            .expect("扫描器连接 REALITY 端口失败");

        let probe_req = b"GET / HTTP/1.1\r\nHost: www.apple.com\r\n\r\n";
        scanner.write_all(probe_req).await.unwrap();

        let mut probe_resp = vec![0u8; 1024];
        let n = scanner.read(&mut probe_resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&probe_resp[..n]);
        assert!(
            resp_str.contains("Hello From Apple Official!"),
            "主动探测时 REALITY 服务端必须透明反代回落至伪装目标: {resp_str}"
        );
    }

    #[tokio::test]
    async fn test_tls_mux_dynamic_sni_routing() {
        // 1. 启动专用 SNI 伪装后端（例如专属的 Microsoft 伪装站）
        let ms_camo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ms_addr = ms_camo.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = ms_camo.accept().await {
                let mut b = [0u8; 512];
                let _ = s.read(&mut b).await;
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS\r\nContent-Length: 9\r\n\r\nMicrosoft")
                    .await;
            }
        });

        // 2. 配置动态 SNI 路由表：将 "www.microsoft.com" 路由至专用伪装站
        let mut sni_routes = HashMap::new();
        sni_routes.insert("www.microsoft.com".to_string(), ms_addr.to_string());

        let ctx = InboundCtx {
            router: Arc::new(crate::test_support::NoopRouter()),
            stats: Arc::new(vp_common::Stats::default()),
            conns: Arc::new(vp_core::ConnTable::new()),
        };

        let options = TlsMuxOptions {
            cert_pem: None,
            key_pem: None,
            reality: None,
            sni_routes,
            fallback: None,
            users: vec![],
            user_mgr: None,
            gate: None,
        };

        let mux_server = Arc::new(TlsMuxInbound::new("127.0.0.1", 0, "mux-sni", options).unwrap());
        let mux_port = mux_server.start(ctx).await.unwrap();

        // 3. 发送构造的带有 SNI: "www.microsoft.com" 的 TLS ClientHello
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", mux_port))
            .await
            .unwrap();

        // 构造简易 TLS 1.2/1.3 ClientHello（包含 extension 00 00 SNI: www.microsoft.com）
        let sni_bytes = b"www.microsoft.com";
        let mut ch_body = Vec::new();
        ch_body.push(0x01); // ClientHello
        ch_body.extend_from_slice(&[0x00, 0x00, 0x00]); // 占位长度
        ch_body.extend_from_slice(&[0x03, 0x03]); // ClientVersion
        ch_body.extend_from_slice(&[0xAA; 32]); // Random
        ch_body.push(0x00); // Session ID len = 0
        ch_body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // Cipher suites (TLS_AES_128_GCM_SHA256)
        ch_body.extend_from_slice(&[0x01, 0x00]); // Compression methods len = 1, null

        // Extensions
        let mut exts = Vec::new();
        // Server Name Indication (0x0000)
        exts.extend_from_slice(&[0x00, 0x00]);
        let sni_list_len = (3 + sni_bytes.len()) as u16;
        let ext_len = (2 + sni_list_len) as u16;
        exts.extend_from_slice(&ext_len.to_be_bytes());
        exts.extend_from_slice(&sni_list_len.to_be_bytes());
        exts.push(0x00); // host_name type
        exts.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        exts.extend_from_slice(sni_bytes);

        ch_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        ch_body.extend_from_slice(&exts);

        // 回填 ClientHello 长度
        let ch_payload_len = (ch_body.len() - 4) as u32;
        ch_body[1] = (ch_payload_len >> 16) as u8;
        ch_body[2] = (ch_payload_len >> 8) as u8;
        ch_body[3] = ch_payload_len as u8;

        // TLS Record Header
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
        record.extend_from_slice(&(ch_body.len() as u16).to_be_bytes());
        record.extend_from_slice(&ch_body);

        client.write_all(&record).await.unwrap();

        // 验证收到的响应来自专属的 Microsoft 后端站点
        let mut resp = [0u8; 256];
        let n = client.read(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(
            resp_str.contains("Microsoft-IIS"),
            "SNI 必须命中专用路由并反代至对应伪装站点: {resp_str}"
        );
    }
}

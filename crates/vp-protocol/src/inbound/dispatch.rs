//! 入站公共分发：协议握手完成后，路由 → 出站连接 → 双向转发。

use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tracing::{debug, warn};

use vp_common::now_millis;
use vp_core::conn_table::ConnMeta;
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;
use vp_core::stream::ProxyStream;
use vp_core::tunnel::{RelayHook, relay};

/// 出站连接失败时向客户端回写的错误（尽力而为）
pub enum ClientReply<'a> {
    /// socks5 错误码
    Socks5(u8),
    /// HTTP 状态行
    Http(&'a str),
    None,
}

/// 完成入站协议应答后调用：路由 + 建立出站 + 转发
pub async fn dispatch_stream(
    ctx: &InboundCtx,
    mut sess: Session,
    mut client: Box<dyn ProxyStream>,
    reply: ClientReply<'_>,
) {
    // 连接资源预算（审计报告任务2）：超限快速拒绝，额度由 RAII 贯穿连接生命周期
    let _conn_permit = match ctx.stats.conn_budget.try_acquire(&sess.inbound) {
        Some(p) => p,
        None => {
            warn!("[TCP] {} 入站 {} 连接数超限，拒绝", sess.dst, sess.inbound);
            match reply {
                ClientReply::Socks5(_) => {
                    let _ = client
                        .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                }
                ClientReply::Http(_) => {
                    let _ = client
                        .write_all(b"HTTP/1.1 503 Too Many Connections\r\n\r\n")
                        .await;
                }
                ClientReply::None => {}
            }
            return;
        }
    };

    // UDP over TCP（UoT）：魔法地址目标交由 UoT 中继处理
    if crate::uot::is_magic(&sess.dst) {
        let _ = crate::uot::serve_client(ctx, sess, client).await;
        return;
    }

    // 进程归属（Windows 查表 + 缓存；其它平台 None）
    if sess.process.is_none() {
        if let Some(src) = sess.src {
            let p = tokio::task::spawn_blocking(move || vp_rule::process::find_process_name(src))
                .await
                .ok()
                .flatten();
            if let Some(p) = p {
                sess.process = Some(Arc::from(p));
            }
        }
    }

    // 协议嗅探：若目标为 IP 且客户端先发言（无协议前置回写需求），窥探 SNI / HTTP Host
    if matches!(sess.dst.host, vp_common::Host::Ip(_)) && matches!(reply, ClientReply::None) {
        let (sniffed, peeked) =
            crate::sniff::sniff_stream(client, std::time::Duration::from_millis(100)).await;
        client = peeked;
        if let Some(domain) = sniffed {
            debug!("sniff: 嗅探到真实域名 {} -> {}", sess.dst, domain);
            sess.dst.host = vp_common::Host::Domain(domain);
        }
    }

    let res = ctx.router.pick(&sess).await;
    let outbound = res.outbound.clone();
    tracing::debug!(
        "dispatch_stream: picked outbound={} via={}",
        outbound.name(),
        res.via
    );

    let meta = ConnMeta {
        id: sess.id,
        inbound: sess.inbound.clone(),
        network: "tcp",
        host: sess.dst.host.to_string(),
        dst_port: sess.dst.port,
        src: sess.src.map(|s| s.to_string()),
        process: sess.process.clone(),
        rule: res
            .rule
            .as_ref()
            .map(|r| format!("{} => {}", r.rule, r.target)),
        chain: Some(if outbound.name() != res.via.as_ref() {
            Arc::from(format!("{} > {}", outbound.name(), res.via))
        } else {
            res.via.clone()
        }),
        start: now_millis(),
    };

    let rule_tag = res
        .rule
        .as_ref()
        .map(|r| r.rule.as_str())
        .unwrap_or("Match()");
    let chain_tag = if outbound.name() != res.via.as_ref() {
        format!("{}[{}]", res.via, outbound.name())
    } else {
        outbound.name().to_string()
    };
    let src_str = sess
        .src
        .map(|s| s.to_string())
        .unwrap_or_else(|| "-".into());
    tracing::info!(
        "[TCP] {} --> {} match {} using {}",
        src_str,
        sess.dst,
        rule_tag,
        chain_tag
    );

    match outbound.connect_stream(&sess, &sess.dst).await {
        Ok(remote) => {
            // 成功应答
            match reply {
                ClientReply::Socks5(rep) => {
                    let _ = client
                        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                }
                ClientReply::Http(status) => {
                    let _ = client
                        .write_all(format!("HTTP/1.1 {status}\r\n\r\n").as_bytes())
                        .await;
                }
                ClientReply::None => {}
            }
            let hook = RelayHook {
                table: Some(ctx.conns.clone()),
                meta: Some(meta),
                stats: Some(ctx.stats.clone()),
            };
            let _ = relay(client, remote, hook).await;
        }
        Err(e) => {
            if outbound.name() == "REJECT" {
                tracing::info!("[TCP] {} 出站 REJECT 阻断", sess.dst);
            } else {
                warn!("[TCP] {} 出站 {} 失败: {}", sess.dst, outbound.name(), e);
            }
            match reply {
                ClientReply::Socks5(_) => {
                    let _ = client
                        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                }
                ClientReply::Http(_) => {
                    let _ = client
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                        .await;
                }
                ClientReply::None => {}
            }
            let _ = client.shutdown().await;
        }
    }
}

//! 入站公共分发：协议握手完成后，路由 → 出站连接 → 双向转发。

use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tracing::{debug, warn};

use vp_common::now_millis;
use vp_core::conn_table::ConnMeta;
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;
use vp_core::stream::ProxyStream;
use vp_core::tunnel::{relay, RelayHook};

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
    // UDP over TCP（UoT）：魔法地址目标交由 UoT 中继处理
    if crate::uot::is_magic(&sess.dst) {
        let _ = crate::uot::serve_client(ctx, sess, client).await;
        return;
    }

    // 进程归属（Windows 查表 + 缓存；其它平台 None）
    if sess.process.is_none() {
        if let Some(src) = sess.src {
            let src = std::net::SocketAddr::from(src);
            let p = tokio::task::spawn_blocking(move || {
                vp_rule::process::find_process_name(src)
            })
            .await
            .ok()
            .flatten();
            if let Some(p) = p {
                sess.process = Some(Arc::from(p));
            }
        }
    }

    let res = ctx.router.pick(&sess).await;
    let outbound = res.outbound.clone();

    let meta = ConnMeta {
        id: sess.id,
        inbound: sess.inbound.clone(),
        network: "tcp",
        host: sess.dst.host.to_string(),
        dst_port: sess.dst.port,
        src: sess.src.map(|s| s.to_string()),
        process: sess.process.clone(),
        rule: res.rule.as_ref().map(|r| format!("{} => {}", r.rule, r.target)),
        chain: Some(res.via.clone()),
        start: now_millis(),
    };

    debug!("{} -> {} via {} ({})", sess.dst, outbound.name(), res.via, sess.inbound);

    match outbound.connect_stream(&sess, &sess.dst).await {
        Ok(remote) => {
            // 成功应答
            match reply {
                ClientReply::Socks5(rep) => {
                    let _ = client.write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
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
            warn!("出站 {} 失败: {}", outbound.name(), e);
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

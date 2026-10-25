//! SOCKS5 服务端入站。

use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, warn};

use vp_common::addr::decode_socks_addr;
use vp_common::{DstAddr, Error, Result};
use vp_core::inbound::InboundCtx;
use vp_core::session::Session;

use super::dispatch::{dispatch_stream, ClientReply};

pub struct Socks5Inbound {
    bind: String,
    port: u16,
    tag: Arc<str>,
}

impl Socks5Inbound {
    pub fn new(bind: String, port: u16, tag: &str) -> Self {
        Socks5Inbound { bind, port, tag: tag.into() }
    }
}

#[async_trait]
impl vp_core::Inbound for Socks5Inbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, ctx: InboundCtx) -> Result<u16> {
        let listener = TcpListener::bind((self.bind.as_str(), self.port)).await?;
        let bound = listener.local_addr()?.port();
        let tag = self.tag.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, src)) => {
                        let ctx = ctx.clone();
                        let tag = tag.clone();
                        tokio::spawn(async move {
                            if let Err(e) =
                                serve_socks5(stream, src, tag, &ctx).await
                            {
                                debug!("socks5 入站会话结束: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        warn!("socks5 入站 accept 失败: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        });
        Ok(bound)
    }
}

/// SOCKS5 服务端协议处理（泛型流，mixed 入站复用）
pub async fn serve_socks5<S>(
    mut stream: S,
    src: std::net::SocketAddr,
    tag: Arc<str>,
    ctx: &InboundCtx,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // 方法协商
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(Error::Proto("socks5 入站: 版本错误"));
    }
    let n = head[1] as usize;
    if n == 0 || n > 8 {
        return Err(Error::Proto("socks5 入站: 方法数非法"));
    }
    let mut methods = vec![0u8; n];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[0x05, 0x00]).await?; // 无认证

    // 请求头：[ver][cmd][rsv]（atyp 起由 read_socks_addr 解析）
    let mut req = [0u8; 3];
    stream.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        return Err(Error::Proto("socks5 入站: 请求版本错误"));
    }
    let dst = read_socks_addr(&mut stream).await?;
    match req[1] {
        0x01 => {
            let sess = Session::new_tcp(tag, Some(src), dst);
            dispatch_stream(ctx, sess, Box::new(stream), ClientReply::Socks5(0x00)).await;
            Ok(())
        }
        0x03 => {
            // UDP ASSOCIATE：M1 优雅拒绝（UDP 随 TUN 里程碑）
            stream
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            Ok(())
        }
        other => Err(Error::ProtoMsg(format!("socks5 入站: 不支持的命令 {other}"))),
    }
}

/// 增量读取 SOCKS 地址
pub async fn read_socks_addr<S>(io: &mut S) -> Result<DstAddr>
where
    S: AsyncRead + Unpin,
{
    let mut rest: Vec<u8> = Vec::with_capacity(300);
    loop {
        match decode_socks_addr(&rest) {
            Ok((dst, _)) => return Ok(dst),
            Err(Error::Proto("address truncated")) | Err(Error::Proto("empty domain")) => {
                let mut b = [0u8; 1];
                io.read_exact(&mut b).await?;
                rest.push(b[0]);
                if rest.len() > 262 {
                    return Err(Error::Proto("地址过长"));
                }
            }
            Err(e) => return Err(e),
        }
    }
}

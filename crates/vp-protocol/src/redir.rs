//! REDIR 透明代理入站（Linux iptables REDIRECT/TPROXY 场景）。
//!
//! 通过 SO_ORIGINAL_DST / IP_TRANSPARENT 获取连接原始目标，
//! 流量不经协议解析直接转发。非 Linux 平台启动时明确报错。

use std::sync::Arc;

use async_trait::async_trait;
#[cfg(target_os = "linux")]
use tokio::net::TcpListener;
#[cfg(target_os = "linux")]
use tracing::{debug, warn};

#[cfg(target_os = "linux")]
use vp_common::addr::DstAddr;
use vp_common::{Error, Result};
use vp_core::Inbound;
#[cfg(target_os = "linux")]
use vp_core::Session;
use vp_core::inbound::InboundCtx;

#[cfg(target_os = "linux")]
use crate::inbound::dispatch::dispatch_stream;

pub struct RedirInbound {
    #[allow(dead_code)]
    bind: String,
    #[allow(dead_code)]
    port: u16,
    tag: Arc<str>,
}

impl RedirInbound {
    pub fn new(bind: &str, port: u16, tag: &str) -> Self {
        RedirInbound {
            bind: bind.into(),
            port,
            tag: tag.into(),
        }
    }
}

#[async_trait]
impl Inbound for RedirInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, ctx: InboundCtx) -> Result<u16> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = &ctx;
            return Err(Error::Unsupported(
                "redir/tproxy 入站仅支持 Linux（当前平台的透明代理由 TUN 模式承担）".into(),
            ));
        }
        #[cfg(target_os = "linux")]
        {
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
                                let dst = match original_dst(&stream) {
                                    Ok(d) => d,
                                    Err(e) => {
                                        debug!("redir: 取原始目标失败: {e}");
                                        return;
                                    }
                                };
                                let sess = Session::new_tcp(tag, Some(src), dst.clone());
                                dispatch_stream(
                                    &ctx,
                                    sess,
                                    Box::new(stream),
                                    crate::inbound::dispatch::ClientReply::None,
                                )
                                .await;
                            });
                        }
                        Err(e) => {
                            warn!("redir accept 失败: {e}");
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        }
                    }
                }
            });
            Ok(bound)
        }
    }
}

#[cfg(target_os = "linux")]
fn original_dst(stream: &tokio::net::TcpStream) -> Result<DstAddr> {
    use std::os::fd::AsRawFd;
    unsafe {
        let fd = stream.as_raw_fd();
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let rc = libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if rc != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);
        Ok(DstAddr::ip(std::net::IpAddr::V4(ip), port))
    }
}

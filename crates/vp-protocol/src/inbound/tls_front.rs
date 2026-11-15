//! TLS 前置入站装饰器：对外终结 TLS，解密后的明文流回送内层监听器（127.0.0.1 回环）。
//!
//! 用途：流式协议入站（trojan/vless/vmess/anytls/mieru/brook/snell/naive）自身不做
//! TLS 终结时，由本层统一承担 —— 内层监听器按 `127.0.0.1:0` 构造（start 时动态
//! 取回实际端口），对公网完全不可达；对外端口 = 本层的 `bind:port`。
//!
//! 说明：内层看到的客户端地址为 127.0.0.1，准入门禁（geo 门禁等）由本层在 TLS
//! 握手前按真实来源 IP 判定；连接统计以内层会话记录为准（本层透明中继）。

use std::net::ToSocketAddrs;
use std::sync::Arc;

use async_trait::async_trait;
use tokio_rustls::TlsAcceptor;

use vp_common::{Error, Result};
use vp_core::inbound::{Inbound, InboundCtx};

pub struct TlsFrontInbound {
    bind: String,
    port: u16,
    tag: Arc<str>,
    acceptor: TlsAcceptor,
    /// 内层监听器（构造时固定 bind=127.0.0.1、port=0）
    inner: Arc<dyn Inbound>,
    gate: Option<Arc<vp_core::InboundGate>>,
    /// start 时由内层实际绑定端口填充
    upstream: tokio::sync::OnceCell<std::net::SocketAddr>,
}

impl TlsFrontInbound {
    pub fn new(
        bind: String,
        port: u16,
        tag: &str,
        acceptor: TlsAcceptor,
        inner: Arc<dyn Inbound>,
        gate: Option<Arc<vp_core::InboundGate>>,
    ) -> Self {
        Self {
            bind,
            port,
            tag: tag.into(),
            acceptor,
            inner,
            gate,
            upstream: tokio::sync::OnceCell::new(),
        }
    }

    /// 内层监听器实际地址（start 后可用；测试/诊断用）
    pub fn upstream(&self) -> Option<std::net::SocketAddr> {
        self.upstream.get().copied()
    }

    async fn pipe(&self, stream: tokio::net::TcpStream) -> Result<()> {
        if let Some(ref g) = self.gate {
            if !g.check_accept(
                stream
                    .peer_addr()
                    .map(|a| a.ip())
                    .unwrap_or(std::net::IpAddr::from([127, 0, 0, 1])),
            ) {
                return Ok(());
            }
        }
        let mut tls = self
            .acceptor
            .accept(stream)
            .await
            .map_err(|e| Error::ProtoMsg(format!("tls-front: TLS 握手失败: {e}")))?;
        if let Some(ref g) = self.gate {
            g.mark_authenticated(std::net::IpAddr::from([127, 0, 0, 1]));
        }
        let upstream = self
            .upstream()
            .ok_or(Error::Proto("tls-front: 内层未就绪"))?;
        let mut inner = tokio::net::TcpStream::connect(upstream).await?;
        tokio::io::copy_bidirectional(&mut tls, &mut inner)
            .await
            .map(|_| ())
            .map_err(|e| Error::Io(std::io::Error::other(e)))
    }
}

#[async_trait]
impl Inbound for TlsFrontInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, ctx: InboundCtx) -> Result<u16> {
        // 1. 先起内层（回环 + 随机端口），拿到上游地址
        let inner_port = self.inner.clone().start(ctx).await?;
        let upstream = std::net::SocketAddr::from(([127, 0, 0, 1], inner_port));
        let _ = self.upstream.set(upstream);

        // 2. 对外绑定 TLS 前置端口
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
                    Ok((stream, _src)) => {
                        let this = this.clone();
                        tokio::spawn(async move {
                            if let Err(e) = this.pipe(stream).await {
                                tracing::debug!("tls-front 会话结束: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("tls-front accept 失败: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        });
        Ok(bound)
    }
}

//! 出站（协议客户端 / 策略组）统一抽象。

use async_trait::async_trait;
use vp_common::{DstAddr, Error, Result};

use crate::session::Session;
use crate::stream::{PacketConn, ProxyStream};

#[async_trait]
pub trait Outbound: Send + Sync {
    /// 唯一名（配置中的 name / DIRECT / REJECT / 组名）
    fn name(&self) -> &str;

    /// 建立到 dst 的字节流隧道
    async fn connect_stream(&self, sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>>;

    /// 在既有隧道之上完成本协议握手（Relay 链式所需）。
    /// 默认不支持。
    async fn connect_over(
        &self,
        sess: &Session,
        dst: &DstAddr,
        underlying: Box<dyn ProxyStream>,
    ) -> Result<Box<dyn ProxyStream>> {
        let _ = (sess, dst, underlying);
        Err(Error::Unsupported(format!(
            "outbound '{}' does not support connect_over",
            self.name()
        )))
    }

    fn support_udp(&self) -> bool {
        false
    }

    async fn connect_packet(&self, sess: &Session, dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        let _ = (sess, dst);
        Err(Error::Unsupported(format!(
            "outbound '{}' has no udp support",
            self.name()
        )))
    }

    /// 节点服务器地址（Relay 链式与健康检查用）
    fn remote_addr(&self) -> Option<(String, u16)> {
        None
    }
}

use std::sync::Arc;

/// 链式代理包装器（dialer-proxy / detour）：
/// 请求时先通过 dialer 出站连接到目标代理的服务器地址 (server:port)，
/// 然后调用目标代理的 connect_over 在已建立的底层流上完成协议层与传输层握手。
pub struct ChainedOutbound {
    inner: Arc<dyn Outbound>,
    dialer: Arc<dyn Outbound>,
}

impl ChainedOutbound {
    pub fn new(inner: Arc<dyn Outbound>, dialer: Arc<dyn Outbound>) -> Self {
        Self { inner, dialer }
    }

    pub fn inner(&self) -> &Arc<dyn Outbound> {
        &self.inner
    }

    pub fn dialer(&self) -> &Arc<dyn Outbound> {
        &self.dialer
    }
}

#[async_trait]
impl Outbound for ChainedOutbound {
    fn name(&self) -> &str {
        self.inner.name()
    }

    async fn connect_stream(&self, sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        let (server, port) = self.inner.remote_addr().ok_or_else(|| {
            Error::Unsupported(format!(
                "出站 '{}' 未暴露远端服务器地址，无法通过前置跳板 '{}' 建连",
                self.inner.name(),
                self.dialer.name()
            ))
        })?;
        let server_dst = DstAddr::new(server, port);
        // 1. 通过 dialer 前置跳板建立到达目标 proxy 服务器的基础传输流
        let underlying = self.dialer.connect_stream(sess, &server_dst).await?;
        // 2. 在隧道之上完成目标节点的传输层与协议层握手
        self.inner.connect_over(sess, dst, underlying).await
    }

    async fn connect_over(
        &self,
        sess: &Session,
        dst: &DstAddr,
        underlying: Box<dyn ProxyStream>,
    ) -> Result<Box<dyn ProxyStream>> {
        self.inner.connect_over(sess, dst, underlying).await
    }

    fn support_udp(&self) -> bool {
        self.inner.support_udp()
    }

    async fn connect_packet(&self, sess: &Session, dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        self.inner.connect_packet(sess, dst).await
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        self.inner.remote_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct TestDialer;
    #[async_trait]
    impl Outbound for TestDialer {
        fn name(&self) -> &str {
            "test-dialer"
        }
        async fn connect_stream(
            &self,
            _s: &Session,
            _dst: &DstAddr,
        ) -> Result<Box<dyn ProxyStream>> {
            let (mut a, b) = tokio::io::duplex(1024);
            tokio::spawn(async move {
                let mut buf = [0u8; 4];
                a.read_exact(&mut buf).await.unwrap();
                a.write_all(b"pong").await.unwrap();
            });
            Ok(Box::new(b))
        }
        async fn connect_packet(
            &self,
            _s: &Session,
            _dst: &DstAddr,
        ) -> Result<Box<dyn PacketConn>> {
            Err(Error::Unsupported("test".into()))
        }
    }

    struct TestTarget;
    #[async_trait]
    impl Outbound for TestTarget {
        fn name(&self) -> &str {
            "test-target"
        }
        async fn connect_stream(
            &self,
            _s: &Session,
            _dst: &DstAddr,
        ) -> Result<Box<dyn ProxyStream>> {
            Err(Error::Unsupported("should call connect_over".into()))
        }
        async fn connect_over(
            &self,
            _s: &Session,
            _dst: &DstAddr,
            underlying: Box<dyn ProxyStream>,
        ) -> Result<Box<dyn ProxyStream>> {
            Ok(underlying)
        }
        async fn connect_packet(
            &self,
            _s: &Session,
            _dst: &DstAddr,
        ) -> Result<Box<dyn PacketConn>> {
            Err(Error::Unsupported("test".into()))
        }
        fn remote_addr(&self) -> Option<(String, u16)> {
            Some(("landing.example.com".into(), 443))
        }
    }

    #[tokio::test]
    async fn test_chained_outbound_e2e() {
        let dialer = Arc::new(TestDialer);
        let target = Arc::new(TestTarget);
        let chained = ChainedOutbound::new(target, dialer);

        let sess = Session::new_tcp("t".into(), None, DstAddr::new("final.com", 80));
        let mut s = chained.connect_stream(&sess, &sess.dst).await.unwrap();
        s.write_all(b"ping").await.unwrap();
        let mut res = [0u8; 4];
        s.read_exact(&mut res).await.unwrap();
        assert_eq!(&res, b"pong");
    }
}

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

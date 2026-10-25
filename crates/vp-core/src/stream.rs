//! 流与数据报抽象：一切协议流量归约为这两类对象。

use bytes::Bytes;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};

use vp_common::Result;

/// TCP 型字节流（内核内统一流对象）
pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

/// UDP 型数据报
#[derive(Debug, Clone)]
pub struct UdpPacket {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub data: Bytes,
}

/// UDP 型会话连接
#[async_trait::async_trait]
pub trait PacketConn: Send {
    async fn send(&self, pkt: &UdpPacket) -> Result<()>;
    async fn recv(&mut self) -> Result<UdpPacket>;
}

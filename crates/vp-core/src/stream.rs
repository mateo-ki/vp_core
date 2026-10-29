//! 流与数据报抽象：一切协议流量归约为这两类对象。

use bytes::Bytes;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};

use vp_common::Result;

/// TCP 型字节流（内核内统一流对象）。
///
/// 不再使用 blanket impl：`raw_socket_fd` 必须能区分"裸 socket"与"封装流"，
/// 这是 Linux splice 零拷贝快速路径的安全判据 —— 封装层（加密/混淆/嗅探）
/// 内部可能持有未消费的缓冲字节，旁路直拷会丢数据，必须回退通用泵。
pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    /// 仅当对象本身就是一条裸 TCP socket 时返回其引用（Linux splice 零拷贝判据）。
    /// 返回引用而非裸 fd：splice 泵需要 tokio 的就绪机制（readable/writable），
    /// 对已注册的 fd 重复 AsyncFd 注册会被拒绝。
    fn raw_socket(&self) -> Option<&tokio::net::TcpStream> {
        None
    }
}

/// 裸 socket：ProxyStream + raw_socket_fd 全开。
impl ProxyStream for tokio::net::TcpStream {
    fn raw_socket(&self) -> Option<&tokio::net::TcpStream> {
        Some(self)
    }
}

/// 封装流：仅 ProxyStream，raw_socket 维持 None。
macro_rules! impl_proxy_stream {
    ($($t:ty),+ $(,)?) => {$(
        impl ProxyStream for $t {}
    )+};
}

// 测试与 TUN 用户态栈用的内存流
impl_proxy_stream![tokio::io::DuplexStream, tokio::io::SimplexStream];

/// 装箱透传：探测穿透 Box（relay 收到的正是 Box<dyn ProxyStream>）。
impl ProxyStream for Box<dyn ProxyStream> {
    fn raw_socket(&self) -> Option<&tokio::net::TcpStream> {
        (**self).raw_socket()
    }
}

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

/// 外来流的通用不透明包装（ipstack / tun / rustls 等无法直接实现本 crate trait 的类型）：
/// 完整转发读写语义，`raw_socket_fd` 恒 None（外来流一律走通用泵）。
pub struct Opaque<S>(pub S);

impl<S: AsyncRead + Unpin> AsyncRead for Opaque<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Opaque<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> ProxyStream for Opaque<S> {}

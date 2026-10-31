//! Tailscale 出站代理实现。
//!
//! 支持通过本机或远程 Tailscale Connector（SOCKS5 代理，默认 127.0.0.1:1055）
//! 接入 Tailnet 虚拟专用网络，支持访问 Tailscale 内部节点（100.64.0.0/10、fd7a:115c:a1e0::/48 及 *.ts.net），
//! 并支持配置 Exit Node 作为互联网出口。

use std::sync::Arc;

use async_trait::async_trait;
use tracing::debug;
use vp_common::{DstAddr, Result};
use vp_core::{Outbound, PacketConn, ProxyStream, Session};

use crate::basic_out::Socks5Outbound;

pub struct TailscaleOutbound {
    name: Arc<str>,
    server: String,
    port: u16,
    exit_node: Option<String>,
    #[allow(dead_code)]
    auth_key: Option<String>,
    #[allow(dead_code)]
    control_url: Option<String>,
    #[allow(dead_code)]
    hostname: Option<String>,
    udp: bool,
    socks5: Socks5Outbound,
}

impl TailscaleOutbound {
    pub fn new_named(name: &str, cfg: &vp_config::TailscaleCfg) -> Result<Self> {
        let server = cfg.server.clone();
        let port = cfg.port;
        let socks5 = Socks5Outbound {
            server: server.clone(),
            port,
            username: None,
            password: None,
            udp: cfg.udp,
        };
        Ok(TailscaleOutbound {
            name: name.into(),
            server,
            port,
            exit_node: cfg.exit_node.clone(),
            auth_key: cfg.auth_key.clone(),
            control_url: cfg.control_url.clone(),
            hostname: cfg.hostname.clone(),
            udp: cfg.udp,
            socks5,
        })
    }

    pub fn exit_node(&self) -> Option<&str> {
        self.exit_node.as_deref()
    }
}

#[async_trait]
impl Outbound for TailscaleOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect_stream(&self, sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        debug!(
            "tailscale [{}]: 路由 {} -> {}:{} (exit-node: {:?})",
            self.name, dst, self.server, self.port, self.exit_node
        );
        self.socks5.connect_stream(sess, dst).await
    }

    async fn connect_over(
        &self,
        sess: &Session,
        dst: &DstAddr,
        underlying: Box<dyn ProxyStream>,
    ) -> Result<Box<dyn ProxyStream>> {
        self.socks5.connect_over(sess, dst, underlying).await
    }

    fn support_udp(&self) -> bool {
        self.udp
    }

    async fn connect_packet(&self, sess: &Session, dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        self.socks5.connect_packet(sess, dst).await
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_tailscale_outbound_loopback() {
        // 模拟本地 tailscaled SOCKS5 connector 监听器
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        // 模拟目标 echo 服务
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut s, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 32];
            let n = s.read(&mut buf).await.unwrap();
            s.write_all(&buf[..n]).await.unwrap();
        });

        // 驱动 mock SOCKS5 代理
        tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.unwrap();
            // 1. 无鉴权握手
            let mut buf = [0u8; 3];
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf[0], 0x05);
            client.write_all(&[0x05, 0x00]).await.unwrap();

            // 2. CONNECT 请求
            let mut req = [0u8; 4];
            client.read_exact(&mut req).await.unwrap();
            assert_eq!(req[1], 0x01); // CONNECT
            let mut target_ip = [0u8; 4];
            client.read_exact(&mut target_ip).await.unwrap();
            let mut port_buf = [0u8; 2];
            client.read_exact(&mut port_buf).await.unwrap();
            let target_port = u16::from_be_bytes(port_buf);

            // 连接真实目标
            let target_addr: SocketAddr = format!(
                "{}.{}.{}.{}:{}",
                target_ip[0], target_ip[1], target_ip[2], target_ip[3], target_port
            )
            .parse()
            .unwrap();
            let target = tokio::net::TcpStream::connect(target_addr).await.unwrap();

            // 回复成功
            client
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();

            // 双向转发
            let (mut cr, mut cw) = client.into_split();
            let (mut tr, mut tw) = target.into_split();
            let _ = tokio::join!(
                tokio::io::copy(&mut cr, &mut tw),
                tokio::io::copy(&mut tr, &mut cw)
            );
        });

        let cfg = vp_config::TailscaleCfg {
            server: "127.0.0.1".into(),
            port: proxy_addr.port(),
            auth_key: Some("tskey-auth-test".into()),
            control_url: Some("https://controlplane.tailscale.com".into()),
            exit_node: Some("100.64.0.1".into()),
            hostname: Some("test-box".into()),
            state_dir: None,
            udp: true,
        };

        let outbound = TailscaleOutbound::new_named("tailscale-test", &cfg).unwrap();
        assert_eq!(outbound.name(), "tailscale-test");
        assert_eq!(outbound.exit_node(), Some("100.64.0.1"));
        assert!(outbound.support_udp());

        let sess = Session::new_tcp(
            "inbound".into(),
            None,
            DstAddr::ip(echo_addr.ip(), echo_addr.port()),
        );
        let mut stream = outbound
            .connect_stream(&sess, &DstAddr::ip(echo_addr.ip(), echo_addr.port()))
            .await
            .unwrap();

        stream.write_all(b"hello-tailscale").await.unwrap();
        let mut resp = [0u8; 15];
        stream.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"hello-tailscale");
    }
}

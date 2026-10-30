//! DIRECT 出站：本地直连（域名经 vp-dns 解析）。

use std::sync::Arc;

use async_trait::async_trait;

use vp_common::{DstAddr, Error, Host, Result};
use vp_core::{Outbound, PacketConn, ProxyStream, Session, UdpPacket};
use vp_dns::Resolver;

pub struct DirectOutbound {
    dns: Arc<Resolver>,
    ipv6: bool,
}

impl DirectOutbound {
    pub fn new(dns: Arc<Resolver>, ipv6: bool) -> Self {
        DirectOutbound { dns, ipv6 }
    }

    pub async fn resolve(&self, dst: &DstAddr) -> Result<Vec<std::net::SocketAddr>> {
        match &dst.host {
            Host::Ip(ip) => Ok(vec![std::net::SocketAddr::new(*ip, dst.port)]),
            Host::Domain(domain) => {
                let ips = self.dns.resolve_domain(domain, self.ipv6).await?;
                Ok(ips
                    .iter()
                    .map(|ip| std::net::SocketAddr::new(*ip, dst.port))
                    .collect())
            }
        }
    }
}

#[async_trait]
impl Outbound for DirectOutbound {
    fn name(&self) -> &str {
        "DIRECT"
    }

    async fn connect_stream(&self, sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        // 防止意外将流量直连回环到自身入站端口形成死循环
        if let Some(in_port) = sess.inbound_port {
            if dst.port == in_port {
                match &dst.host {
                    Host::Ip(ip) if ip.is_loopback() => {
                        return Err(Error::Proto("检测到直接回环死循环 (loopback to inbound)"));
                    }
                    Host::Domain(d)
                        if d.eq_ignore_ascii_case("localhost")
                            || d == "127.0.0.1"
                            || d == "::1" =>
                    {
                        return Err(Error::Proto("检测到直接回环死循环 (loopback to inbound)"));
                    }
                    _ => {}
                }
            }
        }
        let addrs = self.resolve(dst).await?;
        if addrs.is_empty() {
            return Err(Error::Addr(format!("无法解析 {dst}")));
        }
        // 多地址（CDN/双栈）并发竞速：避免单个失效地址吃光系统级连接超时
        let tcp = vp_transport::dial_addrs_multi(
            &addrs,
            &dst.host.to_string(),
            dst.port,
            std::time::Duration::from_secs(8),
        )
        .await?;
        Ok(Box::new(tcp))
    }

    fn support_udp(&self) -> bool {
        true
    }

    async fn connect_packet(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        let bind: std::net::SocketAddr = if dst.host.is_ip() && dst.host.to_string().contains(':') {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let sock = vp_transport::create_udp_socket(bind)?;
        let target = match &dst.host {
            Host::Ip(ip) => std::net::SocketAddr::new(*ip, dst.port),
            Host::Domain(d) => {
                let ips = self.dns.resolve_domain(d, self.ipv6).await?;
                std::net::SocketAddr::new(ips[0], dst.port)
            }
        };
        sock.connect(target).await?;
        Ok(Box::new(DirectPacket { sock, target }))
    }
}

pub struct DirectPacket {
    sock: tokio::net::UdpSocket,
    target: std::net::SocketAddr,
}

#[async_trait]
impl PacketConn for DirectPacket {
    async fn send(&self, pkt: &UdpPacket) -> Result<()> {
        self.sock.send(&pkt.data).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<UdpPacket> {
        let mut buf = vec![0u8; 65535];
        let n = self.sock.recv(&mut buf).await?;
        buf.truncate(n);
        Ok(UdpPacket {
            src: self.target,
            dst: self.target,
            data: buf.into(),
        })
    }
}

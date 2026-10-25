//! DIRECT 出站：本地直连（域名经 vp-dns 解析）。

use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::TcpStream;

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
                Ok(ips.iter().map(|ip| std::net::SocketAddr::new(*ip, dst.port)).collect())
            }
        }
    }
}

#[async_trait]
impl Outbound for DirectOutbound {
    fn name(&self) -> &str {
        "DIRECT"
    }

    async fn connect_stream(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        let addrs = self.resolve(dst).await?;
        let mut last = Error::Addr(format!("无法解析 {dst}"));
        for a in addrs {
            match TcpStream::connect(&a).await {
                Ok(s) => {
                    vp_transport::tune(&s);
                    return Ok(Box::new(s));
                }
                Err(e) => last = e.into(),
            }
        }
        Err(last)
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
        let sock = tokio::net::UdpSocket::bind(bind).await?;
        let target = match &dst.host {
            Host::Ip(ip) => std::net::SocketAddr::new(*ip, dst.port),
            Host::Domain(d) => {
                let ips = self.dns.resolve_domain(d, self.ipv6).await?;
                std::net::SocketAddr::new(ips[0], dst.port)
            }
        };
        sock.connect(target).await?;
        Ok(Box::new(DirectPacket { sock }))
    }
}

pub struct DirectPacket {
    sock: tokio::net::UdpSocket,
}

#[async_trait]
impl PacketConn for DirectPacket {
    async fn send(&self, pkt: &UdpPacket) -> Result<()> {
        self.sock.send_to(&pkt.data, pkt.dst).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<UdpPacket> {
        let mut buf = vec![0u8; 65535];
        let (n, from) = self.sock.recv_from(&mut buf).await?;
        buf.truncate(n);
        Ok(UdpPacket {
            src: from,
            dst: from,
            data: buf.into(),
        })
    }
}

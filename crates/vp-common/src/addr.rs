//! 目标地址模型与 SOCKS 风格地址编解码（ATYP），被 socks5 / vmess / vless / trojan / shadowsocks 共用。

use std::fmt;
use std::net::IpAddr;

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    Domain(String),
    Ip(IpAddr),
}

impl Host {
    pub fn as_domain(&self) -> Option<&str> {
        match self {
            Host::Domain(d) => Some(d),
            Host::Ip(_) => None,
        }
    }

    pub fn is_ip(&self) -> bool {
        matches!(self, Host::Ip(_))
    }

    /// 归一化为小写（域名大小写不敏感）
    pub fn normalize(&self) -> Host {
        match self {
            Host::Domain(d) => Host::Domain(d.to_ascii_lowercase()),
            h => h.clone(),
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Domain(d) => f.write_str(d),
            Host::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DstAddr {
    pub host: Host,
    pub port: u16,
}

impl DstAddr {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        let s: String = host.into();
        let host = match s.parse::<IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Domain(s.to_ascii_lowercase()),
        };
        DstAddr { host, port }
    }

    pub fn ip(ip: IpAddr, port: u16) -> Self {
        DstAddr { host: Host::Ip(ip), port }
    }

    /// 解析 "host:port" 或 "[v6]:port" 形式（端口必填）
    pub fn parse(s: &str) -> Result<Self> {
        parse_host_port(s).map_err(|e| Error::Addr(format!("invalid address {s:?}: {e}")))
    }
}

impl fmt::Display for DstAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Domain(d) => write!(f, "{d}:{}", self.port),
            Host::Ip(IpAddr::V4(v4)) => write!(f, "{v4}:{}", self.port),
            Host::Ip(IpAddr::V6(v6)) => write!(f, "[{v6}]:{}", self.port),
        }
    }
}

fn parse_host_port(s: &str) -> std::result::Result<DstAddr, String> {
    if let Some(rest) = s.strip_prefix('[') {
        // [v6]:port
        let close = rest.find(']').ok_or("missing ']'")?;
        let ip: IpAddr = rest[..close].parse().map_err(|_| "invalid ipv6")?;
        let port = rest[close + 1..]
            .strip_prefix(':')
            .ok_or("missing port")?
            .parse()
            .map_err(|_| "invalid port")?;
        Ok(DstAddr::ip(ip, port))
    } else {
        let colon = s.rfind(':').ok_or("missing port")?;
        let (host, port) = (&s[..colon], &s[colon + 1..]);
        if host.contains(':') {
            return Err("bare ipv6 must be bracketed".into());
        }
        let port: u16 = port.parse().map_err(|_| "invalid port")?;
        Ok(DstAddr::new(host, port))
    }
}

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

/// 编码 SOCKS 风格地址（ATYP + addr + port），追加到 out。
pub fn encode_socks_addr(dst: &DstAddr, out: &mut Vec<u8>) {
    match &dst.host {
        Host::Ip(IpAddr::V4(v4)) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&v4.octets());
        }
        Host::Ip(IpAddr::V6(v6)) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&v6.octets());
        }
        Host::Domain(d) => {
            debug_assert!(d.len() <= 255, "domain too long");
            out.push(ATYP_DOMAIN);
            out.push(d.len() as u8);
            out.extend_from_slice(d.as_bytes());
        }
    }
    out.extend_from_slice(&dst.port.to_be_bytes());
}

/// 从 buf 起始处解码地址，返回地址与消费的字节数。
pub fn decode_socks_addr(buf: &[u8]) -> Result<(DstAddr, usize)> {
    let need = |n: usize| -> Result<()> {
        if buf.len() < n {
            Err(Error::Proto("address truncated"))
        } else {
            Ok(())
        }
    };
    need(1)?;
    let atyp = buf[0];
    match atyp {
        ATYP_IPV4 => {
            need(1 + 4 + 2)?;
            let ip = IpAddr::from([buf[1], buf[2], buf[3], buf[4]]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((DstAddr::ip(ip, port), 7))
        }
        ATYP_DOMAIN => {
            need(2)?;
            let len = buf[1] as usize;
            if len == 0 {
                return Err(Error::Proto("empty domain"));
            }
            need(2 + len + 2)?;
            let domain = std::str::from_utf8(&buf[2..2 + len])
                .map_err(|_| Error::Proto("domain not utf-8"))?
                .to_ascii_lowercase();
            let port = u16::from_be_bytes([buf[2 + len], buf[3 + len]]);
            Ok((
                DstAddr { host: Host::Domain(domain), port },
                2 + len + 2,
            ))
        }
        ATYP_IPV6 => {
            need(1 + 16 + 2)?;
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[1..17]);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((DstAddr::ip(IpAddr::from(o), port), 19))
        }
        _ => Err(Error::Proto("invalid atyp")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_forms() {
        let d = DstAddr::parse("example.com:443").unwrap();
        assert_eq!(d.host.as_domain(), Some("example.com"));
        assert_eq!(d.port, 443);

        let d = DstAddr::parse("1.2.3.4:80").unwrap();
        assert_eq!(d.host, Host::Ip("1.2.3.4".parse().unwrap()));

        let d = DstAddr::parse("[::1]:53").unwrap();
        assert_eq!(d.host, Host::Ip("::1".parse().unwrap()));

        assert!(DstAddr::parse("no-port").is_err());
        assert!(DstAddr::parse("::1:53").is_err());
    }

    #[test]
    fn socks_addr_roundtrip() {
        for s in ["example.com:443", "1.2.3.4:80", "[2001:db8::1]:22"] {
            let d = DstAddr::parse(s).unwrap();
            let mut buf = Vec::new();
            encode_socks_addr(&d, &mut buf);
            let (d2, used) = decode_socks_addr(&buf).unwrap();
            assert_eq!(used, buf.len());
            assert_eq!(d, d2);
        }
    }

    #[test]
    fn socks_addr_truncated() {
        let mut buf = Vec::new();
        encode_socks_addr(&DstAddr::parse("example.com:443").unwrap(), &mut buf);
        for cut in 1..buf.len() {
            assert!(decode_socks_addr(&buf[..cut]).is_err(), "cut={cut}");
        }
    }
}

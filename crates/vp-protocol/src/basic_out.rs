//! REJECT 出站与 SOCKS5 / HTTP 代理出站。

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use vp_common::addr::encode_socks_addr;
use vp_common::{DstAddr, Error, Result};
use vp_core::{Outbound, PacketConn, ProxyStream, Session};

// ---------------------------------------------------------------------------
// REJECT
// ---------------------------------------------------------------------------

pub struct RejectOutbound;

#[async_trait]
impl Outbound for RejectOutbound {
    fn name(&self) -> &str {
        "REJECT"
    }

    async fn connect_stream(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        Err(Error::Unsupported(format!("REJECT: {dst}")))
    }
}

// ---------------------------------------------------------------------------
// SOCKS5 客户端
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Socks5Outbound {
    pub server: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub udp: bool,
}

/// 节点拨号（8s 超时）：与 vp_transport::dial 的 TCP 超时语义对齐
async fn connect_node(server: &str, port: u16) -> Result<TcpStream> {
    let tcp = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        TcpStream::connect((server, port)),
    )
    .await
    .map_err(|_| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("连接 {server}:{port} 超时"),
        ))
    })??;
    Ok(tcp)
}

impl Socks5Outbound {
    /// 在任意流上完成 SOCKS5 握手（支持 relay 链）
    async fn handshake<S>(&self, mut io: S, dst: &DstAddr) -> Result<S>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let has_auth = self.username.is_some();
        // greeting
        if has_auth {
            io.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
        } else {
            io.write_all(&[0x05, 0x01, 0x00]).await?;
        }
        let mut b = [0u8; 2];
        io.read_exact(&mut b).await?;
        if b[0] != 0x05 {
            return Err(Error::Proto("socks5 出站: 版本错误"));
        }
        if b[1] == 0x02 {
            let u = self.username.as_deref().unwrap_or("");
            let p = self.password.as_deref().unwrap_or("");
            if u.len() > 255 || p.len() > 255 {
                return Err(Error::Config("socks5 凭据过长".into()));
            }
            let mut auth = vec![0x01, u.len() as u8];
            auth.extend_from_slice(u.as_bytes());
            auth.push(p.len() as u8);
            auth.extend_from_slice(p.as_bytes());
            io.write_all(&auth).await?;
            let mut r = [0u8; 2];
            io.read_exact(&mut r).await?;
            if r[1] != 0x00 {
                return Err(Error::Proto("socks5 出站: 认证失败"));
            }
        } else if b[1] != 0x00 {
            return Err(Error::Proto("socks5 出站: 不支持的认证方式"));
        }
        // CONNECT
        let mut req = vec![0x05, 0x01, 0x00];
        encode_socks_addr(dst, &mut req);
        io.write_all(&req).await?;
        // 响应: ver rep rsv atyp addr port
        let mut head = [0u8; 4];
        io.read_exact(&mut head).await?;
        if head[1] != 0x00 {
            return Err(Error::ProtoMsg(format!(
                "socks5 出站: 服务器拒绝 (rep={})",
                head[1]
            )));
        }
        let skip = match head[3] {
            0x01 => 4 + 2,
            0x03 => {
                let mut l = [0u8; 1];
                io.read_exact(&mut l).await?;
                l[0] as usize + 2
            }
            0x04 => 16 + 2,
            _ => return Err(Error::Proto("socks5 出站: atyp 非法")),
        };
        let mut rest = vec![0u8; skip];
        io.read_exact(&mut rest).await?;
        Ok(io)
    }
}

#[async_trait]
impl Outbound for Socks5Outbound {
    fn name(&self) -> &str {
        "socks5"
    }

    async fn connect_stream(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        let io = connect_node(&self.server, self.port).await?;
        let hs = tokio::time::timeout(std::time::Duration::from_secs(10), self.handshake(io, dst))
            .await
            .map_err(|_| {
                Error::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "socks5 出站握手超时",
                ))
            })??;
        Ok(Box::new(hs))
    }

    async fn connect_over(
        &self,
        _sess: &Session,
        dst: &DstAddr,
        underlying: Box<dyn ProxyStream>,
    ) -> Result<Box<dyn ProxyStream>> {
        let hs = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            self.handshake(underlying, dst),
        )
        .await
        .map_err(|_| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "socks5 出站握手超时",
            ))
        })??;
        Ok(Box::new(hs))
    }

    fn support_udp(&self) -> bool {
        self.udp
    }

    async fn connect_packet(&self, _sess: &Session, _dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        let conn = crate::udp_out::socks5_udp_connect(
            &self.server,
            self.port,
            &self.username,
            &self.password,
        )
        .await?;
        Ok(Box::new(conn))
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
}

// ---------------------------------------------------------------------------
// HTTP 代理出站（CONNECT）
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct HttpOutbound {
    pub server: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub tls: bool,
    pub skip_cert_verify: bool,
    pub sni: Option<String>,
}

impl HttpOutbound {
    async fn connect_handshake(
        &self,
        mut io: Box<dyn ProxyStream>,
        dst: &DstAddr,
    ) -> Result<Box<dyn ProxyStream>> {
        let mut req = format!("CONNECT {dst} HTTP/1.1\r\nHost: {dst}\r\n");
        if let (Some(u), Some(p)) = (&self.username, &self.password) {
            let cred = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                format!("{u}:{p}").as_bytes(),
            );
            req.push_str(&format!("Proxy-Authorization: Basic {cred}\r\n"));
        }
        req.push_str("\r\n");
        io.write_all(req.as_bytes()).await?;
        let mut buf = Vec::with_capacity(1024);
        let mut byte = [0u8; 1];
        loop {
            let n = io.read(&mut byte).await?;
            if n == 0 {
                return Err(Error::Proto("http 出站: 握手中断"));
            }
            buf.push(byte[0]);
            if buf.len() > 8192 {
                return Err(Error::Proto("http 出站: 响应头过长"));
            }
            if buf.ends_with(b"\r\n\r\n") || buf.ends_with(b"\n\n") {
                break;
            }
        }
        let head = String::from_utf8_lossy(&buf);
        let status = head.lines().next().unwrap_or_default();
        if !status.contains(" 2") {
            return Err(Error::ProtoMsg(format!("http 出站: {status}")));
        }
        Ok(io)
    }
}

#[async_trait]
impl Outbound for HttpOutbound {
    fn name(&self) -> &str {
        "http"
    }

    async fn connect_stream(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        let tcp = connect_node(&self.server, self.port).await?;
        let io: Box<dyn ProxyStream> = if self.tls {
            vp_transport::tls::connect_tls(
                tcp,
                &self.server,
                self.skip_cert_verify,
                self.sni.as_deref(),
            )
            .await?
        } else {
            Box::new(tcp)
        };
        self.connect_handshake(io, dst).await
    }

    async fn connect_over(
        &self,
        _sess: &Session,
        dst: &DstAddr,
        underlying: Box<dyn ProxyStream>,
    ) -> Result<Box<dyn ProxyStream>> {
        let io: Box<dyn ProxyStream> = if self.tls {
            vp_transport::tls::connect_tls(
                underlying,
                &self.server,
                self.skip_cert_verify,
                self.sni.as_deref(),
            )
            .await?
        } else {
            underlying
        };
        self.connect_handshake(io, dst).await
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn http_outbound_against_local_origin() {
        // 本地起一个假 HTTP 代理（接受 CONNECT 并透传）
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let mut n = 0;
            loop {
                let r = s.read(&mut buf[n..]).await.unwrap();
                if r == 0 {
                    break;
                }
                n += r;
                if buf[..n].ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            // 透传
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(b"pong").await.unwrap();
        });
        let out = HttpOutbound {
            server: "127.0.0.1".into(),
            port: addr.port(),
            username: None,
            password: None,
            tls: false,
            skip_cert_verify: false,
            sni: None,
        };
        let dst = DstAddr::new("target.example", 443);
        let mut s = out
            .connect_stream(&Session::new_tcp("t".into(), None, dst.clone()), &dst)
            .await
            .unwrap();
        s.write_all(b"ping").await.unwrap();
        let mut r = [0u8; 4];
        s.read_exact(&mut r).await.unwrap();
        assert_eq!(&r, b"pong");
    }
}

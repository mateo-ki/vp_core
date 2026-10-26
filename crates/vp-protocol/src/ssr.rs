//! ShadowsocksR (SSR) 协议出站与混淆支持。

use async_trait::async_trait;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

use vp_common::{DstAddr, Error, Host, Result};
use vp_core::session::Session;
use vp_core::{Outbound, PacketConn, ProxyStream};
use vp_crypto::ss::Cipher;
use vp_dns::Resolver;

use crate::direct::DirectOutbound;

/// SSR 地址编码（SOCKS5 格式：[atyp][addr][port]）
pub fn encode_addr(dst: &DstAddr, out: &mut Vec<u8>) {
    match &dst.host {
        Host::Ip(std::net::IpAddr::V4(v4)) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        Host::Domain(d) => {
            out.push(0x03);
            out.push(d.len() as u8);
            out.extend_from_slice(d.as_bytes());
        }
        Host::Ip(std::net::IpAddr::V6(v6)) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&dst.port.to_be_bytes());
}

pub struct SsrOutbound {
    name: Arc<str>,
    server: String,
    port: u16,
    password: String,
    cipher: String,
    #[allow(dead_code)]
    protocol: String,
    _protocol_param: Option<String>,
    obfs: String,
    obfs_param: Option<String>,
    direct: Arc<DirectOutbound>,
    udp: bool,
}

impl SsrOutbound {
    pub fn new(cfg: &vp_config::SsrCfg) -> Result<Self> {
        Self::new_named("ssr", cfg, Arc::new(Resolver::system()))
    }

    pub fn new_named(name: &str, cfg: &vp_config::SsrCfg, resolver: Arc<Resolver>) -> Result<Self> {
        Ok(SsrOutbound {
            name: name.into(),
            server: cfg.server.clone(),
            port: cfg.port,
            password: cfg.password.clone(),
            cipher: cfg.cipher.to_ascii_lowercase(),
            protocol: cfg.protocol.to_ascii_lowercase(),
            _protocol_param: cfg.protocol_param.clone(),
            obfs: cfg.obfs.to_ascii_lowercase(),
            obfs_param: cfg.obfs_param.clone(),
            direct: Arc::new(DirectOutbound::new(resolver, false)),
            udp: cfg.udp,
        })
    }

    /// 应用混淆层报头
    fn apply_obfs_header(&self, payload: &[u8]) -> Vec<u8> {
        match self.obfs.as_str() {
            "http_simple" | "http_post" => {
                let host = self.obfs_param.as_deref().unwrap_or(&self.server);
                let head = format!(
                    "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"
                );
                let mut out = head.into_bytes();
                out.extend_from_slice(payload);
                out
            }
            "tls1.2_ticket_auth" => {
                // 模拟 TLS 1.2 ClientHello
                let mut out = Vec::with_capacity(512 + payload.len());
                out.extend_from_slice(&[0x16, 0x03, 0x01]); // Handshake TLS 1.0/1.2
                let inner_len = 128 + payload.len();
                out.extend_from_slice(&(inner_len as u16).to_be_bytes());
                out.push(0x01); // ClientHello
                out.extend_from_slice(&[0x00, 0x00, (inner_len - 4) as u8]);
                out.extend_from_slice(&[0x03, 0x03]); // Client version TLS 1.2
                out.extend_from_slice(&[0u8; 32]); // Random
                out.push(0x00); // Session ID len
                out.extend_from_slice(&[0x00, 0x02, 0xc0, 0x2f]); // Ciphers
                out.extend_from_slice(&[0x01, 0x00]); // Compression
                out.extend_from_slice(payload);
                out
            }
            _ => payload.to_vec(),
        }
    }
}

#[async_trait]
impl Outbound for SsrOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect_stream(&self, sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        let server_dst = DstAddr::new(self.server.clone(), self.port);
        let mut conn = self.direct.connect_stream(sess, &server_dst).await?;

        // 构造地址头
        let mut addr_buf = Vec::with_capacity(32);
        encode_addr(dst, &mut addr_buf);

        // AEAD 加密套件或明文
        let stream: Box<dyn ProxyStream> = match self.cipher.as_str() {
            "none" | "plain" => {
                let init = self.apply_obfs_header(&addr_buf);
                conn.write_all(&init).await?;
                conn
            }
            aead_name if Cipher::parse(aead_name).is_ok() => {
                let cipher = Cipher::parse(aead_name)?;
                let master_key = cipher.derive_key(&self.password)?;
                let salt: Vec<u8> = (0..cipher.salt_len())
                    .map(|_| rand::random::<u8>())
                    .collect();
                let subkey = cipher.subkey(&master_key, &salt)?;
                let mut enc = vp_crypto::ss::AeadChunkCodec::new(&cipher, &subkey)?;

                let sealed_addr = enc.seal_chunk(&addr_buf);
                let mut initial = Vec::with_capacity(salt.len() + sealed_addr.len());
                initial.extend_from_slice(&salt);
                initial.extend_from_slice(&sealed_addr);

                let wrapped = self.apply_obfs_header(&initial);
                conn.write_all(&wrapped).await?;
                conn
            }
            _ => {
                // 默认降级或通用流混淆传输
                let init = self.apply_obfs_header(&addr_buf);
                conn.write_all(&init).await?;
                conn
            }
        };

        Ok(stream)
    }

    fn support_udp(&self) -> bool {
        self.udp
    }

    async fn connect_packet(&self, _sess: &Session, _dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        Err(Error::Unsupported(
            "SSR 原生 UDP 请开启 udp-over-tcp: true".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn ssr_outbound_plain_loopback() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = s.read(&mut buf).await.unwrap();
            // 回送收到的数据
            s.write_all(&buf[..n]).await.unwrap();
        });

        let cfg = vp_config::SsrCfg {
            server: "127.0.0.1".into(),
            port,
            password: "password123".into(),
            cipher: "plain".into(),
            protocol: "origin".into(),
            protocol_param: None,
            obfs: "http_simple".into(),
            obfs_param: Some("www.bing.com".into()),
            udp: true,
        };
        let ob = SsrOutbound::new(&cfg).unwrap();
        let dst = DstAddr::new("example.com", 80);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = ob.connect_stream(&sess, &dst).await.unwrap();

        let mut received = [0u8; 1024];
        let n = s.read(&mut received).await.unwrap();
        let text = String::from_utf8_lossy(&received[..n]);
        assert!(text.contains("GET / HTTP/1.1"));
        assert!(text.contains("Host: www.bing.com"));
    }
}

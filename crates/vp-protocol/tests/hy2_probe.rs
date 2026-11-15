//! hy2 最小探针：直连 mihomo hy2 服务端，auth + TCP 请求 + 原始读。
//! 用法：cargo test -p vp-protocol --test hy2_probe -- --nocapture
//! 需先启动：mihomo -d target/hy2 -f target/hy2/mihomo_server.yaml + 18999 echo。

use vp_protocol::h3_min::auth_roundtrip;

const TCP_REQUEST_ID: u64 = 0x401;

fn write_varint(buf: &mut Vec<u8>, v: u64) {
    if v < 0x40 {
        buf.push(v as u8);
    } else if v < 0x4000 {
        buf.push(0x40 | (v >> 8) as u8);
        buf.push(v as u8);
    } else {
        panic!("probe 不支持更长 varint");
    }
}

fn hysteria_client_config_opts(with_datagram: bool) -> quinn::ClientConfig {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let mut cfg = quinn::ClientConfig::new(std::sync::Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
    ));
    let mut t = quinn::TransportConfig::default();
    if with_datagram {
        t.datagram_receive_buffer_size(Some(1 << 20));
    }
    t.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
    t.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    cfg.transport_config(std::sync::Arc::new(t));
    cfg
}

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _e: &rustls::pki_types::CertificateDer<'_>,
        _i: &[rustls::pki_types::CertificateDer<'_>],
        _n: &rustls::pki_types::ServerName<'_>,
        _o: &[u8],
        _t: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

#[tokio::test]
#[ignore = "需手动启动 mihomo hy2 服务端与 echo：cargo test --test hy2_probe -- --ignored --nocapture"]
async fn hy2_raw_probe() {
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    ep.set_default_client_config(hysteria_client_config_opts(
        std::env::var("PROBE_DATAGRAM").is_ok(),
    ));
    let conn = ep
        .connect("127.0.0.1:18902".parse().unwrap(), "localhost")
        .unwrap()
        .await
        .expect("QUIC 握手");
    println!("[probe] QUIC 握手完成");

    let headers = vec![
        (":method", "POST"),
        (":scheme", "https"),
        (":authority", "hysteria"),
        (":path", "/auth"),
        ("hysteria-auth", "hy2-test-pw"),
        ("hysteria-cc-rx", "0"),
        ("hysteria-padding", "probe0000"),
    ];
    let (resp, _critical) = auth_roundtrip(&conn, &headers).await.expect("auth");
    println!("[probe] auth 响应: {resp:?}");

    let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
    let mut req = Vec::new();
    write_varint(&mut req, TCP_REQUEST_ID);
    let addr = "127.0.0.1:18999";
    write_varint(&mut req, addr.len() as u64);
    req.extend_from_slice(addr.as_bytes());
    write_varint(&mut req, 0); // padding
    let mode = std::env::var("PROBE_MODE").unwrap_or_default();
    let get = b"GET / HTTP/1.1\r\nHost: 127.0.0.1:18999\r\nConnection: close\r\n\r\n";
    if mode == "split" {
        send.write_all(&req).await.unwrap();
        println!("[probe] 仅请求帧已发送 {}B（未 FIN）", req.len());
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        send.write_all(get).await.unwrap();
        println!("[probe] GET 已补发 {}B", get.len());
    } else {
        req.extend_from_slice(get);
        send.write_all(&req).await.unwrap();
        send.finish().unwrap();
        println!("[probe] 请求+GET 一次发送 {}B + FIN", req.len());
    }

    let mut buf = Vec::new();
    let read_all = async {
        loop {
            let mut chunk = [0u8; 4096];
            let n = recv.read(&mut chunk).await.unwrap().unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > 4096 {
                break;
            }
        }
    };
    match tokio::time::timeout(std::time::Duration::from_secs(8), read_all).await {
        Ok(_) => println!(
            "[probe] 收到 {}B: {:?}",
            buf.len(),
            &buf[..buf.len().min(120)]
        ),
        Err(_) => println!("[probe] 8s 无响应！收到 {}B", buf.len()),
    }
    conn.close(0u32.into(), b"probe");
}

/// 用 VP-Core 的 Hysteria2Outbound 走同一服务端，对照定位客户端栈差异
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "需手动启动 mihomo hy2 服务端与 echo"]
async fn hy2_outbound_probe() {
    use vp_common::DstAddr;
    use vp_core::{Outbound, Session};
    use vp_protocol::hysteria2::Hysteria2Outbound;

    let cfg = serde_json::from_value::<vp_config::Hysteria2Cfg>(serde_json::json!({
        "type": "hysteria2",
        "server": "127.0.0.1",
        "port": 18902,
        "password": "hy2-test-pw",
        "skip-cert-verify": true,
        "sni": "local.test"
    }))
    .expect("cfg");
    let out = Hysteria2Outbound::new(&cfg).expect("outbound");
    let sess = Session::new_tcp("probe".into(), None, DstAddr::new("127.0.0.1", 18999));
    let mut s = out
        .connect_stream(&sess, &DstAddr::new("127.0.0.1", 18999))
        .await
        .expect("connect_stream");
    println!("[probe-ob] 连接成功，发送 GET");
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    s.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1:18999\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let read_all = async {
        loop {
            let mut chunk = [0u8; 4096];
            let n = s.read(&mut chunk).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > 4096 {
                break;
            }
        }
    };
    match tokio::time::timeout(std::time::Duration::from_secs(8), read_all).await {
        Ok(_) => println!(
            "[probe-ob] 收到 {}B 前16字节={:02x?} 文本={}",
            buf.len(),
            &buf[..buf.len().min(16)],
            String::from_utf8_lossy(&buf[..buf.len().min(80)])
        ),
        Err(_) => println!("[probe-ob] 8s 无响应！收到 {}B", buf.len()),
    }
}

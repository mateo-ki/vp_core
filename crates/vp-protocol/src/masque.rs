//! MASQUE (RFC 9484 CONNECT-IP / HTTP/3 Datagram) 出站协议实现。
//! 深度兼容 Cloudflare WARP MASQUE 模式与标准 MASQUE 网关。
//!
//! 链路架构：
//! 1. 握手层：QUIC (quinn) + ALPN ["h3"] + mTLS（基于 P-256 密钥对自签客户端证书，对端 SPKI 公钥钉选校验）；
//! 2. 协议层：HTTP/3 单向控制流协商 SETTINGS (CONNECT-IP + H3 Datagram) + 保持 QPACK 双流；
//!    首条双向流发起 Extended CONNECT (:protocol = "cf-connect-ip") 并宣告全网段路由 Capsule；
//! 3. 数据面：QUIC Datagram (Quarter Stream ID + Context ID 0) 承载原始 IP 数据报；
//!    桥接 smoltcp 用户态 TCP/UDP 协议栈（ip_stack）完成高并发点对点通信。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use p256::pkcs8::EncodePrivateKey;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use vp_common::{DstAddr, Error, Result};
use vp_config::MasqueCfg;
use vp_core::{Outbound, PacketConn, ProxyStream, Session};
use vp_dns::Resolver;

use crate::direct::DirectOutbound;
use crate::h3_min::{
    FRAME_DATA, FRAME_SETTINGS, STREAM_CONTROL, STREAM_QPACK_DECODER, STREAM_QPACK_ENCODER,
    decode_header_block, headers_frame, parse_frame,
};
use crate::ip_stack::{
    Cmd, IpStackPacketConn, IpStackTcpStream, SessionInner, SharedQueues, stack_task,
};

const DEFAULT_CONNECT_SNI: &str = "consumer-masque.cloudflareclient.com";
const DEFAULT_CONNECT_URI: &str = "https://cloudflareaccess.com";
const DEFAULT_MTU: u16 = 1280;

/// MASQUE 出站结构体
pub struct MasqueOutbound {
    name: Arc<str>,
    core: Arc<MasqueCore>,
    direct: Arc<DirectOutbound>,
    udp: bool,
}

impl MasqueOutbound {
    pub fn new_named(name: &str, cfg: &MasqueCfg, resolver: Arc<Resolver>) -> Result<Self> {
        let _ = tokio::runtime::Handle::try_current()
            .map_err(|_| Error::Config("masque 出站必须在 tokio 运行时内构建".to_string()))?;

        let core = MasqueCore::init(cfg)?;
        Ok(Self {
            name: name.into(),
            core,
            direct: Arc::new(DirectOutbound::new(resolver, false)),
            udp: cfg.udp,
        })
    }

    async fn resolve(&self, dst: &DstAddr) -> Result<SocketAddr> {
        self.direct
            .resolve(dst)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| Error::Addr(format!("masque 解析 {dst} 无结果")))
    }
}

#[async_trait::async_trait]
impl Outbound for MasqueOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        Some((self.core.server.clone(), self.core.port))
    }

    fn support_udp(&self) -> bool {
        self.udp
    }

    async fn connect_stream(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        let saddr = self.resolve(dst).await?;
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel::<SessionInner>();
        self.core
            .cmd_tx
            .send(Cmd::Connect {
                dst: saddr,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Error::Proto("masque 隧道任务已退出"))?;
        let (up_rx, down_tx) = reply_rx
            .await
            .map_err(|_| Error::Proto("masque 隧道任务已退出"))??;
        Ok(Box::new(IpStackTcpStream::new(up_rx, down_tx)))
    }

    async fn connect_packet(&self, _sess: &Session, _dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel::<
            Result<(
                tokio::sync::mpsc::Receiver<crate::ip_stack::UpMsg>,
                tokio::sync::mpsc::Sender<crate::ip_stack::DownMsg>,
            )>,
        >();
        self.core
            .cmd_tx
            .send(Cmd::ConnectUdp { reply: reply_tx })
            .await
            .map_err(|_| Error::Proto("masque 隧道任务已退出"))?;
        let (up_rx, down_tx) = reply_rx
            .await
            .map_err(|_| Error::Proto("masque 隧道任务已退出"))??;
        let local_addr = SocketAddr::new(IpAddr::V4(self.core.local_v4), 0);
        Ok(Box::new(IpStackPacketConn::new(up_rx, down_tx, local_addr)))
    }
}

// ---------------------------------------------------------------------------
// 核心隧道管理器与后台事件循环
// ---------------------------------------------------------------------------

pub struct MasqueCore {
    cmd_tx: mpsc::Sender<Cmd>,
    local_v4: Ipv4Addr,
    #[allow(dead_code)]
    local_v6: Option<Ipv6Addr>,
    server: String,
    port: u16,
}

impl MasqueCore {
    pub fn init(cfg: &MasqueCfg) -> Result<Arc<Self>> {
        let local_v4: Ipv4Addr = cfg
            .ip
            .as_deref()
            .unwrap_or("172.16.0.2")
            .split('/')
            .next()
            .unwrap_or("172.16.0.2")
            .parse()
            .map_err(|e| Error::Config(format!("masque 非法 IPv4 地址: {e}")))?;

        let local_v6: Option<Ipv6Addr> = cfg
            .ipv6
            .as_deref()
            .and_then(|s| s.split('/').next().unwrap_or("").parse::<Ipv6Addr>().ok());

        let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>(64);
        let core = Arc::new(Self {
            cmd_tx,
            local_v4,
            local_v6,
            server: cfg.server.clone(),
            port: cfg.port,
        });

        let queues = Arc::new(SharedQueues::new());
        let cfg_clone = cfg.clone();
        let queues_clone = queues.clone();

        // 启动隧道网络维护任务与 smoltcp 栈任务
        tokio::spawn(async move {
            let server = cfg_clone.server.clone();
            let port = cfg_clone.port;
            let queues_wire = queues_clone.clone();

            // 持续维护底层 QUIC + HTTP/3 隧道连接
            tokio::spawn(async move {
                tunnel_supervision_loop(cfg_clone, queues_wire).await;
            });

            // 启动 smoltcp 用户态 IP 栈轮询
            stack_task(cmd_rx, queues_clone, local_v4, local_v6).await;
            info!("masque 隧道栈任务正常退出 [{server}:{port}]");
        });

        Ok(core)
    }
}

/// 隧道监管重连循环
async fn tunnel_supervision_loop(cfg: MasqueCfg, queues: Arc<SharedQueues>) {
    let mut backoff = Duration::from_millis(500);
    loop {
        info!("masque 正在连接网关 [{}:{}]...", cfg.server, cfg.port);
        match connect_masque_tunnel(&cfg).await {
            Ok((conn, ep, hold_streams, quarter_stream_id)) => {
                info!("✓ masque 网关握手成功 [{}:{}]", cfg.server, cfg.port);
                backoff = Duration::from_millis(500);
                if let Err(e) =
                    run_tunnel_io(conn, ep, hold_streams, queues.clone(), quarter_stream_id).await
                {
                    warn!("masque 隧道 IO 异常中断: {e}");
                }
            }
            Err(e) => {
                warn!("masque 网关连接失败: {e}，将在 {:?} 后重试", backoff);
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(15));
            }
        }
    }
}

/// 执行数据报双向转发（QUIC Datagram ↔ smoltcp 队列）
async fn run_tunnel_io(
    conn: quinn::Connection,
    _ep: quinn::Endpoint,
    mut hold_streams: H3HoldStreams,
    queues: Arc<SharedQueues>,
    quarter_stream_id: u64,
) -> Result<()> {
    let mut drain_buf = vec![0u8; 4096];

    loop {
        tokio::select! {
            // 接收上行 QUIC Datagram
            res = conn.read_datagram() => {
                let data = match res {
                    Ok(d) => d,
                    Err(e) => return Err(Error::Io(std::io::Error::other(format!("quic read_datagram: {e}")))),
                };
                if let Some(ip_packet) = parse_masque_datagram(&data, quarter_stream_id) {
                    queues.rx.lock().unwrap().push_back(ip_packet);
                }
            }
            // 响应流排空与保活（对端关闭流或发送后续 Capsule）
            read_res = hold_streams.connect_recv.read(&mut drain_buf) => {
                match read_res {
                    Ok(Some(0)) | Ok(None) => {
                        return Err(Error::Proto("masque CONNECT 流被对端关闭"));
                    }
                    Ok(Some(n)) => {
                        debug!("masque 收到双向流后续数据 {n} 字节");
                    }
                    Err(e) => {
                        return Err(Error::ProtoMsg(format!("masque CONNECT 流读取失败: {e}")));
                    }
                }
            }
            // 发送下行待注入隧道的 IP 报文（事件驱动通知）
            _ = queues.notify_tx.notified() => {
                flush_tx_queue(&conn, &queues, quarter_stream_id);
            }
            // 兜底微定时器（防极端竞态）
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                flush_tx_queue(&conn, &queues, quarter_stream_id);
            }
        }
    }
}

fn flush_tx_queue(conn: &quinn::Connection, queues: &SharedQueues, quarter_stream_id: u64) {
    let packets: Vec<Vec<u8>> = {
        let mut tx = queues.tx.lock().unwrap();
        let mut list = Vec::with_capacity(tx.len().min(64));
        while let Some(pkt) = tx.pop_front() {
            list.push(pkt);
            if list.len() >= 64 {
                break;
            }
        }
        list
    };

    for pkt in packets {
        let dgram = encode_masque_datagram(quarter_stream_id, &pkt);
        if let Err(e) = conn.send_datagram(dgram.into()) {
            debug!("masque send_datagram 失败或丢弃: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// 数据报编解码 (RFC 9297 & RFC 9484)
// ---------------------------------------------------------------------------

/// 解析 MASQUE 数据报：[Quarter Stream ID varint][Context ID varint][IP Packet...]
fn parse_masque_datagram(data: &[u8], expected_quarter_stream_id: u64) -> Option<Vec<u8>> {
    let (qid, n1) = parse_quic_varint(data)?;
    if qid != expected_quarter_stream_id {
        return None;
    }
    let (context_id, n2) = parse_quic_varint(&data[n1..])?;
    if context_id != 0 {
        // 非 IP 数据报上下文，予以丢弃
        return None;
    }
    let payload = &data[n1 + n2..];
    if payload.is_empty() {
        return None;
    }
    Some(payload.to_vec())
}

/// 编码 MASQUE 数据报：[Quarter Stream ID varint][Context ID = 0 varint][IP Packet]
fn encode_masque_datagram(quarter_stream_id: u64, packet: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + packet.len());
    write_quic_varint(&mut buf, quarter_stream_id);
    write_quic_varint(&mut buf, 0); // Context ID = 0 (IP payload)
    buf.extend_from_slice(packet);
    buf
}

fn parse_quic_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let first = buf[0];
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut val = (first & 0x3f) as u64;
    for &b in &buf[1..len] {
        val = (val << 8) | (b as u64);
    }
    Some((val, len))
}

fn write_quic_varint(buf: &mut Vec<u8>, val: u64) {
    if val < (1 << 6) {
        buf.push(val as u8);
    } else if val < (1 << 14) {
        buf.push(0x40 | ((val >> 8) as u8));
        buf.push(val as u8);
    } else if val < (1 << 30) {
        buf.push(0x80 | ((val >> 24) as u8));
        buf.push((val >> 16) as u8);
        buf.push((val >> 8) as u8);
        buf.push(val as u8);
    } else {
        buf.push(0xc0 | ((val >> 56) as u8));
        buf.push((val >> 48) as u8);
        buf.push((val >> 40) as u8);
        buf.push((val >> 32) as u8);
        buf.push((val >> 24) as u8);
        buf.push((val >> 16) as u8);
        buf.push((val >> 8) as u8);
        buf.push(val as u8);
    }
}

// ---------------------------------------------------------------------------
// QUIC / TLS / HTTP/3 连接建立
// ---------------------------------------------------------------------------

struct H3HoldStreams {
    #[allow(dead_code)]
    ctl: quinn::SendStream,
    #[allow(dead_code)]
    qpack_enc: quinn::SendStream,
    #[allow(dead_code)]
    qpack_dec: quinn::SendStream,
    #[allow(dead_code)]
    connect_send: quinn::SendStream,
    #[allow(dead_code)]
    connect_recv: quinn::RecvStream,
}

async fn connect_masque_tunnel(
    cfg: &MasqueCfg,
) -> Result<(quinn::Connection, quinn::Endpoint, H3HoldStreams, u64)> {
    let sni = cfg.sni.as_deref().unwrap_or(DEFAULT_CONNECT_SNI);
    let connect_uri = cfg.uri.as_deref().unwrap_or(DEFAULT_CONNECT_URI);

    // 1. 生成并加载客户端 mTLS 证书配置
    let quinn_client_cfg = build_quinn_client_config(cfg, sni)?;

    let mut ep = quinn::Endpoint::client("[::]:0".parse().unwrap())
        .or_else(|_| quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()))
        .map_err(|e| {
            Error::Io(std::io::Error::other(format!(
                "创建 quinn 客户端端点失败: {e}"
            )))
        })?;
    ep.set_default_client_config(quinn_client_cfg);

    // 支持域名解析与 IP 直接解析 (如 engage.cloudflareclient.com)
    let target = match format!("{}:{}", cfg.server, cfg.port).parse::<SocketAddr>() {
        Ok(addr) => addr,
        Err(_) => tokio::net::lookup_host(format!("{}:{}", cfg.server, cfg.port))
            .await
            .map_err(|e| {
                Error::Io(std::io::Error::other(format!(
                    "DNS 解析失败 [{}:{}]: {e}",
                    cfg.server, cfg.port
                )))
            })?
            .next()
            .ok_or_else(|| {
                Error::Config(format!(
                    "未能解析域名 [{}:{}] 的 IP 地址",
                    cfg.server, cfg.port
                ))
            })?,
    };

    let conn = ep
        .connect(target, sni)
        .map_err(|e| Error::ProtoMsg(format!("quic 发起连接失败: {e}")))?
        .await
        .map_err(|e| Error::ProtoMsg(format!("quic 握手失败: {e}")))?;

    // 2. 发起 HTTP/3 控制流与 QPACK 流
    // 控制流: STREAM_CONTROL (0x00) + SETTINGS (0x04) 包含扩展 CONNECT 协议与 Datagram 协商
    let mut ctl = conn.open_uni().await.map_err(quic_err)?;
    let mut ctl_buf = Vec::new();
    write_quic_varint(&mut ctl_buf, STREAM_CONTROL);
    write_quic_varint(&mut ctl_buf, FRAME_SETTINGS);
    // SETTINGS payload:
    // 0x08 (SETTINGS_ENABLE_CONNECT_PROTOCOL) = 1
    // 0x33 (SETTINGS_H3_DATAGRAM) = 1
    // 0x0276 (SETTINGS_H3_DATAGRAM_00) = 1
    let mut settings_payload = Vec::new();
    write_quic_varint(&mut settings_payload, 0x08);
    write_quic_varint(&mut settings_payload, 1);
    write_quic_varint(&mut settings_payload, 0x33);
    write_quic_varint(&mut settings_payload, 1);
    write_quic_varint(&mut settings_payload, 0x276);
    write_quic_varint(&mut settings_payload, 1);

    write_quic_varint(&mut ctl_buf, settings_payload.len() as u64);
    ctl_buf.extend_from_slice(&settings_payload);
    ctl.write_all(&ctl_buf).await.map_err(quic_err)?;

    // QPACK 单向流声明
    let mut qpack_enc = conn.open_uni().await.map_err(quic_err)?;
    let mut enc_buf = Vec::new();
    write_quic_varint(&mut enc_buf, STREAM_QPACK_ENCODER);
    qpack_enc.write_all(&enc_buf).await.map_err(quic_err)?;

    let mut qpack_dec = conn.open_uni().await.map_err(quic_err)?;
    let mut dec_buf = Vec::new();
    write_quic_varint(&mut dec_buf, STREAM_QPACK_DECODER);
    qpack_dec.write_all(&dec_buf).await.map_err(quic_err)?;

    // 3. 打开双向流 (Stream 0) 发送 Extended CONNECT 请求
    let (mut req_send, mut req_recv) = conn.open_bi().await.map_err(quic_err)?;
    let stream_id = req_send.id().index();
    let quarter_stream_id = stream_id / 4;

    // 解析 URI 权威域名与路径
    let (authority, path) = parse_uri_parts(connect_uri);

    let headers = vec![
        (":method", "CONNECT"),
        (":protocol", "cf-connect-ip"),
        (":scheme", "https"),
        (":authority", &authority),
        (":path", &path),
        ("capsule-protocol", "?1"),
        ("user-agent", ""),
    ];

    let h_frame = headers_frame(&headers);
    req_send.write_all(&h_frame).await.map_err(quic_err)?;

    // 4. 等待对端返回响应 HEADERS 帧并校验状态码
    let mut resp_buf = vec![0u8; 4096];
    let n = req_recv.read(&mut resp_buf).await.map_err(quic_err)?;
    let n = n.ok_or(Error::Proto("masque 握手时对端过早关闭流"))?;

    let (frame_ty, payload, _) =
        parse_frame(&resp_buf[..n]).ok_or(Error::Proto("masque 无法解析 HTTP/3 响应帧"))?;
    if frame_ty != crate::h3_min::FRAME_HEADERS {
        return Err(Error::ProtoMsg(format!(
            "masque 预期 HEADERS 帧，收到帧类型 0x{frame_ty:x}"
        )));
    }

    let decoded_headers = decode_header_block(&payload)?;
    let status_str = decoded_headers
        .iter()
        .find(|(k, _)| k == ":status")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let status: u16 = status_str.parse().unwrap_or(0);
    if !(200..=299).contains(&status) {
        return Err(Error::ProtoMsg(format!(
            "masque CONNECT-IP 拒绝连接，HTTP 状态码: {status_str}"
        )));
    }

    // 5. 发送全网段路由宣告 Capsule (Type 3)
    let route_capsule = build_route_advertisement_capsule();
    let mut data_frame = Vec::new();
    write_quic_varint(&mut data_frame, FRAME_DATA);
    write_quic_varint(&mut data_frame, route_capsule.len() as u64);
    data_frame.extend_from_slice(&route_capsule);
    req_send.write_all(&data_frame).await.map_err(quic_err)?;

    Ok((
        conn,
        ep,
        H3HoldStreams {
            ctl,
            qpack_enc,
            qpack_dec,
            connect_send: req_send,
            connect_recv: req_recv,
        },
        quarter_stream_id,
    ))
}

fn parse_uri_parts(uri: &str) -> (String, String) {
    if let Some(rest) = uri.strip_prefix("https://") {
        if let Some((host, path)) = rest.split_once('/') {
            (host.to_string(), format!("/{path}"))
        } else {
            (rest.to_string(), "/".to_string())
        }
    } else {
        (uri.to_string(), "/".to_string())
    }
}

/// 构造全网段 ROUTE_ADVERTISEMENT Capsule (RFC 9484 Type 3)
fn build_route_advertisement_capsule() -> Vec<u8> {
    // 路由项 1: IPv4 0.0.0.0 - 255.255.255.255, protocol 0 (10 字节)
    // 路由项 2: IPv6 :: - ffff:...:ffff, protocol 0 (34 字节)
    // Total len = 44 字节 (0x2c)
    let mut payload = Vec::with_capacity(44);
    // Route 1
    payload.push(4); // IPv4
    payload.extend_from_slice(&[0, 0, 0, 0]);
    payload.extend_from_slice(&[255, 255, 255, 255]);
    payload.push(0); // Protocol 0 (all)

    // Route 2
    payload.push(6); // IPv6
    payload.extend_from_slice(&[0u8; 16]);
    payload.extend_from_slice(&[0xffu8; 16]);
    payload.push(0); // Protocol 0 (all)

    let mut capsule = Vec::with_capacity(2 + payload.len());
    write_quic_varint(&mut capsule, 3); // capsuleTypeRouteAdvertisement = 3
    write_quic_varint(&mut capsule, payload.len() as u64);
    capsule.extend_from_slice(&payload);
    capsule
}

// ---------------------------------------------------------------------------
// TLS 客户端认证与公钥钉选校验
// ---------------------------------------------------------------------------

fn build_quinn_client_config(cfg: &MasqueCfg, _sni: &str) -> Result<quinn::ClientConfig> {
    let priv_der = base64::engine::general_purpose::STANDARD
        .decode(cfg.private_key.trim())
        .map_err(|e| Error::Config(format!("masque private-key base64 格式无效: {e}")))?;

    // 转换 SEC1 到 PKCS#8（如果输入是 SEC1 ECPrivateKey）
    let pkcs8_bytes = if let Ok(secret) = p256::SecretKey::from_sec1_der(&priv_der) {
        secret
            .to_pkcs8_der()
            .map_err(|e| Error::Config(format!("SEC1 转 PKCS8 失败: {e}")))?
            .as_bytes()
            .to_vec()
    } else {
        priv_der.clone()
    };

    // 基于 rcgen 生成自签名客户端证书
    let key_pair = rcgen::KeyPair::try_from(pkcs8_bytes.as_slice())
        .map_err(|e| Error::Config(format!("rcgen 解析 P-256 私钥失败: {e}")))?;
    let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .map_err(|e| Error::Config(format!("生成证书参数失败: {e}")))?;
    let cert = cert_params
        .self_signed(&key_pair)
        .map_err(|e| Error::Config(format!("生成自签名证书失败: {e}")))?;
    let cert_der = cert.der().to_vec();

    let client_cert = vec![rustls::pki_types::CertificateDer::from(cert_der)];
    let client_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8_bytes),
    );

    let pinned_pub = if let Some(ref pub_b64) = cfg.public_key {
        base64::engine::general_purpose::STANDARD
            .decode(pub_b64.trim())
            .ok()
    } else {
        None
    };

    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(MasqueCertVerifier {
            skip_verify: cfg.skip_cert_verify,
            pinned_pubkey: pinned_pub,
        }))
        .with_client_auth_cert(client_cert, client_key)
        .map_err(|e| Error::Config(format!("配置 mTLS 客户端认证失败: {e}")))?;
    crypto.alpn_protocols = vec![b"h3".to_vec()];

    let mut quinn_cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| Error::Config(format!("构建 quic 客户端配置失败: {e}")))?,
    ));

    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(1024 * 1024));
    let mtu = cfg.mtu.unwrap_or(DEFAULT_MTU) as u32;
    let _ = mtu;
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    quinn_cfg.transport_config(Arc::new(transport));

    Ok(quinn_cfg)
}

#[derive(Debug)]
struct MasqueCertVerifier {
    skip_verify: bool,
    pinned_pubkey: Option<Vec<u8>>,
}

impl rustls::client::danger::ServerCertVerifier for MasqueCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if self.skip_verify {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }

        // 钉选对端公钥校验
        if let Some(ref expected) = self.pinned_pubkey {
            let cert_bytes = end_entity.as_ref();
            // 检查证书中是否包含钉选公钥（或 SPKI 的未压缩点字节 65 字节）
            let matched = if expected.len() >= 65 {
                let tail = &expected[expected.len() - 65..];
                cert_bytes.windows(65).any(|w| w == tail)
            } else {
                cert_bytes
                    .windows(expected.len())
                    .any(|w| w == expected.as_slice())
            };

            if !matched {
                warn!("masque 证书公钥与节点配置中 public-key 不匹配");
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ));
            }
        }

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

fn quic_err(e: impl std::fmt::Debug) -> Error {
    Error::Io(std::io::Error::other(format!("quic io: {e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_varint_roundtrip() {
        let test_values = [
            0,
            1,
            63,
            64,
            16383,
            16384,
            1073741823,
            1073741824,
            0x0276,
            u64::MAX >> 2,
        ];
        for val in test_values {
            let mut buf = Vec::new();
            write_quic_varint(&mut buf, val);
            let (decoded, len) = parse_quic_varint(&buf).expect("decode varint");
            assert_eq!(decoded, val);
            assert_eq!(len, buf.len());
        }
    }

    #[test]
    fn test_masque_datagram_roundtrip() {
        let packet = b"hello masque ip packet";
        let quarter_stream_id = 0;
        let dgram = encode_masque_datagram(quarter_stream_id, packet);
        let parsed = parse_masque_datagram(&dgram, quarter_stream_id).expect("parse datagram");
        assert_eq!(parsed, packet);

        // 验证若 quarter_stream_id 不匹配则被丢弃
        assert!(parse_masque_datagram(&dgram, 1).is_none());
    }

    #[test]
    fn test_route_advertisement_capsule() {
        let capsule = build_route_advertisement_capsule();
        assert!(!capsule.is_empty());
        let (capsule_type, n1) = parse_quic_varint(&capsule).expect("capsule type");
        assert_eq!(capsule_type, 3);
        let (payload_len, n2) = parse_quic_varint(&capsule[n1..]).expect("capsule len");
        assert_eq!(capsule.len(), n1 + n2 + payload_len as usize);
        assert_eq!(payload_len, 44);
    }

    #[test]
    fn test_uri_parts_parsing() {
        assert_eq!(
            parse_uri_parts("https://cloudflareaccess.com"),
            ("cloudflareaccess.com".to_string(), "/".to_string())
        );
        assert_eq!(
            parse_uri_parts("https://gateway.example.com:8443/masque"),
            (
                "gateway.example.com:8443".to_string(),
                "/masque".to_string()
            )
        );
    }

    #[test]
    fn test_client_config_generation() {
        let priv_b64 = "MHcCAQEEIBsdMrQ/Ai+aaQdjsexdBeTAbcZOKQthvFEy+urepiGzoAoGCCqGSM49AwEHoUQDQgAE7dGjdy1OZlfH9yaBWRHGG9Esle5yXI43Bia9X+5pSNKsLaRk9qg5AB8a3kgkwTv/+rSJWg+EcrJW79BqyGLlIQ==";
        let pub_b64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==";
        let cfg = MasqueCfg {
            server: "162.159.199.2".to_string(),
            port: 443,
            private_key: priv_b64.to_string(),
            public_key: Some(pub_b64.to_string()),
            ip: Some("172.16.0.2".to_string()),
            ipv6: Some("2606:4700:110::1".to_string()),
            uri: None,
            sni: None,
            mtu: Some(1280),
            udp: true,
            remote_dns_resolve: true,
            dns: vec![],
            skip_cert_verify: false,
            network: None,
        };

        let client_cfg = build_quinn_client_config(&cfg, "consumer-masque.cloudflareclient.com");
        assert!(client_cfg.is_ok(), "应当成功解析私钥并生成自签名证书");
    }
}

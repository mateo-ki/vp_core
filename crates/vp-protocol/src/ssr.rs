//! ShadowsocksR (SSR) 协议出站与混淆支持。
//!
//! 完整实现协议层 + 流式加密两层：
//! - 协议层 `origin`：经典 SS 连续流（[IV][密文...]）；
//! - 协议层 `auth_aes128_md5` / `auth_aes128_sha1`：SSR 原生认证协议
//!   （首包带 uid + AES-128-CBC 加密的 auth 头 + 双 HMAC，后续包带 per-packet MAC）。
//!
//! 字节布局与 shadowsocksr-csharp 参考客户端（Obfs/Auth.cs）对齐：
//! 首包 = [随机1B][HMAC(mac_key,该1B)[:6]][uid(4)][E(P)(16)][HMAC(mac_key,uid‖E(P))[:4]]
//!        [rand_len 随机填充][载荷][HMAC(user_key, 全部)[:4]]
//!   其中 P = utc_time(4LE)‖client_id(4)‖connection_id(4LE)‖data_len(2LE)‖rand_len(2LE)，
//!   E(P) = AES-128-CBC(key=EVP(base64(user_key)+salt,16), iv=0, 无填充) 单块，
//!   mac_key = 流加密 IV ‖ 主密钥，data_len = 35 + 载荷 + rand_len。
//! 数据包 = [len(2LE)][HMAC(k,len)[:2]][pad 前缀+随机填充][载荷][HMAC(k,前缀..)[:4]]，
//!   k = user_key ‖ u32le(pack_id)，pack_id/recv_id 从 1 起每包递增。

use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};

use async_trait::async_trait;
use base64::Engine;
use bytes::{Buf, BufMut, BytesMut};
use hmac::Mac;
use md5::{Digest, Md5};
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use vp_common::{DstAddr, Error, Host, Result};
use vp_core::session::Session;
use vp_core::{Outbound, PacketConn, ProxyStream};
use vp_crypto::ss::evp_bytes_to_key;
use vp_crypto::ss_stream::{StreamSuite, StreamXor};

use crate::direct::DirectOutbound;
use vp_dns::Resolver;

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

// ---------------------------------------------------------------------------
// 协议层定义
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashKind {
    Md5,
    Sha1,
}

impl HashKind {
    fn salt(self) -> &'static str {
        match self {
            HashKind::Md5 => "auth_aes128_md5",
            HashKind::Sha1 => "auth_aes128_sha1",
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            HashKind::Md5 => Md5::digest(data).to_vec(),
            HashKind::Sha1 => Sha1::digest(data).to_vec(),
        }
    }

    fn hmac(self, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        match self {
            HashKind::Md5 => hmac_parts_md5(key, parts),
            HashKind::Sha1 => hmac_parts_sha1(key, parts),
        }
    }
}

fn hmac_parts_md5(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut mac = <hmac::Hmac<Md5> as hmac::Mac>::new_from_slice(key).expect("hmac 密钥合法");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().to_vec()
}

fn hmac_parts_sha1(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut mac = <hmac::Hmac<Sha1> as hmac::Mac>::new_from_slice(key).expect("hmac 密钥合法");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().to_vec()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Origin,
    AuthAes128(HashKind),
}

/// 进程级 client_id / connection_id（同服务器的多个连接共享递增，SSR 服务端据此防重放）
fn next_auth_data() -> [u8; 12] {
    static STATE: OnceLock<Mutex<(u32, u32)>> = OnceLock::new();
    let mut st = STATE
        .get_or_init(|| Mutex::new((0, 0)))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if st.1 > 0xFF00_0000 {
        st.0 = 0;
    }
    if st.0 == 0 {
        let mut b = [0u8; 4];
        vp_common::rand_bytes(&mut b);
        st.0 = u32::from_le_bytes(b).max(1);
        let mut b = [0u8; 4];
        vp_common::rand_bytes(&mut b);
        st.1 = u32::from_le_bytes(b) & 0x00FF_FFFF;
    }
    st.1 = st.1.wrapping_add(1);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    let mut out = [0u8; 12];
    out[..4].copy_from_slice(&now.to_le_bytes());
    out[4..8].copy_from_slice(&st.0.to_le_bytes());
    out[8..].copy_from_slice(&st.1.to_le_bytes());
    out
}

/// 梯形分布随机整数（与参考实现一致的填充长度分布；偏向大填充）
fn trapezoid_random_int(max_val: usize) -> usize {
    if max_val == 0 {
        return 0;
    }
    let mut b = [0u8; 4];
    vp_common::rand_bytes(&mut b);
    let s = u32::from_le_bytes(b) as f64 / (u32::MAX as f64 + 1.0);
    let d = -0.3f64;
    let a = 1.0 - d;
    let v = ((a * a + 4.0 * d * s).sqrt() - a) / (2.0 * d);
    (v * max_val as f64) as usize
}

/// 数据包随机填充长度（参考实现 GetRandLen：tcp_mss=1460, buffer_size=8192, overhead=9）
fn rand_len_for_data(datalen: usize, full_len: usize) -> usize {
    if full_len >= 8192 {
        return 0;
    }
    let tcp_mss = 1460usize;
    let rev_len = tcp_mss.saturating_sub(datalen + 9);
    if rev_len == 0 {
        return 0;
    }
    if datalen > 1100 {
        let mut b = [0u8; 2];
        vp_common::rand_bytes(&mut b);
        (u16::from_le_bytes(b) as usize) % rev_len
    } else {
        trapezoid_random_int(rev_len)
    }
}

/// AES-128-CBC 零 IV、无填充：对单个 16 字节块加密（首包 auth 头专用）
fn aes128_cbc_single_block(key: &[u8; 16], plain: &[u8; 16]) -> [u8; 16] {
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockEncrypt, KeyInit};
    let ek = <aes::Aes128 as KeyInit>::new(GenericArray::from_slice(key));
    let mut block = GenericArray::clone_from_slice(plain);
    ek.encrypt_block(&mut block);
    let mut out = [0u8; 16];
    out.copy_from_slice(&block);
    out
}

// ---------------------------------------------------------------------------
// 出站
// ---------------------------------------------------------------------------

pub struct SsrOutbound {
    name: Arc<str>,
    server: String,
    port: u16,
    suite: StreamSuite,
    master_key: Vec<u8>,
    protocol: Protocol,
    /// protocol_param "uid:pass" 存在时：uid + 独立子密钥 hash(pass)
    uid: u32,
    user_key: Vec<u8>,
    obfs: String,
    obfs_param: Option<String>,
    direct: Arc<DirectOutbound>,
    udp: bool,
}

// ---------------------------------------------------------------------------
// tls1.2_ticket_auth 混淆（对齐 breakwa11/shadowsocksr obfsplugin 客户端语义）
// ---------------------------------------------------------------------------

const TLS12_TICKET_OBFS_STR: &str = "tls1.2_ticket_auth";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsTxState {
    /// 尚未发送 ClientHello（首段 = ClientHello + 握手完成块）
    ClientHello,
    /// 正常 ApplicationData 记录分帧
    Records,
}

#[derive(Debug)]
enum TlsRxState {
    /// 首个服务端响应：缓冲 ≥76 字节后校验 HMAC，再按记录解帧
    First,
    Records,
}

/// tls1.2_ticket_auth 双向状态
#[derive(Debug)]
struct TlsTicket {
    client_id: [u8; 32],
    key: Vec<u8>,
    host: Option<String>,
    tx: TlsTxState,
    rx: TlsRxState,
}

impl TlsTicket {
    fn new(master_key: &[u8], host: Option<String>) -> Self {
        let mut client_id = [0u8; 32];
        vp_common::rand_bytes(&mut client_id);
        // 对齐参考实现：clientID 首 4 字节为 unix 秒
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        client_id[0..4].copy_from_slice(&now.to_be_bytes());
        TlsTicket {
            client_id,
            key: master_key.to_vec(),
            host,
            tx: TlsTxState::ClientHello,
            rx: TlsRxState::First,
        }
    }

    /// HMAC-SHA1(key = master_key || client_id)，截断 10 字节
    fn hmac10(&self, data: &[u8]) -> [u8; 10] {
        use hmac::Mac;
        let mut key_material = Vec::with_capacity(self.key.len() + 32);
        key_material.extend_from_slice(&self.key);
        key_material.extend_from_slice(&self.client_id);
        let mut mac =
            <hmac::Hmac<Sha1> as hmac::Mac>::new_from_slice(&key_material).expect("hmac key");
        mac.update(data);
        let out = mac.finalize().into_bytes();
        out[..10].try_into().expect("10 bytes")
    }

    /// ClientHello：逐字节对齐 mihomo 抓包结构
    /// [0:5] record 0x16 0x03 0x01 len | [5:9] hs 0x01 len24 | [9:11] 0x03 0x03
    /// [11:43] clientID（首 4 字节为 unix 秒）| [43] 0x20 | [44:76] 随机 sid
    /// [76:106] 套件表 | [106:108] 压缩 | [108:110] 扩展长度 | 扩展（SNI 用 obfs-param）
    fn client_hello(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(600);
        // 扩展：renegotiation_info / server_name(obfs-param) / 0x0017 / session_ticket(256)
        //   / signature_algorithms / 0x0005 / 0x0012 / 0x7550 / ec_point_formats / supported_groups
        let mut host = self
            .host
            .as_deref()
            .unwrap_or("")
            .trim()
            .trim_end_matches('.')
            .as_bytes()
            .to_vec();
        if host.len() > 255 {
            host.truncate(255);
        }
        let mut exts: Vec<u8> = Vec::with_capacity(512);
        // 0xff01 renegotiation_info
        exts.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);
        // 0x0000 server_name
        let mut sni = Vec::with_capacity(host.len() + 5);
        sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(&host);
        exts.extend_from_slice(&[0x00, 0x00]);
        exts.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni);
        // 0x0017 extended_master_secret（空）
        exts.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
        // 0x0023 session_ticket：256 字节随机
        let mut ticket = vec![0u8; 256];
        vp_common::rand_bytes(&mut ticket);
        exts.extend_from_slice(&[0x00, 0x23, 0x01, 0x00]);
        exts.extend_from_slice(&ticket);
        // 0x000d signature_algorithms
        exts.extend_from_slice(&[
            0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, 0x06, 0x01, 0x06, 0x03, 0x05, 0x01, 0x05, 0x03,
            0x04, 0x01, 0x04, 0x03, 0x03, 0x01, 0x03, 0x03, 0x02, 0x01, 0x02, 0x03,
        ]);
        // 0x0005 status_request
        exts.extend_from_slice(&[0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]);
        // 0x0012 signed_certificate_timestamp（空）
        exts.extend_from_slice(&[0x00, 0x12, 0x00, 0x00]);
        // 0x7550（空）
        exts.extend_from_slice(&[0x75, 0x50, 0x00, 0x00]);
        // 0x000b ec_point_formats
        exts.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
        // 0x000a supported_groups
        exts.extend_from_slice(&[0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18]);

        let mut body = Vec::with_capacity(exts.len() + 80);
        body.extend_from_slice(&[0x03, 0x03]);
        // random = clientID：首 4 字节 unix 秒 + 28 随机
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        body.extend_from_slice(&now.to_be_bytes());
        body.extend_from_slice(&self.client_id[4..]);
        // session id：0x20 + 32 随机
        body.push(0x20);
        let mut sid = [0u8; 32];
        vp_common::rand_bytes(&mut sid);
        body.extend_from_slice(&sid);
        // 套件表 + 压缩
        body.extend_from_slice(&[
            0x00, 0x1c, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14, 0xcc, 0x13,
            0xc0, 0x0a, 0xc0, 0x14, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x9c, 0x00, 0x35, 0x00, 0x2f,
            0x00, 0x0a,
        ]);
        body.extend_from_slice(&[0x01, 0x00]);
        // 扩展
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        out.extend_from_slice(&[0x16, 0x03, 0x01]);
        out.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        out.push(0x01);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
        out.extend_from_slice(&body);
        out
    }

    /// 握手完成块：CCS 记录 + Finished 记录（22 随机 + HMAC）
    fn handshake_finish(&mut self) -> Vec<u8> {
        let mut body = [0u8; 32];
        vp_common::rand_bytes(&mut body[..22]);
        let tag = self.hmac10(&body[..22]);
        body[22..32].copy_from_slice(&tag);
        let mut out = Vec::with_capacity(43);
        out.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
        out.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x20]);
        out.extend_from_slice(&body);
        out
    }

    /// ApplicationData 记录封装（≤0x3FFF 分块）
    fn wrap_records(&self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + 5 * (data.len() / 0x3FFF + 1));
        for chunk in data.chunks(0x3FFF) {
            out.extend_from_slice(&[0x17, 0x03, 0x03]);
            out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            out.extend_from_slice(chunk);
        }
        out
    }

    /// 发送方向处理：首段产出 ClientHello+finish，其后包 ApplicationData 记录
    fn encode(&mut self, data: &[u8]) -> Vec<u8> {
        match self.tx {
            TlsTxState::ClientHello => {
                self.tx = TlsTxState::Records;
                let mut out = self.client_hello();
                out.extend_from_slice(&self.handshake_finish());
                out.extend_from_slice(&self.wrap_records(data));
                out
            }
            TlsTxState::Records => self.wrap_records(data),
        }
    }

    /// 接收方向处理：首响应校验 HMAC 后按 TLS 记录解帧，输出 SSR 载荷流
    fn decode(&mut self, wire: &mut BytesMut, out: &mut BytesMut) -> Result<()> {
        loop {
            match self.rx {
                TlsRxState::First => {
                    if wire.len() < 76 {
                        tracing::debug!(target: "ssr_obfs", len = wire.len(), "等待服务端首响应");
                        return Ok(()); // 继续缓冲
                    }
                    let expect = self.hmac10(&wire[11..33]);
                    tracing::debug!(
                        target: "ssr_obfs",
                        expect = ?expect,
                        got = ?&wire[33..43],
                        match_ = expect.as_slice() == &wire[33..43],
                        "服务端首响应 HMAC（不匹配仅记录，不影响数据流）"
                    );
                    self.rx = TlsRxState::Records;
                    // 从 0 开始按记录解帧（ServerHello 属 0x16 会被跳过）
                }
                TlsRxState::Records => {
                    if wire.len() < 5 {
                        return Ok(());
                    }
                    let rtype = wire[0];
                    let len = u16::from_be_bytes([wire[3], wire[4]]) as usize;
                    if wire.len() < 5 + len {
                        return Ok(()); // 记录未完整
                    }
                    let payload = wire[5..5 + len].to_vec();
                    wire.advance(5 + len);
                    tracing::debug!(target: "ssr_obfs", rtype, len, "TLS 记录");
                    match rtype {
                        0x17 => out.extend_from_slice(&payload),
                        // 0x16 ServerHello/SessionTicket、0x14 CCS：跳过
                        0x16 | 0x14 => {}
                        other => {
                            return Err(Error::ProtoMsg(format!(
                                "ssr: tls1.2_ticket_auth 异常记录类型 {other:#x}"
                            )));
                        }
                    }
                }
            }
        }
    }
}

impl SsrOutbound {
    pub fn new(cfg: &vp_config::SsrCfg) -> Result<Self> {
        Self::new_named("ssr", cfg, Arc::new(Resolver::system()))
    }

    pub fn new_named(name: &str, cfg: &vp_config::SsrCfg, resolver: Arc<Resolver>) -> Result<Self> {
        let suite = StreamSuite::parse(&cfg.cipher)?;
        let protocol = match cfg.protocol.to_ascii_lowercase().as_str() {
            "origin" => Protocol::Origin,
            "auth_aes128_md5" => Protocol::AuthAes128(HashKind::Md5),
            "auth_aes128_sha1" => Protocol::AuthAes128(HashKind::Sha1),
            other => {
                return Err(Error::Config(format!(
                    "SSR 协议层 {other:?} 暂不支持（支持 origin/auth_aes128_md5/auth_aes128_sha1）"
                )));
            }
        };
        let master_key = suite.derive_key(&cfg.password);
        // protocol_param "uid:pass"：服务端多用户模式下的用户标识与独立子密钥
        let (uid, user_key) = match protocol {
            Protocol::AuthAes128(h) => match cfg.protocol_param.as_deref() {
                Some(p) if !p.is_empty() => match p.split_once(':') {
                    Some((u, pass)) => (u.parse::<u32>().unwrap_or(0), h.digest(pass.as_bytes())),
                    None => (0, master_key.clone()),
                },
                _ => (0, master_key.clone()),
            },
            Protocol::Origin => (0, master_key.clone()),
        };
        Ok(SsrOutbound {
            name: name.into(),
            server: cfg.server.clone(),
            port: cfg.port,
            suite,
            master_key,
            protocol,
            uid,
            user_key,
            obfs: cfg.obfs.to_ascii_lowercase(),
            obfs_param: cfg.obfs_param.clone(),
            direct: Arc::new(DirectOutbound::new(resolver, false)),
            udp: cfg.udp,
        })
    }

    /// 应用混淆层报头（对首个发送段做伪装前缀）
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
        let conn = self.direct.connect_stream(sess, &server_dst).await?;

        // 构造地址头
        let mut addr_buf = Vec::with_capacity(32);
        encode_addr(dst, &mut addr_buf);

        // 发送方向 IV 与连续子密钥（首包与后续写入共享同一密钥流）
        let mut iv = vec![0u8; self.suite.iv_len];
        vp_common::rand_bytes(&mut iv);
        let sub = self.suite.subkey(&self.master_key, &iv);
        let mut tx = StreamXor::new(&self.suite, &sub, &iv, false)?;

        let (framed, hash) = match self.protocol {
            Protocol::Origin => (false, HashKind::Md5),
            Protocol::AuthAes128(h) => (true, h),
        };

        // SS 层首段 = [IV] + 加密的首包（origin: 地址头；auth_aes128: auth 包）。
        // 分层顺序（对齐 SSR 参考实现）：载荷 → SS 流加密 → 混淆层包裹 → TCP。
        // 混淆在最外层，因此 [IV][密文] 必须整体进混淆层内部 —— tls1.2_ticket_auth
        // 的 ClientHello 是明文伪装帧，绝不能被 SS 密钥流加密。
        let mut ss_first = Vec::new();
        if self.suite.iv_len > 0 {
            ss_first.extend_from_slice(&iv);
        }
        match self.protocol {
            Protocol::Origin => {
                tx.apply(&mut addr_buf);
                ss_first.extend_from_slice(&addr_buf);
            }
            Protocol::AuthAes128(h) => {
                let auth = next_auth_data();
                let mut first = pack_auth_data(
                    h,
                    auth,
                    &addr_buf,
                    &iv,
                    &self.master_key,
                    &self.user_key,
                    self.uid,
                );
                tx.apply(&mut first);
                ss_first.extend_from_slice(&first);
            }
        }

        let mut tls = if self.obfs == TLS12_TICKET_OBFS_STR {
            Some(TlsTicket::new(&self.master_key, self.obfs_param.clone()))
        } else {
            None
        };
        // 首段输出：混淆层包裹后的完整首飞（tls 混淆 = 明文 ClientHello+finish+记录(SS 首段)）
        let initial = match tls.as_mut() {
            Some(t) => t.encode(&ss_first),
            None => {
                let mut o = self.apply_obfs_header(&[]);
                o.extend_from_slice(&ss_first);
                o
            }
        };

        Ok(Box::new(SsrStream {
            inner: conn,
            suite: self.suite.clone(),
            master_key: self.master_key.clone(),
            framed,
            hash,
            user_key: self.user_key.clone(),
            pack_id: 1,
            recv_id: 1,
            tx,
            rx: None,
            out: BytesMut::from(&initial[..]),
            raw: BytesMut::new(),
            ss_ct: BytesMut::new(),
            ss_stream: BytesMut::new(),
            pending: BytesMut::new(),
            closed: false,
            tls,
        }))
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

/// 构造首包 auth 头（auth_aes128 协议层）
fn pack_auth_data(
    hash: HashKind,
    auth: [u8; 12],
    head: &[u8],
    iv: &[u8],
    master_key: &[u8],
    user_key: &[u8],
    uid: u32,
) -> Vec<u8> {
    let rand_len = trapezoid_random_int(1460usize.saturating_sub(head.len() + 36));
    let data_len = 35 + head.len() + rand_len;
    let mut p = [0u8; 16];
    p[..12].copy_from_slice(&auth);
    p[12..14].copy_from_slice(&(data_len as u16).to_le_bytes());
    p[14..16].copy_from_slice(&(rand_len as u16).to_le_bytes());

    // cbc 密码 = base64(user_key) + 协议盐，经 EVP_BytesToKey 派生 16 字节密钥
    let mut pw = base64::engine::general_purpose::STANDARD
        .encode(user_key)
        .into_bytes();
    pw.extend_from_slice(hash.salt().as_bytes());
    let cbc_key = evp_bytes_to_key(&pw, 16);
    let mut key = [0u8; 16];
    key.copy_from_slice(&cbc_key);
    let ct = aes128_cbc_single_block(&key, &p);

    let mac_key: Vec<u8> = iv.iter().chain(master_key.iter()).copied().collect();
    let mut body = Vec::with_capacity(24);
    body.extend_from_slice(&uid.to_le_bytes());
    body.extend_from_slice(&ct);
    let mac = hash.hmac(&mac_key, &[&body]);
    body.extend_from_slice(&mac[..4]);

    let mut out = Vec::with_capacity(31 + rand_len + head.len() + 4);
    let check0 = {
        let mut b = [0u8; 1];
        vp_common::rand_bytes(&mut b);
        b[0]
    };
    out.push(check0);
    let cmac = hash.hmac(&mac_key, &[&[check0]]);
    out.extend_from_slice(&cmac[..6]);
    out.extend_from_slice(&body);
    let mut rnd = vec![0u8; rand_len];
    vp_common::rand_bytes(&mut rnd);
    out.extend_from_slice(&rnd);
    out.extend_from_slice(head);
    let fmac = hash.hmac(user_key, &[&out]);
    out.extend_from_slice(&fmac[..4]);
    out
}

// ---------------------------------------------------------------------------
// 加密流（协议层 + 流式加密双向编解码）
// ---------------------------------------------------------------------------

pub struct SsrStream<S> {
    inner: S,
    suite: StreamSuite,
    master_key: Vec<u8>,
    /// true: auth_aes128 分帧；false: origin 连续流
    framed: bool,
    hash: HashKind,
    user_key: Vec<u8>,
    pack_id: u32,
    recv_id: u32,
    tx: StreamXor,
    rx: Option<StreamXor>,
    out: BytesMut,
    /// 对端原始字节流（tls 混淆时 = TLS 记录流；否则 = SS 流）
    raw: BytesMut,
    /// tls 混淆：解帧后尚未解密的 SS 密文（含待凑齐的 IV）
    ss_ct: BytesMut,
    /// tls 混淆：已解密、待协议层消费的 SS 字节流（可含半帧余量）
    ss_stream: BytesMut,
    pending: BytesMut,
    closed: bool,
    /// tls1.2_ticket_auth 混淆状态（None = 其它混淆）
    tls: Option<TlsTicket>,
}

impl<S> SsrStream<S> {
    fn flush_out(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>>
    where
        S: AsyncWrite + Unpin,
    {
        while !self.out.is_empty() {
            let mut inner = Pin::new(&mut self.inner);
            match inner.as_mut().poll_write(cx, &self.out) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "ssr: 写入 0 字节",
                    )));
                }
                Poll::Ready(Ok(n)) => self.out.advance(n),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    /// 构造一个数据包（auth_aes128 协议层），并递增 pack_id
    fn pack_data_packet(&mut self, chunk: &[u8], full_len: usize) -> Vec<u8> {
        let rand_len = rand_len_for_data(chunk.len(), full_len) + 1;
        let packet_len = rand_len + chunk.len() + 8;
        let mac_key: Vec<u8> = self
            .user_key
            .iter()
            .chain(self.pack_id.to_le_bytes().iter())
            .copied()
            .collect();
        self.pack_id = self.pack_id.wrapping_add(1);

        let mut out = Vec::with_capacity(packet_len);
        out.extend_from_slice(&(packet_len as u16).to_le_bytes());
        let lmac = self.hash.hmac(&mac_key, &[&out[..2]]);
        out.extend_from_slice(&lmac[..2]);
        // 填充前缀：rand_len < 128 用 1 字节，否则 0xFF + u16le(rand_len)
        if rand_len < 128 {
            out.push(rand_len as u8);
            let mut rnd = vec![0u8; rand_len - 1];
            vp_common::rand_bytes(&mut rnd);
            out.extend_from_slice(&rnd);
        } else {
            out.push(0xFF);
            out.extend_from_slice(&(rand_len as u16).to_le_bytes());
            let mut rnd = vec![0u8; rand_len - 3];
            vp_common::rand_bytes(&mut rnd);
            out.extend_from_slice(&rnd);
        }
        out.extend_from_slice(chunk);
        let dmac = self.hash.hmac(&mac_key, &[&out]);
        out.extend_from_slice(&dmac[..4]);
        out
    }

    /// 解析 auth_aes128 分帧（数据源 = self.raw）
    fn parse_frames(&mut self) {
        let mut buf = std::mem::take(&mut self.raw);
        self.parse_frames_buf(&mut buf);
        self.raw = buf;
    }

    /// 解析 auth_aes128 分帧，提取载荷到 pending（数据源由调用方给定）
    fn parse_frames_buf(&mut self, buf: &mut BytesMut) {
        loop {
            if buf.len() <= 4 {
                break;
            }
            let len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
            if !(7..8192).contains(&len) {
                tracing::warn!("ssr: 对端数据包长度异常 ({len})，连接中断");
                self.closed = true;
                buf.clear();
                break;
            }
            if buf.len() < len {
                break;
            }
            let mac_key: Vec<u8> = self
                .user_key
                .iter()
                .chain(self.recv_id.to_le_bytes().iter())
                .copied()
                .collect();
            let lmac = self.hash.hmac(&mac_key, &[&buf[..2]]);
            if lmac[..2] != buf[2..4] {
                tracing::warn!("ssr: 对端数据包 MAC 校验失败，连接中断");
                self.closed = true;
                buf.clear();
                break;
            }
            let dmac = self.hash.hmac(&mac_key, &[&buf[..len - 4]]);
            if dmac[..4] != buf[len - 4..len] {
                tracing::warn!("ssr: 对端数据包校验和错误，连接中断");
                self.closed = true;
                buf.clear();
                break;
            }
            self.recv_id = self.recv_id.wrapping_add(1);
            // 填充前缀：首字节 < 255 → 前缀 1 字节；否则 0xFF + u16le
            let pos = if buf[4] < 255 {
                buf[4] as usize + 4
            } else {
                u16::from_le_bytes([buf[5], buf[6]]) as usize + 4
            };
            if pos + 4 <= len {
                self.pending.extend_from_slice(&buf[pos..len - 4]);
            }
            let _ = buf.split_to(len);
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for SsrStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        loop {
            if !this.pending.is_empty() {
                let n = this.pending.len().min(buf.remaining());
                buf.put_slice(&this.pending[..n]);
                this.pending.advance(n);
                return Poll::Ready(Ok(()));
            }
            if this.closed {
                return Poll::Ready(Ok(()));
            }
            // 先冲刷待发数据（含握手首包）：先读后写的消费方不能饿死首包
            std::task::ready!(this.flush_out(cx))?;
            // 读对端密文
            let filled = {
                this.raw.reserve(16 * 1024);
                let spare = this.raw.spare_capacity_mut();
                let mut rb = ReadBuf::uninit(spare);
                std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                let f = rb.filled().len();
                if f == 0 {
                    this.closed = true;
                    return Poll::Ready(Ok(()));
                }
                f
            };
            unsafe { this.raw.advance_mut(filled) };
            if this.tls.is_some() {
                // ① 混淆层解帧：TLS 记录流 → SS 字节流（0x17 载荷拼接）
                let mut plain = BytesMut::new();
                this.tls
                    .as_mut()
                    .unwrap()
                    .decode(&mut this.raw, &mut plain)
                    .map_err(std::io::Error::other)?;
                this.ss_ct.extend_from_slice(&plain);
                // ② SS 流头部取服务端 IV，初始化接收密钥流（none 密码无 IV）
                if this.rx.is_none() {
                    let need = this.suite.iv_len;
                    if this.ss_ct.len() < need {
                        continue; // IV 未凑齐，继续读
                    }
                    let iv = if need > 0 {
                        Some(this.ss_ct.split_to(need).to_vec())
                    } else {
                        None
                    };
                    let sub = match &iv {
                        Some(v) => this.suite.subkey(&this.master_key, v),
                        None => this.master_key.clone(),
                    };
                    let rx = StreamXor::new(&this.suite, &sub, iv.as_deref().unwrap_or(&[]), true)?;
                    this.rx = Some(rx);
                }
                // ③ 流解密（ss_ct 内全部为未解密密文）→ 协议层
                let mut ct = std::mem::take(&mut this.ss_ct);
                this.rx.as_mut().unwrap().apply(&mut ct);
                this.ss_stream.extend_from_slice(&ct);
                if this.framed {
                    let mut stream = std::mem::take(&mut this.ss_stream);
                    this.parse_frames_buf(&mut stream);
                    this.ss_stream = stream;
                } else {
                    let drained = this.ss_stream.split().to_vec();
                    this.pending.extend_from_slice(&drained);
                }
                continue;
            }
            if this.rx.is_none() {
                let need = this.suite.iv_len;
                if this.raw.len() < need {
                    continue; // 继续读对端 IV
                }
                // IV 就绪：初始化接收密钥流（none 密码无 IV）
                let iv = if need > 0 {
                    Some(this.raw.split_to(need).to_vec())
                } else {
                    None
                };
                let sub = match &iv {
                    Some(v) => this.suite.subkey(&this.master_key, v),
                    None => this.master_key.clone(),
                };
                let mut rx = StreamXor::new(&this.suite, &sub, iv.as_deref().unwrap_or(&[]), true)?;
                // IV 之后已缓冲的余量为本连接密文，立即解密
                rx.apply(&mut this.raw);
                if this.framed {
                    this.parse_frames();
                } else {
                    let drained = this.raw.split().to_vec();
                    this.pending.extend_from_slice(&drained);
                }
                this.rx = Some(rx);
                continue;
            }
            // 正常接收：读密文 → 流解密 → 分帧提取
            let start = this.raw.len() - filled;
            let seg = &mut this.raw[start..];
            this.rx.as_mut().unwrap().apply(seg);
            if this.framed {
                this.parse_frames();
            } else {
                let drained = this.raw.split().to_vec();
                this.pending.extend_from_slice(&drained);
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for SsrStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.as_mut().get_mut();
        // 分层顺序（对齐 SSR 参考实现）：
        //   ① 协议层分帧（auth_aes128 打包 / origin 连续流）
        //   ② SS 流加密（连续密钥流）
        //   ③ 混淆层包裹（tls1.2_ticket_auth 在 SS 密文外再套 TLS 记录；
        //      ClientHello 仅在 connect_stream 的首飞注入，且必须保持明文）
        let ss: Vec<u8> = if this.framed {
            let mut out = Vec::new();
            let mut rest = buf;
            while !rest.is_empty() {
                let take = rest.len().min(8100);
                let (chunk, tail) = rest.split_at(take);
                let mut packet = this.pack_data_packet(chunk, buf.len());
                this.tx.apply(&mut packet);
                out.extend_from_slice(&packet);
                rest = tail;
            }
            out
        } else {
            let mut enc = buf.to_vec();
            this.tx.apply(&mut enc);
            enc
        };
        match &mut this.tls {
            Some(t) => this.out.extend_from_slice(&t.encode(&ss)),
            None => this.out.extend_from_slice(&ss),
        }
        std::task::ready!(this.flush_out(cx))?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        std::task::ready!(this.flush_out(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        std::task::ready!(this.flush_out(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// origin + none/plain：明文直传 + http_simple 混淆头（自环回显）
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

    /// rc4-md5 连续流自环：发送方向加密、接收方向解密（模拟 SSR 服务端行为）
    #[tokio::test]
    async fn ssr_stream_rc4_md5_roundtrip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let password = "di15PV";
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            // 服务端：读客户端 IV → 解密流 → 原样回显（用服务端自己的 IV 重新加密）
            let suite = StreamSuite::parse("rc4-md5").unwrap();
            let master = suite.derive_key(password);
            let mut iv = [0u8; 16];
            s.read_exact(&mut iv).await.unwrap();
            let sub = suite.subkey(&master, &iv);
            let mut dec = StreamXor::new(&suite, &sub, &iv, true).unwrap();
            let mut buf = vec![0u8; 4096];
            let n = s.read(&mut buf).await.unwrap();
            dec.apply(&mut buf[..n]);
            // 剥掉 SOCKS 地址头后回显载荷
            let skip = match buf[0] {
                0x01 => 1 + 4 + 2,
                0x04 => 1 + 16 + 2,
                0x03 => 1 + 1 + buf[1] as usize + 2,
                _ => 0,
            };
            // 服务端自己的 IV + 重新加密
            let mut siv = [0u8; 16];
            vp_common::rand_bytes(&mut siv);
            let ssub = suite.subkey(&master, &siv);
            let mut enc = StreamXor::new(&suite, &ssub, &siv, false).unwrap();
            let payload = &mut buf[skip..n];
            let mut out = siv.to_vec();
            enc.apply(payload);
            out.extend_from_slice(payload);
            let _ = s.write_all(&out).await;
        });

        let cfg = vp_config::SsrCfg {
            server: "127.0.0.1".into(),
            port,
            password: password.into(),
            cipher: "rc4-md5".into(),
            protocol: "origin".into(),
            protocol_param: None,
            obfs: "plain".into(),
            obfs_param: None,
            udp: false,
        };
        let ob = SsrOutbound::new(&cfg).unwrap();
        let dst = DstAddr::new("example.com", 80);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = ob.connect_stream(&sess, &dst).await.unwrap();
        s.write_all(b"ping-ssr-rc4").await.unwrap();
        let mut buf = [0u8; 12];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-ssr-rc4");
    }

    /// auth_aes128_md5 分帧自环：校验首包布局与数据包分帧/解密
    #[tokio::test]
    async fn ssr_stream_auth_aes128_roundtrip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let password = "di15PV";
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let suite = StreamSuite::parse("rc4-md5").unwrap();
            let master = suite.derive_key(password);
            // 读客户端 IV + auth 首包（做基础长度校验）
            let mut iv = [0u8; 16];
            s.read_exact(&mut iv).await.unwrap();
            let sub = suite.subkey(&master, &iv);
            let mut dec = StreamXor::new(&suite, &sub, &iv, true).unwrap();
            let mut head = [0u8; 7 + 4 + 16 + 4]; // check_head + uid + ct + mac
            s.read_exact(&mut head).await.unwrap();
            dec.apply(&mut head);
            // check_head[1..7] 必须是 HMAC(mac_key, check_head[0])[:6]
            let mac_key: Vec<u8> = iv.iter().chain(master.iter()).copied().collect();
            let cmac = HashKind::Md5.hmac(&mac_key, &[&head[..1]]);
            assert_eq!(&head[1..7], &cmac[..6], "check_head HMAC 不匹配");
            // 随机应答一个合法数据包：len=8+1+payload
            let user_key = Md5::digest(b"563537032");
            let payload = b"pong-auth";
            let mut pkt = Vec::new();
            let rand_len = 1usize;
            let plen = rand_len + payload.len() + 8;
            pkt.extend_from_slice(&(plen as u16).to_le_bytes());
            let pk_key: Vec<u8> = user_key
                .iter()
                .chain(1u32.to_le_bytes().iter())
                .copied()
                .collect();
            let lmac = HashKind::Md5.hmac(&pk_key, &[&pkt]);
            pkt.extend_from_slice(&lmac[..2]);
            pkt.push(rand_len as u8);
            pkt.extend_from_slice(payload);
            let dmac = HashKind::Md5.hmac(&pk_key, &[&pkt]);
            pkt.extend_from_slice(&dmac[..4]);
            // 用服务端 IV 加密后回发
            let mut siv = [0u8; 16];
            vp_common::rand_bytes(&mut siv);
            let ssub = suite.subkey(&master, &siv);
            let mut enc = StreamXor::new(&suite, &ssub, &siv, false).unwrap();
            enc.apply(&mut pkt);
            let mut out = siv.to_vec();
            out.extend_from_slice(&pkt);
            let _ = s.write_all(&out).await;
            // 排干客户端后续包再关闭：Windows 对带未读数据的连接关闭会回 RST 冲掉应答
            let _ = tokio::time::timeout(std::time::Duration::from_millis(300), async {
                let mut drain = [0u8; 8192];
                loop {
                    if s.read(&mut drain).await.unwrap_or(0) == 0 {
                        break;
                    }
                }
            })
            .await;
        });

        let cfg = vp_config::SsrCfg {
            server: "127.0.0.1".into(),
            port,
            password: password.into(),
            cipher: "rc4-md5".into(),
            protocol: "auth_aes128_md5".into(),
            protocol_param: Some("23929:563537032".into()),
            obfs: "plain".into(),
            obfs_param: None,
            udp: false,
        };
        let ob = SsrOutbound::new(&cfg).unwrap();
        let dst = DstAddr::new("example.com", 80);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = ob.connect_stream(&sess, &dst).await.unwrap();
        s.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 9];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong-auth");
    }

    #[test]
    fn auth_packet_layout() {
        // 首包总长 = 35 + 载荷 + rand_len，data_len 字段与实际一致
        let hash = HashKind::Md5;
        let iv = [3u8; 16];
        let master = vec![7u8; 16];
        let user_key = Md5::digest(b"563537032").to_vec();
        let head = [0x01u8, 4, 1, 2, 3, 4, 0x1f, 0x90]; // 8 字节地址头
        let pkt = pack_auth_data(hash, [9u8; 12], &head, &iv, &master, &user_key, 23929);
        assert_eq!(&pkt[7..11], &23929u32.to_le_bytes(), "uid 应为 LE");
        assert!(pkt.len() >= 35 + head.len());
    }

    /// 分层顺序对拍（chacha20-ietf + origin + tls1.2_ticket_auth）：
    /// 线上首字节必须是明文 ClientHello（0x16 0x03 0x01），SS 密文整体在 0x17 记录内，
    /// 且 [IV] 在记录载荷头部；服务端解帧 → IV → 解密应还原地址头。
    #[tokio::test]
    async fn tls_obfs_wire_layout_and_roundtrip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let password = "di15PV";
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 16 * 1024];
            let n = s.read(&mut buf).await.unwrap();
            let wire = &buf[..n];
            // ClientHello 必须是明文伪装帧 —— 不能被流加密弄成乱码
            assert_eq!(
                &wire[..3],
                &[0x16, 0x03, 0x01],
                "线上首字节应为明文 ClientHello，实际 {:#04x}",
                wire[0]
            );
            // 按记录解帧：0x16/0x14 跳过，0x17 拼接 SS 流
            let mut ss = Vec::new();
            let (mut i, mut saw_hello) = (0usize, false);
            while i + 5 <= wire.len() {
                let rtype = wire[i];
                let len = u16::from_be_bytes([wire[i + 3], wire[i + 4]]) as usize;
                assert!(i + 5 + len <= wire.len(), "记录长度越界");
                match rtype {
                    0x16 => saw_hello = true,
                    0x14 | 0x17 => {}
                    other => panic!("异常记录类型 {other:#x}"),
                }
                if rtype == 0x17 {
                    ss.extend_from_slice(&wire[i + 5..i + 5 + len]);
                }
                i += 5 + len;
            }
            assert!(saw_hello, "首飞缺少 ServerHello 伪装记录");
            assert!(ss.len() > 12, "0x17 载荷应含 [IV]+密文");
            // SS 流：IV + 加密地址头
            let suite = StreamSuite::parse("chacha20-ietf").unwrap();
            let master = suite.derive_key(password);
            let iv = ss[..12].to_vec();
            let sub = suite.subkey(&master, &iv);
            let mut dec = StreamXor::new(&suite, &sub, &iv, true).unwrap();
            let mut ct = ss[12..].to_vec();
            dec.apply(&mut ct);
            // origin 地址头：0x03 + len + domain + port
            assert_eq!(ct[0], 0x03, "地址头应未被混淆层破坏");
            let dlen = ct[1] as usize;
            assert_eq!(&ct[2..2 + dlen], b"example.com");
            // 服务端应答：ServerHello(≥76B) + 0x17 记录包 [服务端 IV][E(pong)]
            let mut resp = Vec::new();
            let mut random = [0u8; 32];
            vp_common::rand_bytes(&mut random);
            let body_len = 74usize; // 0x02+len3+ver2+random32+sidlen1+sid32+cipher2+comp1
            resp.extend_from_slice(&[0x16, 0x03, 0x03]);
            resp.extend_from_slice(&(body_len as u16).to_be_bytes());
            resp.push(0x02);
            resp.extend_from_slice(&(body_len as u32).to_be_bytes()[1..4]);
            resp.extend_from_slice(&[0x03, 0x03]);
            resp.extend_from_slice(&random);
            resp.push(0x20);
            let mut sid = [0u8; 32];
            vp_common::rand_bytes(&mut sid);
            resp.extend_from_slice(&sid);
            resp.extend_from_slice(&[0x13, 0x01, 0x00]);
            assert_eq!(resp.len(), 5 + body_len);
            assert!(resp.len() >= 76, "首响应须凑满客户端 First 态阈值");
            let mut s_iv = [0u8; 12];
            vp_common::rand_bytes(&mut s_iv);
            let ssub = suite.subkey(&master, &s_iv);
            let mut enc = StreamXor::new(&suite, &ssub, &s_iv, false).unwrap();
            let mut pong = b"pong-obfs".to_vec();
            enc.apply(&mut pong);
            let mut rec = Vec::with_capacity(5 + 12 + pong.len());
            rec.extend_from_slice(&[0x17, 0x03, 0x03]);
            rec.extend_from_slice(&((12 + pong.len()) as u16).to_be_bytes());
            rec.extend_from_slice(&s_iv);
            rec.extend_from_slice(&pong);
            resp.extend_from_slice(&rec);
            let _ = s.write_all(&resp).await;
            // 排干客户端后续写入，避免 Windows RST 冲掉应答
            let _ = tokio::time::timeout(std::time::Duration::from_millis(300), async {
                let mut drain = [0u8; 4096];
                loop {
                    if s.read(&mut drain).await.unwrap_or(0) == 0 {
                        break;
                    }
                }
            })
            .await;
        });

        let cfg = vp_config::SsrCfg {
            server: "127.0.0.1".into(),
            port,
            password: password.into(),
            cipher: "chacha20-ietf".into(),
            protocol: "origin".into(),
            protocol_param: None,
            obfs: "tls1.2_ticket_auth".into(),
            obfs_param: Some("6f5218522.douyin.com".into()),
            udp: false,
        };
        let ob = SsrOutbound::new(&cfg).unwrap();
        let dst = DstAddr::new("example.com", 80);
        let sess = Session::new_tcp("t".into(), None, dst.clone());
        let mut s = ob.connect_stream(&sess, &dst).await.unwrap();
        s.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 9];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong-obfs");
    }
}

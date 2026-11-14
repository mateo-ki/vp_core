//! OpenVPN 客户端（proto tcp，tun 模式）+ smoltcp 用户态 TCP/UDP 栈。
//!
//! 控制信道：`HARD_RESET_CLIENT_V2` → 服务器 `HARD_RESET_SERVER_V2` → TLS 握手
//! （P_CONTROL_V1 载荷承载 TLS 记录，分块 1100B，可靠层 ACK）→ Key Method v2
//! （preMaster/random1/random2 + options/username/password/peer-info，凭据内嵌记录）→
//! openvpn PRF（TLS1.0 风格 MD5/SHA1 XOR，label "OpenVPN master secret" /
//! "OpenVPN key expansion"，会话参数为 OpenVPN 侧 session-id）→ `PUSH_REQUEST` →
//! `PUSH_REPLY`（peer-id / data-ciphers / ifconfig 隧道地址）。
//!
//! 数据信道：`P_DATA_V2`（4B 头 = opcode|key_id + 24bit peer-id）+ AEAD
//! （AES-GCM / ChaCha20-Poly1305：明文 packet_id(4B) 在头后，nonce = packet_id XOR
//! implicit-IV（implicit-IV = 4B 零 + HMAC key 前 8B），AAD = v2 头，tag 前置密文），
//! 载荷为 IP 包 → smoltcp。
//!
//! 证书校验：信任订阅下发 CA 并校验链签名，不做主机名匹配（与 OpenVPN 默认
//! verify-x509-name 语义一致）；可选客户端证书。
//!
//! 数据信道支持 AEAD（GCM/ChaCha20）与 CBC+HMAC-SHA1（SoftEther/VPN Gate 系服务器，
//! 数据格式 header|HMAC(20)|IV(16)|密文，明文 = packet_id(4)+载荷+PKCS7 填充）。
//! 限制：不支持 tls-auth/tls-crypt、CBC 族仅 SHA1 认证、UDP proto 与软重协商（软重
//! 到达时保留旧密钥继续；若对端强制切换，数据信道失败并按会话级重连）。

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{Mutex, mpsc, oneshot};

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{IpAddress, IpCidr, IpEndpoint, Ipv4Address};

use bytes::{Buf, Bytes};
use vp_common::{DstAddr, Error, Result};
use vp_core::stream::UdpPacket;
use vp_core::{Outbound, PacketConn, ProxyStream, Session};

const MTU: u32 = 1420;

/// 调试 trace（VPCORE_OVPN_TRACE=1 → stderr）
fn ov_trace(msg: impl std::fmt::Display) {
    if std::env::var("VPCORE_OVPN_TRACE")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        eprintln!("[ovpn-trace] {msg}");
    }
}
const SOCK_BUF: usize = 256 * 1024;
const TICK: std::time::Duration = std::time::Duration::from_millis(1);
const CHAN_CAP: usize = 256;

// ---------------------------------------------------------------------------
// OpenVPN 协议常量
// ---------------------------------------------------------------------------

const OPCODE_SHIFT: u8 = 3;
const KEY_ID_MASK: u8 = 0x07;
const P_CONTROL_V1: u8 = 4;
const P_ACK_V1: u8 = 5;
const P_DATA_V1: u8 = 6;
const P_CONTROL_HARD_RESET_CLIENT_V2: u8 = 7;
const P_CONTROL_HARD_RESET_SERVER_V2: u8 = 8;
const P_DATA_V2: u8 = 9;
const P_CONTROL_SOFT_RESET_V1: u8 = 3;

const SID_SIZE: usize = 8;
/// 单个 P_CONTROL 载荷上限（对齐官方 TLS_MTU 内的默认值）
const MAX_CONTROL_PAYLOAD: usize = 1100;
/// 无 tls-auth/tls-crypt 时 ACK 列表上限（SoftEther 兼容）
const ACK_MAX: usize = 4;
/// 空闲 ACK 刷盘间隔
const ACK_FLUSH: std::time::Duration = std::time::Duration::from_millis(150);
/// 客户端 keepalive 周期
const PING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
/// OpenVPN 官方 PING 探测包
const PING_MAGIC: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
];
/// GCM tag
const TAG_SIZE: usize = 16;
/// CBC 数据信道 HMAC-SHA1 tag 大小
const CBC_AUTH_SIZE: usize = 20;
/// AES 块大小
const CBC_BLOCK: usize = 16;
/// 数据信道重放窗口
const REPLAY_WINDOW: u32 = 64;
/// 握手总超时
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

const KEY_METHOD_V2: u8 = 2;
const KEY_SOURCE_PRE_MASTER_SIZE: usize = 48;
const KEY_SOURCE_RANDOM_SIZE: usize = 32;
const KEY_BLOCK_SIZE: usize = 512; // 2 * (64 + 64)
const MAX_CIPHER_KEY_LEN: usize = 64;

/// peer-id 未分配哨兵
const PEER_ID_UNSET: u32 = 0xffffff;

/// 控制信道明文消息（NUL 结尾）前缀
const CONTROL_MSG_PREFIXES: [&str; 8] = [
    "PUSH_REPLY",
    "AUTH_PENDING",
    "AUTH_FAILED",
    "RESTART",
    "HALT",
    "EXIT",
    "INFO_PRE",
    "CR_RESPONSE",
];

const PUSH_REQUEST: &str = "PUSH_REQUEST";

fn opcode_key_id(opcode: u8, key_id: u8) -> u8 {
    (opcode << OPCODE_SHIFT) | (key_id & KEY_ID_MASK)
}

fn parse_opcode(b: u8) -> u8 {
    b >> OPCODE_SHIFT
}

// ---------------------------------------------------------------------------
// 帧与控制包编解码
// ---------------------------------------------------------------------------

/// TCP 帧：u16 BE 长度前缀
/// 有状态帧组装器：TCP 分段到达时跨调用续读，绝不在半帧上阻塞等待
#[derive(Default)]
struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    /// 尝试取一个完整帧；数据不足返回 Ok(None)（调用方继续驱动 IO）
    async fn read_frame(&mut self, tcp: &mut tokio::net::TcpStream) -> Result<Option<Vec<u8>>> {
        while self.buf.len() < 2 {
            if !self.fill(tcp).await? {
                return Ok(None);
            }
        }
        let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
        if len == 0 {
            return Err(Error::Proto("openvpn: 空帧"));
        }
        while self.buf.len() < 2 + len {
            if !self.fill(tcp).await? {
                return Ok(None);
            }
        }
        let pkt = self.buf[2..2 + len].to_vec();
        self.buf.drain(..2 + len);
        Ok(Some(pkt))
    }

    /// 非阻塞补数据（1ms 可读探测）；无新数据返回 false
    async fn fill(&mut self, tcp: &mut tokio::net::TcpStream) -> Result<bool> {
        if tokio::time::timeout(std::time::Duration::from_millis(1), tcp.readable())
            .await
            .is_err()
        {
            return Ok(false);
        }
        let mut tmp = [0u8; 16384];
        let n = match tcp.try_read(&mut tmp) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) => {
                return Err(Error::Io(std::io::Error::other(format!(
                    "openvpn 帧读: {e}"
                ))));
            }
        };
        if n == 0 {
            return Err(Error::Proto("openvpn: 连接已关闭"));
        }
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(true)
    }
}

async fn write_frame(tcp: &mut tokio::net::TcpStream, pkt: &[u8]) -> Result<()> {
    if pkt.len() > u16::MAX as usize {
        return Err(Error::Proto("openvpn: 帧超长"));
    }
    let mut out = Vec::with_capacity(2 + pkt.len());
    out.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
    out.extend_from_slice(pkt);
    tcp.write_all(&out)
        .await
        .map_err(|e| Error::Io(std::io::Error::other(format!("openvpn 写帧: {e}"))))?;
    tcp.flush()
        .await
        .map_err(|e| Error::Io(std::io::Error::other(format!("openvpn flush: {e}"))))?;
    Ok(())
}

struct ControlPacket {
    opcode: u8,
    #[allow(dead_code)]
    key_id: u8,
    session_id: [u8; SID_SIZE],
    #[allow(dead_code)]
    acks: Vec<u32>,
    msg_id: Option<u32>,
    payload: Vec<u8>,
}

fn decode_control(pkt: &[u8]) -> Result<ControlPacket> {
    if pkt.len() < 1 + SID_SIZE + 1 {
        return Err(Error::Proto("openvpn: 控制包过短"));
    }
    let opcode = parse_opcode(pkt[0]);
    let key_id = pkt[0] & KEY_ID_MASK;
    let mut pos = 1usize;
    let mut session_id = [0u8; SID_SIZE];
    session_id.copy_from_slice(&pkt[pos..pos + SID_SIZE]);
    pos += SID_SIZE;
    let ack_count = pkt[pos] as usize;
    pos += 1;
    let mut acks = Vec::with_capacity(ack_count);
    for _ in 0..ack_count {
        if pos + 4 > pkt.len() {
            return Err(Error::Proto("openvpn: ack 列表截断"));
        }
        acks.push(u32::from_be_bytes([
            pkt[pos],
            pkt[pos + 1],
            pkt[pos + 2],
            pkt[pos + 3],
        ]));
        pos += 4;
    }
    if ack_count > 0 {
        // remote session id（8B）跟随 ack 列表
        if pos + SID_SIZE > pkt.len() {
            return Err(Error::Proto("openvpn: remote sid 截断"));
        }
        pos += SID_SIZE;
    }
    let msg_id = if opcode != P_ACK_V1 {
        if pos + 4 > pkt.len() {
            return Err(Error::Proto("openvpn: msg id 截断"));
        }
        let id = u32::from_be_bytes([pkt[pos], pkt[pos + 1], pkt[pos + 2], pkt[pos + 3]]);
        pos += 4;
        Some(id)
    } else {
        None
    };
    Ok(ControlPacket {
        opcode,
        key_id,
        session_id,
        acks,
        msg_id,
        payload: pkt[pos..].to_vec(),
    })
}

#[allow(clippy::too_many_arguments)]
fn encode_control(
    opcode: u8,
    key_id: u8,
    local_sid: &[u8; SID_SIZE],
    acks: &[u32],
    remote_sid: Option<&[u8; SID_SIZE]>,
    msg_id: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + acks.len() * 4 + payload.len());
    out.push(opcode_key_id(opcode, key_id));
    out.extend_from_slice(local_sid);
    out.push(acks.len().min(ACK_MAX) as u8);
    for id in acks.iter().take(ACK_MAX) {
        out.extend_from_slice(&id.to_be_bytes());
    }
    if !acks.is_empty() {
        if let Some(rsid) = remote_sid {
            out.extend_from_slice(rsid);
        } else {
            out.extend_from_slice(&[0u8; SID_SIZE]);
        }
    }
    if opcode != P_ACK_V1 {
        out.extend_from_slice(&msg_id.to_be_bytes());
        out.extend_from_slice(payload);
    }
    out
}

// ---------------------------------------------------------------------------
// Key Method v2 + PRF
// ---------------------------------------------------------------------------

/// openvpn 字符串：u16 BE 长度（值长+1，含 NUL）+ 值 + NUL；空串仅 2 字节 0
fn append_openvpn_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&((s.len() + 1) as u16).to_be_bytes());
    if !s.is_empty() {
        out.extend_from_slice(s.as_bytes());
        out.push(0);
    }
}

/// 剩余字节是否是跟随在 KM2 记录后的 TLS 控制消息（OpenVPN 2.6 允许同记录拼接）
fn looks_like_control_msg(buf: &[u8]) -> bool {
    CONTROL_MSG_PREFIXES
        .iter()
        .any(|p| buf.len() >= p.len() && buf[..p.len()].eq_ignore_ascii_case(p.as_bytes()))
}

fn build_km2_client(
    options: &str,
    peer_info: &str,
    username: &str,
    password: &str,
    pre_master: &[u8; KEY_SOURCE_PRE_MASTER_SIZE],
    random1: &[u8; KEY_SOURCE_RANDOM_SIZE],
    random2: &[u8; KEY_SOURCE_RANDOM_SIZE],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(200 + options.len() + peer_info.len());
    out.extend_from_slice(&[0u8; 4]);
    out.push(KEY_METHOD_V2);
    out.extend_from_slice(pre_master);
    out.extend_from_slice(random1);
    out.extend_from_slice(random2);
    append_openvpn_string(&mut out, options);
    append_openvpn_string(&mut out, username);
    append_openvpn_string(&mut out, password);
    append_openvpn_string(&mut out, peer_info);
    out
}

struct ServerKm2 {
    random1: [u8; KEY_SOURCE_RANDOM_SIZE],
    random2: [u8; KEY_SOURCE_RANDOM_SIZE],
    /// 记录之后残留的 TLS 控制消息字节（NUL 帧；实际消费走 km2_buf，测试读取）
    #[allow(dead_code)]
    trailing: Vec<u8>,
}

/// 解析服务器 KM2 记录。buf 为当前 TLS 明文累计缓冲；记录不完整时返回 Err
/// （调用方继续读 TLS）。返回 (记录, 已消费字节数)。
fn parse_km2_server(buf: &[u8]) -> Result<(ServerKm2, usize)> {
    let min = 4 + 1 + KEY_SOURCE_RANDOM_SIZE * 2;
    if buf.len() < min {
        return Err(Error::Proto("openvpn: 服务器 KM2 过短"));
    }
    if buf[0..4] != [0u8; 4] {
        return Err(Error::Proto("openvpn: KM2 前缀非法"));
    }
    if buf[4] & 0x0f != KEY_METHOD_V2 {
        return Err(Error::Proto("openvpn: key method 非 v2"));
    }
    let mut pos = 5usize;
    let mut random1 = [0u8; KEY_SOURCE_RANDOM_SIZE];
    random1.copy_from_slice(&buf[pos..pos + KEY_SOURCE_RANDOM_SIZE]);
    pos += KEY_SOURCE_RANDOM_SIZE;
    let mut random2 = [0u8; KEY_SOURCE_RANDOM_SIZE];
    random2.copy_from_slice(&buf[pos..pos + KEY_SOURCE_RANDOM_SIZE]);
    pos += KEY_SOURCE_RANDOM_SIZE;
    // 可选字符串：options（必有）、username/password/peer-info（2.6 可省略）。
    // 残余出现控制消息前缀时停止，视作记录后拼接的 NUL 帧消息。
    let mut consumed_strings = 0usize;
    loop {
        if pos + 2 > buf.len() || looks_like_control_msg(&buf[pos..]) {
            break;
        }
        let l = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        if l == 0 {
            pos += 2;
            consumed_strings += 1;
            continue;
        }
        if pos + 2 + l > buf.len() {
            break; // 字符串不完整 → 等待更多 TLS 字节
        }
        pos += 2 + l;
        consumed_strings += 1;
    }
    if consumed_strings == 0 {
        return Err(Error::Proto("openvpn: KM2 options 缺失"));
    }
    Ok((
        ServerKm2 {
            random1,
            random2,
            trailing: buf[pos..].to_vec(),
        },
        pos,
    ))
}

/// TLS1.0 风格 PRF：P_hash(MD5, s1) XOR P_hash(SHA1, s2)
fn openvpn_prf(
    secret: &[u8],
    label: &str,
    client_seed: &[u8],
    server_seed: &[u8],
    client_session: Option<&[u8]>,
    server_session: Option<&[u8]>,
    out_len: usize,
) -> Vec<u8> {
    use md5::Md5;
    use sha1::Sha1;

    let mut seed = Vec::with_capacity(label.len() + client_seed.len() + server_seed.len() + 16);
    seed.extend_from_slice(label.as_bytes());
    seed.extend_from_slice(client_seed);
    seed.extend_from_slice(server_seed);
    if let Some(cs) = client_session {
        seed.extend_from_slice(cs);
    }
    if let Some(ss) = server_session {
        seed.extend_from_slice(ss);
    }

    let split = secret.len().div_ceil(2);
    let s1 = &secret[..split];
    let s2 = &secret[secret.len() - split..];

    fn p_hash_md5(secret: &[u8], seed: &[u8], size: usize) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        type HmacMd5 = Hmac<Md5>;
        let mut mac = <HmacMd5 as KeyInit>::new_from_slice(secret).expect("hmac key");
        mac.update(seed);
        let mut a = mac.finalize().into_bytes().to_vec();
        let mut out = Vec::with_capacity(size);
        while out.len() < size {
            let mut mac = <HmacMd5 as KeyInit>::new_from_slice(secret).expect("hmac key");
            mac.update(&a);
            mac.update(seed);
            out.extend_from_slice(&mac.finalize().into_bytes());
            let mut mac = <HmacMd5 as KeyInit>::new_from_slice(secret).expect("hmac key");
            mac.update(&a);
            a = mac.finalize().into_bytes().to_vec();
        }
        out.truncate(size);
        out
    }
    fn p_hash_sha1(secret: &[u8], seed: &[u8], size: usize) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        type HmacSha1 = Hmac<Sha1>;
        let mut mac = <HmacSha1 as KeyInit>::new_from_slice(secret).expect("hmac key");
        mac.update(seed);
        let mut a = mac.finalize().into_bytes().to_vec();
        let mut out = Vec::with_capacity(size);
        while out.len() < size {
            let mut mac = <HmacSha1 as KeyInit>::new_from_slice(secret).expect("hmac key");
            mac.update(&a);
            mac.update(seed);
            out.extend_from_slice(&mac.finalize().into_bytes());
            let mut mac = <HmacSha1 as KeyInit>::new_from_slice(secret).expect("hmac key");
            mac.update(&a);
            a = mac.finalize().into_bytes().to_vec();
        }
        out.truncate(size);
        out
    }

    let md5_out = p_hash_md5(s1, &seed, out_len);
    let sha1_out = p_hash_sha1(s2, &seed, out_len);
    md5_out
        .iter()
        .zip(sha1_out.iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

#[derive(Debug, Clone)]
struct DataKeys {
    send_cipher_key: Vec<u8>,
    /// key block [64..128]（AEAD 用于 implicit IV；CBC 截取前 20B 作 HMAC-SHA1 密钥）
    send_hmac_key: Vec<u8>,
    send_implicit_iv: [u8; 12],
    recv_cipher_key: Vec<u8>,
    recv_hmac_key: Vec<u8>,
    recv_implicit_iv: [u8; 12],
}

/// 派生双向密钥（会话参数为 OpenVPN 侧 session-id；先按 32B 派生，使用时按协商裁剪）
fn derive_keys(
    pre_master: &[u8; KEY_SOURCE_PRE_MASTER_SIZE],
    client_random1: &[u8; KEY_SOURCE_RANDOM_SIZE],
    client_random2: &[u8; KEY_SOURCE_RANDOM_SIZE],
    server_random1: &[u8; KEY_SOURCE_RANDOM_SIZE],
    server_random2: &[u8; KEY_SOURCE_RANDOM_SIZE],
    client_sid: &[u8; SID_SIZE],
    server_sid: &[u8; SID_SIZE],
) -> DataKeys {
    let master = openvpn_prf(
        pre_master,
        "OpenVPN master secret",
        client_random1,
        server_random1,
        None,
        None,
        48,
    );
    let block = openvpn_prf(
        &master,
        "OpenVPN key expansion",
        client_random2,
        server_random2,
        Some(client_sid),
        Some(server_sid),
        KEY_BLOCK_SIZE,
    );
    // client→server = 前 128B（cipher@[0..len]，hmac@[64..]）；server→client = 后 128B
    let c2s = &block[0..128];
    let s2c = &block[128..256];
    DataKeys {
        send_cipher_key: c2s[..32].to_vec(),
        send_hmac_key: c2s[MAX_CIPHER_KEY_LEN..MAX_CIPHER_KEY_LEN + 64].to_vec(),
        send_implicit_iv: {
            let mut iv = [0u8; 12];
            iv[4..12].copy_from_slice(&c2s[MAX_CIPHER_KEY_LEN..MAX_CIPHER_KEY_LEN + 8]);
            iv
        },
        recv_cipher_key: s2c[..32].to_vec(),
        recv_hmac_key: s2c[MAX_CIPHER_KEY_LEN..MAX_CIPHER_KEY_LEN + 64].to_vec(),
        recv_implicit_iv: {
            let mut iv = [0u8; 12];
            iv[4..12].copy_from_slice(&s2c[MAX_CIPHER_KEY_LEN..MAX_CIPHER_KEY_LEN + 8]);
            iv
        },
    }
}

// ---------------------------------------------------------------------------
// 数据信道（AEAD）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DataCipher {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    Aes128Cbc,
    Aes256Cbc,
}

impl DataCipher {
    fn key_len(self) -> usize {
        match self {
            DataCipher::Aes128Gcm | DataCipher::Aes128Cbc => 16,
            DataCipher::Aes256Gcm | DataCipher::Aes256Cbc | DataCipher::ChaCha20Poly1305 => 32,
        }
    }
    fn is_aead(self) -> bool {
        !matches!(self, DataCipher::Aes128Cbc | DataCipher::Aes256Cbc)
    }
    fn parse(s: &str) -> Option<DataCipher> {
        match s.trim().to_ascii_uppercase().as_str() {
            "AES-128-GCM" => Some(DataCipher::Aes128Gcm),
            "AES-256-GCM" | "AES-GCM" => Some(DataCipher::Aes256Gcm),
            "CHACHA20-POLY1305" => Some(DataCipher::ChaCha20Poly1305),
            "AES-128-CBC" => Some(DataCipher::Aes128Cbc),
            "AES-256-CBC" | "AES-CBC" => Some(DataCipher::Aes256Cbc),
            _ => None,
        }
    }
}

fn nonce_from(pid: u32, implicit_iv: &[u8; 12]) -> [u8; 12] {
    let mut n = *implicit_iv;
    let pid_b = pid.to_be_bytes();
    for i in 0..4 {
        n[i] ^= pid_b[i];
    }
    n
}

struct ReplayWindow {
    highest: u32,
    window: u64,
}

impl ReplayWindow {
    fn new() -> Self {
        ReplayWindow {
            highest: 0,
            window: 0,
        }
    }
    fn accept(&mut self, id: u32) -> bool {
        if id > self.highest {
            let diff = id - self.highest;
            if diff >= REPLAY_WINDOW {
                self.window = 1;
            } else {
                self.window = (self.window << diff) | 1;
            }
            self.highest = id;
            return true;
        }
        let diff = self.highest - id;
        if diff >= REPLAY_WINDOW {
            return false;
        }
        let bit = 1u64 << diff;
        if self.window & bit != 0 {
            return false;
        }
        self.window |= bit;
        true
    }
}

fn seal_with(
    key: &[u8],
    cipher: DataCipher,
    nonce: &[u8; 12],
    aad: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>> {
    match cipher {
        DataCipher::Aes256Gcm => {
            let aead = <Aes256Gcm as KeyInit>::new_from_slice(key)
                .map_err(|_| Error::Proto("openvpn: AES-256-GCM key"))?;
            aead.encrypt(Nonce::from_slice(nonce), Payload { msg: plain, aad })
                .map_err(|_| Error::Proto("openvpn: AEAD 加密失败"))
        }
        DataCipher::Aes128Gcm => {
            let aead = <Aes128Gcm as KeyInit>::new_from_slice(key)
                .map_err(|_| Error::Proto("openvpn: AES-128-GCM key"))?;
            aead.encrypt(Nonce::from_slice(nonce), Payload { msg: plain, aad })
                .map_err(|_| Error::Proto("openvpn: AEAD 加密失败"))
        }
        DataCipher::ChaCha20Poly1305 => {
            let aead = <ChaCha20Poly1305 as KeyInit>::new_from_slice(key)
                .map_err(|_| Error::Proto("openvpn: ChaCha key"))?;
            aead.encrypt(Nonce::from_slice(nonce), Payload { msg: plain, aad })
                .map_err(|_| Error::Proto("openvpn: AEAD 加密失败"))
        }
        // CBC 走 encrypt_cbc 专用路径
        DataCipher::Aes128Cbc | DataCipher::Aes256Cbc => {
            Err(Error::Proto("openvpn: CBC 加密走专用路径"))
        }
    }
}

fn open_with(
    key: &[u8],
    cipher: DataCipher,
    nonce: &[u8; 12],
    aad: &[u8],
    sealed: &[u8],
) -> Option<Vec<u8>> {
    match cipher {
        DataCipher::Aes256Gcm => {
            let aead = <Aes256Gcm as KeyInit>::new_from_slice(key).ok()?;
            aead.decrypt(Nonce::from_slice(nonce), Payload { msg: sealed, aad })
                .ok()
        }
        DataCipher::Aes128Gcm => {
            let aead = <Aes128Gcm as KeyInit>::new_from_slice(key).ok()?;
            aead.decrypt(Nonce::from_slice(nonce), Payload { msg: sealed, aad })
                .ok()
        }
        DataCipher::ChaCha20Poly1305 => {
            let aead = <ChaCha20Poly1305 as KeyInit>::new_from_slice(key).ok()?;
            aead.decrypt(Nonce::from_slice(nonce), Payload { msg: sealed, aad })
                .ok()
        }
        // CBC 走 decrypt_cbc 专用路径
        DataCipher::Aes128Cbc | DataCipher::Aes256Cbc => None,
    }
}

struct DataCrypt {
    cipher: DataCipher,
    keys: DataKeys,
    send_pid: u32,
    recv_window: ReplayWindow,
    /// v2 数据头（peer-id 安装后缓存；未分配时为 v1 1B 头）
    send_header: Vec<u8>,
}

impl DataCrypt {
    fn new(cipher: DataCipher, keys: &DataKeys, peer_id: Option<u32>, key_id: u8) -> Self {
        let send_header = match peer_id {
            Some(id) => vec![
                opcode_key_id(P_DATA_V2, key_id),
                (id >> 16) as u8,
                (id >> 8) as u8,
                id as u8,
            ],
            None => vec![opcode_key_id(P_DATA_V1, key_id)],
        };
        let cut = |k: &[u8]| k[..cipher.key_len()].to_vec();
        DataCrypt {
            cipher,
            keys: DataKeys {
                send_cipher_key: cut(&keys.send_cipher_key),
                send_hmac_key: keys.send_hmac_key[..CBC_AUTH_SIZE].to_vec(),
                send_implicit_iv: keys.send_implicit_iv,
                recv_cipher_key: cut(&keys.recv_cipher_key),
                recv_hmac_key: keys.recv_hmac_key[..CBC_AUTH_SIZE].to_vec(),
                recv_implicit_iv: keys.recv_implicit_iv,
            },
            // OpenVPN 数据包 id 从 1 开始
            send_pid: 1,
            recv_window: ReplayWindow::new(),
            send_header,
        }
    }

    fn encrypt(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let pid = self.send_pid;
        self.send_pid = self.send_pid.wrapping_add(1);
        let pid_b = pid.to_be_bytes();
        if !self.cipher.is_aead() {
            return self.encrypt_cbc(pid, &pid_b, payload);
        }
        let nonce = nonce_from(pid, &self.keys.send_implicit_iv);
        // AAD：仅 V2（带 peer-id 的 4B 头）含头部；V1 只含 packet_id（与解密侧一致）
        let mut aad = Vec::with_capacity(self.send_header.len() + 4);
        if self.send_header.len() == 4 {
            aad.extend_from_slice(&self.send_header);
        }
        aad.extend_from_slice(&pid_b);
        let sealed = seal_with(
            &self.keys.send_cipher_key,
            self.cipher,
            &nonce,
            &aad,
            payload,
        )?;
        let mut out = Vec::with_capacity(self.send_header.len() + 4 + sealed.len());
        out.extend_from_slice(&self.send_header);
        out.extend_from_slice(&pid_b);
        // AEAD 密文布局：tag(16) 在前，密文在后
        let (ct, tag) = sealed.split_at(sealed.len() - TAG_SIZE);
        out.extend_from_slice(tag);
        out.extend_from_slice(ct);
        Ok(out)
    }

    /// CBC 数据信道：wire = header | HMAC-SHA1(20) | IV(16) | ciphertext；
    /// 明文 = packet_id(4) + 载荷 + PKCS7 填充（恒 ≥1 块），HMAC 覆盖 IV+密文
    fn encrypt_cbc(&mut self, _pid: u32, pid_b: &[u8; 4], payload: &[u8]) -> Result<Vec<u8>> {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;
        type HmacSha1 = Hmac<Sha1>;
        let plain_len = 4 + payload.len();
        let mut pad = CBC_BLOCK - plain_len % CBC_BLOCK;
        if pad == 0 {
            pad = CBC_BLOCK;
        }
        let mut pt = Vec::with_capacity(plain_len + pad);
        pt.extend_from_slice(pid_b);
        pt.extend_from_slice(payload);
        pt.resize(plain_len + pad, pad as u8);
        let mut iv = [0u8; CBC_BLOCK];
        rand_fill(&mut iv);
        let mut ct = pt;
        cbc_crypt(&self.keys.send_cipher_key, &iv, &mut ct);
        let mut authenticated = Vec::with_capacity(CBC_BLOCK + ct.len());
        authenticated.extend_from_slice(&iv);
        authenticated.extend_from_slice(&ct);
        let mut mac = <HmacSha1 as KeyInit>::new_from_slice(&self.keys.send_hmac_key)
            .map_err(|_| Error::Proto("openvpn: CBC HMAC key"))?;
        mac.update(&authenticated);
        let tag = mac.finalize().into_bytes();
        let mut out =
            Vec::with_capacity(self.send_header.len() + CBC_AUTH_SIZE + authenticated.len());
        out.extend_from_slice(&self.send_header);
        out.extend_from_slice(&tag[..CBC_AUTH_SIZE]);
        out.extend_from_slice(&authenticated);
        Ok(out)
    }

    /// 解密数据包；None = 重放/解密失败丢弃
    fn decrypt(&mut self, pkt: &[u8]) -> Option<Vec<u8>> {
        if pkt.is_empty() {
            return None;
        }
        let opcode = parse_opcode(pkt[0]);
        let header_size = match opcode {
            P_DATA_V2 => 4usize,
            P_DATA_V1 => 1usize,
            _ => return None,
        };
        if !self.cipher.is_aead() {
            return self.decrypt_cbc(pkt, header_size);
        }
        if pkt.len() < header_size + 4 + TAG_SIZE {
            return None;
        }
        let pid = u32::from_be_bytes([
            pkt[header_size],
            pkt[header_size + 1],
            pkt[header_size + 2],
            pkt[header_size + 3],
        ]);
        let nonce = nonce_from(pid, &self.keys.recv_implicit_iv);
        let mut aad = Vec::with_capacity(header_size + 4);
        if header_size == 4 {
            aad.extend_from_slice(&pkt[..header_size]);
        }
        aad.extend_from_slice(&pkt[header_size..header_size + 4]);
        // wire 布局：header | pid | tag(16) | ciphertext
        let tag = &pkt[header_size + 4..header_size + 4 + TAG_SIZE];
        let ct = &pkt[header_size + 4 + TAG_SIZE..];
        let mut sealed = Vec::with_capacity(ct.len() + TAG_SIZE);
        sealed.extend_from_slice(ct);
        sealed.extend_from_slice(tag);
        let plain = open_with(
            &self.keys.recv_cipher_key,
            self.cipher,
            &nonce,
            &aad,
            &sealed,
        )?;
        if !self.recv_window.accept(pid) {
            return None;
        }
        Some(plain)
    }

    /// CBC 解密：header | tag(20) | IV(16) | ciphertext → 校验 HMAC → CBC 解密 →
    /// PKCS7 去填充 → 校验 replay 窗口 → 去掉 4B packet_id
    fn decrypt_cbc(&mut self, pkt: &[u8], header_size: usize) -> Option<Vec<u8>> {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;
        type HmacSha1 = Hmac<Sha1>;
        let body = &pkt[header_size..];
        if body.len() < CBC_AUTH_SIZE + CBC_BLOCK * 2 {
            return None;
        }
        let tag = &body[..CBC_AUTH_SIZE];
        let authenticated = &body[CBC_AUTH_SIZE..];
        let mut mac = <HmacSha1 as KeyInit>::new_from_slice(&self.keys.recv_hmac_key).ok()?;
        mac.update(authenticated);
        let expect = mac.finalize().into_bytes();
        let mut diff = 0u8;
        for i in 0..CBC_AUTH_SIZE {
            diff |= tag[i] ^ expect[i];
        }
        if diff != 0 {
            return None;
        }
        let iv: [u8; CBC_BLOCK] = authenticated[..CBC_BLOCK].try_into().ok()?;
        let ct = &authenticated[CBC_BLOCK..];
        if ct.is_empty() || ct.len() % CBC_BLOCK != 0 {
            return None;
        }
        let mut plain = ct.to_vec();
        cbc_inv_crypt(&self.keys.recv_cipher_key, &iv, &mut plain);
        let pad = *plain.last()? as usize;
        if pad == 0 || pad > CBC_BLOCK || pad > plain.len() {
            return None;
        }
        if plain[plain.len() - pad..]
            .iter()
            .any(|b| *b as usize != pad)
        {
            return None;
        }
        plain.truncate(plain.len() - pad);
        if plain.len() < 4 {
            return None;
        }
        let pid = u32::from_be_bytes([plain[0], plain[1], plain[2], plain[3]]);
        if !self.recv_window.accept(pid) {
            return None;
        }
        Some(plain[4..].to_vec())
    }
}

/// AES-128/256-CBC 裸加密（无填充；data 长度须为 16 的倍数）
fn cbc_crypt(key: &[u8], iv: &[u8; CBC_BLOCK], data: &mut [u8]) {
    use aes::cipher::BlockEncrypt;
    use aes::cipher::generic_array::GenericArray;
    debug_assert!(data.len() % CBC_BLOCK == 0);
    let mut prev = *iv;
    for chunk in data.chunks_mut(CBC_BLOCK) {
        for (a, b) in chunk.iter_mut().zip(prev.iter()) {
            *a ^= b;
        }
        let block = GenericArray::from_mut_slice(chunk);
        if key.len() == 16 {
            <aes::Aes128 as KeyInit>::new_from_slice(key)
                .expect("aes-128 key")
                .encrypt_block(block);
        } else {
            <aes::Aes256 as KeyInit>::new_from_slice(key)
                .expect("aes-256 key")
                .encrypt_block(block);
        }
        prev.copy_from_slice(chunk);
    }
}

/// AES-128/256-CBC 裸解密
fn cbc_inv_crypt(key: &[u8], iv: &[u8; CBC_BLOCK], data: &mut [u8]) {
    use aes::cipher::BlockDecrypt;
    use aes::cipher::generic_array::GenericArray;
    debug_assert!(data.len() % CBC_BLOCK == 0);
    let mut prev = *iv;
    for chunk in data.chunks_mut(CBC_BLOCK) {
        let mut cur = [0u8; CBC_BLOCK];
        cur.copy_from_slice(chunk);
        let block = GenericArray::from_mut_slice(chunk);
        if key.len() == 16 {
            <aes::Aes128 as KeyInit>::new_from_slice(key)
                .expect("aes-128 key")
                .decrypt_block(block);
        } else {
            <aes::Aes256 as KeyInit>::new_from_slice(key)
                .expect("aes-256 key")
                .decrypt_block(block);
        }
        for (a, b) in chunk.iter_mut().zip(prev.iter()) {
            *a ^= b;
        }
        prev.copy_from_slice(&cur);
    }
}

// ---------------------------------------------------------------------------
// PUSH_REPLY 解析
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct PushReply {
    peer_id: Option<u32>,
    data_ciphers: Vec<String>,
    cipher: Option<String>,
    ifconfig_v4: Option<IpAddr>,
    continuation: Option<u8>,
}

fn parse_push_reply(msg: &str) -> Result<PushReply> {
    let mut r = PushReply::default();
    for opt in msg
        .trim_end_matches('\0')
        .strip_prefix("PUSH_REPLY")
        .ok_or(Error::Proto("openvpn: 非 PUSH_REPLY"))?
        .split(',')
    {
        let opt = opt.trim();
        if opt.is_empty() {
            continue;
        }
        let mut fields = opt.split_whitespace();
        let key = fields.next().unwrap_or("");
        match key {
            "peer-id" => {
                r.peer_id = Some(
                    fields
                        .next()
                        .and_then(|v| v.parse::<u32>().ok())
                        .filter(|id| *id <= PEER_ID_UNSET)
                        .ok_or(Error::Proto("openvpn: peer-id 非法"))?,
                );
            }
            "data-ciphers" | "ncp-ciphers" => {
                if let Some(v) = fields.next() {
                    r.data_ciphers = v.split(':').map(|c| c.trim().to_string()).collect();
                }
            }
            "cipher" => {
                r.cipher = fields.next().map(|v| v.trim().to_string());
            }
            "ifconfig" => {
                if let Some(v) = fields.next() {
                    if let Ok(ip) = v.parse::<IpAddr>() {
                        r.ifconfig_v4 = Some(ip);
                    }
                }
            }
            "push-continuation" => {
                if let Some(v) = fields.next() {
                    r.continuation = v.parse::<u8>().ok();
                }
            }
            _ => {}
        }
    }
    Ok(r)
}

// ---------------------------------------------------------------------------
// TLS 适配器（rustls ↔ 控制帧循环共享）
// ---------------------------------------------------------------------------

#[derive(Default)]
struct TlsAdapter {
    rx: std::sync::Mutex<VecDeque<u8>>,
    tx: std::sync::Mutex<VecDeque<u8>>,
}

impl std::io::Read for TlsAdapter {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut rx = self.rx.lock().unwrap();
        if rx.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "empty"));
        }
        let n = buf.len().min(rx.len());
        for slot in buf.iter_mut().take(n) {
            *slot = rx.pop_front().unwrap();
        }
        Ok(n)
    }
}

impl std::io::Write for TlsAdapter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.tx.lock().unwrap().extend(buf.iter().copied());
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// rustls StreamOwned 的 socket 侧包装（Arc 共享给帧循环）
#[derive(Clone)]
struct SharedAdapter(Arc<TlsAdapter>);

impl std::io::Read for SharedAdapter {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut rx = self.0.rx.lock().unwrap();
        if rx.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "empty"));
        }
        let n = buf.len().min(rx.len());
        for slot in buf.iter_mut().take(n) {
            *slot = rx.pop_front().unwrap();
        }
        Ok(n)
    }
}

impl std::io::Write for SharedAdapter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        ov_trace(format!("adapter write {}B", buf.len()));
        self.0.tx.lock().unwrap().extend(buf.iter().copied());
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 证书校验（信任下发 CA，校验链签名，不做主机名匹配）
// ---------------------------------------------------------------------------

/// 客户端证书是否全部为 rustls 可接受的现代版本（X.509 v3）
fn client_certs_modern(certs: &[rustls::pki_types::CertificateDer<'_>]) -> bool {
    use x509_parser::prelude::*;
    !certs.is_empty()
        && certs.iter().all(|c| {
            X509Certificate::from_der(c.as_ref())
                .map(|(_, c)| c.version().0 >= 2)
                .unwrap_or(false)
        })
}

#[derive(Debug)]
struct OvpnCertVerifier {
    cas: Vec<rustls::pki_types::CertificateDer<'static>>,
}

impl OvpnCertVerifier {
    fn verify_chain(
        &self,
        end: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
    ) -> bool {
        use x509_parser::prelude::*;
        let Ok((_, end_cert)) = X509Certificate::from_der(end.as_ref()) else {
            return false;
        };
        let mut issuer_certs: Vec<X509Certificate> = intermediates
            .iter()
            .filter_map(|c| X509Certificate::from_der(c.as_ref()).ok().map(|(_, c)| c))
            .collect();
        issuer_certs.extend(
            self.cas
                .iter()
                .filter_map(|c| X509Certificate::from_der(c.as_ref()).ok().map(|(_, c)| c)),
        );
        let ca_certs: Vec<X509Certificate> = self
            .cas
            .iter()
            .filter_map(|c| X509Certificate::from_der(c.as_ref()).ok().map(|(_, c)| c))
            .collect();
        issuer_certs.extend(ca_certs.iter().cloned());
        let mut current = end_cert;
        for _ in 0..8 {
            // 自签且主体匹配某个下发 CA：链终点
            if current.subject() == current.issuer() {
                return ca_certs.iter().any(|rc| rc.subject() == current.subject())
                    && current.verify_signature(None).is_ok();
            }
            let Some(issuer) = issuer_certs
                .iter()
                .find(|i| i.subject() == current.issuer())
            else {
                return false;
            };
            if current.verify_signature(Some(issuer.public_key())).is_err() {
                return false;
            }
            // 上一层即下发 CA（比较 subject + 公钥 DER，避免 DER 重编码差异）：链可信
            if ca_certs.iter().any(|rc| {
                rc.subject() == issuer.subject() && rc.public_key().raw == issuer.public_key().raw
            }) {
                return true;
            }
            current = issuer.clone();
        }
        false
    }
}

impl rustls::client::danger::ServerCertVerifier for OvpnCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _n: &rustls::pki_types::ServerName<'_>,
        _o: &[u8],
        _t: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if self.verify_chain(end_entity, intermediates) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "openvpn: 服务器证书未链到订阅下发的 CA".into(),
            ))
        }
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

// ---------------------------------------------------------------------------
// 控制信道会话状态
// ---------------------------------------------------------------------------

struct OvpnSession {
    local_sid: [u8; SID_SIZE],
    remote_sid: Option<[u8; SID_SIZE]>,
    /// 出站控制 msg_id（下一包）
    msg_id: u32,
    /// 服务器包 msg_id 待 ack 队列
    acks: VecDeque<u32>,
    last_ack_flush: std::time::Instant,
    /// 入站帧组装
    frames: FrameReader,
}

impl OvpnSession {
    fn new() -> Self {
        let mut sid = [0u8; SID_SIZE];
        rand_fill(&mut sid);
        OvpnSession {
            local_sid: sid,
            remote_sid: None,
            msg_id: 0,
            acks: VecDeque::new(),
            last_ack_flush: std::time::Instant::now(),
            frames: FrameReader::default(),
        }
    }

    fn take_acks(&mut self) -> Vec<u32> {
        let take = self.acks.len().min(ACK_MAX);
        self.acks.drain(..take).collect()
    }
}

fn rand_fill(buf: &mut [u8]) {
    use rand::RngCore;
    rand::rng().fill_bytes(buf);
}

// ---------------------------------------------------------------------------
// 握手（reset → TLS → KM2 → PUSH）
// ---------------------------------------------------------------------------

struct OvpnParams {
    server_ip: IpAddr,
    sni: Option<String>,
    username: String,
    password: String,
    ca_pem: Vec<u8>,
    cert_pem: Option<Vec<u8>>,
    key_pem: Option<Vec<u8>>,
    cipher: String,
}

#[allow(clippy::needless_late_init)]
async fn handshake(
    tcp: &mut tokio::net::TcpStream,
    params: &OvpnParams,
    adapter: Arc<TlsAdapter>,
    session: &mut OvpnSession,
) -> Result<(DataCrypt, Ipv4Addr)> {
    let deadline = std::time::Instant::now() + HANDSHAKE_TIMEOUT;

    // 1. 客户端硬重置（msg_id 0、无载荷）
    let reset = encode_control(
        P_CONTROL_HARD_RESET_CLIENT_V2,
        0,
        &session.local_sid,
        &[],
        None,
        0,
        &[],
    );
    write_frame(tcp, &reset).await?;
    // 硬重置占用 msg_id 0；下一控制包从 1 起
    session.msg_id = 1;
    ov_trace("reset sent");

    // 2. rustls 配置（下发 CA 链校验 + 可选客户端证书）
    let cas = rustls_pemfile::certs(&mut &params.ca_pem[..])
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Config(format!("openvpn CA PEM: {e}")))?;
    if cas.is_empty() {
        return Err(Error::Config("openvpn: CA PEM 无证书".into()));
    }
    let verifier = Arc::new(OvpnCertVerifier { cas: cas.clone() });
    let mut roots = rustls::RootCertStore::empty();
    for c in &cas {
        let _ = roots.add(c.clone());
    }
    let builder = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let tls_cfg = if let (Some(cert_pem), Some(key_pem)) = (&params.cert_pem, &params.key_pem) {
        let certs = rustls_pemfile::certs(&mut &cert_pem[..])
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Config(format!("openvpn 客户端证书 PEM: {e}")))?;
        let key = rustls_pemfile::private_key(&mut &key_pem[..])
            .map_err(|e| Error::Config(format!("openvpn 客户端私钥 PEM: {e}")))?
            .ok_or_else(|| Error::Config("openvpn: 缺客户端私钥".into()))?;
        if client_certs_modern(&certs) {
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| Error::Config(format!("openvpn 客户端证书装配: {e}")))?
        } else {
            // VPN Gate / SoftEther 下发的哑客户端证书为 X.509 v1（rustls 拒收），
            // 服务器并不校验客户端证书，直接降级为无证书
            ov_trace("client cert is X.509 v1 dummy -> no client auth");
            builder.with_no_client_auth()
        }
    } else {
        builder.with_no_client_auth()
    };
    let sni: rustls::pki_types::ServerName<'static> = match &params.sni {
        Some(s) => rustls::pki_types::ServerName::try_from(s.clone())
            .map_err(|_| Error::Config("openvpn: sni 非法".into()))?,
        None => rustls::pki_types::ServerName::IpAddress(rustls::pki_types::IpAddr::from(
            params.server_ip,
        )),
    };
    let conn = rustls::ClientConnection::new(Arc::new(tls_cfg), sni)
        .map_err(|e| Error::Config(format!("openvpn TLS 配置: {e}")))?;
    let mut tls = rustls::StreamOwned::new(conn, SharedAdapter(adapter.clone()));

    // 3. TLS 握手（帧循环驱动）
    while tls.conn.is_handshaking() {
        if std::time::Instant::now() > deadline {
            return Err(Error::Proto("openvpn: TLS 握手超时"));
        }
        match stream_complete_io(&mut tls) {
            Ok(moved) => {
                if moved > 0 {
                    ov_trace(format!("tls io moved={moved}"));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => {
                return Err(Error::Io(std::io::Error::other(format!(
                    "openvpn TLS: {e}"
                ))));
            }
        }
        flush_tls_out(tcp, session, &adapter).await?;
        if !tls.conn.is_handshaking() {
            break;
        }
        if tokio::time::timeout(std::time::Duration::from_millis(1), tcp.readable())
            .await
            .is_ok()
        {
            let Some(pkt) = session.frames.read_frame(tcp).await? else {
                continue;
            };
            let c = decode_control(&pkt)?;
            ov_trace(format!(
                "inbound op={} payload={}",
                c.opcode,
                c.payload.len()
            ));
            if let Some(id) = c.msg_id {
                session.acks.push_back(id);
            }
            if session.remote_sid.is_none() {
                session.remote_sid = Some(c.session_id);
            }
            match c.opcode {
                P_CONTROL_V1 => {
                    adapter.rx.lock().unwrap().extend(c.payload.iter().copied());
                }
                P_CONTROL_HARD_RESET_SERVER_V2 => {
                    session.remote_sid = Some(c.session_id);
                }
                _ => {}
            }
            flush_acks(tcp, session).await?;
        }
    }

    // 4. Key Method v2（凭据内嵌记录；KM2 后随 PUSH_REQUEST）
    let (pre_master, random1, random2) = gen_km2_randoms();
    let options = options_string(&params.cipher);
    let peer_info = peer_info_string(&params.cipher);
    let record = build_km2_client(
        &options,
        &peer_info,
        &params.username,
        &params.password,
        &pre_master,
        &random1,
        &random2,
    );
    std::io::Write::write_all(&mut tls, &record)
        .map_err(|e| Error::Io(std::io::Error::other(format!("openvpn KM2 写入: {e}"))))?;
    ov_trace(format!("km2 record written ({}B)", record.len()));
    let req = format!("{PUSH_REQUEST}\0");
    std::io::Write::write_all(&mut tls, req.as_bytes())
        .map_err(|e| Error::Io(std::io::Error::other(format!("openvpn PUSH 写入: {e}"))))?;

    // 5. 读服务器 KM2 + PUSH_REPLY（AUTH_PENDING 期间持续读；PUSH_REQUEST 重发）
    let mut km2_buf: Vec<u8> = Vec::new();
    let mut server_km2: Option<ServerKm2> = None;
    let mut push: Option<PushReply> = None;
    let mut last_push_req = std::time::Instant::now();
    while push.is_none() {
        if std::time::Instant::now() > deadline {
            return Err(Error::Proto("openvpn: KM2/PUSH 超时"));
        }
        // 把 KM2/PUSH_REQUEST 的 TLS 记录发出去（阶段 3 循环已退出，此处自驱动）
        flush_tls_out(tcp, session, &adapter).await?;
        let mut tmp = [0u8; 8192];
        match std::io::Read::read(&mut tls, &mut tmp) {
            Ok(0) => {
                // 无明文：驱动帧 IO
                drive_inbound(tcp, session, &adapter).await?;
            }
            Ok(n) => {
                if server_km2.is_none() {
                    km2_buf.extend_from_slice(&tmp[..n]);
                    match parse_km2_server(&km2_buf) {
                        Ok((km2, consumed)) => {
                            ov_trace(format!(
                                "server km2 parsed ({consumed}B, trailing {})",
                                km2.trailing.len()
                            ));
                            server_km2 = Some(km2);
                            // 记录后残余 → 消息缓冲
                            km2_buf.drain(..consumed);
                        }
                        Err(_) => continue, // 不完整 → 继续
                    }
                } else {
                    km2_buf.extend_from_slice(&tmp[..n]);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                drive_inbound(tcp, session, &adapter).await?;
            }
            Err(e) => {
                return Err(Error::Io(std::io::Error::other(format!(
                    "openvpn 读取: {e}"
                ))));
            }
        }
        if server_km2.is_none() {
            continue;
        }
        // 处理 NUL 帧控制消息
        let mut consumed = 0usize;
        for msg in km2_buf.split_inclusive(|b| *b == 0) {
            let s = String::from_utf8_lossy(msg);
            let s = s.trim_end_matches('\0');
            consumed += msg.len();
            ov_trace(format!("ctrl msg: {s}"));
            if s.starts_with("PUSH_REPLY") {
                let r = parse_push_reply(s)?;
                if r.continuation == Some(2) {
                    // 多段推送：再发一次 PUSH_REQUEST 续取
                    let req = format!("{PUSH_REQUEST}\0");
                    std::io::Write::write_all(&mut tls, req.as_bytes()).map_err(|e| {
                        Error::Io(std::io::Error::other(format!("openvpn PUSH 写入: {e}")))
                    })?;
                    // 合并前段字段：只保留首段缺项（peer-id/cipher 通常在末段）
                    let prev = push.replace(r);
                    push = prev;
                    // 语义：继续读下一段后合并 —— 用字段合并方式
                    // （简单策略：保留已有非空字段）
                } else {
                    push = Some(match push.take() {
                        Some(prev) => merge_push(prev, r),
                        None => r,
                    });
                }
            } else if s.starts_with("AUTH_PENDING") {
                tracing::debug!("openvpn: AUTH_PENDING（继续等待推送）");
            } else if s.starts_with("AUTH_FAILED")
                || s.starts_with("RESTART")
                || s.starts_with("HALT")
                || s.starts_with("EXIT")
            {
                return Err(Error::ProtoMsg(format!("openvpn: 认证/会话失败: {s}")));
            }
        }
        if consumed > 0 {
            km2_buf.drain(..consumed);
        }
        if push.is_none()
            && last_push_req.elapsed() >= std::time::Duration::from_secs(5)
            && server_km2.is_some()
        {
            let req = format!("{PUSH_REQUEST}\0");
            std::io::Write::write_all(&mut tls, req.as_bytes())
                .map_err(|e| Error::Io(std::io::Error::other(format!("openvpn PUSH 写入: {e}"))))?;
            last_push_req = std::time::Instant::now();
        }
        flush_tls_out(tcp, session, &adapter).await?;
    }
    let push = push.unwrap();
    let local_ip = match push.ifconfig_v4 {
        Some(IpAddr::V4(v4)) => v4,
        _ => return Err(Error::Proto("openvpn: 推送缺少 ifconfig 隧道地址")),
    };

    // 6. 协商数据密码 + 派生密钥
    let server_km2 = server_km2.unwrap();
    let km2_keys = derive_keys(
        &pre_master,
        &random1,
        &random2,
        &server_km2.random1,
        &server_km2.random2,
        &session.local_sid,
        session
            .remote_sid
            .as_ref()
            .ok_or(Error::Proto("openvpn: 缺服务器 session-id"))?,
    );
    let cipher = push
        .data_ciphers
        .iter()
        .find_map(|c| DataCipher::parse(c))
        .or_else(|| push.cipher.as_deref().and_then(DataCipher::parse))
        .or_else(|| DataCipher::parse(&params.cipher))
        .ok_or(Error::Proto(
            "openvpn: 无支持的数据密码（仅支持 GCM/ChaCha20/CBC）",
        ))?;
    let crypt = DataCrypt::new(cipher, &km2_keys, push.peer_id, 0);
    Ok((crypt, local_ip))
}

/// 合并多段 PUSH_REPLY（后段覆盖未设字段）
fn merge_push(prev: PushReply, next: PushReply) -> PushReply {
    PushReply {
        peer_id: next.peer_id.or(prev.peer_id),
        data_ciphers: if next.data_ciphers.is_empty() {
            prev.data_ciphers
        } else {
            next.data_ciphers
        },
        cipher: next.cipher.or(prev.cipher),
        ifconfig_v4: next.ifconfig_v4.or(prev.ifconfig_v4),
        continuation: next.continuation,
    }
}

/// options 字符串（对齐官方 installscript 语义：V4 + tun + mtu + proto + cipher + key-method 2）
fn options_string(cipher: &str) -> String {
    let keysize = match DataCipher::parse(cipher) {
        Some(DataCipher::Aes128Gcm) | Some(DataCipher::Aes128Cbc) => 128,
        _ => 256,
    };
    format!(
        "V4,dev-type tun,link-mtu 1550,tun-mtu 1500,proto TCPv4_CLIENT,cipher {cipher},auth SHA1,keysize {keysize},key-method 2,tls-client"
    )
}

/// peer-info 字符串：IV_PROTO = DATA_V2(1<<1) | REQUEST_PUSH(1<<2) | AUTH_PENDING(1<<4)
fn peer_info_string(cipher: &str) -> String {
    let ciphers = match DataCipher::parse(cipher) {
        Some(c) => match c {
            DataCipher::Aes128Gcm => "AES-128-GCM",
            DataCipher::Aes256Gcm => "AES-256-GCM:AES-128-GCM",
            DataCipher::ChaCha20Poly1305 => "CHACHA20-POLY1305",
            DataCipher::Aes128Cbc => "AES-128-CBC",
            DataCipher::Aes256Cbc => "AES-256-CBC:AES-128-CBC:AES-256-GCM:AES-128-GCM",
        },
        None => "AES-256-GCM:AES-128-GCM",
    };
    format!("IV_VER=vproxy-openvpn\nIV_PROTO=22\nIV_CIPHERS={ciphers}\n")
}

fn gen_km2_randoms() -> (
    [u8; KEY_SOURCE_PRE_MASTER_SIZE],
    [u8; KEY_SOURCE_RANDOM_SIZE],
    [u8; KEY_SOURCE_RANDOM_SIZE],
) {
    let mut pm = [0u8; KEY_SOURCE_PRE_MASTER_SIZE];
    let mut r1 = [0u8; KEY_SOURCE_RANDOM_SIZE];
    let mut r2 = [0u8; KEY_SOURCE_RANDOM_SIZE];
    rand_fill(&mut pm);
    rand_fill(&mut r1);
    rand_fill(&mut r2);
    (pm, r1, r2)
}

/// rustls Stream 的同步 complete_io（适配器 WouldBlock 即停）
fn stream_complete_io(
    tls: &mut rustls::StreamOwned<rustls::ClientConnection, SharedAdapter>,
) -> std::io::Result<usize> {
    let (r, w) = tls.conn.complete_io(&mut tls.sock)?;
    ov_trace(format!("complete_io out r={r} w={w}"));
    Ok(r + w)
}

/// 把 TLS 待发字节分块成 P_CONTROL_V1 发出（附带 ACK）
async fn flush_tls_out(
    tcp: &mut tokio::net::TcpStream,
    session: &mut OvpnSession,
    adapter: &Arc<TlsAdapter>,
) -> Result<()> {
    loop {
        let chunk = {
            let mut tx = adapter.tx.lock().unwrap();
            if tx.is_empty() {
                break;
            }
            let n = tx.len().min(MAX_CONTROL_PAYLOAD);
            let mut buf = Vec::with_capacity(n);
            for _ in 0..n {
                buf.push(tx.pop_front().unwrap());
            }
            buf
        };
        let acks = session.take_acks();
        let pkt = encode_control(
            P_CONTROL_V1,
            0,
            &session.local_sid,
            &acks,
            session.remote_sid.as_ref(),
            session.msg_id,
            &chunk,
        );
        session.msg_id = session.msg_id.wrapping_add(1);
        write_frame(tcp, &pkt).await?;
        session.last_ack_flush = std::time::Instant::now();
    }
    if session.last_ack_flush.elapsed() >= ACK_FLUSH && !session.acks.is_empty() {
        let acks = session.take_acks();
        let pkt = encode_control(
            P_ACK_V1,
            0,
            &session.local_sid,
            &acks,
            session.remote_sid.as_ref(),
            0,
            &[],
        );
        write_frame(tcp, &pkt).await?;
        session.last_ack_flush = std::time::Instant::now();
    }
    Ok(())
}

/// 等待并处理一帧入站（TLS 阶段）
/// 独立 ACK 帧：无 TLS 载荷可捎带时及时确认对端控制包（SoftEther 等严格等待 ACK）
async fn flush_acks(tcp: &mut tokio::net::TcpStream, session: &mut OvpnSession) -> Result<()> {
    let acks = session.take_acks();
    if acks.is_empty() {
        return Ok(());
    }
    let pkt = encode_control(
        P_ACK_V1,
        0,
        &session.local_sid,
        &acks,
        session.remote_sid.as_ref(),
        0,
        &[],
    );
    write_frame(tcp, &pkt).await?;
    Ok(())
}

async fn drive_inbound(
    tcp: &mut tokio::net::TcpStream,
    session: &mut OvpnSession,
    adapter: &Arc<TlsAdapter>,
) -> Result<()> {
    if tokio::time::timeout(std::time::Duration::from_millis(1), tcp.readable())
        .await
        .is_err()
    {
        return Ok(());
    }
    let Some(pkt) = session.frames.read_frame(tcp).await? else {
        return Ok(());
    };
    let c = decode_control(&pkt)?;
    ov_trace(format!(
        "inbound op={} payload={}",
        c.opcode,
        c.payload.len()
    ));
    if let Some(id) = c.msg_id {
        session.acks.push_back(id);
    }
    if session.remote_sid.is_none() {
        session.remote_sid = Some(c.session_id);
    }
    if c.opcode == P_CONTROL_V1 {
        adapter.rx.lock().unwrap().extend(c.payload.iter().copied());
    }
    flush_acks(tcp, session).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// smoltcp 队列设备（与 wireguard 同构）
// ---------------------------------------------------------------------------

struct SharedQueues {
    /// 解密后待栈处理的 IP 包
    rx: std::sync::Mutex<std::collections::VecDeque<Vec<u8>>>,
    /// 栈发出待加密的 IP 包
    tx: std::sync::Mutex<std::collections::VecDeque<Vec<u8>>>,
}

struct QueueDevice {
    q: Arc<SharedQueues>,
}

struct OvpnRxToken(Vec<u8>);
impl RxToken for OvpnRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.0)
    }
}

struct OvpnTxToken<'a>(&'a Arc<SharedQueues>);
impl TxToken for OvpnTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.tx.lock().unwrap().push_back(buf);
        r
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = OvpnRxToken;
    type TxToken<'a> = OvpnTxToken<'a>;

    fn receive(&mut self, _t: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.q.rx.lock().unwrap().pop_front()?;
        Some((OvpnRxToken(pkt), OvpnTxToken(&self.q)))
    }

    fn transmit(&mut self, _t: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(OvpnTxToken(&self.q))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU as usize;
        caps.checksum = smoltcp::phy::ChecksumCapabilities::ignored();
        caps
    }
}

type SessionInner = Result<(mpsc::Receiver<UpMsg>, mpsc::Sender<DownMsg>)>;
type SessionReply = tokio::sync::oneshot::Sender<SessionInner>;

enum Cmd {
    Connect {
        dst: SocketAddr,
        reply: SessionReply,
    },
    ConnectUdp {
        reply: tokio::sync::oneshot::Sender<Result<(mpsc::Receiver<UpMsg>, mpsc::Sender<DownMsg>)>>,
    },
}

/// 栈→应用消息（TCP 数据流 / UDP 数据报）
enum UpMsg {
    Tcp(Bytes),
    Udp { src: SocketAddr, data: Bytes },
}

/// 应用→栈消息
enum DownMsg {
    Tcp(Vec<u8>),
    Udp { dst: SocketAddr, data: Vec<u8> },
}

enum SessKind {
    Tcp {
        handle: SocketHandle,
        pending: Option<Vec<u8>>,
    },
    Udp {
        handle: SocketHandle,
    },
}

struct Sess {
    kind: SessKind,
    up_tx: mpsc::Sender<UpMsg>,
    down_rx: mpsc::Receiver<DownMsg>,
    closed: bool,
}

// ---------------------------------------------------------------------------
// 隧道任务：握手 + 数据中继
// ---------------------------------------------------------------------------

async fn tunnel_task(
    mut tcp: tokio::net::TcpStream,
    params: OvpnParams,
    q: Arc<SharedQueues>,
    cmd_rx: mpsc::Receiver<Cmd>,
    ready: oneshot::Sender<Result<Ipv4Addr>>,
) {
    let mut session = OvpnSession::new();
    let adapter = Arc::new(TlsAdapter::default());
    let (mut crypt, local_v4) =
        match handshake(&mut tcp, &params, adapter.clone(), &mut session).await {
            Ok((crypt, local_ip)) => (crypt, local_ip),
            Err(e) => {
                let _ = ready.send(Err(e));
                return;
            }
        };
    let _ = ready.send(Ok(local_v4));

    // 栈任务就绪后开始处理连接命令
    let (stack_ready_tx, stack_ready_rx) = oneshot::channel::<()>();
    tokio::spawn(stack_task(cmd_rx, q.clone(), local_v4, stack_ready_tx));

    let mut ping_tick = tokio::time::interval(PING_INTERVAL);
    ping_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut drain_tick = tokio::time::interval(TICK);
    drain_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut ack_tick = tokio::time::interval(ACK_FLUSH);
    ack_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let _ = stack_ready_rx.await;
    loop {
        tokio::select! {
            pkt = session.frames.read_frame(&mut tcp) => {
                let pkt = match pkt {
                    Ok(Some(p)) => p,
                    Ok(None) => continue,
                    Err(e) => {
                        ov_trace(format!("tunnel end: {e}"));
                        break;
                    }
                };
                let opcode = parse_opcode(pkt.first().copied().unwrap_or(0));
                match opcode {
                    P_DATA_V1 | P_DATA_V2 => {
                        match crypt.decrypt(&pkt) {
                            Some(ip) => {
                                if ip == PING_MAGIC[..] {
                                    ov_trace("ping in");
                                    continue;
                                }
                                ov_trace(format!("data in {}B", ip.len()));
                                q.rx.lock().unwrap().push_back(ip);
                            }
                            None => {
                                ov_trace(format!("data in decrypt FAIL op={} len={}", opcode, pkt.len()))
                            }
                        }
                    }
                    P_CONTROL_V1 | P_ACK_V1 | P_CONTROL_SOFT_RESET_V1 | P_CONTROL_HARD_RESET_SERVER_V2 => {
                        let Ok(c) = decode_control(&pkt) else { continue };
                        if let Some(id) = c.msg_id {
                            session.acks.push_back(id);
                        }
                        // 软重置：MVP 保留旧密钥（ack 由下一包/定时器携带）
                        ov_trace(format!("ctrl in data-phase opcode={opcode}"));
                    }
                    _ => {}
                }
            }
            _ = drain_tick.tick() => {
                // 栈 → 加密 → 帧
                let to_send: Vec<Vec<u8>> = {
                    let mut tx = q.tx.lock().unwrap();
                    let n = tx.len();
                    (0..n).filter_map(|_| tx.pop_front()).collect()
                };
                for ip in to_send {
                    match crypt.encrypt(&ip) {
                        Ok(pkt) => {
                            ov_trace(format!("data out {}B", ip.len()));
                            if write_frame(&mut tcp, &pkt).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::debug!("openvpn 加密失败: {e}");
                        }
                    }
                }
            }
            _ = ping_tick.tick() => {
                if let Ok(pkt) = crypt.encrypt(&PING_MAGIC) {
                    let _ = write_frame(&mut tcp, &pkt).await;
                }
            }
            _ = ack_tick.tick() => {
                if !session.acks.is_empty() {
                    let acks = session.take_acks();
                    let pkt = encode_control(
                        P_ACK_V1,
                        0,
                        &session.local_sid,
                        &acks,
                        session.remote_sid.as_ref(),
                        0,
                        &[],
                    );
                    let _ = write_frame(&mut tcp, &pkt).await;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 栈任务（smoltcp + 会话泵 + 连接命令）
// ---------------------------------------------------------------------------

async fn stack_task(
    mut cmd_rx: mpsc::Receiver<Cmd>,
    q: Arc<SharedQueues>,
    local_v4: std::net::Ipv4Addr,
    ready: oneshot::Sender<()>,
) {
    let iface_v4 = IpCidr::Ipv4(smoltcp::wire::Ipv4Cidr::new(local_v4.into(), 32));
    let mut config = IfaceConfig::new(smoltcp::wire::HardwareAddress::Ip);
    config.random_seed = vp_common::now_millis();
    let mut device = QueueDevice { q: q.clone() };
    let mut iface = Interface::new(config, &mut device, SmolInstant::from_millis(0));
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(iface_v4);
    });
    let mut sockets = SocketSet::new(vec![]);
    let mut sessions: HashMap<u64, Sess> = HashMap::new();
    let mut next_sess_id: u64 = 1;
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let _ = ready.send(());
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break };
                match cmd {
                    Cmd::Connect { dst, reply } => {
                        let r = connect_session(
                            &mut iface, &mut sockets, &mut sessions,
                            &mut next_sess_id, local_v4, dst,
                        );
                        let _ = reply.send(r);
                    }
                    Cmd::ConnectUdp { reply } => {
                        let r = connect_udp_session(&mut sockets, &mut sessions, &mut next_sess_id);
                        let _ = reply.send(r);
                    }
                }
            }
            _ = tick.tick() => {
                let ts = SmolInstant::from_millis(vp_common::now_millis() as i64);
                let _ = iface.poll(ts, &mut device, &mut sockets);
                pump_sessions(&mut sockets, &mut sessions);
            }
        }
    }
}

fn connect_session(
    iface: &mut Interface,
    sockets: &mut SocketSet<'_>,
    sessions: &mut HashMap<u64, Sess>,
    next_sess_id: &mut u64,
    local_v4: std::net::Ipv4Addr,
    dst: SocketAddr,
) -> SessionInner {
    let IpAddr::V4(dst_v4) = dst.ip() else {
        return Err(Error::Config("openvpn 隧道暂仅支持 IPv4 目标".into()));
    };
    iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address(dst_v4.octets()))
        .ok();
    let local = IpEndpoint::new(local_v4.into(), next_local_port());
    let remote = IpEndpoint::from(dst);
    let rx_buf = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
    let tx_buf = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
    let mut sock = tcp::Socket::new(rx_buf, tx_buf);
    sock.set_nagle_enabled(false);
    if let Err(e) = sock.connect(iface.context(), remote, local) {
        return Err(Error::ProtoMsg(format!("openvpn 栈 connect: {:?}", e)));
    }
    let handle = sockets.add(sock);
    let (up_tx, up_rx) = mpsc::channel::<UpMsg>(CHAN_CAP);
    let (down_tx, down_rx) = mpsc::channel::<DownMsg>(CHAN_CAP);
    let id = *next_sess_id;
    *next_sess_id += 1;
    sessions.insert(
        id,
        Sess {
            kind: SessKind::Tcp {
                handle,
                pending: None,
            },
            up_tx,
            down_rx,
            closed: false,
        },
    );
    Ok((up_rx, down_tx))
}

fn connect_udp_session(
    sockets: &mut SocketSet<'_>,
    sessions: &mut HashMap<u64, Sess>,
    next_sess_id: &mut u64,
) -> SessionInner {
    let rx_buf = smoltcp::socket::udp::PacketBuffer::new(
        vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 64],
        vec![0u8; SOCK_BUF],
    );
    let tx_buf = smoltcp::socket::udp::PacketBuffer::new(
        vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 64],
        vec![0u8; SOCK_BUF],
    );
    let mut sock = smoltcp::socket::udp::Socket::new(rx_buf, tx_buf);
    let local_port = next_local_port();
    if let Err(e) = sock.bind(local_port) {
        return Err(Error::ProtoMsg(format!("openvpn 栈 udp bind: {:?}", e)));
    }
    let handle = sockets.add(sock);
    let (up_tx, up_rx) = mpsc::channel::<UpMsg>(CHAN_CAP);
    let (down_tx, down_rx) = mpsc::channel::<DownMsg>(CHAN_CAP);
    let id = *next_sess_id;
    *next_sess_id += 1;
    sessions.insert(
        id,
        Sess {
            kind: SessKind::Udp { handle },
            up_tx,
            down_rx,
            closed: false,
        },
    );
    Ok((up_rx, down_tx))
}

fn next_local_port() -> u16 {
    static LOCAL_PORT_SEQ: AtomicU64 = AtomicU64::new(0);
    (20000 + LOCAL_PORT_SEQ.fetch_add(1, Ordering::Relaxed) % 40000) as u16
}

/// 会话泵：应用下行 → socket 缓冲；socket 上行 → 应用通道；收尾清理
fn pump_sessions(sockets: &mut SocketSet<'_>, sessions: &mut HashMap<u64, Sess>) {
    let mut reaped: Vec<u64> = Vec::new();
    for (id, sess) in sessions.iter_mut() {
        match &mut sess.kind {
            SessKind::Udp { handle } => {
                let sock = sockets.get_mut::<smoltcp::socket::udp::Socket>(*handle);
                loop {
                    if !sock.can_send() {
                        break;
                    }
                    match sess.down_rx.try_recv() {
                        Ok(DownMsg::Udp { dst, data }) => {
                            let remote = IpEndpoint::from(dst);
                            if let Err(e) = sock.send_slice(&data, remote) {
                                tracing::warn!("openvpn udp send_slice: {e:?}");
                            }
                        }
                        _ => break,
                    }
                }
                if sess.up_tx.capacity() > 0 {
                    let mut buf = [0u8; 64 * 1024];
                    loop {
                        match sock.recv_slice(&mut buf) {
                            Ok((0, _)) => break,
                            Ok((n, meta)) => {
                                let src = endpoint_to_std(meta.endpoint);
                                let msg = UpMsg::Udp {
                                    src,
                                    data: Bytes::copy_from_slice(&buf[..n]),
                                };
                                if sess.up_tx.try_send(msg).is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
            SessKind::Tcp { handle, pending } => {
                let sock = sockets.get_mut::<tcp::Socket>(*handle);
                // 应用 → 栈
                if let Some(backlog) = pending.take() {
                    match sock.send_slice(&backlog) {
                        Ok(n) if n < backlog.len() => {
                            *pending = Some(backlog[n..].to_vec());
                        }
                        _ => {}
                    }
                }
                loop {
                    if !sock.can_send() {
                        break;
                    }
                    match sess.down_rx.try_recv() {
                        Ok(DownMsg::Tcp(data)) => match sock.send_slice(&data) {
                            Ok(n) if n < data.len() => {
                                *pending = Some(data[n..].to_vec());
                                break;
                            }
                            _ => {}
                        },
                        Ok(DownMsg::Udp { .. }) => continue,
                        _ => break,
                    }
                }
                if sess.closed && sock.send_queue() == 0 {
                    sock.close();
                }
                // 对端关闭 → 冲刷残余数据后通知应用 EOF
                if sock.may_recv() {
                    if sess.up_tx.capacity() > 0 {
                        let mut buf = [0u8; 64 * 1024];
                        loop {
                            match sock.recv_slice(&mut buf) {
                                Ok(0) => {
                                    if !sess.closed && !sock.can_recv() {
                                        sess.closed = true;
                                    }
                                    break;
                                }
                                Ok(n) => {
                                    if sess
                                        .up_tx
                                        .try_send(UpMsg::Tcp(Bytes::copy_from_slice(&buf[..n])))
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    }
                } else if !sess.closed
                    // SynSent：握手仍在进行，不能立即判死
                    && sock.state() != smoltcp::socket::tcp::State::SynSent
                {
                    sess.closed = true;
                    let _ = sess.up_tx.try_send(UpMsg::Tcp(Bytes::new()));
                }
                if sess.closed && sock.state() == smoltcp::socket::tcp::State::Closed {
                    reaped.push(*id);
                }
            }
        }
    }
    for id in reaped {
        if let Some(s) = sessions.remove(&id) {
            match s.kind {
                SessKind::Tcp { handle, .. } | SessKind::Udp { handle } => {
                    sockets.remove(handle);
                }
            }
        }
    }
}

/// smoltcp IpEndpoint → std SocketAddr
fn endpoint_to_std(ep: IpEndpoint) -> SocketAddr {
    match ep.addr {
        IpAddress::Ipv4(v4) => SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(v4.0)),
            ep.port,
        ),
        IpAddress::Ipv6(v6) => SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(v6.0)),
            ep.port,
        ),
    }
}

// ---------------------------------------------------------------------------
// 出站
// ---------------------------------------------------------------------------

/// OpenVPN 隧道核心（一节点一实例，多连接复用）
pub struct OpenVpnCore {
    cmd_tx: mpsc::Sender<Cmd>,
    local_v4: std::net::Ipv4Addr,
}

pub struct OpenVpnOutbound {
    name: Arc<str>,
    server: String,
    port: u16,
    params: OvpnParams,
    udp: bool,
    session: Mutex<Option<Arc<OpenVpnCore>>>,
}

impl OpenVpnOutbound {
    pub fn new(cfg: &vp_config::OpenVpnCfg) -> Result<Self> {
        let proto = cfg.proto.as_deref().unwrap_or("tcp").to_ascii_lowercase();
        if proto.starts_with("udp") {
            return Err(Error::Config(
                "openvpn: 暂仅支持 proto tcp（UDP 控制信道未实现）".into(),
            ));
        }
        if !cfg.ca.contains("BEGIN CERTIFICATE") {
            return Err(Error::Config("openvpn: ca 不是 PEM 证书".into()));
        }
        let cert_pem = cfg
            .cert
            .as_deref()
            .filter(|s| s.contains("BEGIN CERTIFICATE"))
            .map(|s| s.as_bytes().to_vec());
        let key_pem = cfg
            .key
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.as_bytes().to_vec());
        Ok(OpenVpnOutbound {
            name: "openvpn".into(),
            server: cfg.server.clone(),
            port: cfg.port,
            params: OvpnParams {
                server_ip: "0.0.0.0".parse().unwrap(), // 连接时按解析地址填充
                sni: None,
                username: cfg.username.clone().unwrap_or_default(),
                password: cfg.password.clone().unwrap_or_default(),
                ca_pem: cfg.ca.as_bytes().to_vec(),
                cert_pem,
                key_pem,
                cipher: cfg.cipher.clone().unwrap_or_else(|| "AES-256-GCM".into()),
            },
            udp: cfg.udp,
            session: Mutex::new(None),
        })
    }

    async fn get_or_connect(&self) -> Result<Arc<OpenVpnCore>> {
        let mut guard = self.session.lock().await;
        if let Some(ref s) = *guard {
            return Ok(s.clone());
        }
        let addrs = vp_transport::resolve_node_addrs(&self.server, self.port).await?;
        let mut last_err = Error::Proto("openvpn: 无可用地址");
        for addr in &addrs {
            let tcp = match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                tokio::net::TcpStream::connect(addr),
            )
            .await
            {
                Ok(Ok(t)) => t,
                Ok(Err(e)) => {
                    last_err = Error::Io(std::io::Error::other(format!("openvpn 拨号: {e}")));
                    continue;
                }
                Err(_) => {
                    last_err = Error::Proto("openvpn: 拨号超时");
                    continue;
                }
            };
            let server_ip = addr.ip();
            let params = OvpnParams {
                server_ip,
                sni: self.params.sni.clone(),
                username: self.params.username.clone(),
                password: self.params.password.clone(),
                ca_pem: self.params.ca_pem.clone(),
                cert_pem: self.params.cert_pem.clone(),
                key_pem: self.params.key_pem.clone(),
                cipher: self.params.cipher.clone(),
            };
            let q = Arc::new(SharedQueues {
                rx: std::sync::Mutex::new(VecDeque::new()),
                tx: std::sync::Mutex::new(VecDeque::new()),
            });
            let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>(16);
            let (ready_tx, ready_rx) = oneshot::channel::<Result<std::net::Ipv4Addr>>();
            tokio::spawn(tunnel_task(tcp, params, q.clone(), cmd_rx, ready_tx));
            let local_v4 = match tokio::time::timeout(HANDSHAKE_TIMEOUT, ready_rx).await {
                Ok(Ok(Ok(v4))) => v4,
                Ok(Ok(Err(e))) => {
                    last_err = e;
                    continue;
                }
                Ok(Err(_)) | Err(_) => {
                    last_err = Error::Proto("openvpn: 握手超时");
                    continue;
                }
            };
            let core = Arc::new(OpenVpnCore { cmd_tx, local_v4 });
            *guard = Some(core.clone());
            return Ok(core);
        }
        Err(last_err)
    }

    async fn reset_session(&self) {
        *self.session.lock().await = None;
    }
}

#[async_trait::async_trait]
impl Outbound for OpenVpnOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    async fn connect_stream(&self, _sess: &Session, dst: &DstAddr) -> Result<Box<dyn ProxyStream>> {
        let saddr = self.resolve(dst).await?;
        for attempt in 0..2 {
            let core = match self.get_or_connect().await {
                Ok(c) => c,
                Err(e) => {
                    if attempt == 0 {
                        self.reset_session().await;
                        continue;
                    }
                    return Err(e);
                }
            };
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel::<SessionInner>();
            if core
                .cmd_tx
                .send(Cmd::Connect {
                    dst: saddr,
                    reply: reply_tx,
                })
                .await
                .is_err()
            {
                if attempt == 0 {
                    self.reset_session().await;
                    continue;
                }
                return Err(Error::Proto("openvpn 隧道任务已退出"));
            }
            match tokio::time::timeout(std::time::Duration::from_secs(15), reply_rx).await {
                Ok(Ok(Ok((up_rx, down_tx)))) => {
                    return Ok(Box::new(OvpnTcpStream::new(up_rx, down_tx)));
                }
                _ => {
                    if attempt == 0 {
                        self.reset_session().await;
                        continue;
                    }
                    return Err(Error::Proto("openvpn 栈连接超时"));
                }
            }
        }
        Err(Error::Proto("openvpn 连接重试耗尽"))
    }

    async fn connect_packet(&self, _sess: &Session, _dst: &DstAddr) -> Result<Box<dyn PacketConn>> {
        let core = self.get_or_connect().await?;
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel::<
            Result<(mpsc::Receiver<UpMsg>, mpsc::Sender<DownMsg>)>,
        >();
        core.cmd_tx
            .send(Cmd::ConnectUdp { reply: reply_tx })
            .await
            .map_err(|_| Error::ProtoMsg("openvpn 隧道任务已退出".into()))?;
        let (up_rx, down_tx) = tokio::time::timeout(std::time::Duration::from_secs(15), reply_rx)
            .await
            .map_err(|_| Error::Proto("openvpn 栈 UDP 连接超时"))?
            .map_err(|_| Error::ProtoMsg("openvpn 隧道任务已退出".into()))??;
        Ok(Box::new(OvpnUdpConn {
            up_rx,
            down_tx,
            local: SocketAddr::new(std::net::IpAddr::V4(core.local_v4), 0),
        }))
    }

    fn support_udp(&self) -> bool {
        self.udp
    }

    fn remote_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }
}

/// 目标解析（域名 → 栈内可用 SocketAddr）
impl OpenVpnOutbound {
    async fn resolve(&self, dst: &DstAddr) -> Result<SocketAddr> {
        match &dst.host {
            vp_common::Host::Ip(ip) => Ok(SocketAddr::new(*ip, dst.port)),
            vp_common::Host::Domain(d) => {
                let addrs = vp_transport::resolve_node_addrs(d, dst.port).await?;
                addrs
                    .into_iter()
                    .next()
                    .ok_or_else(|| Error::Addr(format!("openvpn 解析 {d} 无结果")))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 会话流（AsyncRead/AsyncWrite，与 wireguard 同构）
// ---------------------------------------------------------------------------

/// OpenVPN UDP 会话连接：数据报直达栈内 UDP socket，dst 动态携带。
pub struct OvpnUdpConn {
    up_rx: mpsc::Receiver<UpMsg>,
    down_tx: mpsc::Sender<DownMsg>,
    /// 隧道内本机地址（回包 UdpPacket.dst 填充）
    local: SocketAddr,
}

#[async_trait::async_trait]
impl PacketConn for OvpnUdpConn {
    async fn send(&self, pkt: &UdpPacket) -> Result<()> {
        self.down_tx
            .send(DownMsg::Udp {
                dst: pkt.dst,
                data: pkt.data.to_vec(),
            })
            .await
            .map_err(|_| Error::ProtoMsg("openvpn UDP 会话已关闭".into()))
    }

    async fn recv(&mut self) -> Result<UdpPacket> {
        loop {
            match self.up_rx.recv().await {
                Some(UpMsg::Udp { src, data }) => {
                    return Ok(UdpPacket {
                        src,
                        dst: self.local,
                        data,
                    });
                }
                Some(UpMsg::Tcp(_)) => continue,
                None => return Err(Error::ProtoMsg("openvpn UDP 会话已关闭".into())),
            }
        }
    }
}

pub struct OvpnTcpStream {
    up_rx: Pin<Box<mpsc::Receiver<UpMsg>>>,
    down_tx: Pin<Box<mpsc::Sender<DownMsg>>>,
    cur: Option<Bytes>,
    eof: bool,
}

impl ProxyStream for OvpnTcpStream {}

impl OvpnTcpStream {
    fn new(up_rx: mpsc::Receiver<UpMsg>, down_tx: mpsc::Sender<DownMsg>) -> Self {
        OvpnTcpStream {
            up_rx: Box::pin(up_rx),
            down_tx: Box::pin(down_tx),
            cur: None,
            eof: false,
        }
    }
}

impl AsyncRead for OvpnTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        loop {
            if let Some(cur) = this.cur.as_mut() {
                let n = cur.len().min(buf.remaining());
                buf.put_slice(&cur[..n]);
                cur.advance(n);
                if cur.is_empty() {
                    this.cur = None;
                }
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut this.up_rx).poll_recv(cx) {
                Poll::Ready(Some(UpMsg::Tcp(b))) => {
                    if b.is_empty() {
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    this.cur = Some(b);
                }
                Poll::Ready(Some(UpMsg::Udp { .. })) => continue,
                Poll::Ready(None) => {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for OvpnTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        match this.down_tx.try_send(DownMsg::Tcp(buf.to_vec())) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "openvpn 会话已关闭",
                )));
            }
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_layout() {
        assert_eq!(opcode_key_id(P_CONTROL_V1, 0), 4 << 3);
        assert_eq!(opcode_key_id(P_DATA_V2, 0), 9 << 3);
        let b = opcode_key_id(P_CONTROL_HARD_RESET_CLIENT_V2, 0);
        assert_eq!(parse_opcode(b), P_CONTROL_HARD_RESET_CLIENT_V2);
        assert_eq!(b & KEY_ID_MASK, 0);
        let b2 = opcode_key_id(P_DATA_V2, 3);
        assert_eq!(b2 & KEY_ID_MASK, 3);
    }

    #[test]
    fn control_roundtrip() {
        let sid = [7u8; SID_SIZE];
        let remote = [9u8; SID_SIZE];
        let pkt = encode_control(
            P_CONTROL_V1,
            0,
            &sid,
            &[1, 2, 3],
            Some(&remote),
            42,
            b"hello-tls",
        );
        let c = decode_control(&pkt).unwrap();
        assert_eq!(c.opcode, P_CONTROL_V1);
        assert_eq!(c.session_id, sid);
        assert_eq!(c.acks, vec![1, 2, 3]);
        assert_eq!(c.msg_id, Some(42));
        assert_eq!(c.payload, b"hello-tls");

        let pkt = encode_control(P_CONTROL_V1, 0, &sid, &[], None, 1, b"abc");
        let c = decode_control(&pkt).unwrap();
        assert!(c.acks.is_empty());
        assert_eq!(c.payload, b"abc");

        let pkt = encode_control(P_ACK_V1, 0, &sid, &[7], Some(&remote), 0, &[]);
        let c = decode_control(&pkt).unwrap();
        assert_eq!(c.opcode, P_ACK_V1);
        assert_eq!(c.msg_id, None);
        assert!(c.payload.is_empty());
        assert_eq!(c.acks, vec![7]);
    }

    #[test]
    fn km2_client_record_layout() {
        let mut pm = [0u8; KEY_SOURCE_PRE_MASTER_SIZE];
        let mut r1 = [0u8; KEY_SOURCE_RANDOM_SIZE];
        let mut r2 = [0u8; KEY_SOURCE_RANDOM_SIZE];
        rand_fill(&mut pm);
        rand_fill(&mut r1);
        rand_fill(&mut r2);
        let rec = build_km2_client(
            "V4,cipher AES-256-GCM",
            "IV_PROTO=22",
            "vpn",
            "pw",
            &pm,
            &r1,
            &r2,
        );
        assert_eq!(rec[0..4], [0u8; 4]);
        assert_eq!(rec[4], KEY_METHOD_V2);
        assert_eq!(&rec[5..5 + 48], &pm);
        assert_eq!(&rec[53..53 + 32], &r1);
        assert_eq!(&rec[85..85 + 32], &r2);
        let pos = 117;
        let l = u16::from_be_bytes([rec[pos], rec[pos + 1]]) as usize;
        assert_eq!(l as usize, "V4,cipher AES-256-GCM".len() + 1);
    }

    #[test]
    fn km2_server_parse_with_trailing_push() {
        let mut buf = vec![0u8; 4];
        buf.push(KEY_METHOD_V2);
        buf.extend_from_slice(&[1u8; 32]);
        buf.extend_from_slice(&[2u8; 32]);
        append_openvpn_string(&mut buf, "V4,dev-type tun");
        let push = b"PUSH_REPLY,peer-id 5,ifconfig 10.6.0.2 255.255.255.0\0";
        buf.extend_from_slice(push);
        let (km2, consumed) = parse_km2_server(&buf).unwrap();
        assert_eq!(consumed, buf.len() - push.len());
        assert_eq!(km2.random1, [1u8; 32]);
        assert!(km2.trailing.starts_with(b"PUSH_REPLY"));

        // OpenVPN 2.6 省略尾部字符串的形态
        let mut buf = vec![0u8; 4];
        buf.push(KEY_METHOD_V2);
        buf.extend_from_slice(&[3u8; 32]);
        buf.extend_from_slice(&[4u8; 32]);
        append_openvpn_string(&mut buf, "V4,dev-type tun");
        let (km2, _) = parse_km2_server(&buf).unwrap();
        assert_eq!(km2.random2, [4u8; 32]);
        assert!(km2.trailing.is_empty());
    }

    #[test]
    fn prf_deterministic_and_directional() {
        let pm = [5u8; KEY_SOURCE_PRE_MASTER_SIZE];
        let c1 = [1u8; KEY_SOURCE_RANDOM_SIZE];
        let c2 = [2u8; KEY_SOURCE_RANDOM_SIZE];
        let s1 = [3u8; KEY_SOURCE_RANDOM_SIZE];
        let s2 = [4u8; KEY_SOURCE_RANDOM_SIZE];
        let sid_c = [10u8; SID_SIZE];
        let sid_s = [11u8; SID_SIZE];
        let a = derive_keys(&pm, &c1, &c2, &s1, &s2, &sid_c, &sid_s);
        let b = derive_keys(&pm, &c1, &c2, &s1, &s2, &sid_c, &sid_s);
        assert_eq!(a.send_cipher_key, b.send_cipher_key);
        assert_eq!(a.send_cipher_key.len(), 32);
        assert_ne!(a.send_cipher_key, a.recv_cipher_key);
        assert_ne!(a.send_implicit_iv, a.recv_implicit_iv);
        assert_eq!(&a.send_implicit_iv[0..4], &[0u8; 4]);
        assert!(a.send_implicit_iv[4..].iter().any(|x| *x != 0));
        let mut s1b = s1;
        s1b[0] ^= 1;
        let c = derive_keys(&pm, &c1, &c2, &s1b, &s2, &sid_c, &sid_s);
        assert_ne!(a.send_cipher_key, c.send_cipher_key);
    }

    /// VPN Gate 面板下发的哑客户端证书（X.509 v1，CN=VPNGateClientCert1）
    const VPNGATE_DUMMY_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIICxjCCAa4CAQAwDQYJKoZIhvcNAQEFBQAwKTEaMBgGA1UEAxMRVlBOR2F0ZUNs
aWVudENlcnQxCzAJBgNVBAYTAkpQMB4XDTEzMDIxMTAzNDk0OVoXDTM3MDExOTAz
MTQwN1owKTEaMBgGA1UEAxMRVlBOR2F0ZUNsaWVudENlcnQxCzAJBgNVBAYTAkpQ
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5h2lgQQYUjwoKYJbzVZA
5VcIGd5otPc/qZRMt0KItCFA0s9RwReNVa9fDRFLRBhcITOlv3FBcW3E8h1Us7RD
4W8GmJe8zapJnLsD39OSMRCzZJnczW4OCH1PZRZWKqDtjlNca9AF8a65jTmlDxCQ
CjntLIWk5OLLVkFt9/tScc1GDtci55ofhaNAYMPiH7V8+1g66pGHXAoWK6AQVH67
XCKJnGB5nlQ+HsMYPV/O49Ld91ZN/2tHkcaLLyNtywxVPRSsRh480jju0fcCsv6h
p/0yXnTB//mWutBGpdUlIbwiITbAmrsbYnjigRvnPqX1RNJUbi9Fp6C2c/HIFJGD
ywIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQChO5hgcw/4oWfoEFLu9kBa1B//kxH8
hQkChVNn8BRC7Y0URQitPl3DKEed9URBDdg2KOAz77bb6ENPiliD+a38UJHIRMqe
UBHhllOHIzvDhHFbaovALBQceeBzdkQxsKQESKmQmR832950UCovoyRB61UyAV7h
+mZhYPGRKXKSJI6s0Egg/Cri+Cwk4bjJfrb5hVse11yh4D9MHhwSfCOH+0z4hPUT
Fku7dGavURO5SVxMn/sL6En5D+oSeXkadHpDs+Airym2YHh15h0+jPSOoR6yiVp/
6zZeZkrN43kuS73KpKDFjfFPh8t4r1gOIjttkNcQqBccusnplQ7HJpsk
-----END CERTIFICATE-----";

    #[test]
    fn client_certs_modern_rejects_v1_dummy() {
        let der: Vec<Vec<u8>> =
            x509_parser::pem::Pem::iter_from_buffer(VPNGATE_DUMMY_CERT_PEM.as_bytes())
                .collect::<std::result::Result<Vec<_>, _>>()
                .expect("parse pem")
                .into_iter()
                .map(|p| p.contents)
                .collect::<Vec<_>>();
        assert!(!der.is_empty());
        assert!(
            !client_certs_modern(
                &der.iter()
                    .map(|d| rustls::pki_types::CertificateDer::from(d.clone()))
                    .collect::<Vec<_>>()
            ),
            "v1 哑证书应判定为不可用"
        );
    }

    #[test]
    fn data_crypt_roundtrip_v2_and_v1() {
        let keys = DataKeys {
            send_cipher_key: vec![9u8; 32],
            send_hmac_key: vec![7u8; 64],
            send_implicit_iv: [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8],
            recv_cipher_key: vec![8u8; 32],
            recv_hmac_key: vec![6u8; 64],
            recv_implicit_iv: [0, 0, 0, 0, 9, 8, 7, 6, 5, 4, 3, 2],
        };
        let peer_id = 12345u32;
        // 回环：接收方方向键 = 发送方 send（对端视角 recv/send 互换）
        let rx_keys = DataKeys {
            send_cipher_key: keys.recv_cipher_key.clone(),
            send_hmac_key: keys.recv_hmac_key.clone(),
            send_implicit_iv: keys.recv_implicit_iv,
            recv_cipher_key: keys.send_cipher_key.clone(),
            recv_hmac_key: keys.send_hmac_key.clone(),
            recv_implicit_iv: keys.send_implicit_iv,
        };
        let mut send = DataCrypt::new(DataCipher::Aes256Gcm, &keys, Some(peer_id), 0);
        let mut recv = DataCrypt::new(DataCipher::Aes256Gcm, &rx_keys, Some(peer_id), 0);
        let pkt = send.encrypt(b"ip-packet-bytes").unwrap();
        assert_eq!(pkt[0], opcode_key_id(P_DATA_V2, 0));
        assert_eq!(&pkt[1..4], &(peer_id as u32).to_be_bytes()[1..]);
        assert_eq!(&pkt[4..8], &1u32.to_be_bytes());
        let out = recv.decrypt(&pkt).unwrap();
        assert_eq!(out, b"ip-packet-bytes");
        assert!(recv.decrypt(&pkt).is_none(), "窗口内重放拒绝");

        let mut send = DataCrypt::new(DataCipher::Aes256Gcm, &keys, None, 0);
        let mut recv = DataCrypt::new(DataCipher::Aes256Gcm, &rx_keys, None, 0);
        let pkt = send.encrypt(b"hello").unwrap();
        assert_eq!(pkt[0], opcode_key_id(P_DATA_V1, 0));
        assert_eq!(recv.decrypt(&pkt).unwrap(), b"hello");
    }

    #[test]
    fn data_crypt_roundtrip_cbc_v1() {
        // SoftEther/VPN Gate：AES-128-CBC + HMAC-SHA1，无 peer-id（P_DATA_V1）
        let keys = DataKeys {
            send_cipher_key: vec![9u8; 16],
            send_hmac_key: vec![7u8; 64],
            send_implicit_iv: [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8],
            recv_cipher_key: vec![8u8; 16],
            recv_hmac_key: vec![6u8; 64],
            recv_implicit_iv: [0, 0, 0, 0, 9, 8, 7, 6, 5, 4, 3, 2],
        };
        let rx_keys = DataKeys {
            send_cipher_key: keys.recv_cipher_key.clone(),
            send_hmac_key: keys.recv_hmac_key.clone(),
            send_implicit_iv: keys.recv_implicit_iv,
            recv_cipher_key: keys.send_cipher_key.clone(),
            recv_hmac_key: keys.send_hmac_key.clone(),
            recv_implicit_iv: keys.send_implicit_iv,
        };
        let mut send = DataCrypt::new(DataCipher::Aes128Cbc, &keys, None, 0);
        let mut recv = DataCrypt::new(DataCipher::Aes128Cbc, &rx_keys, None, 0);
        let pkt = send.encrypt(b"hello-cbc-payload").unwrap();
        assert_eq!(pkt[0], opcode_key_id(P_DATA_V1, 0));
        // wire = header | tag(20) | iv(16) | ct；明文 4+17=21 → pad 11 → ct 32
        assert_eq!(pkt.len(), 1 + 20 + 16 + 32);
        assert_eq!(recv.decrypt(&pkt).unwrap(), b"hello-cbc-payload");
        assert!(recv.decrypt(&pkt).is_none(), "CBC pid 重放拒绝");
        // HMAC 篡改拒绝
        let mut bad = pkt.clone();
        bad[1] ^= 1;
        assert!(recv.decrypt(&bad).is_none(), "CBC HMAC 校验拒绝");
        // 整块填充（明文恰好对齐 16）
        let pkt = send.encrypt(&[0xABu8; 28]).unwrap(); // 4+28=32 → pad 16
        assert_eq!(recv.decrypt(&pkt).unwrap(), &[0xABu8; 28]);
    }

    #[test]
    fn replay_window() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(1));
        assert!(w.accept(5));
        assert!(w.accept(3));
        assert!(!w.accept(3));
        assert!(w.accept(60));
        assert!(w.accept(0), "窗口内且未见过 → 接受");
        assert!(w.accept(1000));
        assert!(!w.accept(936), "diff == REPLAY_WINDOW → 窗口外拒绝");
        assert!(w.accept(937));
        assert!(!w.accept(1000), "重放");
    }

    #[test]
    fn push_parse() {
        let r = parse_push_reply(
            "PUSH_REPLY,route 10.0.0.0 255.0.0.0,ifconfig 10.6.0.2 255.255.255.0,peer-id 5,data-ciphers AES-256-GCM:AES-128-GCM,dir oserver",
        )
        .unwrap();
        assert_eq!(r.peer_id, Some(5));
        assert_eq!(r.ifconfig_v4, Some("10.6.0.2".parse().unwrap()));
        assert_eq!(r.data_ciphers, vec!["AES-256-GCM", "AES-128-GCM"]);
        assert!(parse_push_reply("AUTH_FAILED").is_err());
    }

    #[test]
    fn cipher_negotiation() {
        assert_eq!(
            DataCipher::parse("aes-256-gcm"),
            Some(DataCipher::Aes256Gcm)
        );
        assert_eq!(
            DataCipher::parse("chacha20-poly1305"),
            Some(DataCipher::ChaCha20Poly1305)
        );
        assert_eq!(
            DataCipher::parse("AES-256-CBC"),
            Some(DataCipher::Aes256Cbc)
        );
        assert_eq!(
            DataCipher::parse("AES-128-CBC"),
            Some(DataCipher::Aes128Cbc)
        );
        assert_eq!(DataCipher::parse("AES-CBC"), Some(DataCipher::Aes256Cbc));
        assert!(DataCipher::parse("AES-256-GCM").unwrap().is_aead());
        assert!(!DataCipher::parse("AES-256-CBC").unwrap().is_aead());
    }

    /// 真实节点探针（`#[ignore]`）：`VPCORE_DEBUG_OVPN_YAML` 或
    /// `target/debug_node.yaml` 指定 openvpn 节点（server/port/username/password/
    /// ca/cert/key），走完整握手 + generate_204 HTTP 请求。
    #[tokio::test]
    #[ignore]
    async fn openvpn_real_node_probe() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let raw = std::env::var("VPCORE_DEBUG_OVPN_YAML")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| std::fs::read_to_string("../../target/debug_node.yaml").ok());
        let Some(raw) = raw else {
            println!("跳过：未提供 VPCORE_DEBUG_OVPN_YAML");
            return;
        };
        let cfg: vp_config::OpenVpnCfg = serde_yaml::from_str(&raw).expect("parse node yaml");
        let out = OpenVpnOutbound::new(&cfg).expect("build");
        let dst = DstAddr {
            host: vp_common::Host::Domain("www.gstatic.com".into()),
            port: 80,
        };
        let sess = Session::new_tcp("ovpn-probe".into(), None, dst.clone());
        let mut s = match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            out.connect_stream(&sess, &dst),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                println!("connect error: {e}");
                return;
            }
            Err(_) => {
                println!("connect timeout");
                return;
            }
        };
        let req =
            b"GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n";
        s.write_all(req).await.unwrap();
        let mut buf = [0u8; 64];
        match tokio::time::timeout(std::time::Duration::from_secs(10), s.read(&mut buf)).await {
            Ok(Ok(0)) => println!("EOF after request"),
            Ok(Ok(n)) => println!(
                "{} bytes: {}",
                n,
                String::from_utf8_lossy(&buf[..n]).replace('\n', "/")
            ),
            Ok(Err(e)) => println!("read error: {e}"),
            Err(_) => println!("read timeout"),
        }
    }
}

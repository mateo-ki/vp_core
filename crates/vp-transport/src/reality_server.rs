//! REALITY 服务端原生监听与握手验证模块
//!
//! 支持直接借用目标站点（如 Apple、Microsoft、Cloudflare 等）的真实公网证书，
//! 服务端通过静态 x25519 私钥验证客户端 ClientHello 中的 session_id 与 short_id。
//! 验证成功则完成 TLS 1.3 服务端握手并建立安全代理隧道；
//! 验证失败（遇到主动探测/扫描器）则透明转发回落至目标网站，返回真实官方证书与网页。

use bytes::BytesMut;
use ring::signature::KeyPair;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::utls::{
    Cursor, Frame, HS_CERT, HS_CERT_VERIFY, HS_EE, HS_FINISHED, MsgIter, REC_APPDATA,
    REC_HANDSHAKE, UtlsStream, aes_256_gcm_open, hkdf_expand_label, hkdf_expand_raw, hkdf_extract,
    read_record, suite_def, traffic_direction,
};
use vp_common::{Error, Result};

type ReplayBuckets = (u64, HashSet<[u8; 16]>, HashSet<[u8; 16]>);

/// 滑动窗口抗重放过滤器
///
/// 采用双桶时间滑动窗口（当前时间桶 + 上一时间桶），
/// 默认窗口周期为 90 秒（总覆盖 180 秒，与时间戳容差对称匹配）。
/// 当收到重复的会话指纹时，立即判定为审查设备的主动重放探测。
pub struct AntiReplayFilter {
    window_secs: u64,
    // (当前桶的起始时间戳, 当前桶记录, 上一桶记录)
    buckets: RwLock<ReplayBuckets>,
}

impl std::fmt::Debug for AntiReplayFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AntiReplayFilter")
            .field("window_secs", &self.window_secs)
            .finish()
    }
}

impl Default for AntiReplayFilter {
    fn default() -> Self {
        Self::new(90) // 2 * 90s = 180s 容差范围
    }
}

impl AntiReplayFilter {
    pub fn new(window_secs: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            window_secs: window_secs.max(10),
            buckets: RwLock::new((now, HashSet::new(), HashSet::new())),
        }
    }

    /// 校验并记录指纹。
    /// 若指纹已存在，返回 false（表示重放攻击检测触发）；
    /// 若指纹为首次出现，记录并返回 true（合法新会话）。
    pub fn check_and_mark(&self, id: &[u8; 16]) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut guard = self.buckets.write().unwrap();
        let (bucket_start, current, prev) = &mut *guard;

        // 检查是否发生时间桶滑动轮转
        if now.saturating_sub(*bucket_start) >= self.window_secs {
            let steps = now.saturating_sub(*bucket_start) / self.window_secs;
            if steps == 1 {
                *prev = std::mem::take(current);
            } else {
                prev.clear();
                current.clear();
            }
            *bucket_start = now;
        }

        // 检查是否存在于当前桶或上一桶
        if current.contains(id) || prev.contains(id) {
            return false; // 重放命中！
        }

        current.insert(*id);
        true
    }
}

/// REALITY 服务端配置
#[derive(Clone)]
pub struct RealityServerConfig {
    /// x25519 静态私钥（32 字节）
    pub private_key: x25519_dalek::StaticSecret,
    /// 派生的 x25519 静态公钥（32 字节）
    pub public_key: x25519_dalek::PublicKey,
    /// 允许的 short_id 列表（每个 8 字节）
    pub short_ids: Vec<[u8; 8]>,
    /// 伪装回落目标（如 "www.apple.com:443"）
    pub dest: String,
    /// 伪装 SNI 列表
    pub server_names: Vec<String>,
    /// 抗重放过滤器
    pub anti_replay: Arc<AntiReplayFilter>,
}

impl std::fmt::Debug for RealityServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityServerConfig")
            .field("public_key", &self.public_key.as_bytes())
            .field("short_ids", &self.short_ids)
            .field("dest", &self.dest)
            .field("server_names", &self.server_names)
            .field("anti_replay", &self.anti_replay)
            .finish()
    }
}

impl RealityServerConfig {
    pub fn new(
        private_key_bytes: [u8; 32],
        short_ids: Vec<[u8; 8]>,
        dest: String,
        server_names: Vec<String>,
    ) -> Self {
        Self::with_anti_replay(
            private_key_bytes,
            short_ids,
            dest,
            server_names,
            Arc::new(AntiReplayFilter::default()),
        )
    }

    pub fn with_anti_replay(
        private_key_bytes: [u8; 32],
        short_ids: Vec<[u8; 8]>,
        dest: String,
        server_names: Vec<String>,
        anti_replay: Arc<AntiReplayFilter>,
    ) -> Self {
        let private_key = x25519_dalek::StaticSecret::from(private_key_bytes);
        let public_key = x25519_dalek::PublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
            short_ids,
            dest,
            server_names,
            anti_replay,
        }
    }
}

/// 解析 16 进制或 base64/base64url 格式的 x25519 私钥
pub fn parse_reality_private_key(s: &str) -> Result<[u8; 32]> {
    let clean = s.trim();
    if clean.len() == 64 {
        if let Ok(b) = hex_to_32(clean) {
            return Ok(b);
        }
    }
    let standard = clean.replace('-', "+").replace('_', "/");
    let padded = match standard.len() % 4 {
        2 => format!("{standard}=="),
        3 => format!("{standard}="),
        _ => standard,
    };
    use base64::Engine;
    if let Ok(vec) = base64::engine::general_purpose::STANDARD.decode(&padded) {
        if vec.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&vec);
            return Ok(arr);
        }
    }
    Err(Error::Config(format!(
        "无效的 REALITY 私钥（需 32 字节 hex 或 base64）: {s}"
    )))
}

fn hex_to_32(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        return Err(Error::Config("hex 长度必须为 64".into()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| Error::Config("非法十六进制字符".into()))?;
    }
    Ok(out)
}

/// 解析 short_id 字符串（例如 "0123456789abcdef" 或空字符串）
pub fn parse_short_id(s: &str) -> Result<[u8; 8]> {
    let clean = s.trim();
    if clean.is_empty() {
        return Ok([0u8; 8]);
    }
    let mut out = [0u8; 8];
    let hex_bytes = hex_to_vec(clean)?;
    if hex_bytes.len() > 8 {
        return Err(Error::Config(format!("short_id 长度超过 8 字节: {s}")));
    }
    out[..hex_bytes.len()].copy_from_slice(&hex_bytes);
    Ok(out)
}

fn hex_to_vec(s: &str) -> Result<Vec<u8>> {
    let clean = s.trim();
    if clean.len() % 2 != 0 {
        return Err(Error::Config("hex 长度必须为偶数".into()));
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    for i in (0..clean.len()).step_by(2) {
        let b = u8::from_str_radix(&clean[i..i + 2], 16)
            .map_err(|_| Error::Config("非法十六进制字符".into()))?;
        out.push(b);
    }
    Ok(out)
}

/// REALITY 服务端握手结果
pub enum RealityHandshakeResult<S> {
    /// 客户端认证成功，已建立端到端加密安全隧道
    Success(Box<UtlsStream<S>>),
    /// 认证失败或主动探测流量，已透明回落反代至真实目标网站
    Fellback,
}

/// 执行 REALITY 服务端握手与主动探测拦截回落
pub async fn reality_server_handshake<S>(
    mut conn: S,
    cfg: Arc<RealityServerConfig>,
) -> Result<RealityHandshakeResult<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // 1. 尝试读取 5 字节 TLS 记录头
    use tokio::io::AsyncReadExt;
    let mut hdr = [0u8; 5];
    if let Err(e) = conn.read_exact(&mut hdr).await {
        return Err(Error::Io(e));
    }
    // TLS 记录头必须为 0x16 (Handshake) 且版本为 0x03, 0x01..=0x03
    if hdr[0] != REC_HANDSHAKE || hdr[1] != 0x03 || hdr[2] > 0x03 {
        // 非 TLS 握手报文（如明文 HTTP GET 探测），立即回落
        handle_camouflage_fallback(conn, &hdr, &cfg.dest).await?;
        return Ok(RealityHandshakeResult::Fellback);
    }
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if !(40..=crate::utls::MAX_CIPHERTEXT).contains(&len) {
        handle_camouflage_fallback(conn, &hdr, &cfg.dest).await?;
        return Ok(RealityHandshakeResult::Fellback);
    }
    let mut ch_record_body = vec![0u8; len];
    if tokio::time::timeout(
        std::time::Duration::from_millis(2000),
        conn.read_exact(&mut ch_record_body),
    )
    .await
    .is_err()
    {
        let mut initial = Vec::with_capacity(5 + len);
        initial.extend_from_slice(&hdr);
        handle_camouflage_fallback(conn, &initial, &cfg.dest).await?;
        return Ok(RealityHandshakeResult::Fellback);
    }

    // 2. 校验与解析 ClientHello
    let auth_res = authenticate_client_hello(&ch_record_body, &cfg);
    let (client_share, aead_key, client_sid) = match auth_res {
        Ok(res) => res,
        Err(err) => {
            tracing::info!(
                dest = %cfg.dest,
                "REALITY 主动探测或凭据不匹配: {err}，透明回落至伪装目标"
            );
            // 组装完整的 ClientHello 报文头并转发给 dest
            let mut full_ch = Vec::with_capacity(5 + ch_record_body.len());
            full_ch.push(REC_HANDSHAKE);
            full_ch.extend_from_slice(&[0x03, 0x01]);
            full_ch.extend_from_slice(&(ch_record_body.len() as u16).to_be_bytes());
            full_ch.extend_from_slice(&ch_record_body);
            handle_camouflage_fallback(conn, &full_ch, &cfg.dest).await?;
            return Ok(RealityHandshakeResult::Fellback);
        }
    };

    // 3. 客户端认证成功，进入 TLS 1.3 服务端握手
    tracing::debug!("REALITY 客户端握手认证通过，开始协商 TLS 1.3 隧道");
    let stream =
        complete_tls13_server_handshake(conn, &ch_record_body, client_share, aead_key, client_sid)
            .await?;

    Ok(RealityHandshakeResult::Success(Box::new(stream)))
}

/// 认证 ClientHello：返回 (client_share, aead_key, client_session_id)
fn authenticate_client_hello(
    ch: &[u8],
    cfg: &RealityServerConfig,
) -> Result<([u8; 32], [u8; 32], [u8; 32])> {
    if ch.len() < 43 + 32 + 2 {
        return Err(Error::Proto("ClientHello 长度不足"));
    }
    if ch[0] != 0x01 {
        return Err(Error::Proto("握手类型非 ClientHello"));
    }

    // random: [6..38]
    let rnd: [u8; 32] = ch[6..38]
        .try_into()
        .map_err(|_| Error::Proto("random 截断"))?;
    let sid_len = ch[38] as usize;
    if sid_len != 32 || ch.len() < 39 + 32 {
        return Err(Error::Proto("session_id 长度非 32 字节"));
    }
    let sid_pos = 39;
    let client_sid: [u8; 32] = ch[sid_pos..sid_pos + 32]
        .try_into()
        .map_err(|_| Error::Proto("session_id 截断"))?;

    // 提取 key_share (ext 51) 中的 x25519 client_share
    let mut c = Cursor::new(ch);
    c.take(39 + 32)?; // 跳过头部与 session_id
    let suites_len = c.u16()? as usize;
    c.take(suites_len)?;
    let comp_len = c.u8()? as usize;
    c.take(comp_len)?;
    let ext_len = c.u16()? as usize;
    let exts = c.take(ext_len)?;

    let mut client_share: Option<[u8; 32]> = None;
    let mut e = Cursor::new(exts);
    while !e.done() {
        let ty = e.u16()?;
        let len = e.u16()? as usize;
        let body = e.take(len)?;
        if ty == 51 {
            // key_share 客户端扩展：总长 u16 + [group u16 + key_len u16 + key]
            let mut k = Cursor::new(body);
            let _total_shares_len = k.u16()?;
            while !k.done() {
                let group = k.u16()?;
                let klen = k.u16()? as usize;
                let kbytes = k.take(klen)?;
                if group == 0x001d && klen == 32 {
                    let mut share = [0u8; 32];
                    share.copy_from_slice(kbytes);
                    client_share = Some(share);
                    break;
                }
            }
        }
    }

    let client_share = client_share.ok_or(Error::Proto("未找到 x25519 key_share"))?;

    // 1. auth_secret = X25519(server_static_pri, client_share)
    let peer_pub = x25519_dalek::PublicKey::from(client_share);
    let auth_secret = cfg.private_key.diffie_hellman(&peer_pub);

    // 2. aead_key = HKDF-SHA256(secret: auth_secret, salt: rnd[0..20], info: "REALITY", len: 32)
    let prk = hkdf_extract(&rnd[0..20], auth_secret.as_bytes())?;
    let aead_key_vec = hkdf_expand_raw(&prk, b"REALITY", 32)?;
    let mut aead_key = [0u8; 32];
    aead_key.copy_from_slice(&aead_key_vec);

    // 3. 准备 AAD：session_id 全零的 ClientHello body
    let mut zeroed_ch = ch.to_vec();
    zeroed_ch[sid_pos..sid_pos + 32].fill(0);

    // 4. AES-256-GCM 解密 session_id
    let nonce: [u8; 12] = rnd[20..32]
        .try_into()
        .map_err(|_| Error::Proto("nonce 越界"))?;
    let mut sid_buf = client_sid;
    let plain = aes_256_gcm_open(&aead_key, &nonce, &zeroed_ch, &mut sid_buf)?;
    if plain.len() < 16 {
        return Err(Error::Proto("REALITY 载荷解密长度不足 16 字节"));
    }

    // 5. 校验时间戳 (plain[4..8]) 与 short_id (plain[8..16])
    let client_secs = u32::from_be_bytes(plain[4..8].try_into().unwrap());
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    if client_secs.abs_diff(now_secs) > 180 {
        return Err(Error::Proto("REALITY 时间戳偏差超过 3 分钟"));
    }

    if !cfg.short_ids.is_empty() {
        let client_short_id: [u8; 8] = plain[8..16].try_into().unwrap();
        if !cfg.short_ids.iter().any(|id| id == &client_short_id) {
            return Err(Error::Proto("REALITY short_id 未在授权许可名单"));
        }
    }

    // 6. 抗重放校验 (Anti-Replay Filter)：防止审查设备录制合法 ClientHello 进行主动重放探测
    let mut replay_id = [0u8; 16];
    replay_id.copy_from_slice(&client_sid[0..16]);
    if !cfg.anti_replay.check_and_mark(&replay_id) {
        return Err(Error::Proto(
            "REALITY: 检测到重复的 ClientHello (主动重放探测攻击)",
        ));
    }

    Ok((client_share, aead_key, client_sid))
}

/// 完成服务端 TLS 1.3 握手
async fn complete_tls13_server_handshake<S>(
    mut conn: S,
    ch_body: &[u8],
    client_share: [u8; 32],
    aead_key: [u8; 32],
    client_sid: [u8; 32],
) -> Result<UtlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let suite = suite_def(0x1301).ok_or(Error::Proto("不支持 0x1301"))?;

    // 1. 生成服务端临时 x25519 密钥对
    let mut srv_pri_bytes = [0u8; 32];
    vp_common::rand_bytes(&mut srv_pri_bytes);
    let srv_pri = x25519_dalek::StaticSecret::from(srv_pri_bytes);
    let srv_pub = x25519_dalek::PublicKey::from(&srv_pri);
    let client_pub = x25519_dalek::PublicKey::from(client_share);
    let shared = srv_pri.diffie_hellman(&client_pub);

    // 2. 组装 ServerHello
    let mut srv_rnd = [0u8; 32];
    vp_common::rand_bytes(&mut srv_rnd);

    let mut sh_body = Vec::with_capacity(128);
    sh_body.push(0x02); // ServerHello
    sh_body.extend_from_slice(&[0, 0, 0]); // 长度占位
    sh_body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    sh_body.extend_from_slice(&srv_rnd);
    sh_body.push(32);
    sh_body.extend_from_slice(&client_sid); // 回显 session_id
    sh_body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    sh_body.extend_from_slice(&[0x01, 0x00]); // compression null

    let mut exts = Vec::new();
    // supported_versions (43): [0x03, 0x04]
    exts.extend_from_slice(&[0x00, 43, 0x00, 0x02, 0x03, 0x04]);
    // key_share (51): group x25519 (0x001d) + 32 字节公钥
    exts.extend_from_slice(&[0x00, 51, 0x00, 36, 0x00, 0x1d, 0x00, 32]);
    exts.extend_from_slice(srv_pub.as_bytes());

    sh_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    sh_body.extend_from_slice(&exts);

    let sh_total = sh_body.len() - 4;
    sh_body[1] = (sh_total >> 16) as u8;
    sh_body[2] = (sh_total >> 8) as u8;
    sh_body[3] = sh_total as u8;

    // 3. 初始化握手 Transcript
    let mut transcript = Vec::with_capacity(2048);
    transcript.extend_from_slice(ch_body);
    transcript.extend_from_slice(&sh_body);

    // 4. 派生 Handshake 流量密钥
    let zeros = vec![0u8; suite.hash_len];
    let early = suite.extract(&zeros, &zeros);
    let empty_hash = suite.digest(&[]);
    let d1 = suite.derive_secret(&early, "derived", &empty_hash)?;
    let hs = suite.extract(&d1, shared.as_bytes());
    let th_sh = suite.digest(&transcript);
    let c_hs_secret = suite.derive_secret(&hs, "c hs traffic", &th_sh)?;
    let s_hs_secret = suite.derive_secret(&hs, "s hs traffic", &th_sh)?;
    let mut s_hs_dir = traffic_direction(suite, &s_hs_secret)?;
    let mut c_hs_dir = traffic_direction(suite, &c_hs_secret)?;

    // 5. 发送 ServerHello 与 dummy CCS
    let mut sh_rec = vec![REC_HANDSHAKE, 0x03, 0x03];
    sh_rec.extend_from_slice(&(sh_body.len() as u16).to_be_bytes());
    sh_rec.extend_from_slice(&sh_body);
    // dummy ChangeCipherSpec (0x14, 0x03, 0x03, 0x00, 0x01, 0x01)
    sh_rec.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    conn.write_all(&sh_rec).await.map_err(Error::Io)?;

    // 6. 构造 EncryptedExtensions, Certificate, CertificateVerify, Finished
    // (a) EE (type 8)
    let ee_msg = [HS_EE, 0, 0, 2, 0, 0];
    transcript.extend_from_slice(&ee_msg);

    // (b) Certificate (type 11)
    let rng = ring::rand::SystemRandom::new();
    let ed_pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| Error::Proto("生成 Ed25519 密钥对失败"))?;
    let ed_key = ring::signature::Ed25519KeyPair::from_pkcs8(ed_pkcs8.as_ref())
        .map_err(|_| Error::Proto("导入 Ed25519 密钥对失败"))?;
    let ed_pub: [u8; 32] = ed_key.public_key().as_ref().try_into().unwrap();

    let hmac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, &aead_key);
    let hmac_sig = ring::hmac::sign(&hmac_key, &ed_pub);
    let hmac_sig_arr: [u8; 64] = hmac_sig.as_ref().try_into().unwrap();

    let cert_der = build_reality_cert_der(&ed_pub, &hmac_sig_arr);
    let mut cert_msg = Vec::with_capacity(cert_der.len() + 16);
    cert_msg.push(HS_CERT);
    let cert_payload_len = 1 + 3 + 3 + cert_der.len() + 2;
    cert_msg.extend_from_slice(&[
        (cert_payload_len >> 16) as u8,
        (cert_payload_len >> 8) as u8,
        cert_payload_len as u8,
    ]);
    cert_msg.push(0); // req_context_len = 0
    let cert_entry_len = 3 + cert_der.len() + 2;
    cert_msg.extend_from_slice(&[
        (cert_entry_len >> 16) as u8,
        (cert_entry_len >> 8) as u8,
        cert_entry_len as u8,
    ]);
    cert_msg.extend_from_slice(&[
        (cert_der.len() >> 16) as u8,
        (cert_der.len() >> 8) as u8,
        cert_der.len() as u8,
    ]);
    cert_msg.extend_from_slice(&cert_der);
    cert_msg.extend_from_slice(&[0x00, 0x00]); // extensions len = 0
    transcript.extend_from_slice(&cert_msg);

    // (c) CertificateVerify (type 15)
    let mut cv_msg = vec![0x20u8; 64];
    cv_msg.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    cv_msg.push(0);
    cv_msg.extend_from_slice(&suite.digest(&transcript));
    let cv_sig = ed_key.sign(&cv_msg);

    let mut cv_full = Vec::with_capacity(4 + 2 + 2 + cv_sig.as_ref().len());
    cv_full.push(HS_CERT_VERIFY);
    let cv_body_len = 2 + 2 + cv_sig.as_ref().len();
    cv_full.extend_from_slice(&[
        (cv_body_len >> 16) as u8,
        (cv_body_len >> 8) as u8,
        cv_body_len as u8,
    ]);
    cv_full.extend_from_slice(&[0x08, 0x07]); // Ed25519 scheme
    cv_full.extend_from_slice(&(cv_sig.as_ref().len() as u16).to_be_bytes());
    cv_full.extend_from_slice(cv_sig.as_ref());
    transcript.extend_from_slice(&cv_full);

    // (d) Server Finished (type 20)
    let s_fk = hkdf_expand_label(
        &ring::hkdf::Prk::new_less_safe(suite.hkdf_alg, &s_hs_secret),
        "finished",
        &[],
        suite.hash_len,
    )?;
    let s_verify_data = ring::hmac::sign(
        &ring::hmac::Key::new(suite.hmac_alg, &s_fk),
        &suite.digest(&transcript),
    );
    let mut s_fin_msg = vec![HS_FINISHED, 0, 0, s_verify_data.as_ref().len() as u8];
    s_fin_msg.extend_from_slice(s_verify_data.as_ref());
    transcript.extend_from_slice(&s_fin_msg);

    // 加密并发送握手记录群
    let mut hs_bundle = Vec::new();
    hs_bundle.extend_from_slice(&ee_msg);
    hs_bundle.extend_from_slice(&cert_msg);
    hs_bundle.extend_from_slice(&cv_full);
    hs_bundle.extend_from_slice(&s_fin_msg);
    hs_bundle.push(REC_HANDSHAKE); // inner content type

    let clen = hs_bundle.len() + 16;
    let rec_hdr = [REC_APPDATA, 0x03, 0x03, (clen >> 8) as u8, clen as u8];
    let mut sealed = BytesMut::from(hs_bundle.as_slice());
    s_hs_dir.seal(&rec_hdr, &mut sealed)?;
    conn.write_all(&rec_hdr).await.map_err(Error::Io)?;
    conn.write_all(&sealed).await.map_err(Error::Io)?;
    conn.flush().await.map_err(Error::Io)?;

    // 7. 读取并验证客户端 Finished
    let frame = read_record(&mut conn, Some(&mut c_hs_dir)).await?;
    let c_fin_payload = match frame {
        Frame::Data { inner, data } if inner == REC_HANDSHAKE => data,
        _ => return Err(Error::Proto("未收到客户端 Finished 握手记录")),
    };

    let mut it = MsgIter::new();
    it.push(&c_fin_payload);
    let (mty, mbody) = it
        .next_msg()
        .ok_or(Error::Proto("客户端 Finished 消息截断"))?;
    if mty != HS_FINISHED {
        return Err(Error::Proto("握手类型非 Finished"));
    }

    let c_fk = hkdf_expand_label(
        &ring::hkdf::Prk::new_less_safe(suite.hkdf_alg, &c_hs_secret),
        "finished",
        &[],
        suite.hash_len,
    )?;
    let expected_c_fin = ring::hmac::sign(
        &ring::hmac::Key::new(suite.hmac_alg, &c_fk),
        &suite.digest(&transcript),
    );
    if mbody.as_slice() != expected_c_fin.as_ref() {
        return Err(Error::Proto("客户端 Finished 认证校验失败"));
    }

    // 8. 派生主应用密钥 (Application Traffic Secrets，transcript 截止至 Server Finished，与客户端对称一致)
    let d2 = suite.derive_secret(&hs, "derived", &empty_hash)?;
    let master = suite.extract(&d2, &zeros);
    let th_fin = suite.digest(&transcript);
    let c_ap_secret = suite.derive_secret(&master, "c ap traffic", &th_fin)?;
    let s_ap_secret = suite.derive_secret(&master, "s ap traffic", &th_fin)?;

    let tx_dir = traffic_direction(suite, &s_ap_secret)?;
    let rx_dir = traffic_direction(suite, &c_ap_secret)?;

    Ok(UtlsStream::new(conn, tx_dir, rx_dir))
}

/// 构造带 HMAC-SHA512 签名的 X.509 Ed25519 证书 DER
fn build_reality_cert_der(ed_pub: &[u8; 32], hmac_sig: &[u8; 64]) -> Vec<u8> {
    let mut tbs = Vec::with_capacity(160);
    // 1. version [0] EXPLICIT INTEGER 2 (v3)
    tbs.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x02]);
    // 2. serialNumber INTEGER 1
    tbs.extend_from_slice(&[0x02, 0x01, 0x01]);
    // 3. signature AlgId (Ed25519 1.3.101.112)
    tbs.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
    // 4. issuer Name: CN=Reality
    tbs.extend_from_slice(&[
        0x30, 0x11, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06, b'R', b'e',
        b'a', b'l', b'i', b't',
    ]);
    // 5. validity: 2020-01-01 到 2035-01-01
    tbs.extend_from_slice(&[
        0x30, 0x1e, 0x17, 0x0d, b'2', b'0', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0',
        b'0', b'Z', 0x17, 0x0d, b'3', b'5', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0',
        b'0', b'Z',
    ]);
    // 6. subject Name: CN=Reality
    tbs.extend_from_slice(&[
        0x30, 0x11, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06, b'R', b'e',
        b'a', b'l', b'i', b't',
    ]);
    // 7. subjectPublicKeyInfo: SEQ { AlgId (7B), BIT STRING (35B) }
    tbs.extend_from_slice(&[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ]);
    tbs.extend_from_slice(ed_pub);

    let mut tbs_seq = Vec::with_capacity(tbs.len() + 4);
    tbs_seq.push(0x30);
    encode_der_len(&mut tbs_seq, tbs.len());
    tbs_seq.extend_from_slice(&tbs);

    // 2. signatureAlgorithm
    let sig_alg = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

    // 3. signatureValue (BIT STRING 0x00 unused bits + 64 bytes HMAC)
    let mut sig_val = Vec::with_capacity(3 + 64);
    sig_val.extend_from_slice(&[0x03, 0x41, 0x00]);
    sig_val.extend_from_slice(hmac_sig);

    // Outer Certificate SEQUENCE
    let total_len = tbs_seq.len() + sig_alg.len() + sig_val.len();
    let mut cert = Vec::with_capacity(total_len + 4);
    cert.push(0x30);
    encode_der_len(&mut cert, total_len);
    cert.extend_from_slice(&tbs_seq);
    cert.extend_from_slice(&sig_alg);
    cert.extend_from_slice(&sig_val);

    cert
}

fn encode_der_len(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

/// 透明反代伪装回落至目标站点
async fn handle_camouflage_fallback<S>(mut client: S, initial: &[u8], dest: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tracing::debug!(dest = %dest, "建立真实伪装连接并反代透传");
    let mut remote = tokio::net::TcpStream::connect(dest)
        .await
        .map_err(Error::Io)?;
    crate::tune(&remote);
    remote.write_all(initial).await.map_err(Error::Io)?;
    remote.flush().await.map_err(Error::Io)?;

    tokio::spawn(async move {
        let _ = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RealityConfig;
    use crate::utls::{Fingerprint, UtlsConfig, utls_connect};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn reality_server_client_e2e() {
        // 1. 生成服务端密钥
        let mut pri_bytes = [0u8; 32];
        vp_common::rand_bytes(&mut pri_bytes);
        let srv_pri = x25519_dalek::StaticSecret::from(pri_bytes);
        let srv_pub = x25519_dalek::PublicKey::from(&srv_pri);
        let short_id = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];

        let cfg = Arc::new(RealityServerConfig::new(
            pri_bytes,
            vec![short_id],
            "127.0.0.1:80".into(),
            vec!["www.apple.com".into()],
        ));

        // 2. 启动服务端监听
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let srv_cfg = cfg.clone();
        let srv_handle = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            match reality_server_handshake(conn, srv_cfg).await.unwrap() {
                RealityHandshakeResult::Success(mut stream) => {
                    let mut buf = [0u8; 4];
                    stream.read_exact(&mut buf).await.unwrap();
                    assert_eq!(&buf, b"ping");
                    stream.write_all(b"pong").await.unwrap();
                    stream.flush().await.unwrap();
                }
                RealityHandshakeResult::Fellback => {
                    panic!("合法 REALITY 连接不应回落");
                }
            }
        });

        // 3. 客户端发起连接
        let client_conn = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let utls_cfg = UtlsConfig {
            fingerprint: Fingerprint::Chrome,
            server_name: Some("www.apple.com".into()),
            alpn: vec!["h2".into(), "http/1.1".into()],
            skip_cert_verify: false,
            reality: Some(RealityConfig {
                public_key: *srv_pub.as_bytes(),
                short_id,
                spider_x: None,
            }),
        };

        let mut client_stream = utls_connect(client_conn, "www.apple.com", &utls_cfg)
            .await
            .unwrap();
        client_stream.write_all(b"ping").await.unwrap();
        client_stream.flush().await.unwrap();

        let mut reply = [0u8; 4];
        client_stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");

        srv_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_reality_probe_fallback() {
        // 1. 启动模拟的伪装站点（如 Apple Web 响应）
        let mock_dest = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_port = mock_dest.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = mock_dest.accept().await.unwrap();
            let mut buf = [0u8; 128];
            let n = s.read(&mut buf).await.unwrap();
            assert!(n > 0);
            s.write_all(b"HTTP/1.1 200 OK\r\nServer: Apple\r\nContent-Length: 5\r\n\r\napple")
                .await
                .unwrap();
        });

        // 2. 启动 REALITY 服务端
        let mut pri_bytes = [0u8; 32];
        vp_common::rand_bytes(&mut pri_bytes);
        let srv_pri = x25519_dalek::StaticSecret::from(pri_bytes);
        let _srv_pub = x25519_dalek::PublicKey::from(&srv_pri);
        let valid_short_id = [1, 2, 3, 4, 5, 6, 7, 8];

        let cfg = Arc::new(RealityServerConfig::new(
            pri_bytes,
            vec![valid_short_id],
            format!("127.0.0.1:{dest_port}"),
            vec!["www.apple.com".into()],
        ));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let srv_port = listener.local_addr().unwrap().port();

        let srv_cfg = cfg.clone();
        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            let res = reality_server_handshake(conn, srv_cfg).await.unwrap();
            assert!(matches!(res, RealityHandshakeResult::Fellback));
        });

        // 3. 扫描器发送非 REALITY 探测包 (例如明文 HTTP 请求)
        let mut probe = tokio::net::TcpStream::connect(("127.0.0.1", srv_port))
            .await
            .unwrap();
        probe
            .write_all(b"GET / HTTP/1.1\r\nHost: www.apple.com\r\n\r\n")
            .await
            .unwrap();
        probe.flush().await.unwrap();

        let mut resp = [0u8; 64];
        let n = probe.read(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("Server: Apple"));
        assert!(resp_str.contains("apple"));
    }

    #[test]
    fn test_anti_replay_filter_sliding_window() {
        let filter = AntiReplayFilter::new(10);
        let id1 = [1u8; 16];
        let id2 = [2u8; 16];

        // 首次出现允许通过
        assert!(filter.check_and_mark(&id1));
        assert!(filter.check_and_mark(&id2));

        // 立即重放必须拦截
        assert!(!filter.check_and_mark(&id1));
        assert!(!filter.check_and_mark(&id2));
    }
}

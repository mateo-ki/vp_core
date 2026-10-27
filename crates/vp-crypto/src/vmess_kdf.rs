//! VMess AEAD 密钥派生（对齐 v2fly/Xray 实现）。
//!
//! KDF 是对 Go `hmac.New(func() hash.Hash { return hash2{parent} }, path)` 链的
//! 逐字节模拟：包装层的 ipad/opad 与中间 digest 都会流入根 HMAC 的消息流，
//! 因此这里用共享可变对象复刻 Go 语义，保证跨实现一致。

use sha2::{Digest, Sha256};

use vp_common::{Error, Result};

pub const KDF_SALT: &str = "VMess AEAD KDF";
pub const SALT_AUTH_ID_ENC: &str = "AES Auth ID Encryption";
pub const SALT_HEADER_LEN_KEY: &str = "VMess Header AEAD Key_Length";
pub const SALT_HEADER_LEN_IV: &str = "VMess Header AEAD Nonce_Length";
pub const SALT_HEADER_KEY: &str = "VMess Header AEAD Key";
pub const SALT_HEADER_IV: &str = "VMess Header AEAD Nonce";
pub const SALT_RESP_LEN_KEY: &str = "AEAD Resp Header Len Key";
pub const SALT_RESP_LEN_IV: &str = "AEAD Resp Header Len IV";
pub const SALT_RESP_KEY: &str = "AEAD Resp Header Key";
pub const SALT_RESP_IV: &str = "AEAD Resp Header IV";

pub const AUTH_WINDOW_SECS: i64 = 120;

// ---------------------------------------------------------------------------
// Go hmac 语义模拟
// ---------------------------------------------------------------------------

trait GoHash {
    fn write(&mut self, data: &[u8]);
    /// Go hash.Hash.Sum：非破坏性
    fn sum(&mut self) -> Vec<u8>;
}

struct Sha256Go(Sha256);

impl GoHash for Sha256Go {
    fn write(&mut self, data: &[u8]) {
        Digest::update(&mut self.0, data);
    }
    fn sum(&mut self) -> Vec<u8> {
        let cloned = self.0.clone();
        cloned.finalize().to_vec()
    }
}

/// Go `hmac.New(hashFactory, key)`：inner/outer 各调用一次 hashFactory。
/// sing-vmess 的 factory（`h.parent.Create`）每次返回**全新**的 parent 实例，
/// 因此每层的 ipad/opad 落在两个独立的 parent 对象中（对齐 mihomo/xray 实测互通语义）。
struct GoHmac {
    outer: Box<dyn GoHash>,
    inner: Box<dyn GoHash>,
}

impl GoHmac {
    #[allow(clippy::new_ret_no_self)]
    fn new(factory: &dyn Fn() -> Box<dyn GoHash>, key: &[u8]) -> Box<dyn GoHash> {
        const BLOCK: usize = 64;
        let mut ipad = vec![0x36u8; BLOCK];
        let mut opad = vec![0x5cu8; BLOCK];
        let padded: Vec<u8> = if key.len() > BLOCK {
            let mut h = Sha256Go(Sha256::new());
            GoHash::write(&mut h, key);
            GoHash::sum(&mut h)
        } else {
            key.to_vec()
        };
        for (i, b) in padded.iter().enumerate() {
            ipad[i] ^= *b;
            opad[i] ^= *b;
        }
        let mut inner = factory();
        let mut outer = factory();
        GoHash::write(&mut *inner, &ipad);
        GoHash::write(&mut *outer, &opad);
        Box::new(GoHmac { outer, inner })
    }
}

impl GoHash for GoHmac {
    fn write(&mut self, data: &[u8]) {
        self.inner.write(data);
    }
    fn sum(&mut self) -> Vec<u8> {
        let d = self.inner.sum();
        self.outer.write(&d);
        self.outer.sum()
    }
}

/// sing-vmess/xray KDF 链：level 0 为根 HMAC("VMess AEAD KDF")，
/// 每向上一层以该层 value 为 key 包装（parent factory 生成独立实例）。
fn kdf_go(key: &[u8], paths: &[&[u8]]) -> Vec<u8> {
    // 链 = 根("VMess AEAD KDF") → salt/path…（sing-vmess kdf.go 的 creator 链）
    let mut levels: Vec<&[u8]> = vec![KDF_SALT.as_bytes()];
    levels.extend_from_slice(paths);
    fn leaf() -> Box<dyn GoHash> {
        Box::new(Sha256Go(Sha256::new()))
    }
    fn create(level: usize, levels: Vec<Vec<u8>>) -> Box<dyn Fn() -> Box<dyn GoHash> + 'static> {
        if level == 0 {
            let v = levels[0].clone();
            Box::new(move || GoHmac::new(&|| leaf(), &v))
        } else {
            let v = levels[level].clone();
            Box::new(move || {
                let parent = create(level - 1, levels.clone());
                GoHmac::new(&|| parent(), &v)
            })
        }
    }
    let owned: Vec<Vec<u8>> = levels.iter().map(|l| l.to_vec()).collect();
    let factory = create(owned.len() - 1, owned);
    let mut hf = factory();
    hf.write(key);
    hf.sum()
}

pub fn kdf(key: &[u8], paths: &[&[u8]]) -> Vec<u8> {
    kdf_go(key, paths)
}

pub fn kdf16(key: &[u8], paths: &[&[u8]]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&kdf(key, paths)[..16]);
    out
}

pub fn kdf_x(key: &[u8], paths: &[&[u8]], x: usize) -> Vec<u8> {
    kdf(key, paths)[..x].to_vec()
}

// ---------------------------------------------------------------------------
// AuthID
// ---------------------------------------------------------------------------

/// 生成 AuthID：明文 [ts8 BE][rand4][crc32(buf12) BE] → AES-128-ECB 单块加密
pub fn create_auth_id(cmd_key: &[u8; 16], ts: i64) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&ts.to_be_bytes());
    let mut rand4 = [0u8; 4];
    vp_common::rand_bytes(&mut rand4);
    buf[8..12].copy_from_slice(&rand4);
    let crc = crc32_ieee(&buf[..12]);
    buf[12..].copy_from_slice(&crc.to_be_bytes());
    aes_ecb_encrypt_block(&kdf16(cmd_key, &[SALT_AUTH_ID_ENC.as_bytes()]), &buf)
}

/// 尝试解出 AuthID：成功返回 (ts, rand4)
pub fn decode_auth_id(cmd_key: &[u8; 16], auth_id: &[u8; 16]) -> Option<(i64, [u8; 4])> {
    let key = kdf16(cmd_key, &[SALT_AUTH_ID_ENC.as_bytes()]);
    let buf = aes_ecb_decrypt_block(&key, auth_id);
    let ts = i64::from_be_bytes(buf[..8].try_into().unwrap());
    let expect = crc32_ieee(&buf[..12]).to_be_bytes();
    if buf[12..] != expect {
        return None;
    }
    let mut rand4 = [0u8; 4];
    rand4.copy_from_slice(&buf[8..12]);
    Some((ts, rand4))
}

fn aes_ecb_encrypt_block(key16: &[u8; 16], block16: &[u8; 16]) -> [u8; 16] {
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockEncrypt, KeyInit};
    let key = GenericArray::from(*key16);
    let cipher = aes::Aes128::new(&key);
    let mut block = GenericArray::from(*block16);
    cipher.encrypt_block(&mut block);
    let mut out = [0u8; 16];
    out.copy_from_slice(block.as_ref());
    out
}

fn aes_ecb_decrypt_block(key16: &[u8; 16], block16: &[u8; 16]) -> [u8; 16] {
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockDecrypt, KeyInit};
    let key = GenericArray::from(*key16);
    let cipher = aes::Aes128::new(&key);
    let mut block = GenericArray::from(*block16);
    cipher.decrypt_block(&mut block);
    let mut out = [0u8; 16];
    out.copy_from_slice(block.as_ref());
    out
}

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------

pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// FNV-1a 32
pub fn fnv1a32(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811C_9DC5;
    for &b in data {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// ChaCha20 密钥扩展（16B → 32B）：MD5(b) || MD5(MD5(b))
pub fn generate_chacha20_key(seed: &[u8; 16]) -> [u8; 32] {
    use md5::Digest;
    let a: [u8; 16] = Md5::digest(seed).into();
    let b: [u8; 16] = Md5::digest(a).into();
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&a);
    out[16..].copy_from_slice(&b);
    out
}

type Md5 = md5::Md5;

/// 解析 UUID 字符串为 16 字节
pub fn parse_uuid(s: &str) -> Result<[u8; 16]> {
    let clean: String = s.chars().filter(|c| *c != '-').collect();
    if clean.len() != 32 {
        return Err(Error::Config(format!("UUID 非法: {s:?}")));
    }
    let mut out = [0u8; 16];
    for (i, v) in out.iter_mut().enumerate() {
        *v = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16)
            .map_err(|_| Error::Config(format!("UUID 非法: {s:?}")))?;
    }
    Ok(out)
}

/// cmdKey = MD5(uuid ‖ "c48619fe-8f02-49e0-b9e9-edf763e17e21")
/// （对齐 xray `NewID` 与 sing-vmess `Key`；v2ray 老版的 MD5(uuid×4) 已弃用）
pub fn uuid_to_cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    use md5::Digest;
    let mut h = Md5::new();
    h.update(uuid);
    h.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    h.finalize().into()
}

/// legacy（alterId>0）认证 key = MD5(uuid ‖ "16167dc8-...")（sing-vmess `AlterId`）
pub fn uuid_alter_key(uuid: &[u8; 16]) -> [u8; 16] {
    use md5::Digest;
    let mut h = Md5::new();
    h.update(uuid);
    h.update(b"16167dc8-16b6-4e6d-b8bb-65dd68113a81");
    let out: [u8; 16] = h.finalize().into();
    if out == *uuid {
        // sing-vmess：结果撞原 uuid 时再混入第三个常量
        let mut h = Md5::new();
        h.update(uuid);
        h.update(b"16167dc8-16b6-4e6d-b8bb-65dd68113a81");
        h.update(b"533eff8a-4113-4b10-b5ce-0f5d76b98cd2");
        h.finalize().into()
    } else {
        out
    }
}

/// responseBodyKey/IV = SHA256(requestBodyKey/IV)[:16]
pub fn sha256_16(input: &[u8]) -> [u8; 16] {
    let d = Sha256::digest(input);
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

// ---------------------------------------------------------------------------
// VMess legacy（alterId>0）认证头派生 —— 对齐 sing-vmess writeHandshake
// ---------------------------------------------------------------------------

type HmacMd5 = hmac::Hmac<md5::Md5>;

/// legacy 认证信息 = HMAC-MD5(K=alterKey, M=时间戳 8B BE)[:16]
pub fn legacy_auth_id(alter_key: &[u8; 16], ts: u64) -> [u8; 16] {
    use hmac::Mac;
    let mut mac = <HmacMd5 as hmac::Mac>::new_from_slice(alter_key).expect("hmac-md5");
    mac.update(&ts.to_be_bytes());
    let out = mac.finalize().into_bytes();
    out[..16].try_into().expect("hmac-md5 16B")
}

/// legacy 指令块 IV = MD5(时间戳 8B BE ×4)（sing-vmess：binary.Write ×4）
pub fn legacy_req_iv(ts: u64) -> [u8; 16] {
    use md5::Digest;
    let mut h = Md5::new();
    let tsb = ts.to_be_bytes();
    for _ in 0..4 {
        h.update(tsb);
    }
    h.finalize().into()
}

/// legacy 指令块 Key = MD5(UUID ‖ "c48619fe-...") = cmdKey（sing-vmess `Key`）
pub fn legacy_req_key(uuid: &[u8; 16]) -> [u8; 16] {
    uuid_to_cmd_key(uuid)
}

/// legacy 响应头 Key/IV = MD5(requestKey) / MD5(requestNonce)
pub fn legacy_resp_keys(body_key: &[u8; 16], body_iv: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    use md5::Digest;
    (Md5::digest(body_key).into(), Md5::digest(body_iv).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_parse() {
        let u = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        assert_eq!(u[0], 0xb8);
        assert_eq!(u[15], 0x11);
        assert!(parse_uuid("xyz").is_err());
    }

    #[test]
    fn auth_id_roundtrip() {
        let cmd = [5u8; 16];
        let ts = 1_700_000_000i64;
        let id = create_auth_id(&cmd, ts);
        let (t2, _) = decode_auth_id(&cmd, &id).unwrap();
        assert_eq!(t2, ts);
        let bad = [6u8; 16];
        assert!(decode_auth_id(&bad, &id).is_none());
    }

    #[test]
    fn kdf_deterministic_and_sensitive() {
        let k = [1u8; 16];
        let a = kdf(&k, &[b"VMess Header AEAD Key"]);
        let b = kdf(&k, &[b"VMess Header AEAD Key"]);
        assert_eq!(a, b);
        let c = kdf(&k, &[b"VMess Header AEAD Nonce"]);
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
        // 多 path
        let d = kdf(&k, &[b"A", b"BB", b"CCC"]);
        assert_ne!(d, a);
        assert_eq!(kdf16(&k, &[b"A"]).len(), 16);
    }

    #[test]
    fn fnv_and_crc() {
        assert_eq!(fnv1a32(b""), 0x811c9dc5);
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn chacha_key_expand() {
        let k = generate_chacha20_key(&[1u8; 16]);
        assert_eq!(k.len(), 32);
        let a: [u8; 16] = Md5::digest([1u8; 16]).into();
        assert_eq!(&k[..16], &a);
    }

    #[test]
    #[ignore = "抓包分析：需要 target/vm_cap_mh_aead.bin"]
    fn decode_captured_auth() {
        let data =
            std::fs::read("D:/project/rust/vs/vpn-parser/target/vm_cap_mh_aead.bin").unwrap();
        let auth: [u8; 16] = data[..16].try_into().unwrap();
        let uuid = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let cmd = uuid_to_cmd_key(&uuid);
        println!("cmdkey(x4) = {}", hex(&cmd));
        match decode_auth_id(&cmd, &auth) {
            Some((ts, _)) => println!("AEAD authID 命中: cmdKey=x4, ts={ts}"),
            None => println!("AEAD authID 未命中 (cmdKey=x4)"),
        }
        use md5::Digest;
        let mut h = md5::Md5::new();
        h.update(uuid);
        let cmd1: [u8; 16] = h.finalize().into();
        match decode_auth_id(&cmd1, &auth) {
            Some((ts, _)) => println!("AEAD authID 命中: cmdKey=x1, ts={ts}"),
            None => println!("AEAD authID 未命中 (cmdKey=x1)"),
        }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    use crate::{AeadKind, AnyAead};

    #[test]
    #[ignore = "xray 服务端逻辑验证 vpcore 抓包头"]
    fn verify_captured_header_as_xray_server() {
        let data = std::fs::read("D:/project/rust/vs/vpn-parser/target/vm_cap_vp.bin").unwrap();
        println!("总长 {}", data.len());
        let uuid = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let cmd = uuid_to_cmd_key(&uuid);
        let auth_id: [u8; 16] = data[..16].try_into().unwrap();
        // xray GetAEAD: decode authID
        match decode_auth_id(&cmd, &auth_id) {
            Some((ts, _)) => println!("[1] authID decode OK ts={ts}"),
            None => {
                println!("[1] authID decode FAILED");
                return;
            }
        }
        let len_ct: [u8; 18] = data[16..34].try_into().unwrap();
        let nonce8: [u8; 8] = data[34..42].try_into().unwrap();
        let pay_ct = &data[42..];
        let len_key = kdf16(&cmd, &[SALT_HEADER_LEN_KEY.as_bytes(), &auth_id, &nonce8]);
        let len_nonce = kdf_x(
            &cmd,
            &[SALT_HEADER_LEN_IV.as_bytes(), &auth_id, &nonce8],
            12,
        );
        let mut n12 = [0u8; 12];
        n12.copy_from_slice(&len_nonce);
        let aead = AnyAead::new(AeadKind::Aes128Gcm, &len_key).unwrap();
        match aead.open_nonce(&n12, &len_ct, &auth_id) {
            Ok(pt) => {
                let l = u16::from_be_bytes([pt[0], pt[1]]) as usize;
                println!(
                    "[2] len 块 OK，明文长度={l}，payload ct 长={}（应 {}）",
                    pay_ct.len(),
                    l + 16
                );
                let pay_key = kdf16(&cmd, &[SALT_HEADER_KEY.as_bytes(), &auth_id, &nonce8]);
                let pay_nonce = kdf_x(&cmd, &[SALT_HEADER_IV.as_bytes(), &auth_id, &nonce8], 12);
                let mut pn12 = [0u8; 12];
                pn12.copy_from_slice(&pay_nonce);
                let paead = AnyAead::new(AeadKind::Aes128Gcm, &pay_key).unwrap();
                match paead.open_nonce(&pn12, pay_ct, &auth_id) {
                    Ok(p) => println!("[3] payload OK，{}B，明文头版本={:02x}", p.len(), p[0]),
                    Err(e) => println!("[3] payload FAILED: {e}"),
                }
            }
            Err(e) => println!("[2] len 块 FAILED: {e}"),
        }
    }
}

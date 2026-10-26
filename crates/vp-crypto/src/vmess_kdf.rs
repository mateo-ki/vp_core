//! VMess AEAD 密钥派生（对齐 v2fly/Xray 实现）。
//!
//! KDF 是对 Go `hmac.New(func() hash.Hash { return hash2{parent} }, path)` 链的
//! 逐字节模拟：包装层的 ipad/opad 与中间 digest 都会流入根 HMAC 的消息流，
//! 因此这里用共享可变对象复刻 Go 语义，保证跨实现一致。

use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::rc::Rc;

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

type Shared = Rc<RefCell<dyn GoHash>>;

/// hash2{parent}：Write/Sum 均转发给父对象
struct Hash2 {
    parent: Shared,
}

impl GoHash for Hash2 {
    fn write(&mut self, data: &[u8]) {
        self.parent.borrow_mut().write(data);
    }
    fn sum(&mut self) -> Vec<u8> {
        self.parent.borrow_mut().sum()
    }
}

struct GoHmac {
    outer: Shared,
    inner: Shared,
}

impl GoHmac {
    /// 等价 Go hmac.New(hashFactory, key)
    fn new_with_factory(factory: &dyn Fn() -> Shared, key: &[u8]) -> Rc<RefCell<GoHmac>> {
        const BLOCK: usize = 64;
        debug_assert!(key.len() <= BLOCK, "vmess kdf path 均为短字符串");
        let mut ipad = vec![0x36u8; BLOCK];
        let mut opad = vec![0x5cu8; BLOCK];
        for (i, b) in key.iter().enumerate() {
            ipad[i] ^= *b;
            opad[i] ^= *b;
        }
        let h = GoHmac {
            outer: factory(),
            inner: factory(),
        };
        GoHash::write(&mut *h.inner.borrow_mut(), &ipad);
        GoHash::write(&mut *h.outer.borrow_mut(), &opad);
        Rc::new(RefCell::new(h))
    }
}

impl GoHash for GoHmac {
    fn write(&mut self, data: &[u8]) {
        self.inner.borrow_mut().write(data);
    }
    fn sum(&mut self) -> Vec<u8> {
        let d = self.inner.borrow_mut().sum();
        self.outer.borrow_mut().write(&d);
        self.outer.borrow_mut().sum()
    }
}

/// v2ray aead.KDF：逐层以 path 为 key 包装父 hmac，最后写入 key 并 Sum。
fn kdf_go(key: &[u8], paths: &[&[u8]]) -> Vec<u8> {
    let mut hmacf: Shared = GoHmac::new_with_factory(
        &|| Rc::new(RefCell::new(Sha256Go(Sha256::new()))),
        KDF_SALT.as_bytes(),
    );
    for p in paths {
        let parent = hmacf.clone();
        let factory = move || -> Shared {
            Rc::new(RefCell::new(Hash2 {
                parent: parent.clone(),
            }))
        };
        hmacf = GoHmac::new_with_factory(&factory, p);
    }
    hmacf.borrow_mut().write(key);
    hmacf.borrow_mut().sum()
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

/// cmdKey = MD5(uuid bytes)
pub fn uuid_to_cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    use md5::Digest;
    Md5::digest(uuid).into()
}

/// responseBodyKey/IV = SHA256(requestBodyKey/IV)[:16]
pub fn sha256_16(input: &[u8]) -> [u8; 16] {
    let d = Sha256::digest(input);
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
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
}

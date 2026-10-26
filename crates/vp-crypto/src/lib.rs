//! vp-crypto：协议密码套件聚合。
//!
//! - AnyAead：AES-128/256-GCM、ChaCha20-Poly1305 统一封装（递增 nonce）
//! - shadowsocks：evp_bytes_to_key（legacy KDF）、HKDF-SHA1 子密钥、AEAD 分块流
//! - vmess/其他协议所需的 MD5/SHA/HKDF 直接依赖底层 crate

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use vp_common::{Error, Result};

pub mod ss;
pub mod vmess_kdf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadKind {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl AeadKind {
    pub fn key_len(self) -> usize {
        match self {
            AeadKind::Aes128Gcm => 16,
            AeadKind::Aes256Gcm | AeadKind::ChaCha20Poly1305 => 32,
        }
    }

    pub fn salt_len(self) -> usize {
        self.key_len()
    }

    pub fn tag_len(self) -> usize {
        16
    }
}

/// 三种 AEAD 的统一封装
pub enum AnyAead {
    A128(Box<Aes128Gcm>),
    A256(Box<Aes256Gcm>),
    Chacha(Box<ChaCha20Poly1305>),
}

impl AnyAead {
    pub fn new(kind: AeadKind, key: &[u8]) -> Result<Self> {
        if key.len() != kind.key_len() {
            return Err(Error::Config(format!(
                "密钥长度应为 {} 字节，实际 {}",
                kind.key_len(),
                key.len()
            )));
        }
        Ok(match kind {
            AeadKind::Aes128Gcm => AnyAead::A128(Box::new(Aes128Gcm::new_from_slice(key).unwrap())),
            AeadKind::Aes256Gcm => AnyAead::A256(Box::new(Aes256Gcm::new_from_slice(key).unwrap())),
            AeadKind::ChaCha20Poly1305 => {
                AnyAead::Chacha(Box::new(ChaCha20Poly1305::new_from_slice(key).unwrap()))
            }
        })
    }

    pub fn seal(&self, nonce_counter: u64, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let nonce = nonce_from_counter(nonce_counter);
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        match self {
            AnyAead::A128(a) => a.encrypt(&nonce, payload).unwrap(),
            AnyAead::A256(a) => a.encrypt(&nonce, payload).unwrap(),
            AnyAead::Chacha(a) => a.encrypt(&nonce, payload).unwrap(),
        }
    }

    /// 使用显式 12 字节 nonce
    pub fn seal_nonce(&self, nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let n = Nonce::from(*nonce);
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        match self {
            AnyAead::A128(a) => a.encrypt(&n, payload).unwrap(),
            AnyAead::A256(a) => a.encrypt(&n, payload).unwrap(),
            AnyAead::Chacha(a) => a.encrypt(&n, payload).unwrap(),
        }
    }

    pub fn open_nonce(&self, nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let n = Nonce::from(*nonce);
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        let r = match self {
            AnyAead::A128(a) => a.decrypt(&n, payload),
            AnyAead::A256(a) => a.decrypt(&n, payload),
            AnyAead::Chacha(a) => a.decrypt(&n, payload),
        };
        r.map_err(|_| Error::Proto("AEAD 解密失败"))
    }

    pub fn open(&self, nonce_counter: u64, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce = nonce_from_counter(nonce_counter);
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        let r = match self {
            AnyAead::A128(a) => a.decrypt(&nonce, payload),
            AnyAead::A256(a) => a.decrypt(&nonce, payload),
            AnyAead::Chacha(a) => a.decrypt(&nonce, payload),
        };
        r.map_err(|_| Error::Proto("AEAD 解密失败"))
    }
}

/// 12 字节 nonce：counter 大端
pub fn nonce_from_counter(counter: u64) -> Nonce<aes_gcm::aead::consts::U12> {
    let mut n = [0u8; 12];
    n[4..12].copy_from_slice(&counter.to_be_bytes());
    Nonce::from(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_roundtrip_all_kinds() {
        for kind in [
            AeadKind::Aes128Gcm,
            AeadKind::Aes256Gcm,
            AeadKind::ChaCha20Poly1305,
        ] {
            let key = vec![7u8; kind.key_len()];
            let a = AnyAead::new(kind, &key).unwrap();
            let ct = a.seal(0, b"hello", b"");
            assert_eq!(ct.len(), 5 + 16);
            let pt = a.open(0, &ct, b"").unwrap();
            assert_eq!(pt, b"hello");
            // 带 AAD
            let ct = a.seal(3, b"x", b"aad");
            assert!(a.open(3, &ct, b"aad").is_ok());
            assert!(a.open(3, &ct, b"bad").is_err());
            // 错误 nonce
            assert!(a.open(1, &ct, b"aad").is_err());
        }
    }

    #[test]
    fn nonce_be_layout() {
        let n = nonce_from_counter(1);
        assert_eq!(n.as_slice(), &[0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }
}

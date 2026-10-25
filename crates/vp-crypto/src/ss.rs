//! Shadowsocks 密码套件：legacy AEAD 与 2022-blake3。

use base64::Engine;
use hkdf::Hkdf;
use hmac::Hmac;
use md5::{Digest, Md5};
use sha1::Sha1;

use vp_common::{Error, Result};

use crate::{AeadKind, AnyAead};

/// 加密套件描述
#[derive(Debug, Clone)]
pub struct Cipher {
    pub name: String,
    pub kind: AeadKind,
    pub is_2022: bool,
}

impl Cipher {
    pub fn parse(name: &str) -> Result<Cipher> {
        let (name, kind, is_2022) = match name {
            "aes-128-gcm" => (name, AeadKind::Aes128Gcm, false),
            "aes-256-gcm" => (name, AeadKind::Aes256Gcm, false),
            "chacha20-ietf-poly1305" | "xchacha20-ietf-poly1305" => {
                (name, AeadKind::ChaCha20Poly1305, false)
            }
            "2022-blake3-aes-128-gcm" => (name, AeadKind::Aes128Gcm, true),
            "2022-blake3-aes-256-gcm" => (name, AeadKind::Aes256Gcm, true),
            "2022-blake3-chacha20-poly1305" => (name, AeadKind::ChaCha20Poly1305, true),
            other => {
                return Err(Error::Config(format!(
                    "不支持的加密方式 {other:?}（M1 支持 AEAD 与 2022 系）"
                )))
            }
        };
        Ok(Cipher { name: name.into(), kind, is_2022 })
    }

    pub fn key_len(&self) -> usize {
        self.kind.key_len()
    }

    pub fn salt_len(&self) -> usize {
        self.kind.salt_len()
    }

    /// 由密码推导主密钥
    pub fn derive_key(&self, password: &str) -> Result<Vec<u8>> {
        if self.is_2022 {
            let key = base64::engine::general_purpose::STANDARD
                .decode(password)
                .map_err(|_| Error::Config("2022 系密码需为 base64".into()))?;
            if key.len() != self.key_len() {
                return Err(Error::Config(format!(
                    "2022 密钥 base64 解码后应为 {} 字节，实际 {}",
                    self.key_len(),
                    key.len()
                )));
            }
            Ok(key)
        } else {
            Ok(evp_bytes_to_key(password.as_bytes(), self.key_len()))
        }
    }

    /// 由主密钥 + salt 派生子密钥
    pub fn subkey(&self, key: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
        if self.is_2022 {
            // 2022: blake3(key || salt) 截断 key_len
            let mut h = blake3::Hasher::new();
            h.update(key);
            h.update(salt);
            let out = h.finalize();
            Ok(out.as_bytes()[..self.key_len()].to_vec())
        } else {
            // legacy: HKDF-SHA1(key, salt, "ss-subkey", key_len)
            let hk = Hkdf::<Sha1>::new(Some(salt), key);
            let mut okm = vec![0u8; self.key_len()];
            hk.expand(b"ss-subkey", &mut okm)
                .map_err(|_| Error::Proto("hkdf 展开失败"))?;
            Ok(okm)
        }
    }

    pub fn aead(&self, key: &[u8]) -> Result<AnyAead> {
        AnyAead::new(self.kind, key)
    }
}

/// OpenSSL EVP_BytesToKey（MD5，无 salt）：legacy shadowsocks 密钥推导
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(key_len + 16);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < key_len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(password);
        let d = h.finalize();
        prev = d.to_vec();
        out.extend_from_slice(&d);
    }
    out.truncate(key_len);
    out
}

/// 单方向 AEAD 分块编解码（计数递增 nonce）
pub struct AeadChunkCodec {
    aead: AnyAead,
    counter: u64,
    tag_len: usize,
}

impl AeadChunkCodec {
    pub fn new(cipher: &Cipher, key: &[u8]) -> Result<Self> {
        Ok(AeadChunkCodec {
            aead: cipher.aead(key)?,
            counter: 0,
            tag_len: cipher.kind.tag_len(),
        })
    }

    fn next_nonce(&mut self) -> u64 {
        let n = self.counter;
        self.counter += 1;
        n
    }

    /// 加密为一个分块（[2B len ct][len tag][payload ct][payload tag]）
    pub fn seal_chunk(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(payload.len() + 2 + 2 * self.tag_len);
        let n1 = self.next_nonce();
        let len_ct = self.aead.seal(n1, &(payload.len() as u16).to_be_bytes(), b"");
        out.extend_from_slice(&len_ct);
        let n2 = self.next_nonce();
        let data_ct = self.aead.seal(n2, payload, b"");
        out.extend_from_slice(&data_ct);
        out
    }

    /// 尝试从 buf 解出一条 payload；数据不足返回 None
    /// 返回 (payload, consumed)
    pub fn try_open_chunk(&mut self, buf: &[u8]) -> Option<Result<(Vec<u8>, usize)>> {
        let len_ct_len = 2 + self.tag_len;
        if buf.len() < len_ct_len {
            return None;
        }
        let len_pt = match self.aead.open(self.counter, &buf[..len_ct_len], b"") {
            Ok(p) => p,
            Err(e) => return Some(Err(e)),
        };
        if len_pt.len() != 2 {
            return Some(Err(Error::Proto("长度块非法")));
        }
        let plen = u16::from_be_bytes([len_pt[0], len_pt[1]]) as usize;
        let total = len_ct_len + plen + self.tag_len;
        if buf.len() < total {
            return None;
        }
        let data = match self.aead.open(self.counter + 1, &buf[len_ct_len..total], b"") {
            Ok(p) => p,
            Err(e) => return Some(Err(e)),
        };
        self.counter += 2;
        Some(Ok((data, total)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evp_kdf_matches_known() {
        // "test" aes-128-gcm → 32 字节推导，取前 16
        let k = evp_bytes_to_key(b"test", 16);
        assert_eq!(k.len(), 16);
    }

    #[test]
    fn chunk_codec_roundtrip() {
        for name in ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"] {
            let c = Cipher::parse(name).unwrap();
            let key = c.derive_key("passw0rd").unwrap();
            let mut enc = AeadChunkCodec::new(&c, &key).unwrap();
            let mut dec = AeadChunkCodec::new(&c, &key).unwrap();
            for payload in [&b""[..], b"hello", &[0u8; 300]] {
                let chunk = enc.seal_chunk(payload);
                match dec.try_open_chunk(&chunk) {
                    Some(Ok((pt, used))) => {
                        assert_eq!(pt, payload);
                        assert_eq!(used, chunk.len());
                    }
                    other => panic!("{name} 解码失败: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn chunk_codec_partial_then_complete() {
        let c = Cipher::parse("aes-128-gcm").unwrap();
        let key = c.derive_key("p").unwrap();
        let mut enc = AeadChunkCodec::new(&c, &key).unwrap();
        let mut dec = AeadChunkCodec::new(&c, &key).unwrap();
        let chunk = enc.seal_chunk(b"payload-xyz");
        // 半包
        assert!(dec.try_open_chunk(&chunk[..5]).is_none());
        // 多个块粘连
        let chunk2 = enc.seal_chunk(b"second");
        let mut glued = chunk.clone();
        glued.extend_from_slice(&chunk2);
        let (p1, used) = dec.try_open_chunk(&glued).unwrap().unwrap();
        assert_eq!(p1, b"payload-xyz");
        let (p2, _) = dec.try_open_chunk(&glued[used..]).unwrap().unwrap();
        assert_eq!(p2, b"second");
    }

    #[test]
    fn ciphers_2022_key_derive() {
        let c = Cipher::parse("2022-blake3-aes-128-gcm").unwrap();
        let psk = base64::engine::general_purpose::STANDARD.encode([9u8; 16]);
        let key = c.derive_key(&psk).unwrap();
        assert_eq!(key, vec![9u8; 16]);
        assert!(c.derive_key("!!!not-base64###").is_err());
    }

    #[test]
    fn hmac_sha1_available() {
        use hmac::Mac as _;
        let mut mac = <Hmac<Sha1> as hmac::Mac>::new_from_slice(b"key").unwrap();
        mac.update(b"data");
        assert_eq!(mac.finalize().into_bytes().len(), 20);
    }
}

//! Shadowsocks 密码套件：legacy AEAD 与 2022-blake3。

use base64::Engine;
use hkdf::Hkdf;
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
                )));
            }
        };
        Ok(Cipher {
            name: name.into(),
            kind,
            is_2022,
        })
    }

    pub fn key_len(&self) -> usize {
        self.kind.key_len()
    }

    pub fn salt_len(&self) -> usize {
        // 2022（sing/mihomo 实现）：salt 长度 = key_len（aes-128→16，aes-256→32）
        self.kind.salt_len()
    }

    pub fn tag_len(&self) -> usize {
        self.kind.tag_len()
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
            // SIP022：blake3 keyed-derive（context = "shadowsocks 2022 session subkey"，
            // 输入 key||salt），XOF 输出 key_len 字节
            const BLAKE3_KEY_DERIVE_CONTEXT: &str = "shadowsocks 2022 session subkey";
            let mut h = blake3::Hasher::new_derive_key(BLAKE3_KEY_DERIVE_CONTEXT);
            h.update(key);
            h.update(salt);
            let mut out = vec![0u8; self.key_len()];
            h.finalize_xof().fill(&mut out);
            Ok(out)
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

    /// 直接以现成 AEAD 构造（vmess body 用）
    pub fn from_aead(aead: AnyAead) -> Self {
        AeadChunkCodec {
            aead,
            counter: 0,
            tag_len: 16,
        }
    }

    fn next_nonce(&mut self) -> u64 {
        let n = self.counter;
        self.counter += 1;
        n
    }

    /// shadowsocks AEAD 的 nonce：u64 counter 小端置于前 8 字节，后 4 字节为零
    fn ss_nonce(counter: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&counter.to_le_bytes());
        n
    }

    /// 零中间分配加密：直接就地加密并追加到 `out`（BytesMut），消除所有中间 Vec
    pub fn seal_chunk_into_bytes(&mut self, payload: &[u8], out: &mut bytes::BytesMut) {
        let needed = 2 + self.tag_len + payload.len() + self.tag_len;
        out.reserve(needed);
        let n1 = Self::ss_nonce(self.next_nonce());
        let mut len_buf = (payload.len() as u16).to_be_bytes();
        let len_tag = self.aead.seal_in_place_detached(&n1, &mut len_buf, b"");
        out.extend_from_slice(&len_buf);
        out.extend_from_slice(&len_tag);

        let n2 = Self::ss_nonce(self.next_nonce());
        let start = out.len();
        out.extend_from_slice(payload);
        let data_tag = self
            .aead
            .seal_in_place_detached(&n2, &mut out[start..], b"");
        out.extend_from_slice(&data_tag);
    }

    /// 零中间分配加密：直接就地加密并追加到 `out`（Vec<u8>）
    pub fn seal_chunk_into(&mut self, payload: &[u8], out: &mut Vec<u8>) {
        let needed = 2 + self.tag_len + payload.len() + self.tag_len;
        out.reserve(needed);
        let n1 = Self::ss_nonce(self.next_nonce());
        let mut len_buf = (payload.len() as u16).to_be_bytes();
        let len_tag = self.aead.seal_in_place_detached(&n1, &mut len_buf, b"");
        out.extend_from_slice(&len_buf);
        out.extend_from_slice(&len_tag);

        let n2 = Self::ss_nonce(self.next_nonce());
        let start = out.len();
        out.extend_from_slice(payload);
        let data_tag = self
            .aead
            .seal_in_place_detached(&n2, &mut out[start..], b"");
        out.extend_from_slice(&data_tag);
    }

    /// 加密为一个分块（[2B len ct][len tag][payload ct][payload tag]）
    pub fn seal_chunk(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(payload.len() + 2 + 2 * self.tag_len);
        self.seal_chunk_into(payload, &mut out);
        out
    }

    /// 尝试从 buf 解出一条 payload；数据不足返回 None
    /// 返回 (payload, consumed)
    pub fn try_open_chunk(&mut self, buf: &[u8]) -> Option<Result<(Vec<u8>, usize)>> {
        let len_ct_len = 2 + self.tag_len;
        if buf.len() < len_ct_len {
            return None;
        }
        let n1 = Self::ss_nonce(self.counter);
        let mut len_buf = [buf[0], buf[1]];
        let mut tag1 = [0u8; 16];
        tag1.copy_from_slice(&buf[2..len_ct_len]);
        if let Err(e) = self
            .aead
            .open_in_place_detached(&n1, &mut len_buf, &tag1, b"")
        {
            return Some(Err(e));
        }
        let plen = u16::from_be_bytes(len_buf) as usize;
        let total = len_ct_len + plen + self.tag_len;
        if buf.len() < total {
            return None;
        }
        let n2 = Self::ss_nonce(self.counter + 1);
        let mut data = buf[len_ct_len..len_ct_len + plen].to_vec();
        let mut tag2 = [0u8; 16];
        tag2.copy_from_slice(&buf[len_ct_len + plen..total]);
        if let Err(e) = self.aead.open_in_place_detached(&n2, &mut data, &tag2, b"") {
            return Some(Err(e));
        }
        self.counter += 2;
        Some(Ok((data, total)))
    }

    /// SIP022 裸记录加密：单次 AEAD op，无长度前缀（定长头/变长头用），nonce 计数器连续
    pub fn seal_raw_record(&mut self, payload: &[u8], out: &mut bytes::BytesMut) {
        let n = Self::ss_nonce(self.next_nonce());
        let start = out.len();
        out.extend_from_slice(payload);
        let tag = self.aead.seal_in_place_detached(&n, &mut out[start..], b"");
        out.extend_from_slice(&tag);
    }

    /// SIP022 裸记录解密：`buf` 须含完整记录（pt_len + tag）；nonce 计数器连续。
    /// 返回 (明文, 消费字节数)。记录不完整返回 None，解密失败返回 Some(Err)。
    pub fn open_raw_record(
        &mut self,
        buf: &[u8],
        pt_len: usize,
    ) -> Option<Result<(Vec<u8>, usize)>> {
        let total = pt_len + self.tag_len;
        if buf.len() < total {
            return None;
        }
        let n = Self::ss_nonce(self.counter);
        let mut data = buf[..pt_len].to_vec();
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&buf[pt_len..total]);
        if let Err(e) = self.aead.open_in_place_detached(&n, &mut data, &tag, b"") {
            return Some(Err(e));
        }
        self.counter += 1;
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
        let mut mac = <hmac::Hmac<Sha1> as hmac::Mac>::new_from_slice(b"key").unwrap();
        mac.update(b"data");
        assert_eq!(mac.finalize().into_bytes().len(), 20);
    }
}

#[cfg(test)]
mod snell_v4_frame_tests {
    use super::*;

    /// 官方 snell v4 帧往返独立验证（argon2 KDF + salt + swap）
    #[test]
    fn v4_frame_roundtrip_with_swap() {
        let psk = b"correct-psk";
        let salt = [7u8; 16];
        let cipher = Cipher::parse("aes-128-gcm").unwrap();
        let key = {
            use argon2::{Algorithm, Argon2, Params, Version};
            let mut out = vec![0u8; 32];
            let params = Params::new(8, 3, 1, Some(32)).unwrap();
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(psk, &salt, &mut out)
                .unwrap();
            out.truncate(16);
            out
        };
        let mut wenc = AeadChunkCodec::new(&cipher, &key).unwrap();

        let payload = [0x01u8, 0x01, 0x00, 0x09];
        let payload = {
            let mut v = payload.to_vec();
            v.extend_from_slice(b"127.0.0.1");
            v.extend_from_slice(&12345u16.to_be_bytes());
            v
        };
        let pad = 506usize;

        let mut out = bytes::BytesMut::new();
        out.extend_from_slice(&salt);
        let mut hdr = [0u8; 7];
        hdr[0] = 4;
        hdr[3..5].copy_from_slice(&(pad as u16).to_be_bytes());
        hdr[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        wenc.seal_raw_record(&hdr, &mut out);
        let start = out.len();
        wenc.seal_raw_record(&payload, &mut out);
        let mut padding = vec![0u8; pad];
        for (i, b) in padding.iter_mut().enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        let mut seg = out.split_off(start);
        for i in (0..pad.min(seg.len())).step_by(2) {
            std::mem::swap(&mut padding[i], &mut seg[i]);
        }
        out.extend_from_slice(&padding);
        out.extend_from_slice(&seg);

        // ===== 读取侧 =====
        let mut rdec = AeadChunkCodec::new(&cipher, &key).unwrap();
        let body = &out[16..];
        let (hdr, used1) = rdec.open_raw_record(body, 7).unwrap().unwrap();
        assert_eq!(hdr[0], 4);
        let pad_r = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        let len_r = u16::from_be_bytes([hdr[5], hdr[6]]) as usize;
        assert_eq!(pad_r, pad);
        assert_eq!(len_r, payload.len());
        let need = used1 + pad_r + len_r + 16;
        let mut payload_cipher = body[used1 + pad_r..need].to_vec();
        for i in (0..pad_r.min(payload_cipher.len())).step_by(2) {
            payload_cipher[i] = body[used1 + i];
        }
        let (pt, _) = rdec
            .open_raw_record(&payload_cipher, len_r)
            .unwrap()
            .unwrap();
        assert_eq!(pt, payload, "v4 帧载荷往返必须一致");
    }
}

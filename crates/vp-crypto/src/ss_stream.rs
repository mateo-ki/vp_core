//! legacy 流式加密（shadowsocks-classic / SSR）：none、rc4、rc4-md5、aes-{128,192,256}-cfb。
//!
//! 与 AEAD 不同，流式加密是连续密钥流：`[IV][ciphertext...]`，无分块帧；
//! 发送方向用 Encryptor、接收方向用 Decryptor（CFB 反馈取自密文字节）。

use cfb_mode::cipher::KeyIvInit;
use cfb_mode::{BufDecryptor, BufEncryptor};
use md5::{Digest, Md5};

use vp_common::{Error, Result};

use crate::ss::evp_bytes_to_key;

/// 流式加密套件
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSuite {
    pub kind: StreamKind,
    pub key_len: usize,
    pub iv_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// 明文（SSR "none" / "plain"）
    None,
    Rc4,
    /// RC4 且连接子密钥 = MD5(master || iv)
    Rc4Md5,
    Aes128Cfb,
    Aes192Cfb,
    Aes256Cfb,
    /// ChaCha20（djb 原始变体，8 字节 nonce）
    ChaCha20,
    /// ChaCha20-IETF（RFC 8439，12 字节 nonce）—— 现存 SSR 节点最常用的流加密
    ChaCha20Ietf,
}

impl StreamSuite {
    pub fn parse(name: &str) -> Result<StreamSuite> {
        let kind = match name.to_ascii_lowercase().as_str() {
            "none" | "plain" => StreamKind::None,
            "rc4" => StreamKind::Rc4,
            "rc4-md5" => StreamKind::Rc4Md5,
            "aes-128-cfb" | "aes-128-cfb1" => StreamKind::Aes128Cfb,
            "aes-192-cfb" => StreamKind::Aes192Cfb,
            "aes-256-cfb" | "aes-256-cfb1" => StreamKind::Aes256Cfb,
            "chacha20" => StreamKind::ChaCha20,
            "chacha20-ietf" => StreamKind::ChaCha20Ietf,
            other => {
                return Err(Error::Config(format!(
                    "不支持的流式加密 {other:?}（支持 none/rc4/rc4-md5/aes-*-cfb/chacha20[-ietf]）"
                )));
            }
        };
        let (key_len, iv_len) = match kind {
            StreamKind::None => (0, 0),
            StreamKind::Rc4 => (16, 0),
            StreamKind::Rc4Md5 | StreamKind::Aes128Cfb => (16, 16),
            StreamKind::Aes192Cfb => (24, 16),
            StreamKind::Aes256Cfb => (32, 16),
            StreamKind::ChaCha20 => (32, 8),
            StreamKind::ChaCha20Ietf => (32, 12),
        };
        Ok(StreamSuite {
            kind,
            key_len,
            iv_len,
        })
    }

    /// 由密码推导主密钥（legacy EVP_BytesToKey）
    pub fn derive_key(&self, password: &str) -> Vec<u8> {
        evp_bytes_to_key(password.as_bytes(), self.key_len)
    }

    /// 连接子密钥：rc4-md5 = MD5(master || iv)，其余直接使用 master
    pub fn subkey(&self, master: &[u8], iv: &[u8]) -> Vec<u8> {
        match self.kind {
            StreamKind::Rc4Md5 => {
                let mut h = Md5::new();
                h.update(master);
                h.update(iv);
                h.finalize().to_vec()
            }
            _ => master[..self.key_len].to_vec(),
        }
    }
}

/// 单方向连续密钥流 XOR 器
pub enum StreamXor {
    None,
    TxRc4(Rc4),
    RxRc4(Rc4),
    TxCfb128_128(BufEncryptor<aes::Aes128>),
    RxCfb128_128(BufDecryptor<aes::Aes128>),
    TxCfb128_192(BufEncryptor<aes::Aes192>),
    RxCfb128_192(BufDecryptor<aes::Aes192>),
    TxCfb128_256(BufEncryptor<aes::Aes256>),
    RxCfb128_256(BufDecryptor<aes::Aes256>),
    /// ChaCha20 / ChaCha20-IETF：密钥流 XOR 两个方向对称，无需区分加密解密器
    ChaChaIetf(chacha20::ChaCha20),
    ChaChaLegacy(chacha20::ChaCha20Legacy),
}

impl StreamXor {
    /// key 为连接子密钥（rc4-md5 已含 MD5 混入），iv 为本方向 IV；
    /// rx=true 表示接收方向（CFB 需用 Decryptor 反馈密文）。
    pub fn new(suite: &StreamSuite, key: &[u8], iv: &[u8], rx: bool) -> Result<Self> {
        Ok(match suite.kind {
            StreamKind::None => StreamXor::None,
            StreamKind::Rc4 | StreamKind::Rc4Md5 => {
                if rx {
                    StreamXor::RxRc4(Rc4::new(key))
                } else {
                    StreamXor::TxRc4(Rc4::new(key))
                }
            }
            StreamKind::Aes128Cfb => {
                let iv_arr = pad_iv(iv)?;
                if rx {
                    StreamXor::RxCfb128_128(BufDecryptor::new(key[..16].into(), (&iv_arr).into()))
                } else {
                    StreamXor::TxCfb128_128(BufEncryptor::new(key[..16].into(), (&iv_arr).into()))
                }
            }
            StreamKind::Aes192Cfb => {
                let iv_arr = pad_iv(iv)?;
                if rx {
                    StreamXor::RxCfb128_192(BufDecryptor::new(key[..24].into(), (&iv_arr).into()))
                } else {
                    StreamXor::TxCfb128_192(BufEncryptor::new(key[..24].into(), (&iv_arr).into()))
                }
            }
            StreamKind::Aes256Cfb => {
                let iv_arr = pad_iv(iv)?;
                if rx {
                    StreamXor::RxCfb128_256(BufDecryptor::new(key[..32].into(), (&iv_arr).into()))
                } else {
                    StreamXor::TxCfb128_256(BufEncryptor::new(key[..32].into(), (&iv_arr).into()))
                }
            }
            StreamKind::ChaCha20Ietf => {
                use cipher::KeyIvInit;
                let nonce: [u8; 12] = iv
                    .try_into()
                    .map_err(|_| Error::Config("chacha20-ietf nonce 须为 12 字节".into()))?;
                let k: [u8; 32] = key[..32]
                    .try_into()
                    .map_err(|_| Error::Config("chacha20-ietf 主密钥须为 32 字节".into()))?;
                StreamXor::ChaChaIetf(chacha20::ChaCha20::new((&k).into(), (&nonce).into()))
            }
            StreamKind::ChaCha20 => {
                use cipher::KeyIvInit;
                let nonce: [u8; 8] = iv
                    .try_into()
                    .map_err(|_| Error::Config("chacha20 nonce 须为 8 字节".into()))?;
                let k: [u8; 32] = key[..32]
                    .try_into()
                    .map_err(|_| Error::Config("chacha20 主密钥须为 32 字节".into()))?;
                StreamXor::ChaChaLegacy(chacha20::ChaCha20Legacy::new((&k).into(), (&nonce).into()))
            }
        })
    }

    /// 原地应用密钥流（发送=加密，接收=解密）
    pub fn apply(&mut self, buf: &mut [u8]) {
        use cipher::StreamCipher;
        match self {
            StreamXor::None => {}
            StreamXor::TxRc4(rc4) | StreamXor::RxRc4(rc4) => rc4.apply(buf),
            StreamXor::TxCfb128_128(c) => c.encrypt(buf),
            StreamXor::RxCfb128_128(c) => c.decrypt(buf),
            StreamXor::TxCfb128_192(c) => c.encrypt(buf),
            StreamXor::RxCfb128_192(c) => c.decrypt(buf),
            StreamXor::TxCfb128_256(c) => c.encrypt(buf),
            StreamXor::RxCfb128_256(c) => c.decrypt(buf),
            StreamXor::ChaChaIetf(c) => c.apply_keystream(buf),
            StreamXor::ChaChaLegacy(c) => c.apply_keystream(buf),
        }
    }
}

fn pad_iv(iv: &[u8]) -> Result<[u8; 16]> {
    if iv.len() > 16 {
        return Err(Error::Config("流式加密 IV 过长".into()));
    }
    let mut out = [0u8; 16];
    out[..iv.len()].copy_from_slice(iv);
    Ok(out)
}

/// RC4（KSA + PRGA）
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (x, b) in s.iter_mut().enumerate() {
            *b = x as u8;
        }
        let key = if key.is_empty() { b"\0" } else { key };
        let mut j: u8 = 0;
        for x in 0..256 {
            j = j.wrapping_add(s[x]).wrapping_add(key[x % key.len()]);
            s.swap(x, j as usize);
        }
        Rc4 { s, i: 0, j: 0 }
    }

    pub fn apply(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k =
                self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *b ^= k;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 经典 RC4 向量（key="Key"，明文全零；与标准 RC4 参考实现对拍）
    #[test]
    fn rc4_keystream_reference() {
        let mut rc4 = Rc4::new(b"Key");
        let mut buf = [0u8; 16];
        rc4.apply(&mut buf);
        assert_eq!(
            buf,
            [
                0xeb, 0x9f, 0x77, 0x81, 0xb7, 0x34, 0xca, 0x72, 0xa7, 0x19, 0x4a, 0x28, 0x67, 0xb6,
                0x42, 0x95
            ]
        );
    }

    #[test]
    fn rc4_symmetric_two_directions() {
        let (mut ta, mut tb) = (Rc4::new(b"secret"), Rc4::new(b"secret"));
        let mut msg = *b"hello stream";
        let orig = msg;
        ta.apply(&mut msg);
        assert_ne!(msg[..6], orig[..6]);
        tb.apply(&mut msg);
        assert_eq!(msg, orig);
    }

    #[test]
    fn cfb_roundtrip_partial_chunks() {
        let suite = StreamSuite::parse("aes-128-cfb").unwrap();
        let key = suite.derive_key("password");
        let iv = [7u8; 16];
        let mut tx = StreamXor::new(&suite, &key, &iv, false).unwrap();
        let mut rx = StreamXor::new(&suite, &key, &iv, true).unwrap();
        let data: Vec<u8> = (0..100u8).collect();
        let mut enc = data.clone();
        // 模拟分片发送
        tx.apply(&mut enc[..3]);
        tx.apply(&mut enc[3..40]);
        tx.apply(&mut enc[40..]);
        rx.apply(&mut enc);
        assert_eq!(enc, data);
    }

    /// 与独立参考实现（RFC 8439 block function）对拍：key=00..1f、nonce 全零、counter 0/1
    #[test]
    fn chacha20_ietf_keystream_reference() {
        let suite = StreamSuite::parse("chacha20-ietf").unwrap();
        assert_eq!((suite.key_len, suite.iv_len), (32, 12));
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let iv = [0u8; 12];
        let mut ks = StreamXor::new(&suite, &key, &iv, false).unwrap();
        let mut buf = [0u8; 128];
        ks.apply(&mut buf);
        let expect: Vec<u8> = [
            "39fd2b7dd9c5196a8dbd0377b8dc4a498a35d86fbcde6accb2cc7d4cd8ea2492",
            "2b23cce7a26023ab3f0eef693ac87f64258235eab1f7a32dc22762a0485b410c",
            "18b84231ade6a6d113615c61af434e27f8b1f3f5e1ad5b5cecf8fc122a35755c",
            "7208086dd1ee3c5d9d815824640e003c9ba0f65ede5d59ce0d2a4a7f31955acd",
        ]
        .into_iter()
        .flat_map(|h| {
            (0..h.len())
                .step_by(2)
                .map(move |i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        })
        .collect();
        assert_eq!(buf.to_vec(), expect);
    }

    #[test]
    fn chacha20_roundtrip_and_legacy_iv() {
        for name in ["chacha20-ietf", "chacha20"] {
            let suite = StreamSuite::parse(name).unwrap();
            let key = suite.derive_key("pw");
            let iv = vec![0xaau8; suite.iv_len];
            let mut tx = StreamXor::new(&suite, &key, &iv, false).unwrap();
            let mut rx = StreamXor::new(&suite, &key, &iv, true).unwrap();
            let data: Vec<u8> = (0..200u8).collect();
            let mut enc = data.clone();
            tx.apply(&mut enc[..1]);
            tx.apply(&mut enc[1..70]);
            tx.apply(&mut enc[70..]);
            rx.apply(&mut enc);
            assert_eq!(enc, data, "{name} 分片往返失败");
        }
        assert!(StreamSuite::parse("chacha20-ietf").unwrap().key_len == 32);
        assert_eq!(StreamSuite::parse("chacha20").unwrap().iv_len, 8);
    }

    #[test]
    fn rc4_md5_subkey_differs_from_master() {
        let c = StreamSuite::parse("rc4-md5").unwrap();
        let master = c.derive_key("password");
        let iv = [1u8; 16];
        let sub = c.subkey(&master, &iv);
        assert_eq!(sub.len(), 16);
        assert_ne!(sub, master);
        // cfb 子密钥 = master 本身
        let c2 = StreamSuite::parse("aes-256-cfb").unwrap();
        let m2 = c2.derive_key("password");
        assert_eq!(c2.subkey(&m2, &iv), m2);
    }
}

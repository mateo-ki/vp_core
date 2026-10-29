//! RFC 9180 HPKE —— 仅覆盖 ECH 需要的套件组合：
//! DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128/256-GCM。
//! rustls 的 ring provider 不带 HPKE（只有 aws-lc-rs 有），为避免引入 aws-lc 构建链，
//! 在现有纯 Rust 依赖（x25519-dalek/hkdf/aes-gcm）上实现 rustls 的 Hpke trait。

use std::sync::Arc;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
};
// rustls 未在稳定接口公开 HPKE 枚举（仅 aws-lc provider 内部使用），但 internal::msgs 是公开的
use rustls::internal::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
use rustls::internal::msgs::handshake::HpkeSymmetricCipherSuite;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use vp_common::{Error, Result};

const KEM_ID: u16 = 0x0020; // DHKEM(X25519, HKDF-SHA256)
const KDF_ID: u16 = 0x0001; // HKDF-SHA256
const NH: usize = 32;
const NSK: usize = 32;
const NN: usize = 12; // GCM nonce
const HPKE_V1: &[u8] = b"HPKE-v1";
const SUITE_ID_KEM: &[u8] = b"KEM\x00\x20";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Aead {
    Aes128,
    Aes256,
}

impl Aead {
    fn id(self) -> u16 {
        match self {
            Aead::Aes128 => 0x0001,
            Aead::Aes256 => 0x0002,
        }
    }
    fn nk(self) -> usize {
        match self {
            Aead::Aes128 => 16,
            Aead::Aes256 => 32,
        }
    }
}

fn err(e: impl std::fmt::Display) -> rustls::Error {
    rustls::Error::Other(rustls::OtherError(Arc::new(std::io::Error::other(
        e.to_string(),
    ))))
}

fn i2osp2(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

fn labeled_extract(salt: &[u8], suite_id: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut labeled = Vec::with_capacity(HPKE_V1.len() + suite_id.len() + label.len() + ikm.len());
    labeled.extend_from_slice(HPKE_V1);
    labeled.extend_from_slice(suite_id);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(ikm);
    // RFC 9180 Extract = 单次 HMAC(salt, labeled_ikm)；不能走 Hkdf::expand（会多套一层计数器 HMAC）
    use hmac::Mac;
    let mut mac = <hmac::Hmac<Sha256> as hmac::Mac>::new_from_slice(salt).expect("hmac 密钥合法");
    mac.update(&labeled);
    mac.finalize().into_bytes().into()
}

fn labeled_expand(
    prk: &[u8; 32],
    suite_id: &[u8],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>> {
    let mut labeled =
        Vec::with_capacity(2 + HPKE_V1.len() + suite_id.len() + label.len() + info.len());
    labeled.extend_from_slice(&i2osp2(len as u16));
    labeled.extend_from_slice(HPKE_V1);
    labeled.extend_from_slice(suite_id);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(info);
    let h = Hkdf::<Sha256>::from_prk(prk).map_err(|e| Error::ProtoMsg(format!("hpke prk: {e}")))?;
    let mut okm = vec![0u8; len];
    h.expand(&labeled, &mut okm)
        .map_err(|e| Error::ProtoMsg(format!("hpke expand: {e}")))?;
    Ok(okm)
}

/// KEM 共私密派生（RFC 9180 §4.1 ExtractAndExpand）
fn extract_and_expand(dh: &[u8; 32], kem_context: &[u8]) -> Result<[u8; 32]> {
    let prk = labeled_extract(&[], SUITE_ID_KEM, b"eae_prk", dh);
    Ok(
        labeled_expand(&prk, SUITE_ID_KEM, b"shared_secret", kem_context, NSK)?
            .try_into()
            .expect("Nsk=32"),
    )
}

/// RFC 9180 §5.1 key_schedule（mode=base，无 PSK）
struct KeySchedule {
    key: Vec<u8>,
    base_nonce: [u8; NN],
    _exporter: Vec<u8>,
}

fn key_schedule(aead: Aead, shared_secret: &[u8; 32], info: &[u8]) -> Result<KeySchedule> {
    let suite_id: Vec<u8> = {
        let mut s = b"HPKE".to_vec();
        s.extend_from_slice(&i2osp2(KEM_ID));
        s.extend_from_slice(&i2osp2(KDF_ID));
        s.extend_from_slice(&i2osp2(aead.id()));
        s
    };
    let psk_id_hash = labeled_extract(&[], &suite_id, b"psk_id_hash", b"");
    let info_hash = labeled_extract(&[], &suite_id, b"info_hash", info);
    let mut ks_context = Vec::with_capacity(1 + 32 + 32);
    ks_context.push(0x00); // mode_base
    ks_context.extend_from_slice(&psk_id_hash);
    ks_context.extend_from_slice(&info_hash);
    let secret = labeled_extract(shared_secret, &suite_id, b"secret", b"");
    let key = labeled_expand(&secret, &suite_id, b"key", &ks_context, aead.nk())?;
    let base_nonce: [u8; NN] = labeled_expand(&secret, &suite_id, b"base_nonce", &ks_context, NN)?
        .try_into()
        .expect("Nn=12");
    let exporter = labeled_expand(&secret, &suite_id, b"exp", &ks_context, NH)?;
    Ok(KeySchedule {
        key,
        base_nonce,
        _exporter: exporter,
    })
}

fn nonce_for(base_nonce: &[u8; NN], seq: u64) -> [u8; NN] {
    let mut n = *base_nonce;
    let seq_bytes = seq.to_be_bytes();
    for (i, b) in seq_bytes.iter().rev().enumerate() {
        n[NN - 1 - i] ^= b;
    }
    n
}

fn aead_seal(aead: Aead, key: &[u8], nonce: &[u8; NN], aad: &[u8], pt: &mut Vec<u8>) -> Result<()> {
    use aes_gcm::aead::generic_array::GenericArray;
    let tag =
        match aead {
            Aead::Aes128 => Aes128Gcm::new(GenericArray::from_slice(key))
                .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, pt),
            Aead::Aes256 => Aes256Gcm::new(GenericArray::from_slice(key))
                .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, pt),
        }
        .map_err(|_| Error::ProtoMsg("hpke seal 失败".into()))?;
    // HPKE 密文布局 = ciphertext || tag
    pt.extend_from_slice(&tag);
    Ok(())
}

fn aead_open(
    aead: Aead,
    key: &[u8],
    nonce: &[u8; NN],
    aad: &[u8],
    ct_and_tag: &mut Vec<u8>,
) -> Result<()> {
    use aes_gcm::aead::generic_array::GenericArray;
    if ct_and_tag.len() < 16 {
        return Err(Error::ProtoMsg("hpke 密文过短".into()));
    }
    let tag = ct_and_tag.split_off(ct_and_tag.len() - 16);
    let res = match aead {
        Aead::Aes128 => Aes128Gcm::new(GenericArray::from_slice(key)).decrypt_in_place_detached(
            Nonce::from_slice(nonce),
            aad,
            ct_and_tag,
            GenericArray::from_slice(&tag),
        ),
        Aead::Aes256 => Aes256Gcm::new(GenericArray::from_slice(key)).decrypt_in_place_detached(
            Nonce::from_slice(nonce),
            aad,
            ct_and_tag,
            GenericArray::from_slice(&tag),
        ),
    };
    res.map_err(|_| Error::ProtoMsg("hpke open 失败（密钥/AAD 不匹配）".into()))
}

/// 上下文（RFC 9180 §5.2）：密封/开启共用，序列号递增
#[derive(Debug)]
struct Context {
    aead: Aead,
    key: Vec<u8>,
    base_nonce: [u8; NN],
    seq: u64,
}

impl HpkeSealer for Context {
    fn seal(
        &mut self,
        aad: &[u8],
        plaintext: &[u8],
    ) -> std::result::Result<Vec<u8>, rustls::Error> {
        let mut buf = plaintext.to_vec();
        let nonce = nonce_for(&self.base_nonce, self.seq);
        self.seq += 1;
        aead_seal(self.aead, &self.key, &nonce, aad, &mut buf)
            .map_err(|e| err(format!("hpke seal: {e}")))?;
        Ok(buf)
    }
}

impl HpkeOpener for Context {
    fn open(
        &mut self,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> std::result::Result<Vec<u8>, rustls::Error> {
        let mut buf = ciphertext.to_vec();
        let nonce = nonce_for(&self.base_nonce, self.seq);
        self.seq += 1;
        aead_open(self.aead, &self.key, &nonce, aad, &mut buf)
            .map_err(|e| err(format!("hpke open: {e}")))?;
        Ok(buf)
    }
}

/// DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128/256-GCM
#[derive(Debug)]
pub struct HpkeX25519 {
    aead: Aead,
}

impl HpkeX25519 {
    pub const AES_128: Self = Self { aead: Aead::Aes128 };
    pub const AES_256: Self = Self { aead: Aead::Aes256 };

    fn x25519_pub(bytes: &[u8]) -> Result<XPublicKey> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::ProtoMsg("hpke 公钥须为 32 字节".into()))?;
        Ok(XPublicKey::from(arr))
    }

    fn encap(&self, pub_key: &HpkePublicKey) -> Result<(Vec<u8>, [u8; 32])> {
        let pk_r = Self::x25519_pub(&pub_key.0)?;
        let mut seed = [0u8; 32];
        vp_common::rand_bytes(&mut seed);
        let sk_e = XStaticSecret::from(seed);
        let pk_e = XPublicKey::from(&sk_e);
        let dh = sk_e.diffie_hellman(&pk_r);
        let mut kem_context = Vec::with_capacity(64);
        kem_context.extend_from_slice(pk_e.as_bytes());
        kem_context.extend_from_slice(pk_r.as_bytes());
        let shared = extract_and_expand(dh.as_bytes(), &kem_context)?;
        Ok((pk_e.as_bytes().to_vec(), shared))
    }

    fn decap(&self, enc: &[u8], secret_key: &HpkePrivateKey) -> Result<[u8; 32]> {
        let pk_e = Self::x25519_pub(enc)?;
        let sk: [u8; 32] = secret_key
            .secret_bytes()
            .try_into()
            .map_err(|_| Error::ProtoMsg("hpke 私钥须为 32 字节".into()))?;
        let sk_r = XStaticSecret::from(sk);
        let pk_r = XPublicKey::from(&sk_r);
        let dh = sk_r.diffie_hellman(&pk_e);
        let mut kem_context = Vec::with_capacity(64);
        kem_context.extend_from_slice(enc);
        kem_context.extend_from_slice(pk_r.as_bytes());
        extract_and_expand(dh.as_bytes(), &kem_context)
    }

    fn schedule(&self, shared: &[u8; 32], info: &[u8]) -> Result<Context> {
        let ks = key_schedule(self.aead, shared, info)?;
        Ok(Context {
            aead: self.aead,
            key: ks.key,
            base_nonce: ks.base_nonce,
            seq: 0,
        })
    }
}

impl Hpke for HpkeX25519 {
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        pub_key: &HpkePublicKey,
    ) -> std::result::Result<(EncapsulatedSecret, Vec<u8>), rustls::Error> {
        let (enc, shared) = self
            .encap(pub_key)
            .map_err(|e| err(format!("hpke encap: {e}")))?;
        let mut ctx = self
            .schedule(&shared, info)
            .map_err(|e| err(format!("{e}")))?;
        let ct = ctx.seal(aad, plaintext)?;
        Ok((EncapsulatedSecret(enc), ct))
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> std::result::Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), rustls::Error>
    {
        let (enc, shared) = self
            .encap(pub_key)
            .map_err(|e| err(format!("hpke encap: {e}")))?;
        let ctx = self
            .schedule(&shared, info)
            .map_err(|e| err(format!("{e}")))?;
        Ok((EncapsulatedSecret(enc), Box::new(ctx)))
    }

    fn open(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> std::result::Result<Vec<u8>, rustls::Error> {
        let shared = self
            .decap(&enc.0, secret_key)
            .map_err(|e| err(format!("hpke decap: {e}")))?;
        let mut ctx = self
            .schedule(&shared, info)
            .map_err(|e| err(format!("{e}")))?;
        ctx.open(aad, ciphertext)
    }

    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> std::result::Result<Box<dyn HpkeOpener + 'static>, rustls::Error> {
        let shared = self
            .decap(&enc.0, secret_key)
            .map_err(|e| err(format!("hpke decap: {e}")))?;
        let ctx = self
            .schedule(&shared, info)
            .map_err(|e| err(format!("{e}")))?;
        Ok(Box::new(ctx))
    }

    fn generate_key_pair(
        &self,
    ) -> std::result::Result<(HpkePublicKey, HpkePrivateKey), rustls::Error> {
        let mut seed = [0u8; 32];
        vp_common::rand_bytes(&mut seed);
        let sk = XStaticSecret::from(seed);
        let pk = XPublicKey::from(&sk);
        Ok((
            HpkePublicKey(pk.as_bytes().to_vec()),
            HpkePrivateKey::from(sk.to_bytes().to_vec()),
        ))
    }

    fn suite(&self) -> HpkeSuite {
        HpkeSuite {
            kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
            sym: HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::HKDF_SHA256,
                aead_id: match self.aead {
                    Aead::Aes128 => HpkeAead::AES_128_GCM,
                    Aead::Aes256 => HpkeAead::AES_256_GCM,
                },
            },
        }
    }
}

/// rustls EchConfig::new 可用的套件表
pub static ECH_HPKE_SUITES: &[&dyn Hpke] = &[&HpkeX25519::AES_128, &HpkeX25519::AES_256];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hpke_seal_open_roundtrip() {
        let info = b"tls ech info";
        let aad = [0xc0u8, 0xff, 0xee];
        let pt = [0xf0u8, 0x0d];
        for hpke in [&HpkeX25519::AES_128, &HpkeX25519::AES_256] {
            let (pk, sk) = hpke.generate_key_pair().unwrap();
            let (enc, mut sealer) = hpke.setup_sealer(info, &pk).unwrap();
            let ct = sealer.seal(&aad, &pt).unwrap();
            // 序列号语义：同一上下文第二条消息 seq=1，仍可按序开启
            let ct2 = sealer.seal(&aad, &pt).unwrap();
            let mut opener = hpke.setup_opener(&enc, info, &sk).unwrap();
            assert_eq!(opener.open(&aad, &ct).unwrap(), pt);
            assert_eq!(opener.open(&aad, &ct2).unwrap(), pt);
            // AAD 错误必须失败
            assert!(opener.open(&[0x00], &ct).is_err());
        }
    }

    #[test]
    fn hpke_single_shot_seal_open() {
        let hpke = &HpkeX25519::AES_128;
        let (pk, sk) = hpke.generate_key_pair().unwrap();
        let (enc, ct) = hpke.seal(b"info", b"aad", b"payload", &pk).unwrap();
        let out = hpke.open(&enc, b"info", b"aad", &ct, &sk).unwrap();
        assert_eq!(out, b"payload");
    }

    #[test]
    fn nonce_seq_xor_layout() {
        let base = [0u8; NN];
        assert_eq!(nonce_for(&base, 1), {
            let mut n = [0u8; NN];
            n[NN - 1] = 1;
            n
        });
        assert_eq!(nonce_for(&base, 256), {
            let mut n = [0u8; NN];
            n[NN - 2] = 1;
            n
        });
    }

    /// RFC 9180 Appendix A.1.1 官方向量对拍：
    /// DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM，Base 模式。
    /// encap 的随机性无法注入，从 skEm 推 dh，其余层全部逐字节对拍。
    #[test]
    fn rfc9180_a1_vectors() {
        let hex = |s: &str| {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect::<Vec<u8>>()
        };
        let tohex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        // A.1.1 Base Setup
        let sk_em = hex("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
        let pk_em = hex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
        let pk_rm = hex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
        let expect_shared = hex("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");
        let sk_e = XStaticSecret::from(<[u8; 32]>::try_from(sk_em.as_slice()).unwrap());
        let pk_r = XPublicKey::from(<[u8; 32]>::try_from(pk_rm.as_slice()).unwrap());
        let dh = sk_e.diffie_hellman(&pk_r);
        println!("dh      = {}", tohex(dh.as_bytes()));
        let mut kem_context = Vec::with_capacity(64);
        kem_context.extend_from_slice(&pk_em);
        kem_context.extend_from_slice(pk_r.as_bytes());
        println!("kem_ctx = {}", tohex(&kem_context));
        let shared = extract_and_expand(dh.as_bytes(), &kem_context).unwrap();
        println!("shared  = {}", tohex(&shared));
        assert_eq!(shared.to_vec(), expect_shared, "shared_secret 不匹配");

        let info = hex("4f6465206f6e2061204772656369616e2055726e");
        let ks = key_schedule(Aead::Aes128, &shared, &info).unwrap();
        let expect_key = hex("4531685d41d65f03dc48f6b8302c05b0");
        let expect_nonce = hex("56d890e5accaaf011cff4b7d");
        let expect_exporter =
            hex("45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8");
        assert_eq!(ks.key, expect_key, "key 不匹配");
        assert_eq!(&ks.base_nonce[..], &expect_nonce[..], "base_nonce 不匹配");
        assert_eq!(ks._exporter, expect_exporter, "exporter_secret 不匹配");

        // A.1.1.1 Encryptions（seq 0/1/2）
        let pt = hex("4265617574792069732074727574682c20747275746820626561757479");
        let cts = [
            hex(
                "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
            ),
            hex(
                "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84",
            ),
            hex(
                "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180",
            ),
        ];
        let mut ctx = Context {
            aead: Aead::Aes128,
            key: ks.key.clone(),
            base_nonce: ks.base_nonce,
            seq: 0,
        };
        for (i, expect_ct) in cts.iter().enumerate() {
            let aad = format!("Count-{i}").into_bytes();
            let ct = ctx.seal(&aad, &pt).unwrap();
            assert_eq!(&ct, expect_ct, "seq {i} 密文不匹配");
        }
    }
}

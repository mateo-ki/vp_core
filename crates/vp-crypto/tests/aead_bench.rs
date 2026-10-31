//! AEAD 微基准：裸加解密吞吐（单核）。判据：≥1 GB/s = 已吃满 AES-NI/AVX2 硬件路径，
//! 换 C/asm 库（ring/BoringSSL）不会有量级收益；几百 MB/s = 有优化空间。
use std::time::Instant;

const SIZE: usize = 64 * 1024 * 1024; // 64MB 明文，跑 3 轮取最好

#[test]
#[ignore = "基准压测：手动执行 cargo test -p vp-crypto --test aead_bench -- --ignored --nocapture"]
fn aead_throughput_report() {
    use aes_gcm::aead::Aead;
    use aes_gcm::{AesGcm, KeyInit, Nonce};
    type Aes128Gcm = AesGcm<aes::Aes128, aes_gcm::aead::consts::U12>;
    let key = [0x42u8; 16];
    let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
    let nonce = Nonce::from_slice(&[7u8; 12]);
    let plain = vec![0xa5u8; SIZE];
    let mut best = f64::MAX;
    for _ in 0..3 {
        let t = Instant::now();
        let ct = cipher.encrypt(nonce, &plain[..]).unwrap();
        let pt = cipher.decrypt(nonce, &ct[..]).unwrap();
        let dt = t.elapsed().as_secs_f64();
        assert_eq!(pt.len(), SIZE);
        best = best.min(dt);
    }
    println!(
        "[AEAD] aes-128-gcm: {:.0} MB/s (加+解合计)",
        SIZE as f64 * 2.0 / best / 1048576.0
    );

    use chacha20poly1305::ChaCha20Poly1305;
    let key2 = [0x42u8; 32];
    let cipher2 = ChaCha20Poly1305::new_from_slice(&key2).unwrap();
    let mut best2 = f64::MAX;
    for _ in 0..3 {
        let t = Instant::now();
        let ct = cipher2.encrypt(nonce, &plain[..]).unwrap();
        let pt = cipher2.decrypt(nonce, &ct[..]).unwrap();
        let dt = t.elapsed().as_secs_f64();
        assert_eq!(pt.len(), SIZE);
        best2 = best2.min(dt);
    }
    println!(
        "[AEAD] chacha20-ietf-poly1305: {:.0} MB/s (加+解合计)",
        SIZE as f64 * 2.0 / best2 / 1048576.0
    );
}

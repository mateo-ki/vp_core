//! MASQUE 注册 API 探针：实测 api.cloudflareclient.com 的注册响应结构，
//! 决定数据面认证设计（mTLS 客户端证书 vs Bearer token）。
//! 依赖真实网络，`cargo test -p vp-protocol --test masque_probe -- --ignored --nocapture` 手动运行。

use base64::Engine;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};

const API_VERSIONS: &[&str] = &["v0a4005", "v0a2507", "v0a2158"];

/// wgcf / warp-plus 风格注册体：key 为 EC P-256 公钥（SPKI DER base64）时走 MASQUE
fn register_body(spki_b64: &str) -> serde_json::Value {
    serde_json::json!({
        "fcm_token": "",
        "install_id": "",
        "key": spki_b64,
        "locale": "en_US",
        "model": "PC",
        "tos": "2024-01-01T00:00:00.000Z",
        "type": "Android",
        "warp_enabled": true,
    })
}

#[test]
#[ignore]
fn probe_warp_masque_registration() {
    // 1. 生成 P-256 密钥对，导出 PKCS8 私钥 / SPKI 公钥（与真实订阅节点字段格式一致）
    let signing = p256::ecdsa::SigningKey::from_slice(&{
        use p256::SecretKey;
        use p256::elliptic_curve::rand_core::OsRng;
        SecretKey::random(&mut OsRng).to_bytes()
    })
    .unwrap();
    let priv_b64 = base64::engine::general_purpose::STANDARD
        .encode(signing.to_pkcs8_der().unwrap().as_bytes());
    let pub_b64 = base64::engine::general_purpose::STANDARD.encode(
        signing
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes(),
    );
    println!("private-key (PKCS8): {priv_b64}");
    println!("public-key  (SPKI):  {pub_b64}");

    // 2. 依次尝试 API 版本注册
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(30))
        .build();
    for ver in API_VERSIONS {
        let url = format!("https://api.cloudflareclient.com/{ver}/reg");
        let req_body = serde_json::to_string(&register_body(&pub_b64)).unwrap();
        let resp = agent
            .post(&url)
            .set("User-Agent", "okhttp/3.12.1")
            .set("Content-Type", "application/json")
            .send_string(&req_body);
        match resp {
            Ok(r) => {
                let status = r.status();
                let body = r.into_string().unwrap_or_default();
                println!("\n=== {ver} → HTTP {status} ===");
                // 美化输出关键字段（完整体打印便于分析，但不应提交到仓库）
                match serde_json::from_str::<serde_json::Value>(&body) {
                    Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
                    Err(_) => println!("非 JSON 响应: {body}"),
                }
                assert!(status == 200 || status == 201, "{ver} 注册失败: {status}");
                return;
            }
            Err(ureq::Error::Status(code, r)) => {
                let body = r.into_string().unwrap_or_default();
                println!("\n=== {ver} → HTTP {code} (拒绝) ===");
                println!("{body}");
            }
            Err(e) => println!("\n=== {ver} → 网络错误: {e} ==="),
        }
    }
    panic!("所有 API 版本注册均失败");
}

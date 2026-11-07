use std::fs;
use std::process::Command;

#[test]
fn test_cli_validate_and_explain_vp_dsl() {
    let unique_id = format!(
        "vp_test_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let temp_dir = std::env::temp_dir().join(unique_id);
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let dsl_path = temp_dir.join("config.vp");

    let dsl_content = r#"
inbound mixed {
    listen: "127.0.0.1:27890"
}

node "us-01" ss {
    server: "1.2.3.4:8388"
    cipher: "aes-128-gcm"
    password: "secretpassword"
}

group "PROXY" select {
    members: ["us-01", "DIRECT"]
}

route {
    process.name == "git" => "PROXY"
    host.endsWith(".google.com") => "PROXY"
    dst.ip in "127.0.0.0/8" => "DIRECT"
    _ => "PROXY"
}
"#;

    fs::write(&dsl_path, dsl_content).expect("write config.vp");

    let vpcore_bin = env!("CARGO_BIN_EXE_vpcore");

    // 1. 验证 vpcore validate -c config.vp
    let validate_output = Command::new(vpcore_bin)
        .arg("validate")
        .arg("-c")
        .arg(&dsl_path)
        .output()
        .expect("run vpcore validate");

    assert!(
        validate_output.status.success(),
        "validate failed: {}",
        String::from_utf8_lossy(&validate_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&validate_output.stdout);
    assert!(
        stdout.contains("配置有效（VP DSL）"),
        "stdout was: {}",
        stdout
    );

    // 2. 验证 vpcore explain https://www.google.com -c config.vp --json
    let explain_output = Command::new(vpcore_bin)
        .arg("explain")
        .arg("https://www.google.com")
        .arg("-c")
        .arg(&dsl_path)
        .arg("--json")
        .output()
        .expect("run vpcore explain");

    assert!(
        explain_output.status.success(),
        "explain failed: {}",
        String::from_utf8_lossy(&explain_output.stderr)
    );
    let explain_json = String::from_utf8_lossy(&explain_output.stdout);
    assert!(
        explain_json.contains("\"target\": \"PROXY\"")
            || explain_json.contains("\"target\":\"PROXY\""),
        "explain json was: {}",
        explain_json
    );

    // 3. 验证无效 DSL 时 validate 返回失败
    let bad_dsl_path = temp_dir.join("bad.vp");
    fs::write(
        &bad_dsl_path,
        "inbound mixed { listen: 12345 } unknown_syntax !!!",
    )
    .unwrap();

    let bad_validate = Command::new(vpcore_bin)
        .arg("validate")
        .arg("-c")
        .arg(&bad_dsl_path)
        .output()
        .expect("run vpcore validate bad");

    assert!(!bad_validate.status.success());
    let stderr = String::from_utf8_lossy(&bad_validate.stderr);
    assert!(
        stderr.contains("VP DSL 语法解析失败") || stderr.contains("配置语义无效"),
        "stderr was: {}",
        stderr
    );

    // 清理临时文件
    let _ = fs::remove_dir_all(&temp_dir);
}

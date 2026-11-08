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

#[test]
fn test_cli_convert_and_fmt() {
    let unique_id = format!(
        "vp_fmt_test_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let temp_dir = std::env::temp_dir().join(unique_id);
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let yaml_path = temp_dir.join("input.yaml");
    let yaml_content = r#"
mixed-port: 7890
mode: rule
log-level: info
proxies:
  - name: "node-1"
    type: ss
    server: 1.1.1.1
    port: 8388
    cipher: aes-128-gcm
    password: "secretpassword"
    udp: true
proxy-groups:
  - name: "PROXY"
    type: select
    proxies:
      - "node-1"
      - "DIRECT"
rules:
  - DOMAIN-SUFFIX,google.com,PROXY
  - MATCH,DIRECT
"#;
    fs::write(&yaml_path, yaml_content).expect("write input.yaml");

    let vpcore_bin = env!("CARGO_BIN_EXE_vpcore");

    // 1. 测试 vpcore convert: YAML -> VP DSL
    let converted_vp = temp_dir.join("converted.vp");
    let convert_out = Command::new(vpcore_bin)
        .arg("convert")
        .arg("-i")
        .arg(&yaml_path)
        .arg("-o")
        .arg(&converted_vp)
        .output()
        .expect("run vpcore convert YAML -> VP");

    assert!(
        convert_out.status.success(),
        "convert YAML -> VP failed: {}",
        String::from_utf8_lossy(&convert_out.stderr)
    );
    assert!(converted_vp.exists());

    // 2. 校验转换生成的 VP DSL 配置合法性
    let val_out = Command::new(vpcore_bin)
        .arg("validate")
        .arg("-c")
        .arg(&converted_vp)
        .output()
        .expect("validate converted.vp");
    assert!(val_out.status.success(), "converted.vp validation failed");

    // 3. 验证 vpcore fmt --check 在生成的规范 DSL 上应当直接通过
    let check_out = Command::new(vpcore_bin)
        .arg("fmt")
        .arg("--check")
        .arg(&converted_vp)
        .output()
        .expect("fmt --check converted.vp");
    assert!(
        check_out.status.success(),
        "fmt --check should pass on generated DSL: {}",
        String::from_utf8_lossy(&check_out.stderr)
    );

    // 4. 验证 vpcore fmt 格式化未对齐/单行代码
    let unformatted_path = temp_dir.join("unformatted.vp");
    fs::write(
        &unformatted_path,
        "node \"test\" ss { server: \"2.2.2.2\" port: 1080 cipher: \"aes-128-gcm\" password: \"pass\" udp: true }\n",
    )
    .expect("write unformatted");

    // 未格式化前 --check 应当报错退出码 1
    let check_bad = Command::new(vpcore_bin)
        .arg("fmt")
        .arg("--check")
        .arg(&unformatted_path)
        .output()
        .expect("fmt --check unformatted");
    assert!(!check_bad.status.success());

    // 执行 -w 原地格式化
    let write_fmt = Command::new(vpcore_bin)
        .arg("fmt")
        .arg("-w")
        .arg(&unformatted_path)
        .output()
        .expect("fmt -w");
    assert!(write_fmt.status.success());

    // 格式化后再 check 应当成功
    let check_good = Command::new(vpcore_bin)
        .arg("fmt")
        .arg("--check")
        .arg(&unformatted_path)
        .output()
        .expect("fmt --check after write");
    assert!(check_good.status.success());

    let formatted_content = fs::read_to_string(&unformatted_path).unwrap();
    assert!(formatted_content.contains("node \"test\" ss {"));
    assert!(formatted_content.contains("    server: \"2.2.2.2\""));

    // 5. 测试 vpcore convert: VP DSL -> YAML
    let back_yaml = temp_dir.join("back.yaml");
    let convert_back = Command::new(vpcore_bin)
        .arg("convert")
        .arg("-i")
        .arg(&converted_vp)
        .arg("-o")
        .arg(&back_yaml)
        .output()
        .expect("convert VP -> YAML");
    assert!(convert_back.status.success());
    assert!(back_yaml.exists());

    let _ = fs::remove_dir_all(&temp_dir);
}

/// convert / fmt 鲁棒性模糊测试：各种畸形输入必须优雅报错退出，绝不允许 panic 崩溃。
#[test]
fn test_cli_convert_chaos_inputs_never_panic() {
    let unique_id = format!(
        "vp_chaos_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let temp_dir = std::env::temp_dir().join(unique_id);
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let vpcore_bin = env!("CARGO_BIN_EXE_vpcore");

    // (描述, 文件名, 内容, 传给 convert 的额外参数)
    let chaos_cases: Vec<(&str, &str, Vec<u8>, Vec<&str>)> = vec![
        ("空文件", "empty.yaml", b"".to_vec(), vec![]),
        (
            "二进制垃圾",
            "garbage.yaml",
            vec![0xFF, 0xFE, 0x00, 0x01, 0x9C, 0xDE, 0xAD],
            vec![],
        ),
        (
            "截断 YAML",
            "truncated.yaml",
            b"mixed-port: 7890\nproxies:\n  - name: \"cut-off".to_vec(),
            vec![],
        ),
        (
            "YAML 制表符缩进",
            "tabs.yaml",
            b"mixed-port: 7890\nproxies:\n\t- name: bad\n\t  type: ss\n".to_vec(),
            vec![],
        ),
        (
            "JSON 字段类型错误",
            "wrong_type.json",
            br#"{"proxies": 42, "rules": "not-a-list"}"#.to_vec(),
            vec![],
        ),
        (
            "JSON 截断",
            "truncated.json",
            br#"{"mixed-port": 7890, "proxies": [{"name":"a""#.to_vec(),
            vec![],
        ),
        (
            "DSL 未闭合大括号",
            "unclosed.vp",
            b"inbound mixed {\n    listen: \"127.0.0.1:7890\"\n".to_vec(),
            vec![],
        ),
        (
            "DSL 非法规则语法",
            "bad_rule.vp",
            b"route {\n    host.invalid_cel_syntax( &&& => \"PROXY\"\n}\n".to_vec(),
            vec![],
        ),
        (
            "格式不匹配 (from vp 但内容是 yaml)",
            "mismatch.yaml",
            b"mixed-port: 7890\n".to_vec(),
            vec!["--from", "vp"],
        ),
        (
            "不支持的输出格式",
            "fine.yaml",
            b"mixed-port: 7890\n".to_vec(),
            vec!["--to", "xml"],
        ),
    ];

    for (desc, filename, content, extra_args) in &chaos_cases {
        let path = temp_dir.join(filename);
        fs::write(&path, content).unwrap_or_else(|e| panic!("写入 {desc} 失败: {e}"));

        let out = Command::new(vpcore_bin)
            .arg("convert")
            .arg("-i")
            .arg(&path)
            .args(extra_args)
            .output()
            .unwrap_or_else(|e| panic!("执行 convert ({desc}) 失败: {e}"));

        assert!(
            !out.status.success(),
            "{desc}: 畸形输入不应转换成功 (exit code: {:?})",
            out.status.code()
        );
        // Rust panic 退出码为 101；同时检查 stderr 中不允许出现 panic 痕迹
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_ne!(
            out.status.code(),
            Some(101),
            "{desc}: convert 发生 panic 崩溃!\nstderr: {stderr}"
        );
        assert!(
            !stderr.contains("panicked at"),
            "{desc}: stderr 中出现 panic 痕迹: {stderr}"
        );
    }

    // fmt 对畸形 DSL 也必须优雅报错而非 panic
    let bad_dsl = temp_dir.join("chaos_fmt.vp");
    fs::write(&bad_dsl, b"inbound mixed { listen: } node ### broken").unwrap();
    let fmt_out = Command::new(vpcore_bin)
        .arg("fmt")
        .arg(&bad_dsl)
        .output()
        .expect("run fmt on chaos");
    assert!(!fmt_out.status.success());
    let fmt_stderr = String::from_utf8_lossy(&fmt_out.stderr);
    assert!(
        !fmt_stderr.contains("panicked at"),
        "fmt 对畸形 DSL 发生 panic: {fmt_stderr}"
    );

    // 不存在的输入文件必须以退出码 2 优雅失败
    let missing = Command::new(vpcore_bin)
        .arg("convert")
        .arg("-i")
        .arg(temp_dir.join("definitely_not_exists.yaml"))
        .output()
        .expect("convert missing file");
    assert_eq!(missing.status.code(), Some(2));

    let _ = fs::remove_dir_all(&temp_dir);
}

/// sub 端到端：本地 mock HTTP 订阅服务器 -> vpcore sub 拉取 -> 直出 .vp DSL -> validate/fmt 门禁全通过。
#[test]
fn test_cli_sub_local_mock_subscription_to_vp_dsl() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let unique_id = format!(
        "vp_sub_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let temp_dir = std::env::temp_dir().join(unique_id);
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    // 启动一次性 mock 订阅服务器（仅服务单个请求）
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let port = listener.local_addr().unwrap().port();
    let body = "mixed-port: 7890\nmode: rule\nlog-level: info\nproxies:\n  - name: \"sub-node-1\"\n    type: ss\n    server: 5.5.5.5\n    port: 8388\n    cipher: aes-128-gcm\n    password: \"subpass\"\n    udp: true\n  - name: \"sub-node-2\"\n    type: trojan\n    server: 6.6.6.6\n    port: 443\n    password: \"trojan-pass\"\n    sni: \"sub.example.com\"\n";
    let server_thread = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/yaml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    let output_vp = temp_dir.join("sub_out.vp");
    let vpcore_bin = env!("CARGO_BIN_EXE_vpcore");

    let sub_out = Command::new(vpcore_bin)
        .arg("sub")
        .arg(format!("http://127.0.0.1:{port}/sub"))
        .arg("-o")
        .arg(&output_vp)
        .output()
        .expect("run vpcore sub");
    let _ = server_thread.join();

    assert!(
        sub_out.status.success(),
        "sub 拉取失败: {}",
        String::from_utf8_lossy(&sub_out.stderr)
    );
    let sub_stdout = String::from_utf8_lossy(&sub_out.stdout);
    assert!(
        sub_stdout.contains("VP DSL"),
        "sub 输出应标注 VP DSL 格式: {sub_stdout}"
    );

    let dsl_content = fs::read_to_string(&output_vp).expect("read sub output");
    assert!(
        dsl_content.contains("node \"sub-node-1\" ss {"),
        "订阅节点应生成规范 DSL: {dsl_content}"
    );
    assert!(
        dsl_content.contains("node \"sub-node-2\" trojan {"),
        "trojan 订阅节点应生成规范 DSL: {dsl_content}"
    );
    assert!(
        dsl_content.contains("group \"PROXY\" select {"),
        "订阅生成的 PROXY 组应存在: {dsl_content}"
    );

    // 生成的 DSL 必须同时通过 validate 与 fmt --check 双门禁
    let val = Command::new(vpcore_bin)
        .arg("validate")
        .arg("-c")
        .arg(&output_vp)
        .output()
        .expect("validate sub output");
    assert!(val.status.success(), "订阅直出 DSL 校验失败");

    let chk = Command::new(vpcore_bin)
        .arg("fmt")
        .arg("--check")
        .arg(&output_vp)
        .output()
        .expect("fmt --check sub output");
    assert!(
        chk.status.success(),
        "订阅直出 DSL 必须已是规范格式: {}",
        String::from_utf8_lossy(&chk.stderr)
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

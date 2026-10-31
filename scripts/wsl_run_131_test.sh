#!/bin/bash
# v1.3.1 修复的 WSL 验证：同步改动文件到 vpc-ci 工作区后跑 vp-dns / vp-transport 测试
set -e
export PATH="$HOME/.cargo/bin:$PATH"
T=/home/loukas/vpc-ci
D=/mnt/d/project/rust/VP_Core
cp "$D/crates/vp-dns/src/lib.rs"        "$T/crates/vp-dns/src/lib.rs"
cp "$D/crates/vp-transport/src/lib.rs"  "$T/crates/vp-transport/src/lib.rs"
cp "$D/crates/vp-transport/src/tls.rs"  "$T/crates/vp-transport/src/tls.rs"
cp "$D/crates/vp-tun/src/auto_route.rs" "$T/crates/vp-tun/src/auto_route.rs"
cp "$D/Cargo.toml" "$D/Cargo.lock" "$T/"
cd "$T"
echo "== cargo test vp-dns + vp-transport =="
cargo test -p vp-dns -p vp-transport 2>&1 | grep -E "test result|FAILED|error\[|^error" | head -12
echo "== cargo check --workspace（Linux 编译面）=="
cargo check --workspace 2>&1 | grep -E "^error|warning: unused|Finished" | head -10
echo "== WSL verify done =="

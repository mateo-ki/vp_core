#!/usr/bin/env bash
# vpcore↔mihomo 跨内核互操作矩阵驱动（AGENTS.md 规则6 可执行化）
#
# 用法: run_matrix.sh <vpcore_bin> <mihomo_bin> [输出目录]
#
# 方向A: vpcore 作服务端(18501-18514)，mihomo 作客户端逐协议切换 → curl --noproxy "" 过 mixed:17880
# 方向B: mihomo 作服务端(18601-18613)，vpcore test 全节点探测 → 全部必须出延迟
# 额外: B-naive / B-brook 打 vpcore 服务端（mihomo 无对应监听），作内核自洽校验
set -uo pipefail

VPCORE_BIN="${1:?用法: run_matrix.sh <vpcore_bin> <mihomo_bin> [out_dir]}"
MIHOMO_BIN="${2:?缺少 mihomo_bin}"
OUT_DIR="${3:-target/matrix_run}"
VPCORE_BIN="$(cd "$(dirname "$VPCORE_BIN")" && pwd)/$(basename "$VPCORE_BIN")"
MIHOMO_BIN="$(cd "$(dirname "$MIHOMO_BIN")" && pwd)/$(basename "$MIHOMO_BIN")"

PY="$(command -v python3 || command -v python)"
[ -x "$PY" ] || { echo "✗ 需要 python3"; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---- 预检：端口残留（AGENTS 纪律：残留实例曾污染测试结果）----
for port in 17880 17899 18501 18601 18700 18999 19090 19099; do
  if command -v netstat >/dev/null 2>&1 && netstat -an 2>/dev/null | grep -q "[:.]${port}[[:space:]].*LISTEN"; then
    echo "✗ 端口 $port 已被占用（残留实例），先清点 netstat -ano 并精确清理"
    exit 2
  fi
done

"$PY" "$SCRIPT_DIR/gen_matrix.py" "$OUT_DIR" || exit 2
mkdir -p "$OUT_DIR/mh_client_home" "$OUT_DIR/mh_server_home"

PASS=0; FAIL=0; FAILED_LIST=()
report() {
  if [ "$1" = 0 ]; then PASS=$((PASS+1)); echo "  ✓ $2"; else FAIL=$((FAIL+1)); FAILED_LIST+=("$2"); echo "  ✗ $2"; fi
}

"$PY" "$SCRIPT_DIR/echo_204.py" 18999 & TARGET_PID=$!
A_VP_PID=""; A_MH_PID=""; B_MH_PID=""; B_VP_PID=""
cleanup() {
  # 按 PID 精确清理（禁用过宽的 CommandLine 模糊匹配 —— 历史误杀教训）
  for p in "${A_VP_PID:-}" "${A_MH_PID:-}" "${B_MH_PID:-}" "${B_VP_PID:-}" "${TARGET_PID:-}"; do
    [ -n "$p" ] && kill "$p" 2>/dev/null && wait "$p" 2>/dev/null
  done
}
trap cleanup EXIT

wait_tcp() {
  local port="$1"
  local label="$2"
  for _ in $(seq 1 30); do
    if "$PY" -c "import socket, sys; s = socket.create_connection(('127.0.0.1', int(sys.argv[1])), 0.5); s.close()" "$port" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  echo "  （警告: $label 端口 $port 15s 内未就绪）"
  return 1
}

sleep 0.5
wait_tcp 18999 "echo_204" || true

# ==================== 方向 A：vpcore 服务端 ← mihomo 客户端 ====================
echo "==> 方向A: vpcore 服务端 + mihomo 客户端"
"$VPCORE_BIN" run -c "$OUT_DIR/vpcore_server.yaml" >"$OUT_DIR/dir_a_vpcore.log" 2>&1 & A_VP_PID=$!
"$MIHOMO_BIN" -d "$OUT_DIR/mh_client_home" -f "$OUT_DIR/mihomo_client.yaml" >"$OUT_DIR/dir_a_mihomo.log" 2>&1 & A_MH_PID=$!

# 等 vpcore 服务端、mihomo 控制器与 mixed 口均就绪（最多 15s）
wait_tcp 18501 "vpcore_server" || true
wait_tcp 19090 "mihomo_client_ctrl" || true
ready=0
for _ in $(seq 1 30); do
  if curl -s --noproxy "" -x http://127.0.0.1:17880 -o /dev/null --max-time 2 http://127.0.0.1:18999/generate_204 2>/dev/null; then ready=1; break; fi
  sleep 0.5
done
[ "$ready" = 1 ] || echo "  （mihomo mixed 口尚未就绪，继续逐协议尝试）"

for node in A-socks A-http A-ss A-ss22 A-vmess A-vless A-trojan A-anytls A-mieru A-snell A-tuic A-hy2; do
  curl -s --noproxy "" -X PUT -H 'Content-Type: application/json' \
    -d "{\"name\":\"$node\"}" http://127.0.0.1:19090/proxies/GLOBAL >/dev/null 2>&1
  code="$(curl -s --noproxy "" -x http://127.0.0.1:17880 -o /dev/null -w '%{http_code}' \
    --max-time 10 http://127.0.0.1:18999/generate_204 2>/dev/null || echo 000)"
  report "$([ "$code" = 204 ] && echo 0 || echo 1)" "A/$node → HTTP $code"
done

kill "$A_VP_PID" "$A_MH_PID" 2>/dev/null; wait "$A_VP_PID" "$A_MH_PID" 2>/dev/null
A_VP_PID=""; A_MH_PID=""
sleep 1

# ==================== 方向 B：mihomo 服务端 ← vpcore 客户端 ====================
echo "==> 方向B: mihomo 服务端 + vpcore test 探测"
# 证书在 $OUT_DIR 内，-d 必须指 OUT_DIR（mihomo 拒绝加载 home 目录外证书：SAFE_PATHS 校验）
"$MIHOMO_BIN" -d "$OUT_DIR" -f "$OUT_DIR/mihomo_server.yaml" >"$OUT_DIR/dir_b_mihomo.log" 2>&1 & B_MH_PID=$!
# B-naive / B-brook 打 vpcore 服务端监听（18513/18514）作内核自洽校验——需同场运行
"$VPCORE_BIN" run -c "$OUT_DIR/vpcore_server.yaml" >"$OUT_DIR/dir_b_vpcore.log" 2>&1 & B_VP_PID=$!
wait_tcp 19099 "mihomo_server_ctrl" || true
wait_tcp 18601 "mihomo_server_socks" || true
wait_tcp 18513 "vpcore_server_naive" || true
sleep 0.5

"$VPCORE_BIN" test -c "$OUT_DIR/vpcore_client.yaml" >"$OUT_DIR/dir_b.log" 2>&1
B_EXIT=$?
grep -E "组 MATRIX" "$OUT_DIR/dir_b.log" >/dev/null || echo "  （vpcore test 输出异常，exit=$B_EXIT，详见 $OUT_DIR/dir_b.log）"

for node in B-socks B-http B-ss B-ss22 B-vmess B-vless B-trojan B-anytls B-mieru B-snell B-tuic B-hy2 B-naive B-brook; do
  line="$(grep -E "^\s+${node}\s" "$OUT_DIR/dir_b.log" | tail -1)"
  case "$line" in
    *失败) report 1 "B/$node → $line" ;;
    *ms*)  report 0 "B/$node → $line" ;;
    "")    report 1 "B/$node → 未在输出中找到" ;;
  esac
done

kill "$B_MH_PID" "$B_VP_PID" 2>/dev/null; wait "$B_MH_PID" "$B_VP_PID" 2>/dev/null
B_MH_PID=""; B_VP_PID=""

# ==================== 汇总 ====================
echo "=============================================="
echo "矩阵结果: PASS=$PASS FAIL=$FAIL  输出目录: $OUT_DIR"
if [ "$FAIL" -gt 0 ]; then
  echo "失败项: ${FAILED_LIST[*]}"
  echo "--- dir_b.log ---"
  cat "$OUT_DIR/dir_b.log" 2>/dev/null || true
  for f in "$OUT_DIR"/dir_*.log; do
    [ "$f" = "$OUT_DIR/dir_b.log" ] && continue
    echo "--- $(basename "$f") (tail 30) ---"
    tail -n 30 "$f" 2>/dev/null || true
  done
  exit 1
fi
echo "✓ 跨内核矩阵全绿"

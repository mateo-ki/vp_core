# -*- coding: utf-8 -*-
"""生成 vpcore↔mihomo 跨内核互操作矩阵全套配置与凭据（AGENTS.md 规则6 可执行化）。

用法:
  python3 gen_matrix.py <输出目录>            # 默认 target/matrix_run

输出:
  cert.pem / key.pem         自签证书 (CN=local.test, SAN 127.0.0.1)
  vpcore_server.yaml         vpcore 监听器 18501-18514（方向A服务端：mihomo 客户端连它）
  mihomo_server.yaml         mihomo 监听器 18601-18613（方向B服务端：vpcore 客户端连它）
  mihomo_client.yaml         mihomo 客户端配置（方向A：mixed 17880，控制器 19090）
  vpcore_client.yaml         vpcore 客户端配置（方向B：mixed 18700，SELECT 组带测速 url）

端口约定避开常用段：mihomo 客户端 mixed 17880 / 控制器 19090
（17898 是用户常用 mihomo 端口，历史教训：端口冲突会污染本地实测结果）。
"""
import base64
import os
import subprocess
import sys

OUT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "target/matrix_run")
os.makedirs(OUT, exist_ok=True)

# ---- 凭据（纯回环测试用假凭据，无真实敏感信息）----
SS256_PW = "matrix-ss256-pw"
SS22_256_PSK = base64.b64encode(bytes(range(32))).decode()  # 32B
VMESS_UUID = "23ad6b10-8d1a-40f7-8ad0-e3e35cd38297"
VLESS_UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
TROJAN_PW = "matrix-trojan-pw"
ANYTLS_PW = "matrix-anytls-pw"
MIERU_USER, MIERU_PASS = "matrix", "mieru-pass"
SNELL_PSK = "matrix-snell-psk"
TUIC_PW = "matrix-tuic-pw"
HY2_PW = "matrix-hy2-pw"
NAIVE_USER, NAIVE_PASS = "matrix", "naive-pass"
BROOK_PW = "matrix-brook-pw"

CERT = os.path.join(OUT, "cert.pem").replace("\\", "/")
KEY = os.path.join(OUT, "key.pem").replace("\\", "/")

# ---- 证书 ----
if not os.path.exists(CERT):
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", KEY, "-out", CERT, "-days", "365",
         "-subj", "/CN=local.test",
         "-addext", "subjectAltName=DNS:local.test,IP:127.0.0.1"],
        check=True, capture_output=True,
    )


def write(name, text):
    path = os.path.join(OUT, name)
    with open(path, "w", newline="\n", encoding="utf-8") as f:
        f.write(text)
    return path


# ---- vpcore 服务端（方向 A）----
write("vpcore_server.yaml", f"""listeners:
  - {{name: A-socks, type: socks5, listen: 127.0.0.1, port: 18501}}
  - {{name: A-http, type: http, listen: 127.0.0.1, port: 18502}}
  - {{name: A-ss, type: ss, listen: 127.0.0.1, port: 18503, cipher: aes-256-gcm, users: ["{SS256_PW}"]}}
  - {{name: A-ss22, type: ss, listen: 127.0.0.1, port: 18504, cipher: 2022-blake3-aes-256-gcm, users: ["{SS22_256_PSK}"]}}
  - {{name: A-vmess, type: vmess, listen: 127.0.0.1, port: 18505, users: ["{VMESS_UUID}"]}}
  - {{name: A-vless, type: vless, listen: 127.0.0.1, port: 18506, users: ["{VLESS_UUID}"]}}
  - {{name: A-trojan, type: trojan, listen: 127.0.0.1, port: 18507, cert: "{CERT}", key: "{KEY}", users: ["{TROJAN_PW}"]}}
  - {{name: A-anytls, type: anytls, listen: 127.0.0.1, port: 18508, cert: "{CERT}", key: "{KEY}", users: ["{ANYTLS_PW}"]}}
  - {{name: A-mieru, type: mieru, listen: 127.0.0.1, port: 18509, users: ["{MIERU_USER}:{MIERU_PASS}"]}}
  - {{name: A-snell, type: snell, listen: 127.0.0.1, port: 18510, users: ["{SNELL_PSK}"]}}
  - {{name: A-tuic, type: tuic, listen: 127.0.0.1, port: 18511, cert: "{CERT}", key: "{KEY}", users: ["{VMESS_UUID}:{TUIC_PW}"]}}
  - {{name: A-hy2, type: hysteria2, listen: 127.0.0.1, port: 18512, cert: "{CERT}", key: "{KEY}", users: ["{HY2_PW}"]}}
  - {{name: A-naive, type: naive, listen: 127.0.0.1, port: 18513, cert: "{CERT}", key: "{KEY}", users: ["{NAIVE_USER}:{NAIVE_PASS}"]}}
  - {{name: A-brook, type: brook, listen: 127.0.0.1, port: 18514, users: ["{BROOK_PW}"]}}
rules:
  - MATCH,DIRECT
""")

# ---- mihomo 服务端（方向 B；mihomo 不支持 naive/brook 监听）----
write("mihomo_server.yaml", f"""mixed-port: 17899
external-controller: 127.0.0.1:19099
mode: global
log-level: warning
listeners:
  - {{name: B-socks, type: socks, port: 18601, listen: 127.0.0.1}}
  - {{name: B-http, type: http, port: 18602, listen: 127.0.0.1}}
  - {{name: B-ss, type: shadowsocks, port: 18603, listen: 127.0.0.1, cipher: aes-256-gcm, password: "{SS256_PW}", udp: true}}
  - {{name: B-ss22, type: shadowsocks, port: 18604, listen: 127.0.0.1, cipher: 2022-blake3-aes-256-gcm, password: "{SS22_256_PSK}", udp: true}}
  - {{name: B-vmess, type: vmess, port: 18605, listen: 127.0.0.1, users: [{{username: "", uuid: "{VMESS_UUID}", alterId: 0}}]}}
  - {{name: B-vless, type: vless, port: 18606, listen: 127.0.0.1, users: [{{username: "", uuid: "{VLESS_UUID}"}}], certificate: "{CERT}", private-key: "{KEY}"}}
  - {{name: B-trojan, type: trojan, port: 18607, listen: 127.0.0.1, users: [{{username: "u1", password: "{TROJAN_PW}"}}], certificate: "{CERT}", private-key: "{KEY}"}}
  - {{name: B-anytls, type: anytls, port: 18608, listen: 127.0.0.1, users: {{u1: "{ANYTLS_PW}"}}, certificate: "{CERT}", private-key: "{KEY}"}}
  - {{name: B-mieru, type: mieru, port: 18609, listen: 127.0.0.1, transport: TCP, users: {{u1: "{MIERU_PASS}"}}, port-range: 18609-18610}}
  - {{name: B-snell, type: snell, port: 18611, listen: 127.0.0.1, psk: "{SNELL_PSK}"}}
  - {{name: B-tuic, type: tuic, port: 18612, listen: 127.0.0.1, users: {{"{VMESS_UUID}": "{TUIC_PW}"}}, certificate: "{CERT}", private-key: "{KEY}"}}
  - {{name: B-hy2, type: hysteria2, port: 18613, listen: 127.0.0.1, users: {{u1: "{HY2_PW}"}}, certificate: "{CERT}", private-key: "{KEY}"}}
rules:
  - MATCH,DIRECT
""")

# ---- mihomo 客户端（方向 A → vpcore 服务端）----
write("mihomo_client.yaml", f"""mixed-port: 17880
external-controller: 127.0.0.1:19090
mode: global
log-level: warning
proxies:
  - {{name: A-socks, type: socks5, server: 127.0.0.1, port: 18501, udp: true}}
  - {{name: A-http, type: http, server: 127.0.0.1, port: 18502}}
  - {{name: A-ss, type: ss, server: 127.0.0.1, port: 18503, cipher: aes-256-gcm, password: "{SS256_PW}", udp: true}}
  - {{name: A-ss22, type: ss, server: 127.0.0.1, port: 18504, cipher: 2022-blake3-aes-256-gcm, password: "{SS22_256_PSK}", udp: true}}
  - {{name: A-vmess, type: vmess, server: 127.0.0.1, port: 18505, uuid: "{VMESS_UUID}", alterId: 0, cipher: aes-128-gcm, udp: true}}
  - {{name: A-vless, type: vless, server: 127.0.0.1, port: 18506, uuid: "{VLESS_UUID}", udp: true}}
  - {{name: A-trojan, type: trojan, server: 127.0.0.1, port: 18507, password: "{TROJAN_PW}", sni: local.test, skip-cert-verify: true, udp: true}}
  - {{name: A-anytls, type: anytls, server: 127.0.0.1, port: 18508, password: "{ANYTLS_PW}", sni: local.test, skip-cert-verify: true, udp: true}}
  - {{name: A-mieru, type: mieru, server: 127.0.0.1, port: 18509, transport: TCP, username: "{MIERU_USER}", password: "{MIERU_PASS}"}}
  - {{name: A-snell, type: snell, server: 127.0.0.1, port: 18510, psk: "{SNELL_PSK}"}}
  - {{name: A-tuic, type: tuic, server: 127.0.0.1, port: 18511, uuid: "{VMESS_UUID}", password: "{TUIC_PW}", sni: local.test, skip-cert-verify: true, congestion-controller: bbr, udp-relay-mode: native}}
  - {{name: A-hy2, type: hysteria2, server: 127.0.0.1, port: 18512, password: "{HY2_PW}", sni: local.test, skip-cert-verify: true}}
proxy-groups: []
rules:
  - MATCH,DIRECT
""")

# ---- vpcore 客户端（方向 B → mihomo 服务端）----
# B-naive / B-brook：mihomo 无对应监听，指向 vpcore 服务端 18513/18514 作内核自洽校验
write("vpcore_client.yaml", f"""mixed-port: 18700
mode: rule
log-level: warning
proxies:
  - {{name: B-socks, type: socks5, server: 127.0.0.1, port: 18601, udp: true}}
  - {{name: B-http, type: http, server: 127.0.0.1, port: 18602}}
  - {{name: B-ss, type: ss, server: 127.0.0.1, port: 18603, cipher: aes-256-gcm, password: "{SS256_PW}", udp: true}}
  - {{name: B-ss22, type: ss, server: 127.0.0.1, port: 18604, cipher: 2022-blake3-aes-256-gcm, password: "{SS22_256_PSK}", udp: true}}
  - {{name: B-vmess, type: vmess, server: 127.0.0.1, port: 18605, uuid: "{VMESS_UUID}", alterId: 0, cipher: aes-128-gcm, udp: true}}
  - {{name: B-vless, type: vless, server: 127.0.0.1, port: 18606, uuid: "{VLESS_UUID}", tls: true, servername: local.test, skip-cert-verify: true, udp: true}}
  - {{name: B-trojan, type: trojan, server: 127.0.0.1, port: 18607, password: "{TROJAN_PW}", sni: local.test, skip-cert-verify: true, udp: true}}
  - {{name: B-anytls, type: anytls, server: 127.0.0.1, port: 18608, password: "{ANYTLS_PW}", sni: local.test, skip-cert-verify: true, udp: true}}
  - {{name: B-mieru, type: mieru, server: 127.0.0.1, port: 18609, username: matrix, password: "{MIERU_PASS}"}}
  - {{name: B-snell, type: snell, server: 127.0.0.1, port: 18611, psk: "{SNELL_PSK}"}}
  - {{name: B-tuic, type: tuic, server: 127.0.0.1, port: 18612, uuid: "{VMESS_UUID}", password: "{TUIC_PW}", sni: local.test, skip-cert-verify: true, congestion-controller: bbr}}
  - {{name: B-hy2, type: hysteria2, server: 127.0.0.1, port: 18613, password: "{HY2_PW}", sni: local.test, skip-cert-verify: true}}
  - {{name: B-naive, type: naive, server: 127.0.0.1, port: 18513, username: "{NAIVE_USER}", password: "{NAIVE_PASS}", sni: local.test, skip-cert-verify: true}}
  - {{name: B-brook, type: brook, server: 127.0.0.1, port: 18514, password: "{BROOK_PW}"}}
proxy-groups:
  - {{name: MATRIX, type: select, proxies: [B-socks, B-http, B-ss, B-ss22, B-vmess, B-vless, B-trojan, B-anytls, B-mieru, B-snell, B-tuic, B-hy2, B-naive, B-brook], url: "http://127.0.0.1:18999/generate_204", interval: 3600}}
rules:
  - MATCH,MATRIX
""")

print("matrix configs generated at", OUT)

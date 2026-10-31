# 加密链路端到端基准（同口径对比）：
# 1. DIRECT: SOCKS5 -> DIRECT -> sink（基准地板）
# 2. SS-AES128: SOCKS5 -> ss-out(aes-128-gcm) -> ss-in -> DIRECT -> sink
# 3. SS-AES256: SOCKS5 -> ss-out(aes-256-gcm) -> ss-in -> DIRECT -> sink
# 4. SS-ChaCha20: SOCKS5 -> ss-out(chacha20-ietf-poly1305) -> ss-in -> DIRECT -> sink
import socket, struct, subprocess, sys, time, os

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    KERNEL = os.environ.get("VPCORE_BIN", r"D:\project\rust\VP_Core\target\release\vpcore.exe")
    HOME = os.environ.get("VPCORE_BENCH_HOME", r"C:\Users\loukas\AppData\Local\Temp\kernel-bench\crypto-bench")
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.windll.kernel32
    def cpu_secs(pid):
        h = k32.OpenProcess(0x1000, False, pid)
        if not h:
            return None
        ctime, etime = wintypes.FILETIME(), wintypes.FILETIME()
        ktime, utime = wintypes.FILETIME(), wintypes.FILETIME()
        ok = k32.GetProcessTimes(h, ctypes.byref(ctime), ctypes.byref(etime),
                                 ctypes.byref(ktime), ctypes.byref(utime))
        k32.CloseHandle(h)
        if not ok:
            return None
        kt = (ktime.dwHighDateTime << 32) | ktime.dwLowDateTime
        ut = (utime.dwHighDateTime << 32) | utime.dwLowDateTime
        return (kt + ut) / 1e7
else:
    KERNEL = os.environ.get("VPCORE_BIN", os.path.expanduser("~/vpc-ci/target/release/vpcore"))
    HOME = os.environ.get("VPCORE_BENCH_HOME", "/tmp/kernel-bench/crypto-bench")
    def cpu_secs(pid):
        try:
            with open(f"/proc/{pid}/stat", "r") as f:
                parts = f.read().split()
                utime = int(parts[13])
                stime = int(parts[14])
                clk_tck = os.sysconf(os.sysconf_names.get('SC_CLK_TCK', 100))
                return (utime + stime) / float(clk_tck)
        except Exception:
            return None

CFG = os.path.join(HOME, "config.yaml")
SOCKS_PORT = 7895
SS_PORT = 18389
SINK_PORT = 19997
MB = 1024 * 1024

os.makedirs(HOME, exist_ok=True)

def write_config(cipher):
    if cipher == "DIRECT":
        cfg = f"""mixed-port: {SOCKS_PORT}
allow-lan: false
mode: rule
log-level: warn
ipv6: false
rules:
  - MATCH,DIRECT
"""
    elif cipher.startswith("vmess:"):
        sec = cipher.split(":", 1)[1]
        cfg = f"""mixed-port: {SOCKS_PORT}
allow-lan: false
mode: rule
log-level: warn
ipv6: false

listeners:
  - name: vm-in
    type: vmess
    port: {SS_PORT}
    users:
      - b831381d-6324-4d53-ad4f-8cda48b30811

proxies:
  - name: vm-out
    type: vmess
    server: 127.0.0.1
    port: {SS_PORT}
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: {sec}

rules:
  - IN-PORT,{SOCKS_PORT},vm-out
  - MATCH,DIRECT
"""
    else:
        cfg = f"""mixed-port: {SOCKS_PORT}
allow-lan: false
mode: rule
log-level: warn
ipv6: false

listeners:
  - name: ss-in
    type: ss
    port: {SS_PORT}
    cipher: {cipher}
    password: benchmark_password_secret_key

proxies:
  - name: ss-out
    type: ss
    server: 127.0.0.1
    port: {SS_PORT}
    cipher: {cipher}
    password: benchmark_password_secret_key

rules:
  - IN-PORT,{SOCKS_PORT},ss-out
  - MATCH,DIRECT
"""
    with open(CFG, "w", encoding="utf-8") as f:
        f.write(cfg)

def start_sink():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", SINK_PORT))
    s.listen(16)
    import threading
    def loop():
        while True:
            c, _ = s.accept()
            def drain(c=c):
                try:
                    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    buf = bytearray(128 * 1024)
                    while c.recv_into(buf, 128 * 1024):
                        pass
                except OSError:
                    pass
                finally:
                    c.close()
            threading.Thread(target=drain, daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()

def socks_connect(dst_port):
    s = socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=10)
    s.settimeout(120)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.sendall(b"\x05\x01\x00")
    assert s.recv(2) == b"\x05\x00"
    req = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", dst_port)
    s.sendall(req)
    resp = s.recv(512)
    assert resp[1] == 0, f"socks reply {resp!r}"
    return s

CHUNK = 4 * MB
payload = b"\xa5" * CHUNK
mv = memoryview(payload)

def one_round(mb):
    s = socks_connect(SINK_PORT)
    sent, t0 = 0, time.perf_counter()
    while sent < mb * MB:
        n = min(CHUNK, mb * MB - sent)
        s.sendall(mv[:n])
        sent += n
    s.shutdown(socket.SHUT_WR)
    try:
        while s.recv(1 << 20):
            pass
    except (OSError, socket.timeout):
        pass
    s.close()
    return time.perf_counter() - t0

def bench_suite(name, rounds=5, mb=128):
    write_config(name)
    kwargs = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if IS_WINDOWS:
        kwargs["creationflags"] = 0x08000000
    kern = subprocess.Popen([KERNEL, "run", "-d", HOME, "-c", CFG], **kwargs)
    time.sleep(2.0)
    one_round(32)  # warm-up
    res = []
    for i in range(rounds):
        c0 = cpu_secs(kern.pid)
        dt = one_round(mb)
        c1 = cpu_secs(kern.pid)
        mps = mb / dt
        cpu = (c1 - c0) if (c0 is not None and c1 is not None) else None
        res.append((mps, cpu))
        print(f"  round {i+1}: {mps:7.1f} MB/s  cpu={cpu if cpu is not None else -1:6.3f}s", flush=True)
    kern.kill()
    time.sleep(0.5)
    mids = sorted(r[0] for r in res)
    cpus = sorted(r[1] for r in res if r[1] is not None)
    median_mps = mids[len(mids)//2]
    max_mps = mids[-1]
    cpu_rate = cpus[len(cpus)//2] / mb if cpus else 0.0
    print(f"[{name:<22}] MEDIAN {median_mps:7.1f} MB/s   MAX {max_mps:7.1f} MB/s   CPU {cpu_rate:.4f} s/MB\n", flush=True)
    return median_mps, max_mps, cpu_rate

def main():
    start_sink()
    time.sleep(0.5)
    print("=== 端到端加密链路吞吐基准（128MB / 轮，5 轮取中位）===\n")
    bench_suite("DIRECT", rounds=5, mb=128)
    bench_suite("aes-128-gcm", rounds=5, mb=128)
    bench_suite("aes-256-gcm", rounds=5, mb=128)
    bench_suite("chacha20-ietf-poly1305", rounds=5, mb=128)
    bench_suite("vmess:auto", rounds=5, mb=128)

if __name__ == "__main__":
    main()

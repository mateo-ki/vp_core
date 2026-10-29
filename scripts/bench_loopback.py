# 环回吞吐基准 v3：标定工具上限 + 经内核对比
# Phase A: 直连 sink（不经过内核）= 工具上限
# Phase B: SOCKS5 -> vpcore(MATCH,DIRECT) -> sink = 内核全链路
# CPU: ctypes GetProcessTimes（精确、无 PowerShell 开销）
import socket, struct, subprocess, sys, time, os, ctypes
from ctypes import wintypes

KERNEL = r"D:\project\rust\VP_Core\target\release\vpcore.exe"
HOME = r"C:\Users\loukas\AppData\Local\Temp\kernel-bench\vp-loop-home"
CFG = os.path.join(HOME, "config.yaml")
SOCKS_PORT = 7891
SINK_PORT = 19999
MB = 1024 * 1024

k32 = ctypes.windll.kernel32
def cpu_secs(pid):
    h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
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
    return (kt + ut) / 1e7  # 100ns ticks -> seconds

os.makedirs(HOME, exist_ok=True)
with open(CFG, "w", encoding="utf-8") as f:
    f.write(f"""mixed-port: {SOCKS_PORT}
allow-lan: false
mode: rule
log-level: warn
ipv6: false
rules:
  - MATCH,DIRECT
""")

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
                    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
                    buf = bytearray(1 << 20)
                    while c.recv_into(buf, 1 << 20):
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
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
    s.sendall(b"\x05\x01\x00")
    assert s.recv(2) == b"\x05\x00"
    req = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", dst_port)
    s.sendall(req)
    resp = s.recv(512)
    assert resp[1] == 0, f"socks reply {resp!r}"
    return s

def direct_connect(dst_port):
    s = socket.create_connection(("127.0.0.1", dst_port), timeout=10)
    s.settimeout(120)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
    return s

CHUNK = 4 * MB
payload = b"\xa5" * CHUNK
mv = memoryview(payload)

def one_round(mb, connect):
    s = connect(SINK_PORT)
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

def bench(tag, connect, kern_pid, rounds, mb):
    one_round(32, connect)  # 预热
    res = []
    for i in range(rounds):
        c0 = cpu_secs(kern_pid) if kern_pid else None
        dt = one_round(mb, connect)
        c1 = cpu_secs(kern_pid) if kern_pid else None
        mps = mb / dt
        cpu = (c1 - c0) if (kern_pid and c0 is not None and c1 is not None) else None
        res.append((mps, cpu))
        print(f"{tag} round {i+1}: {mps:7.1f} MB/s  cpu={cpu if cpu is not None else -1:6.3f}s", flush=True)
    mids = sorted(r[0] for r in res)
    cpus = sorted(r[1] for r in res if r[1] is not None)
    print(f"{tag} MEDIAN {mids[len(mids)//2]:.1f} MB/s   MAX {mids[-1]:.1f} MB/s"
          + (f"   CPU median {cpus[len(cpus)//2]/mb:.4f} s/MB" if cpus else ""), flush=True)
    return mids[len(mids)//2]

def main():
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 9
    mb = int(sys.argv[2]) if len(sys.argv) > 2 else 256
    start_sink()
    time.sleep(0.3)
    direct = bench("DIRECT ", direct_connect, None, rounds, mb)
    kern = subprocess.Popen([KERNEL, "run", "-d", HOME, "-c", CFG],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            creationflags=0x08000000)
    time.sleep(2.0)
    via = bench("KERNEL ", socks_connect, kern.pid, rounds, mb)
    print(f"工具上限 {direct:.0f} MB/s；经内核 {via:.0f} MB/s（{via/direct*100:.0f}%）", flush=True)
    kern.kill()

if __name__ == "__main__":
    main()

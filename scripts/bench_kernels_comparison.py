# -*- coding: utf-8 -*-
"""
多内核稳定性、资源占用（CPU/内存）、读写吞吐与波动性横向评测
对比对象：
  1. Mihomo (Clash.Meta v1.19.33)
  2. Sing-Box (v1.14.4)
  3. VP-Core (v1.1.0)

测试规模：
  - 20 个 Shadowsocks 节点 (10 个 AES-256-GCM + 10 个 ChaCha20-Poly1305)
  - 20 个 VMess 节点 (20 个独立 UUID + AEAD Auto)
  - 共计 40 个真实加密节点依次压测
  - 每节点传输 64 MB 数据（单内核全套 2560 MB 突发流量）
"""

import os
import sys
import time
import json
import math
import socket
import struct
import ctypes
import urllib.request
import urllib.error
import subprocess
import threading
from ctypes import wintypes

try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass

# 路径常量
VPCORE_BIN = r"D:\software\VPN Parser\data\kernels\vpcore\vpcore.exe"
MIHOMO_BIN = r"D:\software\VPN Parser\data\kernels\mihomo\mihomo.exe"
SINGBOX_BIN = r"D:\software\VPN Parser\data\kernels\sing-box\sing-box.exe"

WORK_DIR = r"C:\Users\loukas\AppData\Local\Temp\kernel-bench\multi-kernel"
os.makedirs(WORK_DIR, exist_ok=True)

# 端口规划
SINK_PORT = 29999
SERVER_SOCKS = 29990
CLIENT_SOCKS = 17890
CLIENT_API = 19090

SS_BASE_PORT = 21001      # 21001 .. 21020 (20 nodes)
VMESS_BASE_PORT = 21021   # 21021 .. 21040 (20 nodes)
DATA_PER_NODE_MB = 64
CHUNK_SIZE = 4 * 1024 * 1024
PAYLOAD = b"\x5a" * CHUNK_SIZE
PAYLOAD_MV = memoryview(PAYLOAD)

# Windows API 获取精准 CPU 时间与内存
k32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi

class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]

def get_cpu_secs(pid):
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

def get_memory_info(pid):
    h = k32.OpenProcess(0x1000 | 0x0400, False, pid)
    if not h:
        return None, None
    pmc = PROCESS_MEMORY_COUNTERS()
    pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
    ok = psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb)
    k32.CloseHandle(h)
    if not ok:
        return None, None
    rss = pmc.WorkingSetSize / (1024 * 1024)
    peak = pmc.PeakWorkingSetSize / (1024 * 1024)
    return rss, peak

# 启动高速 Sink
def start_sink():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", SINK_PORT))
    s.listen(64)
    def loop():
        while True:
            conn, _ = s.accept()
            def drain(c=conn):
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

# 生成 40 个节点的服务端与客户端定义
def generate_node_definitions():
    nodes = []
    # 20 个 SS 节点
    for i in range(1, 21):
        cipher = "aes-256-gcm" if i <= 10 else "chacha20-ietf-poly1305"
        port = SS_BASE_PORT + i - 1
        password = f"secret_pass_ss_{i:02d}_bench"
        nodes.append({
            "proto": "ss",
            "name": f"ss-{i:02d}",
            "port": port,
            "cipher": cipher,
            "password": password,
        })
    # 20 个 VMess 节点
    for i in range(1, 21):
        port = VMESS_BASE_PORT + i - 1
        uuid = f"b831381d-6324-4d53-ad4f-8cda48b3{i:04d}"
        nodes.append({
            "proto": "vmess",
            "name": f"vmess-{i:02d}",
            "port": port,
            "cipher": "auto",
            "uuid": uuid,
        })
    return nodes

NODES = generate_node_definitions()

def write_backend_server_config():
    cfg_path = os.path.join(WORK_DIR, "backend_server.yaml")
    lines = [
        f"mixed-port: {SERVER_SOCKS}",
        "allow-lan: false",
        "mode: rule",
        "log-level: warn",
        "ipv6: false",
        "listeners:",
    ]
    for n in NODES:
        if n["proto"] == "ss":
            lines.extend([
                f"  - name: srv-{n['name']}",
                "    type: ss",
                f"    port: {n['port']}",
                f"    cipher: {n['cipher']}",
                "    users:",
                f"      - {n['password']}",
            ])
        else:
            lines.extend([
                f"  - name: srv-{n['name']}",
                "    type: vmess",
                f"    port: {n['port']}",
                "    users:",
                f"      - {n['uuid']}",
            ])
    lines.extend([
        "rules:",
        "  - MATCH,DIRECT",
    ])
    with open(cfg_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return cfg_path

def write_clash_client_config(filename):
    cfg_path = os.path.join(WORK_DIR, filename)
    lines = [
        f"mixed-port: {CLIENT_SOCKS}",
        f"external-controller: 127.0.0.1:{CLIENT_API}",
        "allow-lan: false",
        "mode: rule",
        "log-level: warning",
        "ipv6: false",
        "proxies:",
    ]
    for n in NODES:
        if n["proto"] == "ss":
            lines.extend([
                f"  - name: {n['name']}",
                "    type: ss",
                "    server: 127.0.0.1",
                f"    port: {n['port']}",
                f"    cipher: {n['cipher']}",
                f"    password: {n['password']}",
            ])
        else:
            lines.extend([
                f"  - name: {n['name']}",
                "    type: vmess",
                "    server: 127.0.0.1",
                f"    port: {n['port']}",
                f"    uuid: {n['uuid']}",
                "    alterId: 0",
                "    cipher: auto",
            ])
    lines.append("proxy-groups:")
    lines.append("  - name: PROXY")
    lines.append("    type: select")
    lines.append("    proxies:")
    for n in NODES:
        lines.append(f"      - {n['name']}")
    lines.extend([
        "rules:",
        f"  - IN-PORT,{CLIENT_SOCKS},PROXY",
        "  - MATCH,PROXY",
    ])
    with open(cfg_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return cfg_path

def write_singbox_client_config(filename):
    cfg_path = os.path.join(WORK_DIR, filename)
    outbounds = [
        {
            "type": "selector",
            "tag": "PROXY",
            "outbounds": [n["name"] for n in NODES],
        }
    ]
    for n in NODES:
        if n["proto"] == "ss":
            outbounds.append({
                "type": "shadowsocks",
                "tag": n["name"],
                "server": "127.0.0.1",
                "server_port": n["port"],
                "method": n["cipher"],
                "password": n["password"],
            })
        else:
            outbounds.append({
                "type": "vmess",
                "tag": n["name"],
                "server": "127.0.0.1",
                "server_port": n["port"],
                "uuid": n["uuid"],
                "security": "auto",
                "alter_id": 0,
            })
    cfg = {
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": CLIENT_SOCKS,
            }
        ],
        "outbounds": outbounds,
        "route": {
            "rules": [
                {
                    "inbound": ["mixed-in"],
                    "outbound": "PROXY",
                }
            ]
        },
        "experimental": {
            "clash_api": {
                "external_controller": f"127.0.0.1:{CLIENT_API}",
            }
        }
    }
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    return cfg_path

def switch_node(node_name):
    url = f"http://127.0.0.1:{CLIENT_API}/proxies/PROXY"
    data = json.dumps({"name": node_name}).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="PUT")
    req.add_header("Content-Type", "application/json")
    for _ in range(5):
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.status in (200, 204):
                    return True
        except Exception:
            time.sleep(0.1)
    return False

def socks_send_data(mb):
    s = socket.create_connection(("127.0.0.1", CLIENT_SOCKS), timeout=10)
    s.settimeout(60)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.sendall(b"\x05\x01\x00")
    assert s.recv(2) == b"\x05\x00"
    req = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", SINK_PORT)
    s.sendall(req)
    resp = s.recv(512)
    assert resp[1] == 0, f"socks handshake err: {resp!r}"

    sent, t0 = 0, time.perf_counter()
    target_bytes = mb * 1024 * 1024
    while sent < target_bytes:
        n = min(CHUNK_SIZE, target_bytes - sent)
        s.sendall(PAYLOAD_MV[:n])
        sent += n
    s.shutdown(socket.SHUT_WR)
    try:
        while s.recv(1024 * 1024):
            pass
    except (OSError, socket.timeout):
        pass
    s.close()
    return time.perf_counter() - t0

def test_kernel_pipeline(name, spawn_fn):
    print(f"\n=======================================================")
    print(f" 开始评测内核: 【{name}】 (20 SS + 20 VMess, 共 40 节点)")
    print(f"=======================================================")

    proc = spawn_fn()
    time.sleep(2.0)  # 等待内核初始化与监听建立

    base_rss, _ = get_memory_info(proc.pid)
    cpu_start = get_cpu_secs(proc.pid) or 0.0
    print(f"  [就绪] 进程 PID={proc.pid}, 初始常驻内存 (RSS): {base_rss:.1f} MB")

    # 预热首个节点
    switch_node(NODES[0]["name"])
    try:
        socks_send_data(8)
    except Exception as e:
        print(f"  [警告] 预热失败: {e}")

    results = []
    peak_rss_during = base_rss or 0.0

    for idx, node in enumerate(NODES, start=1):
        sw_ok = switch_node(node["name"])
        if not sw_ok:
            results.append({
                "node": node["name"],
                "proto": node["proto"],
                "speed": 0.0,
                "ok": False,
                "err": "switch_failed",
            })
            print(f"  [{idx:02d}/40] {node['name']} ({node['proto']}) -> 切换失败!")
            continue

        err_msg = None
        speed = 0.0
        try:
            dt = socks_send_data(DATA_PER_NODE_MB)
            speed = DATA_PER_NODE_MB / dt
        except Exception as e:
            err_msg = str(e)

        rss, peak = get_memory_info(proc.pid)
        if peak and peak > peak_rss_during:
            peak_rss_during = peak
        if rss and rss > peak_rss_during:
            peak_rss_during = rss

        status = "OK" if err_msg is None else "FAIL"
        results.append({
            "node": node["name"],
            "proto": node["proto"],
            "speed": speed,
            "ok": err_msg is None,
            "err": err_msg,
        })
        print(f"  [{idx:02d}/40] {node['name']:<8} ({node['proto']:<5}) -> {speed:7.1f} MB/s  [RSS: {rss:.1f}MB, 状态: {status}]")

    time.sleep(2.0)  # 等待连接归还与 GC
    settled_rss, total_peak_rss = get_memory_info(proc.pid)
    cpu_end = get_cpu_secs(proc.pid) or 0.0
    total_cpu = max(0.0, cpu_end - cpu_start)

    proc.kill()
    proc.wait()
    time.sleep(0.5)

    # 统计数据
    ss_results = [r for r in results if r["proto"] == "ss" and r["ok"]]
    vm_results = [r for r in results if r["proto"] == "vmess" and r["ok"]]
    all_ok = [r for r in results if r["ok"]]

    def calc_stats(lst):
        if not lst:
            return 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
        speeds = sorted(r["speed"] for r in lst)
        min_v = speeds[0]
        max_v = speeds[-1]
        med_v = speeds[len(speeds) // 2]
        avg_v = sum(speeds) / len(speeds)
        var = sum((s - avg_v) ** 2 for s in speeds) / len(speeds)
        std = math.sqrt(var)
        fluctuation = (std / avg_v * 100.0) if avg_v > 0 else 0.0
        return min_v, med_v, avg_v, max_v, std, fluctuation

    ss_stats = calc_stats(ss_results)
    vm_stats = calc_stats(vm_results)
    all_stats = calc_stats(all_ok)

    summary = {
        "name": name,
        "total_nodes": len(NODES),
        "success_nodes": len(all_ok),
        "success_rate": len(all_ok) / len(NODES) * 100.0,
        "base_rss": base_rss,
        "peak_rss": max(peak_rss_during, total_peak_rss or 0.0),
        "settled_rss": settled_rss,
        "mem_growth": (settled_rss - base_rss) if (settled_rss and base_rss) else 0.0,
        "total_cpu_secs": total_cpu,
        "cpu_rate": (total_cpu / (len(all_ok) * DATA_PER_NODE_MB)) if all_ok else 0.0,
        "ss_stats": ss_stats,
        "vm_stats": vm_stats,
        "all_stats": all_stats,
        "raw_results": results,
    }
    return summary

def main():
    print("=== 初始化后端 40 端口中继服务端与 Sink 接收端 ===")
    start_sink()
    time.sleep(0.5)

    srv_cfg = write_backend_server_config()
    srv_proc = subprocess.Popen([VPCORE_BIN, "run", "-d", WORK_DIR, "-c", srv_cfg],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                creationflags=0x08000000)
    time.sleep(2.0)
    print(f"后端服务已启动 (PID={srv_proc.pid}), 40 节点监听就绪。\n")

    mihomo_cfg = write_clash_client_config("mihomo_client.yaml")
    vpcore_cfg = write_clash_client_config("vpcore_client.yaml")
    singbox_cfg = write_singbox_client_config("singbox_client.json")

    # 1. 第一轮测试：Mihomo
    mihomo_summary = test_kernel_pipeline(
        "Mihomo Meta v1.19.33",
        lambda: subprocess.Popen([MIHOMO_BIN, "-d", WORK_DIR, "-f", mihomo_cfg],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 creationflags=0x08000000)
    )

    # 2. 第二轮测试：Sing-Box
    singbox_summary = test_kernel_pipeline(
        "Sing-Box v1.14.4",
        lambda: subprocess.Popen([SINGBOX_BIN, "run", "-D", WORK_DIR, "-c", singbox_cfg],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 creationflags=0x08000000)
    )

    # 3. 第三轮测试：VP-Core
    vpcore_summary = test_kernel_pipeline(
        "VP-Core v1.1.0",
        lambda: subprocess.Popen([VPCORE_BIN, "run", "-d", WORK_DIR, "-c", vpcore_cfg],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 creationflags=0x08000000)
    )

    srv_proc.kill()
    srv_proc.wait()

    # 输出 JSON 报告供留档
    with open(os.path.join(WORK_DIR, "summary_report.json"), "w", encoding="utf-8") as f:
        json.dump([mihomo_summary, singbox_summary, vpcore_summary], f, indent=2, ensure_ascii=False)

    print("\n\n###################################################################")
    print("                      全内核 40 节点终极横向评测报告                  ")
    print("###################################################################\n")

    for s in [mihomo_summary, singbox_summary, vpcore_summary]:
        print(f"【{s['name']}】")
        print(f"  - 节点成功率: {s['success_nodes']}/{s['total_nodes']} ({s['success_rate']:.1f}%)")
        print(f"  - 内存表现: 初始 {s['base_rss']:.1f} MB -> 压测峰值 {s['peak_rss']:.1f} MB -> 终态常驻 {s['settled_rss']:.1f} MB (净增量: {s['mem_growth']:+.1f} MB)")
        print(f"  - CPU 开销: 累计耗时 {s['total_cpu_secs']:.3f} 秒 (平均处理单兆耗时 {s['cpu_rate']*1000:.2f} ms/MB)")
        s_all = s["all_stats"]
        print(f"  - 综合吞吐: 中位 {s_all[1]:.1f} MB/s | 平均 {s_all[2]:.1f} MB/s | 最高 {s_all[3]:.1f} MB/s | 最低 {s_all[0]:.1f} MB/s")
        print(f"  - 波动系数: 变异系数 CV={s_all[5]:.1f}% (标准差: ±{s_all[4]:.1f} MB/s)")
        s_ss = s["ss_stats"]
        print(f"    * SS 20节点 : 中位 {s_ss[1]:.1f} MB/s | 最高 {s_ss[3]:.1f} MB/s | 波动率 CV={s_ss[5]:.1f}%")
        s_vm = s["vm_stats"]
        print(f"    * VMess 20节点: 中位 {s_vm[1]:.1f} MB/s | 最高 {s_vm[3]:.1f} MB/s | 波动率 CV={s_vm[5]:.1f}%")
        print()

if __name__ == "__main__":
    main()

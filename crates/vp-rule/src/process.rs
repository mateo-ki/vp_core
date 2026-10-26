//! 进程归属查询：连接源地址 → 进程名（PROCESS-NAME / PROCESS-PATH 规则）。
//! 阻塞系统调用 + 短 TTL 缓存，调用方需在 spawn_blocking 中使用。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const TTL: Duration = Duration::from_secs(30);
const CACHE_CAP: usize = 8192;

#[derive(Clone)]
struct CacheEntry {
    name: Option<String>,
    at: Instant,
}

#[derive(Default)]
struct Cache {
    map: HashMap<SocketAddr, CacheEntry>,
}

fn cache() -> &'static Mutex<Cache> {
    static CACHE: std::sync::OnceLock<Mutex<Cache>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(Cache::default()))
}

/// 查询进程名（含 .exe 等），未找到返回 None。结果短缓存。
pub fn find_process_name(src: SocketAddr) -> Option<String> {
    let now = Instant::now();
    {
        let c = cache().lock().unwrap();
        if let Some(e) = c.map.get(&src) {
            if now.duration_since(e.at) < TTL {
                return e.name.clone();
            }
        }
    }
    let name = find_process_name_uncached(src);
    let mut c = cache().lock().unwrap();
    if c.map.len() >= CACHE_CAP {
        c.map.clear(); // 简单粗暴的容量控制
    }
    c.map.insert(
        src,
        CacheEntry {
            name: name.clone(),
            at: now,
        },
    );
    name
}

#[cfg(windows)]
fn find_process_name_uncached(src: SocketAddr) -> Option<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };

    unsafe {
        let pid = tcp_row_pid(src)?;
        if pid == 0 || pid == 4 {
            return None; // 0=系统空闲 4=内核
        }
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        if ok == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        std::path::Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
    }
}

#[cfg(windows)]
fn tcp_row_pid(src: SocketAddr) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    unsafe {
        let family: u32 = if src.is_ipv4() {
            AF_INET as u32
        } else {
            AF_INET6 as u32
        };
        let mut size: u32 = 0;
        // 第一次调用取大小
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut _,
            &mut size,
            0,
            family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if ret != 0 {
            return None;
        }
        // MIB_TCPTABLE_OWNER_PID 布局: DWORD numEntries; MIB_TCPROW_OWNER_PID rows[]
        // MIB_TCPROW_OWNER_PID (v4): DWORD state, localAddr, localPort, remoteAddr, remotePort, pid
        let ptr = buf.as_ptr();
        let num = *(ptr as *const u32);
        let rows = ptr.add(4) as *const u32;
        const ROW_U32: usize = 6;
        let (want_addr, want_port): (u32, u32) = match src {
            SocketAddr::V4(v4) => {
                let o = v4.ip().octets();
                (
                    u32::from_be_bytes([o[0], o[1], o[2], o[3]]),
                    (v4.port() as u32) << 16,
                )
            }
            SocketAddr::V6(_) => return None, // v6 表行结构不同，M1 先支持 v4
        };
        for i in 0..num as usize {
            let r = rows.add(i * ROW_U32);
            let local_addr = *r.add(1);
            let local_port = *r.add(2);
            if local_addr == want_addr && local_port == want_port {
                return Some(*r.add(5));
            }
        }
        None
    }
}

#[cfg(target_os = "linux")]
fn find_process_name_uncached(src: SocketAddr) -> Option<String> {
    let inode = find_socket_inode_linux(src)?;
    find_process_by_inode_linux(inode)
}

#[cfg(target_os = "linux")]
fn find_socket_inode_linux(src: SocketAddr) -> Option<u64> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let (file_path, target_hex) = match src {
        SocketAddr::V4(v4) => {
            let ip = u32::from_ne_bytes(v4.ip().octets());
            let port = v4.port();
            ("/proc/net/tcp", format!("{ip:08X}:{port:04X}"))
        }
        SocketAddr::V6(v6) => {
            let o = v6.ip().octets();
            let p1 = u32::from_ne_bytes([o[0], o[1], o[2], o[3]]);
            let p2 = u32::from_ne_bytes([o[4], o[5], o[6], o[7]]);
            let p3 = u32::from_ne_bytes([o[8], o[9], o[10], o[11]]);
            let p4 = u32::from_ne_bytes([o[12], o[13], o[14], o[15]]);
            let port = v6.port();
            (
                "/proc/net/tcp6",
                format!("{p1:08X}{p2:08X}{p3:08X}{p4:08X}:{port:04X}"),
            )
        }
    };

    let f = File::open(file_path).ok()?;
    let reader = BufReader::new(f);
    for line in reader.lines().skip(1) {
        let line = line.ok()?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() > 9 && parts[1].eq_ignore_ascii_case(&target_hex) {
            return parts[9].parse::<u64>().ok();
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn find_process_by_inode_linux(inode: u64) -> Option<String> {
    use std::fs;
    let target = format!("socket:[{inode}]");
    let proc_dir = fs::read_dir("/proc").ok()?;

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_str()?;
        if !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let fd_dir = entry.path().join("fd");
        if let Ok(fds) = fs::read_dir(&fd_dir) {
            for fd in fds.flatten() {
                if let Ok(link) = fs::read_link(fd.path()) {
                    if link.to_string_lossy() == target {
                        let comm_path = entry.path().join("comm");
                        if let Ok(comm) = fs::read_to_string(comm_path) {
                            let trimmed = comm.trim().to_string();
                            if !trimmed.is_empty() {
                                return Some(trimmed);
                            }
                        }
                        let exe_path = entry.path().join("exe");
                        if let Ok(exe) = fs::read_link(exe_path) {
                            if let Some(file_name) = exe.file_name() {
                                return Some(file_name.to_string_lossy().to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

#[cfg(all(not(windows), not(target_os = "linux")))]
fn find_process_name_uncached(_src: SocketAddr) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miss_returns_none() {
        // 不存在的连接：Windows 上查表无此行 → None；缓存后仍 None
        let a: SocketAddr = "203.0.113.7:54321".parse().unwrap();
        assert!(find_process_name(a).is_none());
    }
}

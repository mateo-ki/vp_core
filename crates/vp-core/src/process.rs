//! 本地 socket → 进程名解析（软件进程流量统计的数据源）。
//!
//! Windows：iphlpapi 的 `GetExtendedTcpTable` / `GetExtendedUdpTable` 拿到
//! (本地地址, PID) 全表，按连接源地址匹配出 PID，再 `QueryFullProcessImageNameW`
//! 取镜像基名。每次新建连接调用一次（系统调用微秒级，无需缓存）；
//! 远端来源（allow-lan）、已退出进程、权限不足一律返回 None，调用方无需关心。

use std::sync::Arc;

/// 按连接的本地源地址解析进程名（返回基名，如 `chrome.exe`）。
pub fn resolve_process(network: &str, src: Option<std::net::SocketAddr>) -> Option<Arc<str>> {
    let src = src?;
    #[cfg(windows)]
    {
        windows_lookup::lookup(network, src).map(Arc::from)
    }
    #[cfg(not(windows))]
    {
        let _ = network;
        let _ = src;
        None
    }
}

#[cfg(windows)]
mod windows_lookup {
    use std::net::{IpAddr, SocketAddr};

    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPTABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };

    /// 按协议与源地址在系统连接表里找归属 PID
    fn pid_by_local(network: &str, src: SocketAddr) -> Option<u32> {
        if src.ip() != IpAddr::from(std::net::Ipv4Addr::UNSPECIFIED)
            && !matches!(src.ip(), IpAddr::V4(_))
        {
            // IPv6 连接表结构不同（MIB_TCP6TABLE_OWNER_PID），少见，先不解析
            return None;
        }
        let local_addr = match src.ip() {
            IpAddr::V4(v4) => u32::from(v4),
            IpAddr::V6(_) => return None,
        };
        let local_port = src.port() as u32;
        match network.to_ascii_lowercase().as_str() {
            "tcp" => {
                let mut size: u32 = 0;
                // 第一次空表调用：返回 ERROR_INSUFFICIENT_BUFFER 并带出所需缓冲区大小
                let ret = unsafe {
                    GetExtendedTcpTable(
                        std::ptr::null_mut(),
                        &mut size,
                        0,
                        AF_INET as u32,
                        TCP_TABLE_OWNER_PID_ALL,
                        0,
                    )
                };
                if ret != ERROR_INSUFFICIENT_BUFFER || size == 0 {
                    return None;
                }
                let mut buf = vec![0u8; size as usize];
                let ret = unsafe {
                    GetExtendedTcpTable(
                        buf.as_mut_ptr().cast(),
                        &mut size,
                        0,
                        AF_INET as u32,
                        TCP_TABLE_OWNER_PID_ALL,
                        0,
                    )
                };
                if ret != NO_ERROR {
                    return None;
                }
                let table = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
                let count = unsafe { (*table).dwNumEntries } as usize;
                let rows = unsafe { (*table).table.as_ptr() };
                for i in 0..count {
                    let row = unsafe { &*rows.add(i) };
                    // dwLocalAddr 是网络字节序（LE 读出后 to_be 还原）；端口同理取低 16 位
                    if row.dwLocalAddr.to_be() == local_addr
                        && u16::from_be(row.dwLocalPort as u16) as u32 == local_port
                    {
                        return Some(row.dwOwningPid);
                    }
                }
                None
            }
            "udp" => {
                let mut size: u32 = 0;
                let ret = unsafe {
                    GetExtendedUdpTable(
                        std::ptr::null_mut(),
                        &mut size,
                        0,
                        AF_INET as u32,
                        UDP_TABLE_OWNER_PID,
                        0,
                    )
                };
                if ret != ERROR_INSUFFICIENT_BUFFER || size == 0 {
                    return None;
                }
                let mut buf = vec![0u8; size as usize];
                let ret = unsafe {
                    GetExtendedUdpTable(
                        buf.as_mut_ptr().cast(),
                        &mut size,
                        0,
                        AF_INET as u32,
                        UDP_TABLE_OWNER_PID,
                        0,
                    )
                };
                if ret != NO_ERROR {
                    return None;
                }
                let table = buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
                let count = unsafe { (*table).dwNumEntries } as usize;
                let rows = unsafe { (*table).table.as_ptr() };
                for i in 0..count {
                    let row = unsafe { &*rows.add(i) };
                    if row.dwLocalAddr.to_be() == local_addr
                        && u16::from_be(row.dwLocalPort as u16) as u32 == local_port
                    {
                        return Some(row.dwOwningPid);
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// PID → 可执行文件基名（打不开进程 / 取不到镜像名一律 None）
    fn process_name(pid: u32) -> Option<String> {
        if pid == 0 {
            return None;
        }
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut size = buf.len() as u32;
        let ok = unsafe {
            QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut size)
        };
        unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
        if ok == 0 || size == 0 {
            return None;
        }
        let full = String::from_utf16_lossy(&buf[..size as usize]);
        std::path::Path::new(&full)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
    }

    pub fn lookup(network: &str, src: SocketAddr) -> Option<String> {
        let pid = pid_by_local(network, src)?;
        process_name(pid)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// 自证：本测试进程自己发起的连接，必须能解析出自己（vp_core 测试可执行文件名）。
    /// listener 与 client 必须活到查询之后 —— 连接一关，系统表里就没有这行了。
    #[tokio::test]
    async fn resolves_own_tcp_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();

        let name = windows_lookup::lookup("tcp", addr).expect("本进程 socket 应解析出进程名");
        assert!(
            name.starts_with("vp_core") || name.contains("vp_core"),
            "进程名应为本测试可执行文件，实际: {name}"
        );
    }

    /// 未监听端口解析不出进程，也不该 panic
    #[test]
    fn unknown_socket_returns_none() {
        let src = "127.0.0.1:1".parse().unwrap();
        assert_eq!(windows_lookup::lookup("tcp", src), None);
    }
}

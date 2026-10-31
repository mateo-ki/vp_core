//! Linux TPROXY 透明代理入站（TCP + UDP）。
//!
//! 基于 Linux 内核 `IP_TRANSPARENT` 与 `cmsg` 辅助控制报文（`IP_RECVORIGDSTADDR`）：
//! - TCP：套接字设置 `IP_TRANSPARENT`，直接 accept 来自 iptables TPROXY 的连接并提取原始目标。
//! - UDP：通过 `recvmsg` 与辅助数据提取每个数据报的真实目标地址，并使用绑定原目标的透明套接字回包。
//! - 非 Linux 平台启动时明确报错提示。

use std::sync::Arc;

use async_trait::async_trait;
use vp_common::Result;
use vp_core::Inbound;
use vp_core::inbound::InboundCtx;

pub struct TproxyInbound {
    #[allow(dead_code)]
    bind: String,
    #[allow(dead_code)]
    port: u16,
    tag: Arc<str>,
}

impl TproxyInbound {
    pub fn new(bind: &str, port: u16, tag: &str) -> Self {
        TproxyInbound {
            bind: bind.into(),
            port,
            tag: tag.into(),
        }
    }
}

#[async_trait]
impl Inbound for TproxyInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(self: Arc<Self>, ctx: InboundCtx) -> Result<u16> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = &ctx;
            return Err(vp_common::Error::Unsupported(
                "tproxy 入站仅支持 Linux（当前平台的透明代理由 TUN 模式承担）".into(),
            ));
        }

        #[cfg(target_os = "linux")]
        {
            linux_impl::start_tproxy(self, ctx).await
        }
    }
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::os::fd::{AsRawFd, RawFd};
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;
    use tokio::io::unix::AsyncFd;
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::sync::Mutex;
    use tracing::{debug, info, warn};

    use vp_common::addr::DstAddr;
    use vp_common::{Error, Result};
    use vp_core::inbound::InboundCtx;
    use vp_core::session::{Network, Session};
    use vp_core::stream::UdpPacket;

    use super::TproxyInbound;
    use crate::inbound::dispatch::{ClientReply, dispatch_stream};

    type UdpFlowMap =
        Arc<Mutex<HashMap<(SocketAddr, SocketAddr), tokio::sync::mpsc::Sender<Bytes>>>>;

    pub async fn start_tproxy(inbound: Arc<TproxyInbound>, ctx: InboundCtx) -> Result<u16> {
        let bind_ip: std::net::IpAddr = inbound
            .bind
            .parse()
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let bind_addr = SocketAddr::new(bind_ip, inbound.port);

        // 1. 启动 TCP TPROXY 监听器
        let tcp_listener = create_tproxy_tcp_listener(bind_addr)?;
        let bound_port = tcp_listener.local_addr()?.port();
        let tag = inbound.tag.clone();

        {
            let ctx = ctx.clone();
            let tag = tag.clone();
            tokio::spawn(async move {
                loop {
                    match tcp_listener.accept().await {
                        Ok((stream, src)) => {
                            vp_transport::tune(&stream);
                            let ctx = ctx.clone();
                            let tag = tag.clone();
                            tokio::spawn(async move {
                                let dst = match tproxy_tcp_dst(&stream) {
                                    Ok(d) => d,
                                    Err(e) => {
                                        debug!("tproxy tcp 获取原始目标失败: {e}");
                                        return;
                                    }
                                };
                                let sess = Session::new_tcp(tag, Some(src), dst);
                                dispatch_stream(&ctx, sess, Box::new(stream), ClientReply::None)
                                    .await;
                            });
                        }
                        Err(e) => {
                            warn!("tproxy tcp accept 失败: {e}");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            });
        }

        // 2. 启动 UDP TPROXY 接收器与状态分发
        let udp_sock = create_tproxy_udp_socket(bind_addr)?;
        let udp_async_fd = Arc::new(
            unsafe { AsyncFd::register(udp_sock) }.map_err(|e| Error::Io(e.into_parts().1))?,
        );

        {
            let ctx = ctx.clone();
            let tag = tag.clone();
            let flows: UdpFlowMap = Arc::new(Mutex::new(HashMap::new()));

            tokio::spawn(async move {
                loop {
                    let mut guard = match udp_async_fd.readable().await {
                        Ok(g) => g,
                        Err(e) => {
                            warn!("tproxy udp async_fd 错误: {e}");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                    };

                    match guard.try_io(|inner| recv_tproxy_udp_msg(inner.as_raw_fd())) {
                        Ok(Ok((src, orig_dst, data))) => {
                            if data.is_empty() {
                                continue;
                            }
                            let payload = Bytes::from(data);
                            let flow_key = (src, orig_dst);

                            // 取出活跃流的 tx 后立即释放锁再投递：流任务终止时需要抢同一把锁
                            // （remove），持锁 send 在通道满时会与其互等死锁，进而瘫痪整个收包器
                            let existing = flows.lock().await.get(&flow_key).cloned();
                            if let Some(tx) = existing {
                                if tx.send(payload.clone()).await.is_ok() {
                                    continue;
                                }
                                // 流任务已终止（其结束路径会移除本键），清理滞留句柄后走新建流程
                                flows.lock().await.remove(&flow_key);
                            }

                            // 首包/旧流已亡：路由解析与出站建连（可能慢）在锁外执行，不阻塞其他流
                            match spawn_tproxy_udp_flow(flow_key, &ctx, tag.clone(), flows.clone())
                                .await
                            {
                                Ok(tx) => {
                                    let _ = tx.send(payload).await;
                                    flows.lock().await.insert(flow_key, tx);
                                }
                                Err(e) => {
                                    debug!("tproxy udp 新建流失败 {src} -> {orig_dst}: {e}");
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            if e.kind() != std::io::ErrorKind::WouldBlock {
                                debug!("tproxy udp 读报文失败: {e}");
                            }
                        }
                        Err(_would_block) => {}
                    }
                }
            });
        }

        info!("tproxy (TCP+UDP) 监听 {}:{}", inbound.bind, bound_port);
        Ok(bound_port)
    }

    fn create_tproxy_tcp_listener(bind_addr: SocketAddr) -> Result<TcpListener> {
        let domain = if bind_addr.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        };
        let sock = socket2::Socket::new(domain, socket2::Type::STREAM, None).map_err(Error::Io)?;
        sock.set_reuse_address(true).map_err(Error::Io)?;
        let _ = sock.set_reuse_port(true);

        unsafe {
            let opt: libc::c_int = 1;
            let res = if bind_addr.is_ipv6() {
                libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::SOL_IPV6,
                    libc::IPV6_TRANSPARENT,
                    &opt as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&opt) as libc::socklen_t,
                )
            } else {
                libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::SOL_IP,
                    libc::IP_TRANSPARENT,
                    &opt as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&opt) as libc::socklen_t,
                )
            };
            if res != 0 {
                return Err(Error::Io(std::io::Error::last_os_error()));
            }
        }

        sock.bind(&bind_addr.into()).map_err(Error::Io)?;
        sock.listen(1024).map_err(Error::Io)?;
        sock.set_nonblocking(true).map_err(Error::Io)?;

        let std_listener: std::net::TcpListener = sock.into();
        TcpListener::from_std(std_listener).map_err(Error::Io)
    }

    fn create_tproxy_udp_socket(bind_addr: SocketAddr) -> Result<std::net::UdpSocket> {
        let domain = if bind_addr.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        };
        let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, None).map_err(Error::Io)?;
        sock.set_reuse_address(true).map_err(Error::Io)?;
        let _ = sock.set_reuse_port(true);

        unsafe {
            let opt: libc::c_int = 1;
            let res = if bind_addr.is_ipv6() {
                let r1 = libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::SOL_IPV6,
                    libc::IPV6_TRANSPARENT,
                    &opt as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&opt) as libc::socklen_t,
                );
                let r2 = libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::SOL_IPV6,
                    libc::IPV6_RECVORIGDSTADDR,
                    &opt as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&opt) as libc::socklen_t,
                );
                r1 | r2
            } else {
                let r1 = libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::SOL_IP,
                    libc::IP_TRANSPARENT,
                    &opt as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&opt) as libc::socklen_t,
                );
                let r2 = libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::SOL_IP,
                    libc::IP_RECVORIGDSTADDR,
                    &opt as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&opt) as libc::socklen_t,
                );
                let r3 = libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::SOL_IP,
                    libc::IP_PKTINFO,
                    &opt as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&opt) as libc::socklen_t,
                );
                r1 | r2 | r3
            };
            if res != 0 {
                return Err(Error::Io(std::io::Error::last_os_error()));
            }
        }

        sock.bind(&bind_addr.into()).map_err(Error::Io)?;
        sock.set_nonblocking(true).map_err(Error::Io)?;

        Ok(sock.into())
    }

    fn tproxy_tcp_dst(stream: &tokio::net::TcpStream) -> Result<DstAddr> {
        // TPROXY 模式下 stream.local_addr() 即为被重定向的真实原始目标
        match stream.local_addr() {
            Ok(addr) => Ok(DstAddr::ip(addr.ip(), addr.port())),
            Err(_) => {
                // 兜底尝试 SO_ORIGINAL_DST
                crate::redir::original_dst(stream)
            }
        }
    }

    fn recv_tproxy_udp_msg(fd: RawFd) -> std::io::Result<(SocketAddr, SocketAddr, Vec<u8>)> {
        let mut buf = [0u8; 65535];
        let mut cmsg_buf = [0u8; 512];
        let mut src_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut msg = libc::msghdr {
            msg_name: &mut src_storage as *mut _ as *mut libc::c_void,
            msg_namelen: std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: cmsg_buf.as_mut_ptr() as *mut libc::c_void,
            msg_controllen: cmsg_buf.len(),
            msg_flags: 0,
        };

        let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let src = parse_sockaddr_storage(&src_storage)?;
        // 严格模式：cmsg 缺失说明 iptables 使用了 REDIRECT 而非 TPROXY 目标（UDP 无原始目标
        // 可恢复），回退 src 会把数据报静默路由回客户端自身 —— 必须明确报错丢弃以便排查
        let orig_dst = parse_orig_dst_cmsg(&msg).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "缺失 IP_ORIGDSTADDR 辅助数据（iptables 需使用 TPROXY 目标而非 REDIRECT）",
            )
        })?;
        Ok((src, orig_dst, buf[..n as usize].to_vec()))
    }

    fn parse_sockaddr_storage(storage: &libc::sockaddr_storage) -> std::io::Result<SocketAddr> {
        unsafe {
            if storage.ss_family == libc::AF_INET as libc::sa_family_t {
                let sin = &*(storage as *const _ as *const libc::sockaddr_in);
                let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                let port = u16::from_be(sin.sin_port);
                Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port))
            } else if storage.ss_family == libc::AF_INET6 as libc::sa_family_t {
                let sin6 = &*(storage as *const _ as *const libc::sockaddr_in6);
                let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                let port = u16::from_be(sin6.sin6_port);
                Ok(SocketAddr::new(std::net::IpAddr::V6(ip), port))
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "不支持的 sockaddr 协议族",
                ))
            }
        }
    }

    fn parse_orig_dst_cmsg(msg: &libc::msghdr) -> Option<SocketAddr> {
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(msg);
            while !cmsg.is_null() {
                let level = (*cmsg).cmsg_level;
                let msg_type = (*cmsg).cmsg_type;

                if level == libc::SOL_IP
                    && (msg_type == libc::IP_RECVORIGDSTADDR || msg_type == libc::IP_ORIGDSTADDR)
                {
                    let data_ptr = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in;
                    let addr = &*data_ptr;
                    let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
                    let port = u16::from_be(addr.sin_port);
                    return Some(SocketAddr::new(std::net::IpAddr::V4(ip), port));
                }

                if level == libc::SOL_IPV6
                    && (msg_type == libc::IPV6_RECVORIGDSTADDR
                        || msg_type == libc::IPV6_ORIGDSTADDR)
                {
                    let data_ptr = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6;
                    let addr = &*data_ptr;
                    let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
                    let port = u16::from_be(addr.sin6_port);
                    return Some(SocketAddr::new(std::net::IpAddr::V6(ip), port));
                }

                cmsg = libc::CMSG_NXTHDR(msg, cmsg);
            }
        }
        None
    }

    /// 创建透明回包套接字：bind 到原始目标地址，以原始目标 IP 作为源地址向客户端回复
    fn create_transparent_reply_socket(orig_dst: SocketAddr) -> Result<UdpSocket> {
        let domain = if orig_dst.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        };
        let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, None).map_err(Error::Io)?;
        sock.set_reuse_address(true).map_err(Error::Io)?;
        let _ = sock.set_reuse_port(true);

        unsafe {
            let opt: libc::c_int = 1;
            let res = if orig_dst.is_ipv6() {
                libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::SOL_IPV6,
                    libc::IPV6_TRANSPARENT,
                    &opt as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&opt) as libc::socklen_t,
                )
            } else {
                libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::SOL_IP,
                    libc::IP_TRANSPARENT,
                    &opt as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&opt) as libc::socklen_t,
                )
            };
            if res != 0 {
                return Err(Error::Io(std::io::Error::last_os_error()));
            }
        }

        sock.bind(&orig_dst.into()).map_err(Error::Io)?;
        sock.set_nonblocking(true).map_err(Error::Io)?;

        let std_sock: std::net::UdpSocket = sock.into();
        UdpSocket::from_std(std_sock).map_err(Error::Io)
    }

    async fn spawn_tproxy_udp_flow(
        (src, orig_dst): (SocketAddr, SocketAddr),
        ctx: &InboundCtx,
        tag: Arc<str>,
        flows: UdpFlowMap,
    ) -> Result<tokio::sync::mpsc::Sender<Bytes>> {
        let dst_addr = DstAddr::ip(orig_dst.ip(), orig_dst.port());
        let mut sess = Session::new_udp(tag, Some(src), dst_addr.clone());
        sess.network = Network::Udp;

        let res = ctx.router.pick(&sess).await;
        if !res.outbound.support_udp() {
            return Err(Error::Unsupported(format!(
                "出站 {} 不支持 UDP",
                res.outbound.name()
            )));
        }

        let mut conn = res.outbound.connect_packet(&sess, &dst_addr).await?;
        let reply_sock = create_transparent_reply_socket(orig_dst)?;

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(64);
        let key = (src, orig_dst);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    // 远端出站 -> 客户端透明回包
                    recv_res = conn.recv() => {
                        match recv_res {
                            Ok(pkt) => {
                                if let Err(e) = reply_sock.send_to(&pkt.data, src).await {
                                    debug!("tproxy udp 回包失败: {e}");
                                    break;
                                }
                            }
                            Err(e) => {
                                debug!("tproxy udp 远端接收失败: {e}");
                                break;
                            }
                        }
                    }
                    // 客户端 -> 远端出站
                    Some(data) = rx.recv() => {
                        let pkt = UdpPacket {
                            src,
                            dst: orig_dst,
                            data,
                        };
                        if let Err(e) = conn.send(&pkt).await {
                            debug!("tproxy udp 出站发送失败: {e}");
                            break;
                        }
                    }
                    // 60秒空闲回收
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {
                        break;
                    }
                }
            }
            flows.lock().await.remove(&key);
        });

        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tproxy_inbound_creation() {
        let inb = TproxyInbound::new("0.0.0.0", 7895, "tproxy");
        assert_eq!(inb.tag(), "tproxy");
        assert_eq!(inb.port, 7895);
        assert_eq!(inb.bind, "0.0.0.0");
    }
}

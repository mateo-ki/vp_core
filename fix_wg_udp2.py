p = 'crates/vp-protocol/src/wireguard.rs'
with open(p, 'rb') as f:
    data = f.read()

def rep(old, new, must=True):
    global data
    o = old.encode('utf-8'); nw = new.encode('utf-8')
    if o not in data:
        if must:
            raise AssertionError('NOT FOUND: ' + old[:80])
        return
    data = data.replace(o, nw, 1)

# ---- 4) pump_sessions 全量重写（TCP/UDP 分支）----
start = data.find('    let mut reaped: Vec<u64> = Vec::new();'.encode('utf-8'))
end_marker = '// ---------------------------------------------------------------------------\n// 会话流（AsyncRead/AsyncWrite）'.encode('utf-8')
end = data.find(end_marker)
assert start > 0 and end > start, (start, end)

new_pump = '''    let mut reaped: Vec<u64> = Vec::new();
    for (id, sess) in sessions.iter_mut() {
        match &sess.kind {
            SessKind::Udp { handle } => {
                let sock = sockets.get_mut::<smoltcp::socket::udp::Socket>(*handle);
                // 应用 → 栈
                loop {
                    if !sock.can_send() {
                        break;
                    }
                    match sess.down_rx.try_recv() {
                        Ok(DownMsg::Udp { dst, data }) => {
                            let remote = IpEndpoint::from(dst);
                            if let Err(e) = sock.send_slice(&data, remote) {
                                warn!("wireguard udp send_slice: {e:?}");
                            }
                        }
                        _ => break,
                    }
                }
                // 栈 → 应用
                if sess.up_tx.capacity() > 0 {
                    let mut buf = [0u8; 64 * 1024];
                    loop {
                        match sock.recv_slice(&mut buf) {
                            Ok((0, _)) => break,
                            Ok((n, meta)) => {
                                let src = endpoint_to_std(meta.endpoint);
                                let msg = UpMsg::Udp {
                                    src,
                                    data: Bytes::copy_from_slice(&buf[..n]),
                                };
                                if sess.up_tx.try_send(msg).is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
                continue;
            }
            SessKind::Tcp { handle, pending } => {
                let sock = sockets.get_mut::<tcp::Socket>(*handle);
                // 应用 → 栈（先冲上轮部分写入的残留）
                while sock.can_send() {
                    if let Some(p) = pending.take() {
                        match sock.send_slice(&p) {
                            Ok(n) if n == p.len() => continue,
                            Ok(n) => {
                                *pending = Some(p[n..].to_vec());
                                break;
                            }
                            Err(e) => {
                                warn!("wireguard pump pending err: {e:?}");
                                sess.closed = true;
                                break;
                            }
                        }
                    }
                    match sess.down_rx.try_recv() {
                        Ok(DownMsg::Tcp(data)) => {
                            match sock.send_slice(&data) {
                                Ok(n) if n == data.len() => {}
                                Ok(n) => {
                                    // 部分写入（缓冲满）：未发部分暂存，下轮续写
                                    *pending = Some(data[n..].to_vec());
                                    break;
                                }
                                Err(e) => {
                                    warn!("wireguard pump send err: {e:?}");
                                    sess.closed = true;
                                    break;
                                }
                            }
                        }
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            // 应用侧写完：半关闭（发 FIN）
                            sock.close();
                            break;
                        }
                        Ok(_) => {}
                    }
                }
                // 栈 → 应用（通道满时不取，数据留在 socket 缓冲待下轮）
                loop {
                    if !sock.may_recv() {
                        if sock.state() == tcp::State::Closed {
                            sess.closed = true;
                        }
                        break;
                    }
                    if sess.up_tx.capacity() == 0 {
                        break;
                    }
                    let mut buf = [0u8; 64 * 1024];
                    match sock.recv_slice(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            match sess
                                .up_tx
                                .try_send(UpMsg::Tcp(Bytes::copy_from_slice(&buf[..n])))
                            {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => break,
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    sess.closed = true;
                                    break;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                    // 尽量搬空
                }
                if sess.closed {
                    reaped.push(*id);
                }
            }
        }
    }
    for id in reaped {
        if let Some(s) = sessions.remove(&id) {
            match s.kind {
                SessKind::Tcp { handle, .. } => sockets.remove(handle),
                SessKind::Udp { handle } => sockets.remove(handle),
            }
        }
    }
}

/// smoltcp IpEndpoint → std SocketAddr
fn endpoint_to_std(ep: smoltcp::wire::IpEndpoint) -> SocketAddr {
    match ep.addr {
        IpAddress::Ipv4(v4) => {
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::from(v4.0)), ep.port)
        }
        IpAddress::Ipv6(v6) => {
            SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::from(v6.0)), ep.port)
        }
    }
}

'''
data = data[:start] + new_pump.encode('utf-8') + data[end:]

with open(p, 'wb') as f:
    f.write(data)
print('part2 done')

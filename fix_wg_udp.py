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

# ---- 1) Cmd 加 ConnectUdp ----
rep('''enum Cmd {
    Connect {
        dst: SocketAddr,
        reply: SessionReply,
    },
}''',
'''enum Cmd {
    Connect {
        dst: SocketAddr,
        reply: SessionReply,
    },
    ConnectUdp {
        reply: tokio::sync::oneshot::Sender<
            Result<(mpsc::Receiver<UpMsg>, mpsc::Sender<DownMsg>)>,
        >,
    },
}''')

# ---- 2) Sess：UpMsg/DownMsg 枚举 ----
rep('''struct Sess {
    handle: SocketHandle,
    /// 部分写入时的未发数据
    pending: Option<Vec<u8>>,
    /// 栈→应用数据
    up_tx: mpsc::Sender<Bytes>,
    /// 应用→栈数据
    down_rx: mpsc::Receiver<Vec<u8>>,
    /// 栈侧已读满/关闭标志
    closed: bool,
}''',
'''/// 栈→应用消息（TCP 数据流 / UDP 数据报）
pub enum UpMsg {
    Tcp(Bytes),
    Udp { src: SocketAddr, data: Bytes },
}

/// 应用→栈消息
pub enum DownMsg {
    Tcp(Vec<u8>),
    Udp { dst: SocketAddr, data: Vec<u8> },
}

enum SessKind {
    Tcp { handle: SocketHandle, pending: Option<Vec<u8>> },
    Udp { handle: SocketHandle },
}

struct Sess {
    kind: SessKind,
    /// 栈→应用数据
    up_tx: mpsc::Sender<UpMsg>,
    /// 应用→栈数据
    down_rx: mpsc::Receiver<DownMsg>,
    /// 栈侧已读满/关闭标志
    closed: bool,
}''')

# ---- 3) connect_session 适配 ----
rep('''    let mut sock = tcp::Socket::new(rx_buf, tx_buf);
    // sock.set_nagle_enabled(false); // 实验：恢复 Nagle 观察重复段
    if let Err(e) = sock.connect(iface.context(), remote, local) {
        return Err(Error::ProtoMsg(format!("wireguard 栈 connect: {:?}", e)));
    }
    let handle = sockets.add(sock);

    let (up_tx, up_rx) = mpsc::channel::<Bytes>(CHAN_CAP);
    let (down_tx, down_rx) = mpsc::channel::<Vec<u8>>(CHAN_CAP);
    let id = *next_sess_id;
    *next_sess_id += 1;
    sessions.insert(
        id,
        Sess {
            handle,
            pending: None,
            up_tx,
            down_rx,
            closed: false,
        },
    );

    Ok((up_rx, down_tx))
}''',
'''    let mut sock = tcp::Socket::new(rx_buf, tx_buf);
    sock.set_nagle_enabled(false);
    if let Err(e) = sock.connect(iface.context(), remote, local) {
        return Err(Error::ProtoMsg(format!("wireguard 栈 connect: {:?}", e)));
    }
    let handle = sockets.add(sock);

    let (up_tx, up_rx) = mpsc::channel::<UpMsg>(CHAN_CAP);
    let (down_tx, down_rx) = mpsc::channel::<DownMsg>(CHAN_CAP);
    let id = *next_sess_id;
    *next_sess_id += 1;
    sessions.insert(
        id,
        Sess {
            kind: SessKind::Tcp {
                handle,
                pending: None,
            },
            up_tx,
            down_rx,
            closed: false,
        },
    );

    Ok((up_rx, down_tx))
}

/// 新建栈内 UDP 会话（connect_packet 的 dst 在 send 时动态携带）。
fn connect_udp_session(
    sockets: &mut SocketSet<'_>,
    sessions: &mut HashMap<u64, Sess>,
    next_sess_id: &mut u64,
) -> Result<(mpsc::Receiver<UpMsg>, mpsc::Sender<DownMsg>)> {
    let rx_buf = smoltcp::socket::udp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
    let tx_buf = smoltcp::socket::udp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
    let mut sock = smoltcp::socket::udp::Socket::new(rx_buf, tx_buf);
    let local_port = WgCore::next_local_port();
    if let Err(e) = sock.bind(local_port) {
        return Err(Error::ProtoMsg(format!("wireguard 栈 udp bind: {:?}", e)));
    }
    let handle = sockets.add(sock);

    let (up_tx, up_rx) = mpsc::channel::<UpMsg>(CHAN_CAP);
    let (down_tx, down_rx) = mpsc::channel::<DownMsg>(CHAN_CAP);
    let id = *next_sess_id;
    *next_sess_id += 1;
    sessions.insert(
        id,
        Sess {
            kind: SessKind::Udp { handle },
            up_tx,
            down_rx,
            closed: false,
        },
    );

    Ok((up_rx, down_tx))
}''')

with open(p, 'wb') as f:
    f.write(data)
print('part1 done')

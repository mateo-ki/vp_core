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

# ---- 1) stack_task 的 Cmd 处理加 ConnectUdp ----
rep('''                match cmd {
                    Cmd::Connect { dst, reply } => {
                        let r = connect_session(
                            &mut iface, &mut sockets, &mut sessions,
                            &mut next_sess_id, local_v4, local_v6, dst,
                        );
                        let _ = reply.send(r);
                    }
                }''',
'''                match cmd {
                    Cmd::Connect { dst, reply } => {
                        let r = connect_session(
                            &mut iface, &mut sockets, &mut sessions,
                            &mut next_sess_id, local_v4, local_v6, dst,
                        );
                        let _ = reply.send(r);
                    }
                    Cmd::ConnectUdp { reply } => {
                        let r = connect_udp_session(&mut sockets, &mut sessions, &mut next_sess_id);
                        let _ = reply.send(r);
                    }
                }''')

# ---- 2) WgUdpConn + connect_packet（替换现有 connect_packet 的报错实现）----
rep('''    async fn connect_packet(
        &self,
        _sess: &Session,
        _dst: &DstAddr,
    ) -> Result<Box<dyn PacketConn>> {
        Err(Error::Unsupported("wireguard UDP 出站暂未实现".into()))
    }''',
'''    async fn connect_packet(
        &self,
        _sess: &Session,
        _dst: &DstAddr,
    ) -> Result<Box<dyn PacketConn>> {
        let (reply_tx, reply_rx): (
            _,
            tokio::sync::oneshot::Sender<Result<(mpsc::Receiver<UpMsg>, mpsc::Sender<DownMsg>)>>,
        ) = tokio::sync::oneshot::channel();
        self.core
            .cmd_tx
            .send(Cmd::ConnectUdp { reply: reply_tx })
            .await
            .map_err(|_| Error::ProtoMsg("wireguard 隧道任务已退出".into()))?;
        let (up_rx, down_tx) = reply_rx
            .await
            .map_err(|_| Error::ProtoMsg("wireguard 隧道任务已退出".into()))??;
        Ok(Box::new(WgUdpConn {
            up_rx,
            down_tx,
            local: SocketAddr::new(
                std::net::IpAddr::V4(self.core.local_v4),
                0,
            ),
        }))
    }''')

# ---- 3) 在 WgTcpStream 定义之前插入 WgUdpConn ----
rep('''// ---------------------------------------------------------------------------
// 会话流（AsyncRead/AsyncWrite）
// ---------------------------------------------------------------------------''',
'''/// UDP 会话连接：数据报直达栈内 UDP socket，dst 动态携带（多点目标）。
pub struct WgUdpConn {
    up_rx: mpsc::Receiver<UpMsg>,
    down_tx: mpsc::Sender<DownMsg>,
    /// 隧道内本机地址（回包 UdpPacket.dst 填充）
    local: SocketAddr,
}

#[async_trait::async_trait]
impl PacketConn for WgUdpConn {
    async fn send(&self, pkt: &UdpPacket) -> Result<()> {
        self.down_tx
            .send(DownMsg::Udp {
                dst: pkt.dst,
                data: pkt.data.to_vec(),
            })
            .await
            .map_err(|_| Error::ProtoMsg("wireguard UDP 会话已关闭".into()))
    }

    async fn recv(&mut self) -> Result<UdpPacket> {
        loop {
            match self.up_rx.recv().await {
                Some(UpMsg::Udp { src, data }) => {
                    return Ok(UdpPacket {
                        src,
                        dst: self.local,
                        data,
                    });
                }
                Some(UpMsg::Tcp(_)) => continue,
                None => return Err(Error::ProtoMsg("wireguard UDP 会话已关闭".into())),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 会话流（AsyncRead/AsyncWrite）
// ---------------------------------------------------------------------------''')

# ---- 4) WgTcpStream 适配 UpMsg/DownMsg ----
rep('''pub struct WgTcpStream {
    up_rx: Pin<Box<mpsc::Receiver<Bytes>>>,
    down_tx: Pin<Box<mpsc::Sender<Vec<u8>>>>,''',
'''pub struct WgTcpStream {
    up_rx: Pin<Box<mpsc::Receiver<UpMsg>>>,
    down_tx: Pin<Box<mpsc::Sender<DownMsg>>>,''')
rep('''            match Pin::new(&mut this.up_rx).poll_recv(cx) {
                Poll::Ready(Some(b)) => {
                    if b.is_empty() {
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    this.cur = Some(b);
                }''',
'''            match Pin::new(&mut this.up_rx).poll_recv(cx) {
                Poll::Ready(Some(UpMsg::Tcp(b))) => {
                    if b.is_empty() {
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    this.cur = Some(b);
                }
                Poll::Ready(Some(UpMsg::Udp { .. })) => continue,''')
rep('''        // 快路径 try_send；满时唤醒重试（栈任务 ≤1ms 后泵走数据）
        match this.down_tx.try_send(buf.to_vec()) {''',
'''        // 快路径 try_send；满时唤醒重试（栈任务 ≤1ms 后泵走数据）
        match this.down_tx.try_send(DownMsg::Tcp(buf.to_vec())) {''')
rep('''    fn new(up_rx: mpsc::Receiver<Bytes>, down_tx: mpsc::Sender<Vec<u8>>) -> Self {''',
'''    fn new(up_rx: mpsc::Receiver<UpMsg>, down_tx: mpsc::Sender<DownMsg>) -> Self {''')

with open(p, 'wb') as f:
    f.write(data)
print('part3 done')

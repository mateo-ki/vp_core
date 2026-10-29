//! Linux splice 零拷贝转发快速路径（裸 socket ↔ 裸 socket 直连）。
//!
//! 数据全程驻留内核：socket → pipe → socket，一次内存拷贝都没有。
//! syscall 形状：每次最多 CHUNK 字节，2 次 splice（入 + 出）；
//! 对比通用泵的 read + write 至少省掉两次用户态拷贝与缓冲占用。
//!
//! 就绪机制：socket 侧用 tokio 自带的 readable()/writable()（fd 已在 reactor
//! 注册，不得重复注册）；管道自持、O_NONBLOCK，用 AsyncFd 包装。
//!
//! 排空不变量：进入"填管道"步骤时管道必为空（上轮已排干），
//! 因此填管道返回 EAGAIN 只可能是 socket 暂无数据，无歧义。
//!
//! 失败语义：建管道/AsyncFd 注册失败发生在任何数据移动之前，
//! 返回 Err 由调用方回退通用泵；数据移动开始后出错则按半关闭收场。

use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tokio::net::TcpStream;

use vp_common::Stats;

/// 单次 splice 的字节数上限。
const CHUNK: usize = 1 << 18; // 256KB
/// 管道缓冲目标大小（best-effort，内核默认 64KB 也能正确工作）。
const PIPE_CAP: usize = 1 << 20; // 1MB

/// 拥有并关闭一个 fd（Drop 顺序：AsyncFd 先解注册，FdGuard 后 close）。
struct FdGuard(RawFd);

impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

/// 仅作 AsyncFd 注册载体的裸 fd 视图（不拥有 fd）。
struct FdView(RawFd);

impl AsRawFd for FdView {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

struct PipeEnd {
    /// 先声明：Drop 时先解注册再关 fd。
    _afd: AsyncFd<FdView>,
    fd: FdGuard,
}

impl PipeEnd {
    fn new(fd: RawFd) -> io::Result<Self> {
        Ok(PipeEnd {
            _afd: AsyncFd::new(FdView(fd))?,
            fd: FdGuard(fd),
        })
    }
}

struct Pipe {
    r: PipeEnd,
    w: PipeEnd,
}

impl Pipe {
    fn new() -> io::Result<Self> {
        let mut fds = [0 as RawFd; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // 扩到 1MB 失败也不影响正确性（默认 64KB 只是批量小一些）
        unsafe { libc::fcntl(fds[1], libc::F_SETPIPE_SZ, PIPE_CAP) };
        Ok(Pipe {
            r: PipeEnd::new(fds[0])?,
            w: PipeEnd::new(fds[1])?,
        })
    }
}

fn splice_try(fd_in: RawFd, fd_out: RawFd, len: usize) -> io::Result<isize> {
    let n = unsafe {
        libc::splice(
            fd_in,
            std::ptr::null_mut(),
            fd_out,
            std::ptr::null_mut(),
            len,
            libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
        )
    };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n)
    }
}

fn shutdown_write(s: &TcpStream) {
    unsafe { libc::shutdown(s.as_raw_fd(), libc::SHUT_WR) };
}

/// 单方向零拷贝泵：input → pipe → output，直到 input EOF。
/// 与通用 pump 相同的统计语义（per-iteration 一次 fetch_add）。
async fn pump_dir(
    input: &TcpStream,
    output: &TcpStream,
    pipe: &Pipe,
    counter: &AtomicU64,
    stats: Option<&Arc<Stats>>,
    up: bool,
) -> io::Result<()> {
    loop {
        // 1) 填管道：input → pipe.w（管道此时必为空，EAGAIN 仅意味着暂无数据）
        let n = loop {
            match splice_try(input.as_raw_fd(), pipe.w.fd.0, CHUNK) {
                Ok(n) => break n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    input.readable().await?;
                }
                Err(e) => return Err(e),
            }
        };
        if n == 0 {
            // EOF：半关闭对端写侧，收场
            shutdown_write(output);
            return Ok(());
        }
        // 2) 排空：pipe.r → output，恰好 n 字节
        let mut left = n as usize;
        while left > 0 {
            match splice_try(pipe.r.fd.0, output.as_raw_fd(), left) {
                Ok(m) => left -= m as usize,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    output.writable().await?;
                }
                Err(e) => return Err(e),
            }
        }
        counter.fetch_add(n as u64, Ordering::Relaxed);
        if let Some(st) = stats {
            if up {
                st.add_up(n as u64);
            } else {
                st.add_down(n as u64);
            }
        }
    }
}

/// 裸 socket 双向零拷贝转发：返回 (up, down) 字节数。
/// 两个方向在同一个任务里 join（任一方向 EOF → shutdown 对端写侧，与通用泵语义一致）。
pub async fn relay_pair(a: &TcpStream, b: &TcpStream, stats: Option<Arc<Stats>>) -> io::Result<(u64, u64)> {
    let up_pipe = Pipe::new()?;
    let down_pipe = Pipe::new()?;
    let up = Arc::new(AtomicU64::new(0));
    let down = Arc::new(AtomicU64::new(0));

    let (r1, r2) = tokio::join!(
        pump_dir(a, b, &up_pipe, &up, stats.as_ref(), true),
        pump_dir(b, a, &down_pipe, &down, stats.as_ref(), false),
    );
    r1?;
    r2?;
    Ok((up.load(Ordering::Relaxed), down.load(Ordering::Relaxed)))
}

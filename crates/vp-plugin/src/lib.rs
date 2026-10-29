//! vp-plugin：C-ABI 插件宿主。
//!
//! 加载 transform 插件动态库，包装为流装饰器：
//! 写路径（上行）与读路径（下行）经插件变换后透传。

use std::ffi::c_void;
use std::os::raw::c_char;
use std::pin::Pin;
use std::ptr;
use std::sync::Arc;
use std::task::{Context, Poll};

use libloading::{Library, Symbol};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use vp_common::{Error, Result};
use vp_core::ProxyStream;
use vp_plugin_sdk::{DIR_DOWNSTREAM, DIR_UPSTREAM, VpTransformVt};

/// 已加载的 transform 插件
pub struct TransformPlugin {
    _lib: Library,
    vt: &'static VpTransformVt,
    handle: *mut c_void,
}

unsafe impl Send for TransformPlugin {}
unsafe impl Sync for TransformPlugin {}

impl TransformPlugin {
    /// 加载动态库并创建实例
    pub fn load(path: &std::path::Path, cfg_json: &str) -> Result<Self> {
        unsafe {
            let lib = Library::new(path)
                .map_err(|e| Error::Plugin(format!("加载 {} 失败: {e}", path.display())))?;
            let sym: Symbol<unsafe extern "C" fn() -> *const VpTransformVt> = lib
                .get(b"vp_transform_abi")
                .map_err(|e| Error::Plugin(format!("缺少导出 vp_transform_abi: {e}")))?;
            let vt = sym();
            if vt.is_null() {
                return Err(Error::Plugin("vp_transform_abi 返回空".into()));
            }
            let vt = &*vt;
            if (vt.abi_version)() != vp_plugin_sdk::ABI_VERSION {
                return Err(Error::Plugin(format!(
                    "ABI 版本不匹配：插件 {}，宿主 {}",
                    (vt.abi_version)(),
                    vp_plugin_sdk::ABI_VERSION
                )));
            }
            let cfg_bytes = cfg_json.as_bytes();
            let handle = (vt.create)(cfg_bytes.as_ptr() as *const c_char, cfg_bytes.len());
            if handle.is_null() {
                return Err(Error::Plugin("插件 create 失败".into()));
            }
            debug!("插件已加载: {}", path.display());
            Ok(TransformPlugin {
                _lib: lib,
                vt,
                handle,
            })
        }
    }

    /// 变换；返回 None 表示透传
    pub fn transform(&self, dir: u32, input: &[u8]) -> Result<Option<Vec<u8>>> {
        unsafe {
            let mut out_ptr: *mut u8 = ptr::null_mut();
            let mut out_len: usize = 0;
            let rc = (self.vt.transform)(
                self.handle,
                dir,
                input.as_ptr(),
                input.len(),
                &mut out_ptr,
                &mut out_len,
            );
            if rc != 0 {
                return Err(Error::Plugin(format!("transform 返回 {rc}")));
            }
            if out_ptr.is_null() {
                return Ok(None);
            }
            // 先拷贝再由插件释放，避免跨分配器问题
            let out = std::slice::from_raw_parts(out_ptr, out_len).to_vec();
            (self.vt.free_buf)(self.handle, out_ptr, out_len);
            Ok(Some(out))
        }
    }
}

impl Drop for TransformPlugin {
    fn drop(&mut self) {
        unsafe { (self.vt.destroy)(self.handle) }
    }
}

// ---------------------------------------------------------------------------
// 流装饰器
// ---------------------------------------------------------------------------

pub struct TransformStream<S> {
    inner: S,
    plugin: Arc<TransformPlugin>,
    pending: Vec<u8>, // 变换后待读
    out: Vec<u8>,     // 写方向积压
    closed: bool,
}

impl<S> vp_core::ProxyStream for TransformStream<S> where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
}

impl<S> TransformStream<S> {
    pub fn new(inner: S, plugin: Arc<TransformPlugin>) -> Self {
        TransformStream {
            inner,
            plugin,
            pending: Vec::new(),
            out: Vec::new(),
            closed: false,
        }
    }

    fn drain_pending(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.pending.is_empty() {
            return false;
        }
        let n = self.pending.len().min(buf.remaining());
        buf.put_slice(&self.pending[..n]);
        self.pending.drain(..n);
        true
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TransformStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        loop {
            if this.drain_pending(buf) {
                return Poll::Ready(Ok(()));
            }
            if this.closed {
                return Poll::Ready(Ok(()));
            }
            // 读到底层
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
            let filled = rb.filled().len();
            if filled == 0 {
                this.closed = true;
                return Poll::Ready(Ok(()));
            }
            match this.plugin.transform(DIR_DOWNSTREAM, &tmp[..filled]) {
                Ok(Some(v)) => this.pending.extend_from_slice(&v),
                Ok(None) => this.pending.extend_from_slice(&tmp[..filled]),
                Err(_) => {
                    this.closed = true;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TransformStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if this.closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "plugin stream 已关闭",
            )));
        }
        while !this.out.is_empty() {
            let mut inner = Pin::new(&mut this.inner);
            match inner.as_mut().poll_write(cx, &this.out) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "写入 0 字节",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.out.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        match this.plugin.transform(DIR_UPSTREAM, buf) {
            Ok(Some(v)) => this.out.extend_from_slice(&v),
            Ok(None) => this.out.extend_from_slice(buf),
            Err(e) => return Poll::Ready(Err(std::io::Error::other(e.to_string()))),
        }
        while !this.out.is_empty() {
            let mut inner = Pin::new(&mut this.inner);
            match inner.as_mut().poll_write(cx, &this.out) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "写入 0 字节",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.out.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        while !this.out.is_empty() {
            let mut inner = Pin::new(&mut this.inner);
            match inner.as_mut().poll_write(cx, &this.out) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "写入 0 字节",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.out.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        this.closed = true;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// 将任意流包上插件变换
pub fn wrap_stream(
    stream: Box<dyn ProxyStream>,
    plugin: Arc<TransformPlugin>,
) -> Box<dyn ProxyStream> {
    Box::new(TransformStream::new(stream, plugin))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 本地回声 + 插件变换往返（需先构建 xor_mask：cargo build -p xor_mask）
    #[tokio::test]
    async fn xor_mask_plugin_roundtrip() {
        let dll = find_plugin();
        let (require_build, path) = dll;
        if require_build.is_none() {
            eprintln!("跳过：先运行 cargo build -p xor_mask");
            return;
        }
        let plugin = Arc::new(TransformPlugin::load(&path, r#"{"key":"abc"}"#).unwrap());
        // 变换可逆
        let t = plugin.transform(DIR_UPSTREAM, b"hello").unwrap().unwrap();
        assert_ne!(t, b"hello");
        let back = plugin.transform(DIR_DOWNSTREAM, &t).unwrap().unwrap();
        assert_eq!(back, b"hello");

        // 流往返
        let (a, mut b) = tokio::io::duplex(4096);
        let mut wrapped = TransformStream::new(a, plugin);
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        wrapped.write_all(b"ping-plugin").await.unwrap();
        let mut got = [0u8; 11];
        b.read_exact(&mut got).await.unwrap(); // 服务端收到密文
        assert_ne!(&got, b"ping-plugin");
        b.write_all(&got).await.unwrap(); // 原样返回
        let mut plain = [0u8; 11];
        wrapped.read_exact(&mut plain).await.unwrap();
        assert_eq!(&plain, b"ping-plugin");
    }

    // 返回 (Option<()>, path)：dll 不存在时 None
    fn find_plugin() -> (Option<()>, std::path::PathBuf) {
        let name = if cfg!(windows) {
            "xor_mask.dll"
        } else {
            "libxor_mask.so"
        };
        for cand in [
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/release")
                .join(name),
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/debug")
                .join(name),
        ] {
            if cand.exists() {
                return (Some(()), cand);
            }
        }
        (None, cand0(name))
    }

    fn cand0(name: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/release")
            .join(name)
    }
}

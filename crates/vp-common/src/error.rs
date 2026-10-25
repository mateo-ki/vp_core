//! 统一错误类型。

use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// 协议格式非法，携带静态描述（避免热路径分配）
    Proto(&'static str),
    /// 协议错误，携带动态描述
    ProtoMsg(String),
    /// 配置错误（含定位信息）
    Config(String),
    /// DNS 解析失败
    Dns(String),
    /// 不支持的能力
    Unsupported(String),
    /// 插件错误
    Plugin(String),
    /// 目标地址无法解析
    Addr(String),
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Proto(m) => write!(f, "protocol: {m}"),
            Error::ProtoMsg(m) => write!(f, "protocol: {m}"),
            Error::Config(m) => write!(f, "config: {m}"),
            Error::Dns(m) => write!(f, "dns: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported: {m}"),
            Error::Plugin(m) => write!(f, "plugin: {m}"),
            Error::Addr(m) => write!(f, "addr: {m}"),
            Error::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Io(io) => io,
            other => std::io::Error::new(std::io::ErrorKind::Other, other.to_string()),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[macro_export]
macro_rules! bail {
    ($kind:ident, $($arg:tt)*) => {
        return Err($crate::error::Error::$kind(format!($($arg)*)))
    };
}

#[macro_export]
macro_rules! proto_err {
    ($($arg:tt)*) => {
        Err($crate::error::Error::ProtoMsg(format!($($arg)*)))
    };
}

impl Error {
    /// 连接类错误（对端拒绝/超时等）——用于健康检查判定节点存活
    pub fn is_connect_failure(&self) -> bool {
        matches!(self, Error::Io(e) if matches!(
            e.kind(),
            std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::HostUnreachable
                | std::io::ErrorKind::NetworkUnreachable
        ))
    }
}

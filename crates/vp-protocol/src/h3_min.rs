//! 最小 HTTP/3（RFC 9114）认证层 —— hysteria2 专用。
//!
//! 设计取舍：两端皆为本内核时，QPACK 全部采用 literal-without-name-reference、
//! 不使用 Huffman、不使用动态表 —— 编解码器因此只有百余行。
//! 对接官方 hysteria2 服务端：literal/Huffman-free 编码是合法 QPACK，可正常认证；
//! 官方客户端连本服务端时若使用 Huffman/动态表则不兼容（明确的设计边界）。
//!
//! 帧格式：`[varint type][varint len][payload]`
//! 流类型（uni 流首 varint）：0x00 控制流 / 0x02 QPACK encoder / 0x03 QPACK decoder

use vp_common::{Error, Result};

use super::hysteria2::{read_varint, write_varint};

pub const FRAME_HEADERS: u64 = 0x1;
pub const FRAME_DATA: u64 = 0x0;
pub const FRAME_SETTINGS: u64 = 0x4;
pub const STREAM_CONTROL: u64 = 0x00;
pub const STREAM_QPACK_ENCODER: u64 = 0x02;
pub const STREAM_QPACK_DECODER: u64 = 0x03;

// ---------------------------------------------------------------------------
// QPACK 极简编解码（literal no-name-ref / no huffman / no dynamic）
// ---------------------------------------------------------------------------

/// 编码一个头字段：`[0b00100000][len][name][len][value]`（H=0，name index=0）
fn qpack_literal(out: &mut Vec<u8>, name: &str, value: &str) {
    out.push(0x20); // literal without name reference, never indexed, huffman off
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
    out.push(value.len() as u8);
    out.extend_from_slice(value.as_bytes());
}

/// 编码头块 → HEADERS 帧完整字节
pub fn headers_frame(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut block = Vec::new();
    for (n, v) in fields {
        qpack_literal(&mut block, n, v);
    }
    let mut frame = Vec::with_capacity(block.len() + 8);
    write_varint(&mut frame, FRAME_HEADERS);
    write_varint(&mut frame, block.len() as u64);
    frame.extend_from_slice(&block);
    frame
}

/// 解码头块（仅支持本编码器产生的形式）
pub fn decode_header_block(block: &[u8]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < block.len() {
        let b = block[i];
        match b & 0xE0 {
            0x20 | 0x10 => {
                // literal（可索引/不可索引，均按 literal 处理）
                i += 1;
                let nlen = *block.get(i).ok_or(Error::Proto("qpack: name len"))? as usize;
                i += 1;
                let name = std::str::from_utf8(
                    block.get(i..i + nlen).ok_or(Error::Proto("qpack: name"))?,
                )
                .map_err(|_| Error::Proto("qpack: name utf8"))?;
                i += nlen;
                let vlen = *block.get(i).ok_or(Error::Proto("qpack: value len"))? as usize;
                i += 1;
                let value = std::str::from_utf8(
                    block.get(i..i + vlen).ok_or(Error::Proto("qpack: value"))?,
                )
                .map_err(|_| Error::Proto("qpack: value utf8"))?;
                i += vlen;
                out.push((name.to_string(), value.to_string()));
            }
            _ => {
                return Err(Error::ProtoMsg(format!(
                    "qpack: 不支持的编码形式 {b:#04x}（indexed/huffman/dynamic）"
                )))
            }
        }
    }
    Ok(out)
}

/// 解析单帧：返回 (type, payload, consumed)
pub fn parse_frame(buf: &[u8]) -> Option<(u64, Vec<u8>, usize)> {
    let (ty, a) = read_varint(buf)?;
    let (len, b) = read_varint(&buf[a..])?;
    let start = a + b;
    let end = start.checked_add(len as usize)?;
    if buf.len() < end {
        return None;
    }
    Some((ty, buf[start..end].to_vec(), end))
}

// ---------------------------------------------------------------------------
// 客户端（认证请求）
// ---------------------------------------------------------------------------

/// 打开 H3 必需的 uni 流（控制流发空 SETTINGS；QPACK 流保持）
async fn open_h3_streams(conn: &quinn::Connection) -> Result<()> {
    // 控制流
    let mut ctl = conn.open_uni().await.map_err(quic_io_err)?;
    let mut buf = Vec::new();
    write_varint(&mut buf, STREAM_CONTROL);
    write_varint(&mut buf, FRAME_SETTINGS);
    write_varint(&mut buf, 0); // 空 SETTINGS
    use tokio::io::AsyncWriteExt;
    ctl.write_all(&buf).await.map_err(quic_io_err)?;
    // QPACK encoder/decoder 流（保持打开即可）
    for t in [STREAM_QPACK_ENCODER, STREAM_QPACK_DECODER] {
        let mut s = conn.open_uni().await.map_err(quic_io_err)?;
        let mut b = Vec::new();
        write_varint(&mut b, t);
        s.write_all(&b).await.map_err(quic_io_err)?;
        // 不 finish：保持打开
    }
    Ok(())
}

fn quic_io_err(e: impl std::fmt::Debug) -> Error {
    Error::Io(std::io::Error::other(format!("quic: {e:?}")))
}

/// 发送认证请求并等待响应状态码；返回响应头
pub async fn auth_roundtrip(
    conn: &quinn::Connection,
    headers: &[(&str, &str)],
) -> Result<Vec<(String, String)>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    open_h3_streams(conn).await?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(quic_io_err)?;
    send.write_all(&headers_frame(headers)).await.map_err(quic_io_err)?;
    send.finish().map_err(quic_io_err)?;
    // 读响应：帧头 + 头块（可能分片到达，增量解析）
    let mut buf = Vec::with_capacity(512);
    loop {
        let mut chunk = [0u8; 1024];
        let n = recv.read(&mut chunk).await.map_err(quic_io_err)?.unwrap_or(0);
        if n == 0 {
            return Err(Error::Proto("h3min: 响应中断"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some((ty, payload, _)) = parse_frame(&buf) {
            if ty != FRAME_HEADERS {
                return Err(Error::ProtoMsg(format!("h3min: 期望 HEADERS 帧，得到 {ty}")));
            }
            return decode_header_block(&payload);
        }
        if buf.len() > 16 * 1024 {
            return Err(Error::Proto("h3min: 响应过大"));
        }
    }
}

// ---------------------------------------------------------------------------
// 服务端
// ---------------------------------------------------------------------------

/// 服务端握手流初始化：控制流上回应空 SETTINGS
pub async fn server_init_stream(mut s: quinn::SendStream, stream_type: u64) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    if stream_type == STREAM_CONTROL {
        let mut b = Vec::new();
        write_varint(&mut b, STREAM_CONTROL);
        write_varint(&mut b, FRAME_SETTINGS);
        write_varint(&mut b, 0);
        s.write_all(&b).await.map_err(quic_io_err)?;
    }
    Ok(())
}

/// 从 bi 流读一个 HEADERS 帧并解码（增量直到完整）
pub async fn read_request_headers(
    recv: &mut quinn::RecvStream,
) -> Result<Vec<(String, String)>> {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::with_capacity(512);
    loop {
        // 先尽力解析帧
        if let Some((ty, payload, _)) = parse_frame(&buf) {
            if ty != FRAME_HEADERS {
                return Err(Error::ProtoMsg(format!("h3min: 首帧非 HEADERS（{ty}）")));
            }
            return decode_header_block(&payload);
        }
        let mut chunk = [0u8; 1024];
        let n = recv.read(&mut chunk).await.map_err(quic_io_err)?.unwrap_or(0);
        if n == 0 {
            return Err(Error::Proto("h3min: 请求中断"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 16 * 1024 {
            return Err(Error::Proto("h3min: 请求过大"));
        }
    }
}

/// 写响应 HEADERS 帧
pub async fn write_response_headers(
    send: &mut quinn::SendStream,
    fields: &[(&str, &str)],
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    send.write_all(&headers_frame(fields)).await.map_err(quic_io_err)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let f = headers_frame(&[(":method", "POST"), ("hysteria-auth", "pw")]);
        let (ty, payload, used) = parse_frame(&f).unwrap();
        assert_eq!(ty, FRAME_HEADERS);
        assert_eq!(used, f.len());
        let h = decode_header_block(&payload).unwrap();
        assert_eq!(h[0], (":method".to_string(), "POST".to_string()));
        assert_eq!(h[1], ("hysteria-auth".to_string(), "pw".to_string()));
    }

    #[test]
    fn literal_layout() {
        // 0x20 | name_len | name | value_len | value
        let mut b = Vec::new();
        qpack_literal(&mut b, "a", "bc");
        assert_eq!(b, vec![0x20, 1, b'a', 2, b'b', b'c']);
    }
}

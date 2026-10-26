//! 最小 HTTP/3（RFC 9114）认证层 —— hysteria2 专用。
//!
//! 设计取舍：QPACK 编码端保持最简（literal with literal name、无 Huffman、
//! 无动态表 —— 这是合法 QPACK，官方对端可正常解码）；解码端完整支持
//! RFC 9204 的静态表索引引用与 Huffman 字符串，因此官方 hysteria2 客户端/
//! 服务端均可与本端互通。动态表仅在两端都宣告容量时才会被使用，而本端
//! 发送空 SETTINGS（容量 0），对端不会插入动态条目；若对端仍发来动态表
//! 引用则明确报错。
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
// QPACK 编解码（编码：literal / 解码：静态表 + Huffman 全支持）
// ---------------------------------------------------------------------------

/// RFC 9204 附录 A 静态表（99 项）
static STATIC_TABLE: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains; preload",
    ),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

fn static_entry(idx: u64) -> Result<(&'static str, &'static str)> {
    STATIC_TABLE
        .get(idx as usize)
        .copied()
        .ok_or_else(|| Error::ProtoMsg(format!("qpack: 静态表索引越界 {idx}")))
}

/// HPACK/QPACK 静态 Huffman 表（RFC 7541 附录 B，257 符号）—— 规范序符号表。
const HUFF_SYMS: [u16; 257] = [
    48, 49, 50, 97, 99, 101, 105, 111, 115, 116, 32, 37, 45, 46, 47, 51, 52, 53, 54, 55, 56, 57,
    61, 65, 95, 98, 100, 102, 103, 104, 108, 109, 110, 112, 114, 117, 58, 66, 67, 68, 69, 70, 71,
    72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 89, 106, 107, 113, 118, 119,
    120, 121, 122, 38, 42, 44, 59, 88, 90, 33, 34, 40, 41, 63, 39, 43, 124, 35, 62, 0, 36, 64, 91,
    93, 126, 94, 125, 60, 96, 123, 92, 195, 208, 128, 130, 131, 162, 184, 194, 224, 226, 153, 161,
    167, 172, 176, 177, 179, 209, 216, 217, 227, 229, 230, 129, 132, 133, 134, 136, 146, 154, 156,
    160, 163, 164, 169, 170, 173, 178, 181, 185, 186, 187, 189, 190, 196, 198, 228, 232, 233, 1,
    135, 137, 138, 139, 140, 141, 143, 147, 149, 150, 151, 152, 155, 157, 158, 165, 166, 168, 174,
    175, 180, 182, 183, 188, 191, 197, 231, 239, 9, 142, 144, 145, 148, 159, 171, 206, 215, 225,
    236, 237, 199, 207, 234, 235, 192, 193, 200, 201, 202, 205, 210, 213, 218, 219, 238, 240, 242,
    243, 255, 203, 204, 211, 212, 214, 221, 222, 223, 241, 244, 245, 246, 247, 248, 250, 251, 252,
    253, 254, 2, 3, 4, 5, 6, 7, 8, 11, 12, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 25, 26, 27, 28,
    29, 30, 31, 127, 220, 249, 10, 13, 22, 256,
];

/// 逐位解码表：按码长 5..=30 索引（`idx = len - 5`），条目为 (首码, 规范序
/// 符号起始偏移, 符号数)；count=0 表示该码长无符号（继续累计）。
const HUFF_DECODE: [(u32, u16, u16); 26] = [
    (0x00000000, 0, 10),   // 5 bits
    (0x00000014, 10, 26),  // 6 bits
    (0x0000005c, 36, 32),  // 7 bits
    (0x000000f8, 68, 6),   // 8 bits
    (0x00000000, 0, 0),    // 9 bits (无)
    (0x000003f8, 74, 5),   // 10 bits
    (0x000007fa, 79, 3),   // 11 bits
    (0x00000ffa, 82, 2),   // 12 bits
    (0x00001ff8, 84, 6),   // 13 bits
    (0x00003ffc, 90, 2),   // 14 bits
    (0x00007ffc, 92, 3),   // 15 bits
    (0x00000000, 0, 0),    // 16 bits (无)
    (0x00000000, 0, 0),    // 17 bits (无)
    (0x00000000, 0, 0),    // 18 bits (无)
    (0x0007fff0, 95, 3),   // 19 bits
    (0x000fffe6, 98, 8),   // 20 bits
    (0x001fffdc, 106, 13), // 21 bits
    (0x003fffd2, 119, 26), // 22 bits
    (0x007fffd8, 145, 29), // 23 bits
    (0x00ffffea, 174, 12), // 24 bits
    (0x01ffffec, 186, 4),  // 25 bits
    (0x03ffffe0, 190, 15), // 26 bits
    (0x07ffffde, 205, 19), // 27 bits
    (0x0fffffe2, 224, 29), // 28 bits
    (0x00000000, 0, 0),    // 29 bits (无)
    (0x3ffffffc, 253, 4),  // 30 bits
];

/// Huffman 解码（规范码逐位累计 + 首码区间比对）
fn huffman_decode(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() * 2);
    let mut code = 0u32;
    let mut len = 0usize;
    for &byte in data {
        for k in (0..8).rev() {
            code = (code << 1) | ((byte >> k) & 1) as u32;
            len += 1;
            if len < 5 {
                continue;
            }
            if len > 30 {
                return Err(Error::Proto("qpack: huffman 码长越界"));
            }
            let (first, off, count) = HUFF_DECODE[len - 5];
            if count == 0 || code < first {
                continue;
            }
            if code < first + count as u32 {
                let sym = HUFF_SYMS[off as usize + (code - first) as usize];
                if sym == 256u16 {
                    return Err(Error::Proto("qpack: huffman 含 EOS"));
                }
                out.push(sym as u8);
                code = 0;
                len = 0;
            }
        }
    }
    // 残余位必须全部为 1（EOS 前缀填充），且不足一个完整码长
    if len != 0 && (len > 7 || code != (1 << len) - 1) {
        return Err(Error::Proto("qpack: huffman 填充非法"));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// HPACK 风格前缀整数 / 字符串
// ---------------------------------------------------------------------------

/// 读前缀整数：首字节值 `cur`（低 `prefix_bits` 位有效），
/// 消费该首字节（`i` 前进 1）及全部续字节
fn pint_from(buf: &[u8], i: &mut usize, cur: u8, prefix_bits: u8) -> Result<u64> {
    *i += 1;
    let max = ((1u16 << prefix_bits) - 1) as u8;
    let mut val = (cur & max) as u64;
    if val < max as u64 {
        return Ok(val);
    }
    let mut shift = 0u32;
    loop {
        let b = *buf.get(*i).ok_or(Error::Proto("qpack: 前缀整数截断"))?;
        *i += 1;
        val += ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok(val);
        }
        if shift > 42 {
            return Err(Error::Proto("qpack: 前缀整数过长"));
        }
    }
}

/// 读前缀整数（自行读首字节）
fn read_pint(buf: &[u8], i: &mut usize, prefix_bits: u8) -> Result<u64> {
    let b = *buf.get(*i).ok_or(Error::Proto("qpack: 前缀整数截断"))?;
    pint_from(buf, i, b, prefix_bits)
}

/// 写前缀整数：`flags` 是首字节中位于前缀位之上的标志位
fn push_pint(out: &mut Vec<u8>, val: u64, prefix_bits: u8, flags: u8) {
    let max = ((1u16 << prefix_bits) - 1) as u64;
    if val < max {
        out.push(flags | val as u8);
    } else {
        out.push(flags | max as u8);
        let mut v = val - max;
        while v >= 0x80 {
            out.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        out.push(v as u8);
    }
}

/// 读字符串字面量：首字节 = H 位 + (prefix_bits-1) 位前缀长度
fn read_string(buf: &[u8], i: &mut usize, prefix_bits: u8) -> Result<String> {
    let b = *buf.get(*i).ok_or(Error::Proto("qpack: 字符串截断"))?;
    let huff = b & 0x80 != 0;
    let len = pint_from(buf, i, b & 0x7f, prefix_bits - 1)? as usize;
    let raw = buf
        .get(*i..*i + len)
        .ok_or(Error::Proto("qpack: 字符串越界"))?;
    *i += len;
    let bytes = if huff {
        huffman_decode(raw)?
    } else {
        raw.to_vec()
    };
    String::from_utf8(bytes).map_err(|_| Error::Proto("qpack: 字符串非 UTF-8"))
}

/// 写字符串字面量（H=0）
fn push_string(out: &mut Vec<u8>, s: &str, prefix_bits: u8) {
    push_pint(out, s.len() as u64, prefix_bits - 1, 0x00);
    out.extend_from_slice(s.as_bytes());
}

// ---------------------------------------------------------------------------
// 头块编解码
// ---------------------------------------------------------------------------

/// 编码一个头字段：literal with literal name（001 N 0 | name | value），
/// N=0（可索引）。本编码器不用 Huffman / 动态表。
fn qpack_literal(out: &mut Vec<u8>, name: &str, value: &str) {
    // 首字节：001 N=0 H=0 + 名字长度（3 位前缀，H 占 bit3）
    push_pint(out, name.len() as u64, 3, 0x20);
    out.extend_from_slice(name.as_bytes());
    push_string(out, value, 8); // H=0 + 8 位前缀字符串
}

/// 编码头块 → HEADERS 帧完整字节（含 QPACK 前缀：insert count 0、base 0）
pub fn headers_frame(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut block = vec![0x00, 0x00]; // 前缀：RIC=0（8 位前缀），S=0 delta=0（7 位前缀）
    for (n, v) in fields {
        qpack_literal(&mut block, n, v);
    }
    let mut frame = Vec::with_capacity(block.len() + 8);
    write_varint(&mut frame, FRAME_HEADERS);
    write_varint(&mut frame, block.len() as u64);
    frame.extend_from_slice(&block);
    frame
}

/// 解码头块：完整支持 RFC 9204 的静态表索引引用与 Huffman 字符串；
/// 动态表引用（本端宣告容量 0，正常对端不应使用）明确报错。
pub fn decode_header_block(block: &[u8]) -> Result<Vec<(String, String)>> {
    let mut i = 0usize;
    let ric = read_pint(block, &mut i, 8)?;
    if ric != 0 {
        return Err(Error::ProtoMsg(format!(
            "qpack: 需要动态表状态（insert count {ric}），本端容量为 0"
        )));
    }
    // base：S 位 + 7 位前缀 delta；不含动态引用时无需 base 值
    let base0 = *block.get(i).ok_or(Error::Proto("qpack: 缺 base"))?;
    let _ = (base0 & 0x80 != 0, pint_from(block, &mut i, base0, 7)?);

    let mut out = Vec::new();
    while i < block.len() {
        let b = block[i];
        if b & 0x80 != 0 {
            // Indexed Field Line：'1' T(bit6) | 索引（6 位前缀，与首字节共享）
            if b & 0x40 == 0 {
                return Err(Error::Proto("qpack: 动态表索引引用，本端容量为 0"));
            }
            let idx = pint_from(block, &mut i, b, 6)?;
            let (n, v) = static_entry(idx)?;
            out.push((n.to_string(), v.to_string()));
        } else if b & 0xC0 == 0x40 {
            // Literal with Name Reference：'01' N(bit5) T(bit4) | 名字索引（4 位前缀）| 值字符串
            if b & 0x10 == 0 {
                return Err(Error::Proto("qpack: 动态表名字引用，本端容量为 0"));
            }
            let nidx = pint_from(block, &mut i, b, 4)?;
            let (n, _) = static_entry(nidx)?;
            let value = read_string(block, &mut i, 8)?;
            out.push((n.to_string(), value));
        } else if b & 0xE0 == 0x20 {
            // Literal with Literal Name：'001' N(bit4) H(bit3) | 名字长度（3 位前缀）| 值字符串
            let huff = b & 0x08 != 0;
            let nlen = pint_from(block, &mut i, b, 3)? as usize;
            let raw = block
                .get(i..i + nlen)
                .ok_or(Error::Proto("qpack: 名字越界"))?;
            i += nlen;
            let bytes = if huff {
                huffman_decode(raw)?
            } else {
                raw.to_vec()
            };
            let name = String::from_utf8(bytes).map_err(|_| Error::Proto("qpack: 名字非 UTF-8"))?;
            let value = read_string(block, &mut i, 8)?;
            out.push((name, value));
        } else {
            // 0001 / 0000：post-base 动态表引用
            return Err(Error::ProtoMsg(format!(
                "qpack: 不支持的形式 {b:#04x}（post-base/动态表）"
            )));
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
    open_h3_streams(conn).await?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(quic_io_err)?;
    send.write_all(&headers_frame(headers))
        .await
        .map_err(quic_io_err)?;
    send.finish().map_err(quic_io_err)?;
    // 读响应：帧头 + 头块（可能分片到达，增量解析）
    let mut buf = Vec::with_capacity(512);
    loop {
        let mut chunk = [0u8; 1024];
        let n = recv
            .read(&mut chunk)
            .await
            .map_err(quic_io_err)?
            .unwrap_or(0);
        if n == 0 {
            return Err(Error::Proto("h3min: 响应中断"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some((ty, payload, _)) = parse_frame(&buf) {
            if ty != FRAME_HEADERS {
                return Err(Error::ProtoMsg(format!(
                    "h3min: 期望 HEADERS 帧，得到 {ty}"
                )));
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
pub async fn read_request_headers(recv: &mut quinn::RecvStream) -> Result<Vec<(String, String)>> {
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
        let n = recv
            .read(&mut chunk)
            .await
            .map_err(quic_io_err)?
            .unwrap_or(0);
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
    send.write_all(&headers_frame(fields))
        .await
        .map_err(quic_io_err)?;
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
        // 0x21 (=001 N=0 + 名字长 1) | name | value_len(H=0,7位前缀) | value
        let mut b = Vec::new();
        qpack_literal(&mut b, "a", "bc");
        assert_eq!(b, vec![0x21, b'a', 2, b'b', b'c']);
    }

    #[test]
    fn long_name_value_prefix_varint() {
        // 名字 > 15 字节、值 > 127 字节：前缀整数必须用续字节（此前为截断 bug）
        let name = "x".repeat(300);
        let value = "y".repeat(500);
        // 头块层面（含前缀字节与超长前缀整数续字节）
        let f = headers_frame(&[(&name, &value)]);
        let (_, payload, _) = parse_frame(&f).unwrap();
        assert_eq!(decode_header_block(&payload).unwrap(), vec![(name, value)]);
    }

    #[test]
    fn huffman_known_vectors() {
        // RFC 7541 附录 C 已知向量
        assert_eq!(
            huffman_decode(&[
                0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff
            ])
            .unwrap(),
            b"www.example.com".to_vec()
        );
        assert_eq!(
            huffman_decode(&[0xae, 0xc3, 0x77, 0x1a, 0x4b]).unwrap(),
            b"private".to_vec()
        );
        assert_eq!(
            huffman_decode(&[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f]).unwrap(),
            b"custom-key".to_vec()
        );
    }

    /// 测试用编码器：由 HUFF_SYMS/HUFF_DECODE 反推每符号 (码, 码长)
    /// （规范序内码连续：组内第 k 个符号的码 = 首码 + k），与解码表天然一致。
    #[cfg(test)]
    fn huff_encode(s: &str) -> Vec<u8> {
        let mut codes = [0u32; 257];
        let mut lens = [0u8; 257];
        for (gi, &(first, off, count)) in HUFF_DECODE.iter().enumerate() {
            if count == 0 {
                continue;
            }
            let len = (gi + 5) as u8;
            for k in 0..count {
                let sym = HUFF_SYMS[off as usize + k as usize] as usize;
                codes[sym] = first + k as u32;
                lens[sym] = len;
            }
        }
        let mut bits = String::new();
        for &c in s.as_bytes() {
            assert_ne!(lens[c as usize], 0, "符号 {c} 无码（测试字符串超集）");
            bits.push_str(&format!(
                "{:0width$b}",
                codes[c as usize],
                width = lens[c as usize] as usize
            ));
        }
        bits.push_str(&"1".repeat((8 - bits.len() % 8) % 8));
        bits.as_bytes()
            .chunks(8)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 2).unwrap())
            .collect()
    }

    #[test]
    fn huffman_roundtrip_via_qpack() {
        let s = "hysteria2-auth-password";
        let enc = huff_encode(s);
        assert_eq!(huffman_decode(&enc).unwrap(), s.as_bytes());
    }

    #[test]
    fn huffman_bad_padding_rejected() {
        // "a" 编码 5 位 + 全 0 填充（非 EOS 前缀）
        assert!(huffman_decode(&[0b0110_0000]).is_err());
        // 超 7 位残余
        assert!(huffman_decode(&[0b0110_0000, 0b0111_1111, 0xff]).is_err());
    }

    #[test]
    fn qpack_static_indexed() {
        // 前缀（RIC=0, base=0）+ indexed static :method GET(17) + :status 200(25)
        let block = [0x00, 0x00, 0xC0 | 17, 0xC0 | 25];
        let h = decode_header_block(&block).unwrap();
        assert_eq!(
            h,
            vec![
                (":method".into(), "GET".into()),
                (":status".into(), "200".into())
            ]
        );
    }

    #[test]
    fn qpack_literal_name_ref_static() {
        // '01' N=0 T=1(bit4) | 名字索引 5 (cookie, 4 位前缀) | 值 "a=b"
        let block = [0x00, 0x00, 0x40 | 0x10 | 5, 3, b'a', b'=', b'b'];
        let h = decode_header_block(&block).unwrap();
        assert_eq!(h, vec![("cookie".into(), "a=b".into())]);
    }

    #[test]
    fn qpack_huffman_value_string() {
        // literal with literal name，值用 Huffman（H=1）："private" = aec3771a4b
        let name = b":path";
        let mut block = vec![0x00, 0x00, 0x20 | name.len() as u8];
        block.extend_from_slice(name);
        block.push(0x80 | 5); // H=1 + 长度 5（7 位前缀）
        block.extend_from_slice(&[0xae, 0xc3, 0x77, 0x1a, 0x4b]);
        let h = decode_header_block(&block).unwrap();
        assert_eq!(h, vec![(":path".into(), "private".into())]);
    }

    #[test]
    fn qpack_dynamic_ref_rejected() {
        // indexed with T=0（动态表）
        assert!(decode_header_block(&[0x00, 0x00, 0x80]).is_err());
        // 非零 insert count
        assert!(decode_header_block(&[0x02, 0x00]).is_err());
    }

    #[test]
    fn qpack_mixed_official_style() {
        // 模拟官方客户端：前缀 + 静态索引 :method GET + literal(Huffman 名字引用
        // :scheme https(23) 需续字节) + literal literal name Huffman 值
        let mut b = vec![0x00, 0x00, 0xC0 | 17];
        // literal with name ref：'01' N T | 索引 23 (:scheme https) → 4 位前缀装不下，
        // 首字节低 4 位 = 15，续字节 8
        b.push(0x40 | 0x10 | 0x0F);
        b.push(23 - 15);
        push_string(&mut b, "https", 8);
        // :authority 用 literal + Huffman 值 "example.com"（huff_encode 子集无 '.'，
        // 换用纯字母值）
        b.push(0x20 | 4); // 001 N=0 H=0 + 名字长 4
        b.extend_from_slice(b"host");
        push_string(&mut b, "abcde", 8);
        let h = decode_header_block(&b).unwrap();
        assert_eq!(
            h,
            vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "https".into()),
                ("host".into(), "abcde".into()),
            ]
        );
    }
}

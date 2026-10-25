//! DNS 报文编解码（RFC 1035 子集：查询构造 + A/AAAA/CNAME 解析）。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_PTR: u16 = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QType {
    A,
    Aaaa,
}

impl QType {
    pub fn code(self) -> u16 {
        match self {
            QType::A => TYPE_A,
            QType::Aaaa => TYPE_AAAA,
        }
    }
}

/// 构造查询报文
pub fn build_query(id: u16, domain: &str, qtype: QType) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + 18);
    out.extend_from_slice(&id.to_be_bytes());
    // RD=1 递归
    out.extend_from_slice(&[0x01, 0x00]);
    out.extend_from_slice(&[0x00, 0x01]); // qd
    out.extend_from_slice(&[0x00, 0x00]); // an
    out.extend_from_slice(&[0x00, 0x00]); // ns
    out.extend_from_slice(&[0x00, 0x00]); // ar
    for label in domain.trim_end_matches('.').split('.').filter(|s| !s.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.code().to_be_bytes());
    out.extend_from_slice(&[0x00, 0x01]); // IN
    out
}

#[derive(Debug, Clone)]
pub struct Answer {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub data: RData,
}

#[derive(Debug, Clone)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Other,
}

#[derive(Debug)]
pub struct Message {
    pub id: u16,
    pub rcode: u16,
    pub answers: Vec<Answer>,
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn u16(&mut self) -> Option<u16> {
        let hi = self.u8()? as u16;
        let lo = self.u8()? as u16;
        Some(hi << 8 | lo)
    }

    fn u32(&mut self) -> Option<u32> {
        let b3 = self.u16()? as u32;
        let b2 = self.u16()? as u32;
        Some(b3 << 16 | b2)
    }

    /// 读域名（支持压缩指针，防循环）
    fn name(&mut self, depth: u8) -> Option<String> {
        let mut labels = Vec::new();
        let mut pos = self.pos;
        let mut jumped = false;
        let mut hops = 0;
        loop {
            let len = *self.buf.get(pos)?;
            match len {
                0 => {
                    pos += 1;
                    break;
                }
                l if l & 0xc0 == 0xc0 => {
                    let ptr_hi = (l & 0x3f) as usize;
                    let ptr_lo = *self.buf.get(pos + 1)? as usize;
                    let target = ptr_hi << 8 | ptr_lo;
                    if !jumped {
                        self.pos = pos + 2; // 跳转后不再更新 self.pos
                        jumped = true;
                    }
                    pos = target;
                    hops += 1;
                    if hops > 16 || depth > 0 {
                        return None;
                    }
                }
                l => {
                    pos += 1;
                    let end = pos.checked_add(l as usize)?;
                    if end > self.buf.len() {
                        return None;
                    }
                    labels.push(String::from_utf8_lossy(&self.buf[pos..end]).into_owned());
                    pos = end;
                    if labels.len() > 128 {
                        return None;
                    }
                }
            }
        }
        if !jumped {
            self.pos = pos;
        }
        Some(labels.join("."))
    }
}

/// 解析查询报文首个问题：返回 (id, 域名, qtype)
pub fn parse_query(buf: &[u8]) -> Option<(u16, String, u16)> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let qd = u16::from_be_bytes([buf[4], buf[5]]);
    if qd == 0 {
        return None;
    }
    let mut r = Reader { buf, pos: 12 };
    let name = r.name(0)?;
    let qtype = r.u16()?;
    let _class = r.u16()?;
    Some((id, name, qtype))
}

/// 基于查询构造 A 记录应答（fake-ip）
pub fn build_a_response(query: &[u8], answer_ip: std::net::Ipv4Addr) -> Vec<u8> {
    // 问题段长度 = 域名 + 4
    let qend = query_question_end(query).unwrap_or(query.len());
    let mut out = Vec::with_capacity(qend + 16);
    out.extend_from_slice(&query[..2]); // id
    out.extend_from_slice(&[0x81, 0x80]); // QR=1 RD=1 RA=1
    out.extend_from_slice(&query[4..6]); // qdcount
    out.extend_from_slice(&[0x00, 0x01]); // ancount=1
    out.extend_from_slice(&[0x00, 0x00]); // ns
    out.extend_from_slice(&[0x00, 0x00]); // ar
    out.extend_from_slice(&query[12..qend]);
    // answer: 指针回问题名
    out.extend_from_slice(&[0xc0, 0x0c]);
    out.extend_from_slice(&TYPE_A.to_be_bytes());
    out.extend_from_slice(&[0x00, 0x01]); // IN
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // ttl=1
    out.extend_from_slice(&[0x00, 0x04]);
    out.extend_from_slice(&answer_ip.octets());
    out
}

/// 构造 PTR 应答（fake-ip → 域名）
pub fn build_ptr_response(query: &[u8], domain: &str) -> Vec<u8> {
    let qend = query_question_end(query).unwrap_or(query.len());
    let mut out = Vec::with_capacity(qend + 32);
    out.extend_from_slice(&query[..2]);
    out.extend_from_slice(&[0x81, 0x80]);
    out.extend_from_slice(&query[4..6]);
    out.extend_from_slice(&[0x00, 0x01]);
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    out.extend_from_slice(&query[12..qend]);
    out.extend_from_slice(&[0xc0, 0x0c]);
    out.extend_from_slice(&TYPE_PTR.to_be_bytes());
    out.extend_from_slice(&[0x00, 0x01]);
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    // rdata: 域名标签
    let mut rdata = Vec::new();
    for label in domain.trim_end_matches('.').split('.').filter(|l| !l.is_empty()) {
        rdata.push(label.len() as u8);
        rdata.extend_from_slice(label.as_bytes());
    }
    rdata.push(0);
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&rdata);
    out
}

/// 构造空 NOERROR 应答（如 fake-ip 模式下的 AAAA）
pub fn build_empty_response(query: &[u8]) -> Vec<u8> {
    let qend = query_question_end(query).unwrap_or(query.len());
    let mut out = Vec::with_capacity(qend);
    out.extend_from_slice(&query[..2]);
    out.extend_from_slice(&[0x81, 0x80]);
    out.extend_from_slice(&query[4..6]);
    out.extend_from_slice(&[0x00, 0x00]); // an=0
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    out.extend_from_slice(&query[12..qend]);
    out
}

/// 问题段结束偏移（含 qtype/qclass）
fn query_question_end(query: &[u8]) -> Option<usize> {
    let mut pos = 12usize;
    loop {
        let len = *query.get(pos)? as usize;
        if len == 0 {
            return Some(pos + 5);
        }
        pos += 1 + len;
        if pos > query.len() {
            return None;
        }
    }
}

/// 解析响应报文
pub fn parse_response(buf: &[u8]) -> Option<Message> {
    let mut r = Reader { buf, pos: 0 };
    let id = r.u16()?;
    let flags = r.u16()?;
    let qd = r.u16()?;
    let an = r.u16()?;
    let _ns = r.u16()?;
    let _ar = r.u16()?;
    let rcode = flags & 0x0f;
    for _ in 0..qd {
        r.name(0)?;
        r.u16()?; // qtype
        r.u16()?; // qclass
    }
    let mut answers = Vec::with_capacity(an.min(64) as usize);
    for _ in 0..an {
        let name = r.name(0)?;
        let rtype = r.u16()?;
        let _class = r.u16()?;
        let ttl = r.u32()?;
        let rdlen = r.u16()? as usize;
        let rdata_start = r.pos;
        let data = match rtype {
            TYPE_A if rdlen == 4 => RData::A(Ipv4Addr::new(
                r.u8()?,
                r.u8()?,
                r.u8()?,
                r.u8()?,
            )),
            TYPE_AAAA if rdlen == 16 => {
                let mut o = [0u8; 16];
                for b in o.iter_mut() {
                    *b = r.u8()?;
                }
                RData::Aaaa(Ipv6Addr::from(o))
            }
            TYPE_CNAME => RData::Cname(r.name(1)?),
            _ => {
                r.pos = rdata_start.checked_add(rdlen)?;
                RData::Other
            }
        };
        // 对齐到 rdata 末尾（name() 可能未消费完整 rdata）
        r.pos = rdata_start + rdlen;
        answers.push(Answer { name, rtype, ttl, data });
    }
    Some(Message { id, rcode, answers })
}

/// 从应答中提取目标类型的 IP（跟随 CNAME）
pub fn extract_ips(msg: &Message, want: u16) -> Vec<(IpAddr, u32)> {
    let mut out = Vec::new();
    for a in &msg.answers {
        match (&a.data, want) {
            (RData::A(ip), TYPE_A) => out.push((IpAddr::V4(*ip), a.ttl)),
            (RData::Aaaa(ip), TYPE_AAAA) => out.push((IpAddr::V6(*ip), a.ttl)),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_roundtrip_bytes() {
        let q = build_query(0x1234, "www.example.com", QType::A);
        assert_eq!(&q[0..2], &[0x12, 0x34]);
        // qname 结尾应能找到 example.com
        let tail = &q[12..];
        assert!(tail.starts_with(&[3, b'w', b'w', b'w']));
    }

    #[test]
    fn parse_a_response() {
        // 手工构造：qd=1(www.x.com A IN)，an=1(www.x.com A 60 1.2.3.4)
        let mut m = Vec::new();
        m.extend_from_slice(&[0xab, 0xcd, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        m.extend_from_slice(&[3, b'w', b'w', b'w', 1, b'x', 3, b'c', b'o', b'm', 0]);
        m.extend_from_slice(&[0, 1, 0, 1]);
        // answer 用指针指回 qname
        m.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        let msg = parse_response(&m).unwrap();
        assert_eq!(msg.id, 0xabcd);
        assert_eq!(msg.rcode, 0);
        let ips = extract_ips(&msg, TYPE_A);
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].0.to_string(), "1.2.3.4");
        assert_eq!(ips[0].1, 60);
    }

    #[test]
    fn cname_chain() {
        let mut m = Vec::new();
        m.extend_from_slice(&[0, 1, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0]);
        m.extend_from_slice(&[1, b'a', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
        // CNAME a.com -> b.com
        m.extend_from_slice(&[0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 30, 0, 7, 1, b'b', 3, b'c', b'o', b'm', 0]);
        // A b.com -> 9.9.9.9
        m.extend_from_slice(&[1, b'b', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 9, 9, 9, 9]);
        let msg = parse_response(&m).unwrap();
        assert_eq!(msg.answers.len(), 2);
        assert!(matches!(msg.answers[0].data, RData::Cname(ref c) if c == "b.com"));
        assert_eq!(extract_ips(&msg, TYPE_A)[0].0.to_string(), "9.9.9.9");
    }

    #[test]
    fn truncated_rejected() {
        let q = build_query(1, "x.com", QType::A);
        for cut in 4..q.len() {
            assert!(parse_response(&q[..cut]).is_none());
        }
    }
}

//! DNS 报文编解码（RFC 1035 子集：查询构造 + A/AAAA/CNAME 解析）。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_PTR: u16 = 12;
/// SVCB/HTTPS（RFC 9460）：ECH 配置随 HTTPS 记录下发
pub const TYPE_HTTPS: u16 = 65;
/// SvcParam 键：ech（ECHConfigList 原始字节）
pub const SVCB_KEY_ECH: u16 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QType {
    A,
    Aaaa,
    Https,
}

impl QType {
    pub fn code(self) -> u16 {
        match self {
            QType::A => TYPE_A,
            QType::Aaaa => TYPE_AAAA,
            QType::Https => TYPE_HTTPS,
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
    for label in domain
        .trim_end_matches('.')
        .split('.')
        .filter(|s| !s.is_empty())
    {
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
    /// SVCB/HTTPS 记录：(priority, SvcParams[(key, value)])
    Https(u16, Vec<(u16, Vec<u8>)>),
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
    fn name(&mut self) -> Option<String> {
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
                    if hops > 16 {
                        return None;
                    }
                }
                l if l <= 63 => {
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
                _ => return None,
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
    let name = r.name()?;
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

/// 基于查询构造 AAAA 记录应答
pub fn build_aaaa_response(query: &[u8], answer_ip: std::net::Ipv6Addr) -> Vec<u8> {
    let qend = query_question_end(query).unwrap_or(query.len());
    let mut out = Vec::with_capacity(qend + 28);
    out.extend_from_slice(&query[..2]); // id
    out.extend_from_slice(&[0x81, 0x80]); // QR=1 RD=1 RA=1
    out.extend_from_slice(&query[4..6]); // qdcount
    out.extend_from_slice(&[0x00, 0x01]); // ancount=1
    out.extend_from_slice(&[0x00, 0x00]); // ns
    out.extend_from_slice(&[0x00, 0x00]); // ar
    out.extend_from_slice(&query[12..qend]);
    // answer: 指针回问题名
    out.extend_from_slice(&[0xc0, 0x0c]);
    out.extend_from_slice(&TYPE_AAAA.to_be_bytes());
    out.extend_from_slice(&[0x00, 0x01]); // IN
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // ttl=1
    out.extend_from_slice(&[0x00, 0x10]); // rdlen = 16
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
    for label in domain
        .trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
    {
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
        r.name()?;
        r.u16()?; // qtype
        r.u16()?; // qclass
    }
    let mut answers = Vec::with_capacity(an.min(64) as usize);
    for _ in 0..an {
        let name = r.name()?;
        let rtype = r.u16()?;
        let _class = r.u16()?;
        let ttl = r.u32()?;
        let rdlen = r.u16()? as usize;
        let rdata_start = r.pos;
        let next_pos = rdata_start.checked_add(rdlen)?;
        if next_pos > r.buf.len() {
            return None;
        }
        let data = match rtype {
            TYPE_A if rdlen == 4 => RData::A(Ipv4Addr::new(r.u8()?, r.u8()?, r.u8()?, r.u8()?)),
            TYPE_AAAA if rdlen == 16 => {
                let mut o = [0u8; 16];
                for b in o.iter_mut() {
                    *b = r.u8()?;
                }
                RData::Aaaa(Ipv6Addr::from(o))
            }
            TYPE_CNAME => match r.name() {
                Some(target) => RData::Cname(target),
                None => RData::Other,
            },
            TYPE_HTTPS => {
                // RFC 9460：priority(u16) + target(域名) + SvcParams[(key u16)(len u16)(value)]
                let priority = r.u16().unwrap_or(0);
                let _target = r.name().unwrap_or_default();
                let mut params = Vec::new();
                while r.pos + 4 <= next_pos {
                    let key = r.u16().unwrap_or(0);
                    let len = r.u16().unwrap_or(0) as usize;
                    let end = r.pos + len;
                    if end > next_pos {
                        break;
                    }
                    let val = r.buf[r.pos..end].to_vec();
                    r.pos = end;
                    params.push((key, val));
                }
                RData::Https(priority, params)
            }
            _ => RData::Other,
        };
        // 始终对齐到 rdata 末尾（即便 r.name() 未消费完整 rdata 或遇到其它记录）
        r.pos = next_pos;
        answers.push(Answer {
            name,
            rtype,
            ttl,
            data,
        });
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

/// 提取应答中的首个 CNAME 目标域名（用于非递归上游返回纯 CNAME 时的重定向跟随）
pub fn extract_cname(msg: &Message) -> Option<String> {
    for a in &msg.answers {
        if let RData::Cname(ref target) = a.data {
            return Some(target.clone());
        }
    }
    None
}

/// 从 HTTPS(type65) 应答中提取 ech SvcParam（RFC 9460 §9：值为 ECHConfigList 原始字节，
/// rustls `EchConfig::new` 直接可用）
pub fn extract_ech_config(msg: &Message) -> Option<Vec<u8>> {
    for a in &msg.answers {
        if let RData::Https(_, params) = &a.data {
            for (key, val) in params {
                if *key == SVCB_KEY_ECH && !val.is_empty() {
                    return Some(val.clone());
                }
            }
        }
    }
    None
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
        m.extend_from_slice(&[
            0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 30, 0, 7, 1, b'b', 3, b'c', b'o', b'm', 0,
        ]);
        // A b.com -> 9.9.9.9
        m.extend_from_slice(&[
            1, b'b', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 9, 9, 9, 9,
        ]);
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

    #[test]
    fn https_record_ech_extraction() {
        // 手工构造 HTTPS 应答：an=1，rdata = priority=1 + target=root + params{alpn=h2, ech=0xdead..}
        let ech_val: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0xfe];
        let mut m = Vec::new();
        m.extend_from_slice(&[0xaa, 0x01, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        m.extend_from_slice(&[3, b'w', b'w', b'w', 1, b'x', 3, b'c', b'o', b'm', 0]);
        m.extend_from_slice(&[0, 65, 0, 1]); // qtype HTTPS
        // answer：名字用压缩指针 0xc00c
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&1u16.to_be_bytes()); // priority
        rdata.push(0); // target = root
        // SvcParam alpn (key=1)：h2
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.extend_from_slice(&2u16.to_be_bytes());
        rdata.extend_from_slice(b"h2");
        // SvcParam ech (key=5)
        rdata.extend_from_slice(&SVCB_KEY_ECH.to_be_bytes());
        rdata.extend_from_slice(&(ech_val.len() as u16).to_be_bytes());
        rdata.extend_from_slice(&ech_val);
        m.extend_from_slice(&[0xc0, 0x0c, 0, 65, 0, 1, 0, 0, 0, 60]);
        m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        m.extend_from_slice(&rdata);
        let msg = parse_response(&m).unwrap();
        assert_eq!(msg.answers.len(), 1);
        assert!(matches!(msg.answers[0].data, RData::Https(1, _)));
        assert_eq!(extract_ech_config(&msg).unwrap(), ech_val);
        // 无 ech 参数时返回 None：去掉 ech SvcParam（key2+len2+val6=10 字节）并修正 rdata 长度
        let ech_param_len = 2 + 2 + ech_val.len();
        let rdata_len = 2 + 1 + (2 + 2 + 2); // priority + target + alpn 参数
        let mut no_ech = m.clone();
        no_ech.truncate(no_ech.len() - ech_param_len);
        let len_pos = no_ech.len() - rdata_len - 2;
        no_ech[len_pos..len_pos + 2].copy_from_slice(&(rdata_len as u16).to_be_bytes());
        let msg2 = parse_response(&no_ech).unwrap();
        assert_eq!(extract_ech_config(&msg2), None);
    }

    #[test]
    fn cname_with_compression_pointer_real_doh() {
        // 来自腾讯 DoH (1.12.12.12 / doh.pub) 查询 www.baidu.com 的真实应答报文
        // 包含 CNAME www.a.shifen.com（末尾指向 com 压缩指针 0xc016）及 A 记录 183.2.172.177
        let hex = "1234818000010002000000010377777705626169647503636f6d0000010001c00c000500010000044b000f0377777701610673686966656ec016c02b000100010000001f0004b702acb1";
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let msg = parse_response(&bytes).expect("DoH 真实报文解析失败");
        assert_eq!(msg.id, 0x1234);
        assert_eq!(msg.rcode, 0);
        assert_eq!(msg.answers.len(), 2);
        assert_eq!(msg.answers[0].name, "www.baidu.com");
        assert!(matches!(msg.answers[0].data, RData::Cname(ref c) if c == "www.a.shifen.com"));
        assert_eq!(msg.answers[1].name, "www.a.shifen.com");
        let ips = extract_ips(&msg, TYPE_A);
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].0.to_string(), "183.2.172.177");
    }

    #[test]
    fn cname_extraction_for_non_recursive_resolvers() {
        let mut m = Vec::new();
        m.extend_from_slice(&[0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        m.extend_from_slice(&[1, b'a', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
        m.extend_from_slice(&[
            0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 30, 0, 7, 1, b'b', 3, b'c', b'o', b'm', 0,
        ]);
        let msg = parse_response(&m).unwrap();
        assert_eq!(extract_ips(&msg, TYPE_A).len(), 0);
        assert_eq!(extract_cname(&msg), Some("b.com".to_string()));
    }
}

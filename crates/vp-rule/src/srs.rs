//! sing-box SRS (.srs) 二进制规则集解析器。
//!
//! 规范对齐 SagerNet/sing-box：
//! - 魔数 Header: `SRS` (0x53, 0x52, 0x53) + Version (1..=5)
//! - 外层由 zlib 压缩流封装
//! - 内部格式：
//!   - uvarint: 规则总数 length
//!   - 逐项规则解析：
//!     - Type: 0 (Default) / 1 (Logical)
//!     - 规则项 tagged items (Item 2: Domain, Item 3: Keyword, Item 6: IPCIDR 等)
//!     - 终止标记 0xFF + Invert (bool/u8)

use std::io::Read;

use flate2::read::ZlibDecoder;

pub use crate::consts::*;
use crate::domain::DomainTrie;
use crate::ipset::IpIntervalSetBuilder;
use crate::mrs::dump_succinct_keys;
use crate::provider::{DomainSet, ProviderPayload};

/// 解析 sing-box SRS 二进制规则集
pub fn parse_srs(data: &[u8]) -> Result<ProviderPayload, String> {
    if data.len() < 4 {
        return Err("SRS 数据长度不足".into());
    }

    if data[0..3] != SRS_MAGIC {
        return Err("无效的 sing-box SRS 魔数".into());
    }

    let version = data[3];
    if !(1..=5).contains(&version) {
        return Err(format!("不支持的 sing-box SRS 版本: {version}"));
    }

    // 解压 zlib 数据流
    let mut decoder = ZlibDecoder::new(&data[4..]);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| format!("zlib 解压 SRS 失败: {e}"))?;

    let mut r = CursorReader::new(&decompressed);
    let rules_count = r.read_uvarint()?;

    let mut trie = DomainTrie::new();
    let mut keywords = Vec::new();
    let mut ip_builder = IpIntervalSetBuilder::new();
    let mut has_ip = false;
    let mut has_domain = false;

    for _ in 0..rules_count {
        let rule_type = r.read_u8()?;
        if rule_type == 0 {
            // Default Rule
            parse_srs_default_rule(
                &mut r,
                &mut trie,
                &mut keywords,
                &mut ip_builder,
                &mut has_domain,
                &mut has_ip,
            )?;
        } else if rule_type == 1 {
            // Logical Rule: 简单遍历内部子规则提取域名与 IP
            let _mode = r.read_u8()?;
            let sub_count = r.read_uvarint()?;
            for _ in 0..sub_count {
                let sub_type = r.read_u8()?;
                if sub_type == 0 {
                    parse_srs_default_rule(
                        &mut r,
                        &mut trie,
                        &mut keywords,
                        &mut ip_builder,
                        &mut has_domain,
                        &mut has_ip,
                    )?;
                } else {
                    // 嵌套过深或未知直接跳过
                    let _ = r.read_u8();
                }
            }
        } else {
            return Err(format!("未知的 SRS rule type: {rule_type}"));
        }
    }

    // 根据提取到的特征返回对应 Payload
    if has_ip && !has_domain {
        Ok(ProviderPayload::Ip(Box::new(ip_builder.build())))
    } else {
        Ok(ProviderPayload::Domain(Box::new(DomainSet {
            trie,
            keywords,
        })))
    }
}

fn parse_srs_default_rule(
    r: &mut CursorReader,
    trie: &mut DomainTrie,
    keywords: &mut Vec<Box<str>>,
    ip_builder: &mut IpIntervalSetBuilder,
    has_domain: &mut bool,
    has_ip: &mut bool,
) -> Result<(), String> {
    loop {
        let item_type = r.read_u8()?;
        match item_type {
            RULE_ITEM_DOMAIN => {
                *has_domain = true;
                let (exacts, suffixes) = parse_srs_succinct_set(r)?;
                for e in exacts {
                    trie.insert_exact(&e);
                }
                for s in suffixes {
                    trie.insert_suffix_all(&s);
                }
            }
            RULE_ITEM_DOMAIN_KEYWORD => {
                *has_domain = true;
                let kws = r.read_string_slice()?;
                for kw in kws {
                    keywords.push(kw.to_ascii_lowercase().into());
                }
            }
            RULE_ITEM_DOMAIN_REGEX => {
                *has_domain = true;
                let _ = r.read_string_slice()?;
            }
            RULE_ITEM_IP_CIDR | RULE_ITEM_SOURCE_IP_CIDR => {
                *has_ip = true;
                parse_srs_ip_set(r, ip_builder)?;
            }
            RULE_ITEM_NETWORK | RULE_ITEM_PROCESS_NAME | RULE_ITEM_PROCESS_PATH => {
                let _ = r.read_string_slice()?;
            }
            RULE_ITEM_PORT | RULE_ITEM_SOURCE_PORT => {
                let count = r.read_uvarint()?;
                for _ in 0..count {
                    let _ = r.read_u16()?;
                }
            }
            RULE_ITEM_PORT_RANGE | RULE_ITEM_SOURCE_PORT_RANGE => {
                let _ = r.read_string_slice()?;
            }
            RULE_ITEM_QUERY_TYPE => {
                let count = r.read_uvarint()?;
                for _ in 0..count {
                    let _ = r.read_u16()?;
                }
            }
            RULE_ITEM_FINAL => {
                // 读取 Invert 标志 (1 字节)
                let _invert = r.read_u8()?;
                break;
            }
            _ => {
                // 跳过不支持或较少见的 Item
                break;
            }
        }
    }
    Ok(())
}

fn parse_srs_succinct_set(r: &mut CursorReader) -> Result<(Vec<String>, Vec<String>), String> {
    let _version = r.read_u8()?;
    let leaves_count = r.read_uvarint()? as usize;
    let mut leaves = Vec::with_capacity(leaves_count);
    for _ in 0..leaves_count {
        leaves.push(r.read_u64()?);
    }

    let bitmap_count = r.read_uvarint()? as usize;
    let mut label_bitmap = Vec::with_capacity(bitmap_count);
    for _ in 0..bitmap_count {
        label_bitmap.push(r.read_u64()?);
    }

    let labels_count = r.read_uvarint()? as usize;
    let labels = r.read_bytes(labels_count)?;

    let raw_keys = dump_succinct_keys(&leaves, &label_bitmap, labels);
    let mut exacts = Vec::new();
    let mut suffixes = Vec::new();

    const PREFIX_LABEL: u8 = 1;
    const ROOT_LABEL: u8 = 2;

    for key in raw_keys {
        let reversed: Vec<u8> = key.bytes().rev().collect();
        if reversed.is_empty() {
            continue;
        }
        if reversed[0] == PREFIX_LABEL || reversed[0] == ROOT_LABEL {
            if let Ok(s) = std::str::from_utf8(&reversed[1..]) {
                suffixes.push(s.to_string());
            }
        } else if let Ok(s) = std::str::from_utf8(&reversed) {
            exacts.push(s.to_string());
        }
    }

    Ok((exacts, suffixes))
}

fn parse_srs_ip_set(
    r: &mut CursorReader,
    builder: &mut IpIntervalSetBuilder,
) -> Result<(), String> {
    let version = r.read_u8()?;
    if version != 1 {
        return Err(format!("不支持的 sing-box IPSet 版本: {version}"));
    }
    let length = r.read_u64()?;
    for _ in 0..length {
        let from_len = r.read_uvarint()? as usize;
        let from_bytes = r.read_bytes(from_len)?;
        let to_len = r.read_uvarint()? as usize;
        let to_bytes = r.read_bytes(to_len)?;

        if from_len == 4 && to_len == 4 {
            let from = u32::from_be_bytes(from_bytes.try_into().unwrap());
            let to = u32::from_be_bytes(to_bytes.try_into().unwrap());
            builder.push_v4_range(from, to);
        } else if from_len == 16 && to_len == 16 {
            let from = u128::from_be_bytes(from_bytes.try_into().unwrap());
            let to = u128::from_be_bytes(to_bytes.try_into().unwrap());
            builder.push_v6_range(from, to);
        }
    }
    Ok(())
}

struct CursorReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> CursorReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, String> {
        if self.offset < self.data.len() {
            let b = self.data[self.offset];
            self.offset += 1;
            Ok(b)
        } else {
            Err("数据流意外结束".into())
        }
    }

    fn read_u16(&mut self) -> Result<u16, String> {
        if self.offset + 2 <= self.data.len() {
            let v = u16::from_be_bytes(self.data[self.offset..self.offset + 2].try_into().unwrap());
            self.offset += 2;
            Ok(v)
        } else {
            Err("读取 u16 截断".into())
        }
    }

    fn read_u64(&mut self) -> Result<u64, String> {
        if self.offset + 8 <= self.data.len() {
            let v = u64::from_be_bytes(self.data[self.offset..self.offset + 8].try_into().unwrap());
            self.offset += 8;
            Ok(v)
        } else {
            Err("读取 u64 截断".into())
        }
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], String> {
        if self.offset + len <= self.data.len() {
            let slice = &self.data[self.offset..self.offset + len];
            self.offset += len;
            Ok(slice)
        } else {
            Err("读取字节片段截断".into())
        }
    }

    fn read_uvarint(&mut self) -> Result<u64, String> {
        let mut x: u64 = 0;
        let mut s: u32 = 0;
        for _ in 0..10 {
            let b = self.read_u8()?;
            if b < 0x80 {
                return Ok(x | ((b as u64) << s));
            }
            x |= ((b & 0x7f) as u64) << s;
            s += 7;
        }
        Err("uvarint 溢出".into())
    }

    fn read_string_slice(&mut self) -> Result<Vec<String>, String> {
        let count = self.read_uvarint()? as usize;
        let mut list = Vec::with_capacity(count);
        for _ in 0..count {
            let len = self.read_uvarint()? as usize;
            let slice = self.read_bytes(len)?;
            if let Ok(s) = std::str::from_utf8(slice) {
                list.push(s.to_string());
            }
        }
        Ok(list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_srs_decompression_and_parse() {
        // 构建一个模拟的 SRS 二进制文件
        let mut inner = vec![
            1,                        // 规则数: 1 (uvarint)
            0,                        // 规则类型: 0 (Default)
            RULE_ITEM_DOMAIN_KEYWORD, // Tag: RULE_ITEM_DOMAIN_KEYWORD (3)
            1,                        // 字符串列表: 1 个
            6,                        // 字符串长度: 6
        ];
        inner.extend_from_slice(b"google");
        inner.push(RULE_ITEM_FINAL); // 终结: 0xFF
        inner.push(0); // Invert: 0

        // zlib 压缩
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&inner).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut file = Vec::new();
        file.extend_from_slice(&SRS_MAGIC);
        file.push(1); // version: 1
        file.extend_from_slice(&compressed);

        let payload = parse_srs(&file).expect("应当成功解析 SRS 文件");
        if let ProviderPayload::Domain(d) = payload {
            assert!(d.matches("www.google.com"));
            assert!(!d.matches("www.baidu.com"));
        } else {
            panic!("预期得到 DomainSet");
        }
    }
}

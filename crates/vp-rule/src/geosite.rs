//! v2ray geosite `.dat` 解析（protobuf wire 手写解码，零依赖）。
//!
//! ```proto
//! message GeoSiteList { repeated GeoSite entry = 1; }
//! message GeoSite { string country_code = 1; repeated Domain domain = 2; }
//! message Domain {
//!   enum Type { Plain = 0; Regex = 1; Root = 2; Full = 3; }
//!   Type type = 1; string value = 2;
//! }
//! ```

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::domain::DomainTrie;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteEntryKind {
    /// 关键字
    Plain,
    /// 正则
    Regex,
    /// 根域（后缀，含自身）
    Root,
    /// 精确
    Full,
}

#[derive(Debug, Clone)]
pub struct RawSite {
    pub code: String,
    pub entries: Vec<(SiteEntryKind, String)>,
}

/// 解析整个 .dat
pub fn parse_dat(bytes: &[u8]) -> Result<Vec<RawSite>, String> {
    let mut sites = Vec::new();
    let mut r = PbReader::new(bytes);
    while let Some((field, wire)) = r.next_tag()? {
        if field == 1 && wire == 2 {
            let msg = r.bytes()?;
            sites.push(parse_site(msg)?);
        } else {
            r.skip(wire)?;
        }
    }
    Ok(sites)
}

fn parse_site(msg: &[u8]) -> Result<RawSite, String> {
    let mut code = String::new();
    let mut entries = Vec::new();
    let mut r = PbReader::new(msg);
    while let Some((field, wire)) = r.next_tag()? {
        match (field, wire) {
            (1, 2) => code = String::from_utf8_lossy(r.bytes()?).into_owned(),
            (2, 2) => {
                let d = r.bytes()?;
                let mut kind = SiteEntryKind::Plain;
                let mut value = String::new();
                let mut dr = PbReader::new(d);
                while let Some((f, w)) = dr.next_tag()? {
                    match (f, w) {
                        (1, 0) => {
                            kind = match dr.varint()? {
                                0 => SiteEntryKind::Plain,
                                1 => SiteEntryKind::Regex,
                                2 => SiteEntryKind::Root,
                                3 => SiteEntryKind::Full,
                                _ => SiteEntryKind::Plain,
                            }
                        }
                        (2, 2) => value = String::from_utf8_lossy(dr.bytes()?).into_owned(),
                        _ => dr.skip(w)?,
                    }
                }
                entries.push((kind, value));
            }
            _ => r.skip(wire)?,
        }
    }
    Ok(RawSite { code, entries })
}

/// 流式直接解码 entry 进 Trie、关键词和正则，零中间 String 与 Vec 分配
fn decode_site_into(
    msg: &[u8],
    trie: &mut DomainTrie,
    keywords: &mut Vec<Box<str>>,
    regexes: &mut Vec<regex::Regex>,
) -> Result<(), String> {
    let mut r = PbReader::new(msg);
    while let Some((field, wire)) = r.next_tag()? {
        match (field, wire) {
            (2, 2) => {
                let d = r.bytes()?;
                let mut kind = 0u64;
                let mut val_bytes: Option<&[u8]> = None;
                let mut dr = PbReader::new(d);
                while let Some((f, w)) = dr.next_tag()? {
                    match (f, w) {
                        (1, 0) => kind = dr.varint()?,
                        (2, 2) => val_bytes = Some(dr.bytes()?),
                        _ => dr.skip(w)?,
                    }
                }
                if let Some(bytes) = val_bytes {
                    let val = String::from_utf8_lossy(bytes);
                    match kind {
                        0 => keywords.push(val.to_ascii_lowercase().into()),
                        1 => {
                            if let Ok(re) = regex::Regex::new(&format!("(?i){val}")) {
                                regexes.push(re);
                            }
                        }
                        2 => trie.insert_suffix_all(&val),
                        3 => trie.insert_exact(&val),
                        _ => keywords.push(val.to_ascii_lowercase().into()),
                    }
                }
            }
            _ => r.skip(wire)?,
        }
    }
    Ok(())
}

pub(crate) struct PbReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> PbReader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        PbReader { buf, pos: 0 }
    }

    pub(crate) fn eof(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub(crate) fn varint(&mut self) -> Result<u64, String> {
        let mut result: u64 = 0;
        let mut shift = 0;
        loop {
            if self.eof() {
                return Err("protobuf: varint 截断".into());
            }
            let b = self.buf[self.pos];
            self.pos += 1;
            result |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift > 63 {
                return Err("protobuf: varint 过长".into());
            }
        }
    }

    /// 返回 (field_number, wire_type)
    pub(crate) fn next_tag(&mut self) -> Result<Option<(u64, u8)>, String> {
        if self.eof() {
            return Ok(None);
        }
        let tag = self.varint()?;
        Ok(Some((tag >> 3, (tag & 0x7) as u8)))
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], String> {
        let len = self.varint()? as usize;
        if self.pos + len > self.buf.len() {
            return Err("protobuf: 长度字段越界".into());
        }
        let out = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(out)
    }

    pub(crate) fn skip(&mut self, wire: u8) -> Result<(), String> {
        match wire {
            0 => {
                self.varint()?;
            }
            1 => {
                self.take(8)?;
            }
            2 => {
                self.bytes()?;
            }
            5 => {
                self.take(4)?;
            }
            _ => return Err(format!("protobuf: 未知 wire type {wire}")),
        }
        Ok(())
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<(), String> {
        if self.pos + n > self.buf.len() {
            return Err("protobuf: 定长字段截断".into());
        }
        self.pos += n;
        Ok(())
    }
}

/// geosite 底层数据源（支持 mmap 零拷贝映射或内存块）
#[derive(Clone)]
pub enum GeoSiteBuffer {
    Mmap(Arc<memmap2::Mmap>),
    Bytes(Arc<[u8]>),
}

impl AsRef<[u8]> for GeoSiteBuffer {
    fn as_ref(&self) -> &[u8] {
        match self {
            GeoSiteBuffer::Mmap(m) => m.as_ref(),
            GeoSiteBuffer::Bytes(b) => b.as_ref(),
        }
    }
}

impl std::ops::Deref for GeoSiteBuffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_ref()
    }
}

/// 快速扫描 .dat 二进制，建立 tag -> Vec<(offset, len)> 稀疏索引表（仅几 KB 内存，零堆字符串反序列化）
pub fn build_tag_index(bytes: &[u8]) -> Result<HashMap<String, Vec<(usize, usize)>>, String> {
    let mut index: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
    let mut r = PbReader::new(bytes);
    while let Some((field, wire)) = r.next_tag()? {
        if field == 1 && wire == 2 {
            // entry = 1 (GeoSite message)
            let len = r.varint()? as usize;
            let start = r.pos;
            if start + len > bytes.len() {
                return Err("protobuf: geosite entry 越界".into());
            }
            let entry_bytes = &bytes[start..start + len];
            r.pos += len;

            // 仅解码 entry_bytes 内的 field 1: country_code，跳过全部域名明细
            let mut er = PbReader::new(entry_bytes);
            while let Some((efield, ewire)) = er.next_tag()? {
                if efield == 1 && ewire == 2 {
                    let code_raw = er.bytes()?;
                    let code = String::from_utf8_lossy(code_raw).trim().to_ascii_lowercase();
                    if !code.is_empty() {
                        index.entry(code).or_default().push((start, len));
                    }
                    break;
                } else {
                    er.skip(ewire)?;
                }
            }
        } else {
            r.skip(wire)?;
        }
    }
    Ok(index)
}

/// geosite 库：按需标签索引（Lazy Tag Indexing）+ 零拷贝 mmap，仅按需反序列化被规则命中的 tag
#[derive(Clone)]
pub struct GeoSiteDb {
    buffer: GeoSiteBuffer,
    tag_index: Arc<HashMap<String, Vec<(usize, usize)>>>,
    cache: Arc<RwLock<HashMap<String, Arc<CompiledSite>>>>,
}

impl GeoSiteDb {
    /// 从文件加载 geosite.dat（优先使用 memmap2 零拷贝内核页映射，失败自动回退标准读取）
    pub fn load_file(path: &std::path::Path) -> Result<Self, String> {
        let file = std::fs::File::open(path)
            .map_err(|e| format!("打开 GeoSite 文件 {} 失败: {e}", path.display()))?;
        let buf = match unsafe { memmap2::Mmap::map(&file) } {
            Ok(mmap) => GeoSiteBuffer::Mmap(Arc::new(mmap)),
            Err(_) => {
                let bytes = std::fs::read(path)
                    .map_err(|e| format!("读取 GeoSite 文件 {} 失败: {e}", path.display()))?;
                GeoSiteBuffer::Bytes(Arc::from(bytes.into_boxed_slice()))
            }
        };
        let tag_index = build_tag_index(&buf)?;
        Ok(GeoSiteDb {
            buffer: buf,
            tag_index: Arc::new(tag_index),
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// 从内存字节加载（快速构建索引，按需解码）
    pub fn load(bytes: &[u8]) -> Result<Self, String> {
        let buf = GeoSiteBuffer::Bytes(Arc::from(bytes.to_vec().into_boxed_slice()));
        let tag_index = build_tag_index(&buf)?;
        Ok(GeoSiteDb {
            buffer: buf,
            tag_index: Arc::new(tag_index),
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn has(&self, tag: &str) -> bool {
        self.tag_index.contains_key(&tag.to_ascii_lowercase())
    }

    /// 编译某 tag 为域名匹配集（trie + 正则），仅首次请求该 tag 时跳转解码对应片段，结果自动常驻缓存
    pub fn compile(&self, tag: &str) -> Option<Arc<CompiledSite>> {
        let tag_lower = tag.to_ascii_lowercase();
        {
            let c = self.cache.read().unwrap();
            if let Some(hit) = c.get(&tag_lower) {
                return Some(hit.clone());
            }
        }
        let ranges = self.tag_index.get(&tag_lower)?;
        let mut trie = DomainTrie::new();
        let mut keywords: Vec<Box<str>> = Vec::new();
        let mut regexes: Vec<regex::Regex> = Vec::new();

        for &(offset, len) in ranges {
            if offset + len <= self.buffer.len() {
                let msg = &self.buffer[offset..offset + len];
                let _ = decode_site_into(msg, &mut trie, &mut keywords, &mut regexes);
            }
        }

        keywords.shrink_to_fit();
        regexes.shrink_to_fit();

        let compiled = Arc::new(CompiledSite {
            trie,
            keywords,
            regexes,
        });
        self.cache
            .write()
            .unwrap()
            .insert(tag_lower, compiled.clone());
        Some(compiled)
    }
}

#[derive(Clone)]
pub struct CompiledSite {
    pub trie: DomainTrie,
    pub keywords: Vec<Box<str>>,
    pub regexes: Vec<regex::Regex>,
}

impl CompiledSite {
    pub fn matches(&self, domain: &str) -> bool {
        if self.trie.is_match(domain) {
            return true;
        }
        let lower = domain.to_ascii_lowercase();
        if self.keywords.iter().any(|k| lower.contains(&**k)) {
            return true;
        }
        self.regexes.iter().any(|re| re.is_match(domain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 手工构造一个最小 .dat
    fn build_dat() -> Vec<u8> {
        // Domain { type=Full(3), value="example.com" }
        let mut d1 = vec![1u8 << 3, 3]; // field1 varint 3
        d1.push((2 << 3) | 2); // field2 len-delim
        d1.push(b"example.com".len() as u8);
        d1.extend_from_slice(b"example.com");
        // Domain { type=Root(2), value="root.com" }
        let mut d2 = vec![1u8 << 3, 2];
        d2.push((2 << 3) | 2);
        d2.push(b"root.com".len() as u8);
        d2.extend_from_slice(b"root.com");
        // GeoSite { country_code="test", domain=[d1,d2] }
        let mut site = vec![(1 << 3) | 2, 4];
        site.extend_from_slice(b"test");
        site.push((2 << 3) | 2);
        site.push(d1.len() as u8);
        site.extend_from_slice(&d1);
        site.push((2 << 3) | 2);
        site.push(d2.len() as u8);
        site.extend_from_slice(&d2);
        // GeoSiteList { entry=site }
        let mut out = vec![(1 << 3) | 2];
        out.push(site.len() as u8);
        out.extend_from_slice(&site);
        out
    }

    #[test]
    fn parses_handbuilt_dat() {
        let dat = build_dat();
        let db = GeoSiteDb::load(&dat).unwrap();
        assert!(db.has("test"));
        assert!(db.has("TEST"));
        let compiled = db.compile("test").unwrap();
        assert!(compiled.matches("example.com")); // Full
        assert!(!compiled.matches("www.example.com"));
        assert!(compiled.matches("root.com")); // Root
        assert!(compiled.matches("a.root.com"));
    }

    #[test]
    fn garbage_rejected() {
        assert!(parse_dat(&[0xff, 0xff]).is_err() || GeoSiteDb::load(&[0xff]).is_err());
    }
}

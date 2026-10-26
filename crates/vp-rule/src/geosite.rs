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

struct PbReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> PbReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        PbReader { buf, pos: 0 }
    }

    fn eof(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn varint(&mut self) -> Result<u64, String> {
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
    fn next_tag(&mut self) -> Result<Option<(u64, u8)>, String> {
        if self.eof() {
            return Ok(None);
        }
        let tag = self.varint()?;
        Ok(Some((tag >> 3, (tag & 0x7) as u8)))
    }

    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let len = self.varint()? as usize;
        if self.pos + len > self.buf.len() {
            return Err("protobuf: 长度字段越界".into());
        }
        let out = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(out)
    }

    fn skip(&mut self, wire: u8) -> Result<(), String> {
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

    fn take(&mut self, n: usize) -> Result<(), String> {
        if self.pos + n > self.buf.len() {
            return Err("protobuf: 定长字段截断".into());
        }
        self.pos += n;
        Ok(())
    }
}

/// geosite 库：加载一次，按 tag 惰性编译 trie 并缓存
#[derive(Clone)]
pub struct GeoSiteDb {
    sites: HashMap<String, Vec<(SiteEntryKind, String)>>,
}

impl GeoSiteDb {
    pub fn load(bytes: &[u8]) -> Result<Self, String> {
        let raw = parse_dat(bytes)?;
        let mut sites = HashMap::new();
        for s in raw {
            sites
                .entry(s.code.to_ascii_lowercase())
                .or_insert_with(Vec::new)
                .extend(s.entries);
        }
        Ok(GeoSiteDb { sites })
    }

    pub fn has(&self, tag: &str) -> bool {
        self.sites.contains_key(&tag.to_ascii_lowercase())
    }

    /// 编译某 tag 为域名匹配集（trie + 正则）
    pub fn compile(&self, tag: &str) -> Option<CompiledSite> {
        let entries = self.sites.get(&tag.to_ascii_lowercase())?;
        let mut trie = DomainTrie::new();
        let mut keywords: Vec<Box<str>> = Vec::new();
        let mut regexes: Vec<regex::Regex> = Vec::new();
        for (kind, value) in entries {
            match kind {
                SiteEntryKind::Root => trie.insert_suffix_all(value),
                SiteEntryKind::Full => trie.insert_exact(value),
                SiteEntryKind::Plain => keywords.push(value.to_ascii_lowercase().into()),
                SiteEntryKind::Regex => {
                    if let Ok(re) = regex::Regex::new(&format!("(?i){value}")) {
                        regexes.push(re);
                    }
                }
            }
        }
        Some(CompiledSite { trie, keywords, regexes })
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
        let mut d1 = vec![(1u8 << 3) | 0, 3]; // field1 varint 3
        d1.push((2 << 3) | 2); // field2 len-delim
        d1.push(b"example.com".len() as u8);
        d1.extend_from_slice(b"example.com");
        // Domain { type=Root(2), value="root.com" }
        let mut d2 = vec![(1u8 << 3) | 0, 2];
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

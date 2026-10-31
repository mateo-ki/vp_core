//! GeoIP（支持 MaxMind mmdb 与 V2Ray / Xray geoip.dat 双格式）匹配。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Arc;

use crate::geosite::PbReader;
use crate::ipset::{IpIntervalSet, IpIntervalSetBuilder};

#[derive(Clone)]
pub enum GeoIpDb {
    MmdbMmap(Arc<maxminddb::Reader<memmap2::Mmap>>),
    MmdbMem(Arc<maxminddb::Reader<Vec<u8>>>),
    Dat(Arc<HashMap<String, Arc<IpIntervalSet>>>),
}

#[derive(serde::Deserialize, Debug, Clone)]
struct CountryNode {
    iso_code: Option<String>,
}

#[derive(serde::Deserialize, Debug, Clone)]
struct ContinentNode {
    code: Option<String>,
}

#[derive(serde::Deserialize, Debug, Clone)]
#[serde(untagged)]
enum CountryField {
    Object(CountryNode),
    String(String),
}

#[derive(serde::Deserialize, Debug, Clone)]
#[serde(untagged)]
enum ContinentField {
    Object(ContinentNode),
    String(String),
}

#[derive(serde::Deserialize, Debug, Clone)]
#[serde(untagged)]
enum TagsField {
    List(Vec<String>),
    Single(String),
}

#[derive(serde::Deserialize, Debug, Clone)]
#[serde(untagged)]
enum MmdbRecord {
    /// 字典格式（兼顾 MaxMind 标准结构、自定义 code/country 扁平字段以及 tags 标签）
    Map {
        #[serde(default)]
        country: Option<CountryField>,
        #[serde(default)]
        registered_country: Option<CountryField>,
        #[serde(default)]
        continent: Option<ContinentField>,
        #[serde(default)]
        code: Option<String>,
        #[serde(default)]
        iso_code: Option<String>,
        #[serde(default)]
        tags: Option<TagsField>,
    },
    /// MetaCubeX / meta-rules-dat `geoip.metadb` (DatabaseType: "Meta-geoip0")：
    /// 存储为字符串数组，如 ["cn", "google"]
    StringList(Vec<String>),
    /// 存储为单个字符串，如 "cn"
    Single(String),
}

impl MmdbRecord {
    pub fn matches_code(&self, target: &str) -> bool {
        match self {
            MmdbRecord::Map {
                country,
                registered_country,
                continent,
                code,
                iso_code,
                tags,
            } => {
                if let Some(c) = country {
                    match c {
                        CountryField::Object(node) => {
                            if let Some(iso) = node.iso_code.as_deref() {
                                if iso.eq_ignore_ascii_case(target) {
                                    return true;
                                }
                            }
                        }
                        CountryField::String(s) => {
                            if s.eq_ignore_ascii_case(target) {
                                return true;
                            }
                        }
                    }
                }
                if let Some(c) = registered_country {
                    match c {
                        CountryField::Object(node) => {
                            if let Some(iso) = node.iso_code.as_deref() {
                                if iso.eq_ignore_ascii_case(target) {
                                    return true;
                                }
                            }
                        }
                        CountryField::String(s) => {
                            if s.eq_ignore_ascii_case(target) {
                                return true;
                            }
                        }
                    }
                }
                if let Some(c) = continent {
                    match c {
                        ContinentField::Object(node) => {
                            if let Some(code) = node.code.as_deref() {
                                if code.eq_ignore_ascii_case(target) {
                                    return true;
                                }
                            }
                        }
                        ContinentField::String(s) => {
                            if s.eq_ignore_ascii_case(target) {
                                return true;
                            }
                        }
                    }
                }
                if let Some(c) = code.as_deref() {
                    if c.eq_ignore_ascii_case(target) {
                        return true;
                    }
                }
                if let Some(c) = iso_code.as_deref() {
                    if c.eq_ignore_ascii_case(target) {
                        return true;
                    }
                }
                if let Some(t) = tags {
                    match t {
                        TagsField::List(list) => {
                            if list.iter().any(|item| item.eq_ignore_ascii_case(target)) {
                                return true;
                            }
                        }
                        TagsField::Single(s) => {
                            if s.eq_ignore_ascii_case(target) {
                                return true;
                            }
                        }
                    }
                }
                false
            }
            MmdbRecord::StringList(list) => {
                list.iter().any(|item| item.eq_ignore_ascii_case(target))
            }
            MmdbRecord::Single(s) => s.eq_ignore_ascii_case(target),
        }
    }
}

impl GeoIpDb {
    /// 自动识别并加载 .mmdb 或 .dat (v2ray protobuf)，优先采用零拷贝 mmap 映射
    pub fn load(path: &Path) -> Result<Self, String> {
        let is_dat = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("dat"))
            .unwrap_or(false);

        if is_dat {
            let file = std::fs::File::open(path)
                .map_err(|e| format!("打开 GeoIP dat 文件 {} 失败: {e}", path.display()))?;
            let dat_map = match unsafe { memmap2::Mmap::map(&file) } {
                Ok(mmap) => parse_geoip_dat(&mmap)
                    .map_err(|e| format!("解析 GeoIP dat 文件 {} 失败: {e}", path.display()))?,
                Err(_) => {
                    let bytes = std::fs::read(path)
                        .map_err(|e| format!("读取 GeoIP dat 文件 {} 失败: {e}", path.display()))?;
                    parse_geoip_dat(&bytes)
                        .map_err(|e| format!("解析 GeoIP dat 文件 {} 失败: {e}", path.display()))?
                }
            };
            Ok(GeoIpDb::Dat(Arc::new(dat_map)))
        } else {
            // 优先采用零拷贝 mmap，由 OS 页缓存管理虚拟内存，内存压力下自动回收，彻底消除 10~15MB 堆占用
            match maxminddb::Reader::open_mmap(path) {
                Ok(reader) => Ok(GeoIpDb::MmdbMmap(Arc::new(reader))),
                Err(_) => {
                    let reader = maxminddb::Reader::open_readfile(path)
                        .map_err(|e| format!("打开 GeoIP 数据库 {} 失败: {e}", path.display()))?;
                    Ok(GeoIpDb::MmdbMem(Arc::new(reader)))
                }
            }
        }
    }

    /// 从字节加载 geoip.dat
    pub fn load_dat(bytes: &[u8]) -> Result<Self, String> {
        let dat_map = parse_geoip_dat(bytes)?;
        Ok(GeoIpDb::Dat(Arc::new(dat_map)))
    }

    /// 国家代码或特殊类别（LAN/PRIVATE/GOOGLE/TELEGRAM/NETFLIX 等）匹配器
    pub fn matcher(&self, code: String) -> Option<GeoIpMatcher> {
        let code = code.trim().to_ascii_uppercase();
        if code.is_empty() {
            return None;
        }
        if code == "LAN" || code == "PRIVATE" {
            return Some(GeoIpMatcher::LanOrPrivate);
        }
        match self {
            GeoIpDb::MmdbMmap(reader) => Some(GeoIpMatcher::MmdbMmap {
                code,
                reader: reader.clone(),
            }),
            GeoIpDb::MmdbMem(reader) => Some(GeoIpMatcher::MmdbMem {
                code,
                reader: reader.clone(),
            }),
            GeoIpDb::Dat(map) => map
                .get(&code)
                .map(|set| GeoIpMatcher::Dat { set: set.clone() }),
        }
    }
}

#[derive(Clone)]
pub enum GeoIpMatcher {
    LanOrPrivate,
    MmdbMmap {
        code: String,
        reader: Arc<maxminddb::Reader<memmap2::Mmap>>,
    },
    MmdbMem {
        code: String,
        reader: Arc<maxminddb::Reader<Vec<u8>>>,
    },
    Dat {
        set: Arc<IpIntervalSet>,
    },
}

impl GeoIpMatcher {
    pub fn matches(&self, ip: IpAddr) -> bool {
        match self {
            GeoIpMatcher::LanOrPrivate => {
                ip.is_loopback()
                    || ip.is_unspecified()
                    || match ip {
                        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
                        std::net::IpAddr::V6(v6) => {
                            let s = v6.segments();
                            (s[0] & 0xfe00) == 0xfc00 /*ULA*/ || (s[0] & 0xffc0) == 0xfe80
                        }
                    }
            }
            GeoIpMatcher::MmdbMmap { code, reader } => {
                let hit: Option<MmdbRecord> = reader.lookup(ip).ok().flatten();
                hit.is_some_and(|r| r.matches_code(code))
            }
            GeoIpMatcher::MmdbMem { code, reader } => {
                let hit: Option<MmdbRecord> = reader.lookup(ip).ok().flatten();
                hit.is_some_and(|r| r.matches_code(code))
            }
            GeoIpMatcher::Dat { set } => set.contains(ip),
        }
    }
}

/// 解析 v2ray geoip.dat protobuf 二进制
fn parse_geoip_dat(bytes: &[u8]) -> Result<HashMap<String, Arc<IpIntervalSet>>, String> {
    let mut map: HashMap<String, IpIntervalSetBuilder> = HashMap::new();
    let mut r = PbReader::new(bytes);
    while let Some((field, wire)) = r.next_tag()? {
        if field == 1 && wire == 2 {
            let entry_bytes = r.bytes()?;
            let mut er = PbReader::new(entry_bytes);
            let mut country_code = String::new();
            let mut cidrs = Vec::new();
            while let Some((efield, ewire)) = er.next_tag()? {
                match (efield, ewire) {
                    (1, 2) => {
                        country_code = String::from_utf8_lossy(er.bytes()?)
                            .trim()
                            .to_ascii_uppercase();
                    }
                    (2, 2) => {
                        let cidr_bytes = er.bytes()?;
                        let mut cr = PbReader::new(cidr_bytes);
                        let mut ip_bytes = None;
                        let mut prefix = 0u32;
                        while let Some((cfield, cwire)) = cr.next_tag()? {
                            match (cfield, cwire) {
                                (1, 2) => ip_bytes = Some(cr.bytes()?),
                                (2, 0) => prefix = cr.varint()? as u32,
                                _ => cr.skip(cwire)?,
                            }
                        }
                        if let Some(raw_ip) = ip_bytes {
                            let ip_addr = match raw_ip.len() {
                                4 => Some(IpAddr::V4(Ipv4Addr::new(
                                    raw_ip[0], raw_ip[1], raw_ip[2], raw_ip[3],
                                ))),
                                16 => {
                                    let mut arr = [0u8; 16];
                                    arr.copy_from_slice(raw_ip);
                                    Some(IpAddr::V6(Ipv6Addr::from(arr)))
                                }
                                _ => None,
                            };
                            if let Some(ip) = ip_addr {
                                cidrs.push((ip, prefix));
                            }
                        }
                    }
                    _ => er.skip(ewire)?,
                }
            }
            if !country_code.is_empty() && !cidrs.is_empty() {
                let builder = map.entry(country_code).or_default();
                for (ip, prefix) in cidrs {
                    let _ = builder.insert_cidr(&format!("{ip}/{prefix}"));
                }
            }
        } else {
            r.skip(wire)?;
        }
    }
    let mut final_map = HashMap::new();
    for (k, v) in map {
        final_map.insert(k, Arc::new(v.build()));
    }
    Ok(final_map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geoip_dat_wire_format_parsing() {
        // 手工构造合法 v2ray protobuf wire 格式的 geoip.dat
        // 包含类别 GOOGLE (8.8.8.0/24) 和 CN (114.114.114.0/24)
        let mut entry_google = Vec::new();
        // field 1: country_code = "GOOGLE"
        entry_google.extend_from_slice(&[10, 6, b'G', b'O', b'O', b'G', b'L', b'E']);
        // field 2: cidr (8.8.8.0/24)
        entry_google.extend_from_slice(&[18, 8, 10, 4, 8, 8, 8, 0, 16, 24]);

        let mut entry_cn = Vec::new();
        // field 1: country_code = "CN"
        entry_cn.extend_from_slice(&[10, 2, b'C', b'N']);
        // field 2: cidr (114.114.114.0/24)
        entry_cn.extend_from_slice(&[18, 8, 10, 4, 114, 114, 114, 0, 16, 24]);

        let mut dat = Vec::new();
        // GeoIPList field 1 (entry_google)
        dat.push(10);
        dat.push(entry_google.len() as u8);
        dat.extend_from_slice(&entry_google);

        // GeoIPList field 1 (entry_cn)
        dat.push(10);
        dat.push(entry_cn.len() as u8);
        dat.extend_from_slice(&entry_cn);

        let db = GeoIpDb::load_dat(&dat).expect("解析 geoip.dat 应当成功");

        // 验证 GOOGLE 类别匹配
        let google_matcher = db
            .matcher("google".to_string())
            .expect("应当找到 GOOGLE 类别");
        assert!(google_matcher.matches("8.8.8.8".parse().unwrap()));
        assert!(!google_matcher.matches("1.1.1.1".parse().unwrap()));

        // 验证 CN 类别匹配
        let cn_matcher = db.matcher("CN".to_string()).expect("应当找到 CN 类别");
        assert!(cn_matcher.matches("114.114.114.114".parse().unwrap()));
        assert!(!cn_matcher.matches("8.8.8.8".parse().unwrap()));

        // 验证特殊类别 LAN / PRIVATE
        let lan_matcher = db.matcher("LAN".to_string()).expect("应当支持 LAN");
        assert!(lan_matcher.matches("192.168.1.1".parse().unwrap()));
        assert!(lan_matcher.matches("127.0.0.1".parse().unwrap()));
        assert!(!lan_matcher.matches("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_mmdb_record_polymorphic_deserialization() {
        // 1. MaxMind 标准嵌套对象
        let standard_json = r#"{"country": {"iso_code": "CN"}}"#;
        let rec: MmdbRecord = serde_yaml::from_str(standard_json).unwrap();
        assert!(rec.matches_code("cn"));
        assert!(rec.matches_code("CN"));
        assert!(!rec.matches_code("US"));

        // 2. 大洲代码
        let continent_json = r#"{"continent": {"code": "AS"}}"#;
        let rec: MmdbRecord = serde_yaml::from_str(continent_json).unwrap();
        assert!(rec.matches_code("AS"));

        // 3. MetaCubeX meta-rules-dat `geoip.metadb` 字符串数组
        let list_json = r#"["cn", "google"]"#;
        let rec: MmdbRecord = serde_yaml::from_str(list_json).unwrap();
        assert!(rec.matches_code("CN"));
        assert!(rec.matches_code("google"));
        assert!(rec.matches_code("GOOGLE"));
        assert!(!rec.matches_code("telegram"));

        // 4. sing-geoip 单个字符串
        let single_json = r#""cn""#;
        let rec: MmdbRecord = serde_yaml::from_str(single_json).unwrap();
        assert!(rec.matches_code("CN"));
        assert!(!rec.matches_code("HK"));

        // 5. 扁平 Map 格式
        let map_json = r#"{"code": "HK"}"#;
        let rec: MmdbRecord = serde_yaml::from_str(map_json).unwrap();
        assert!(rec.matches_code("hk"));
    }
}

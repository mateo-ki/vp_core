//! IP-ASN（MaxMind GeoLite2-ASN mmdb 格式）匹配。
//!
//! 与 geoip.rs 的 mmdb 路径同构：mmap 优先、回退整读；
//! 查询结构为 `{ autonomous_system_number }`。

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone)]
pub enum AsnDb {
    MmdbMmap(Arc<maxminddb::Reader<memmap2::Mmap>>),
    MmdbMem(Arc<maxminddb::Reader<Vec<u8>>>),
}

#[derive(serde::Deserialize)]
struct AsnLookup {
    #[serde(rename = "autonomous_system_number", alias = "autonomousSystemNumber")]
    asn: Option<u32>,
}

impl AsnDb {
    /// 加载 ASN mmdb（mmap 优先，失败回退整读）
    pub fn load(path: &Path) -> Result<Self, String> {
        match maxminddb::Reader::open_mmap(path) {
            Ok(reader) => Ok(AsnDb::MmdbMmap(Arc::new(reader))),
            Err(_) => {
                let reader = maxminddb::Reader::open_readfile(path)
                    .map_err(|e| format!("打开 ASN 数据库 {} 失败: {e}", path.display()))?;
                Ok(AsnDb::MmdbMem(Arc::new(reader)))
            }
        }
    }

    /// 解析 payload（"13335" / "AS13335"，支持逗号分隔多个）为匹配器
    pub fn matcher(&self, payload: &str) -> Option<AsnMatcher> {
        let asns: Vec<u32> = payload
            .split(',')
            .filter_map(|p| {
                let s = p.trim().to_ascii_uppercase();
                let s = s.strip_prefix("AS").unwrap_or(&s);
                s.parse::<u32>().ok()
            })
            .collect();
        if asns.is_empty() {
            return None;
        }
        Some(AsnMatcher {
            asns: asns.into(),
            db: self.clone(),
        })
    }
}

#[derive(Clone)]
pub struct AsnMatcher {
    asns: Arc<[u32]>,
    db: AsnDb,
}

impl AsnMatcher {
    pub fn matches(&self, ip: IpAddr) -> bool {
        let hit: Option<AsnLookup> = match &self.db {
            AsnDb::MmdbMmap(reader) => reader.lookup(ip).ok().flatten(),
            AsnDb::MmdbMem(reader) => reader.lookup(ip).ok().flatten(),
        };
        hit.and_then(|a| a.asn)
            .is_some_and(|n| self.asns.contains(&n))
    }
}

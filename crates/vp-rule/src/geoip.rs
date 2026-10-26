//! GeoIP（MaxMind mmdb）匹配。

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone)]
pub struct GeoIpDb {
    reader: Arc<maxminddb::Reader<Vec<u8>>>,
}

#[derive(serde::Deserialize)]
struct CountryNode {
    iso_code: Option<String>,
}

#[derive(serde::Deserialize)]
struct CountryLookup {
    country: Option<CountryNode>,
}

impl GeoIpDb {
    pub fn load(path: &Path) -> Result<Self, String> {
        let reader = maxminddb::Reader::open_readfile(path)
            .map_err(|e| format!("打开 GeoIP 数据库 {} 失败: {e}", path.display()))?;
        Ok(GeoIpDb { reader: Arc::new(reader) })
    }

    /// 国家代码匹配器（实际国家判定在查询时进行）
    pub fn matcher(&self, code: String) -> Option<GeoIpMatcher> {
        let code = code.to_ascii_uppercase();
        // 简单校验：2 字母国家码或特殊类别
        if code.len() != 2 && code != "LAN" && code != "PRIVATE" {
            return None;
        }
        Some(GeoIpMatcher { code, reader: self.reader.clone() })
    }
}

pub struct GeoIpMatcher {
    code: String,
    reader: Arc<maxminddb::Reader<Vec<u8>>>,
}

impl GeoIpMatcher {
    pub fn matches(&self, ip: IpAddr) -> bool {
        if self.code == "LAN" || self.code == "PRIVATE" {
            return ip.is_loopback() || ip.is_unspecified()
                || match ip {
                    std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
                    std::net::IpAddr::V6(v6) => {
                        let s = v6.segments();
                        (s[0] & 0xfe00) == 0xfc00 /*ULA*/ || (s[0] & 0xffc0) == 0xfe80
                    }
                };
        }
        let hit: Option<CountryLookup> = self
            .reader
            .lookup(ip)
            .ok()
            .flatten();
        hit.and_then(|c| c.country)
            .and_then(|c| c.iso_code)
            .is_some_and(|iso| iso.eq_ignore_ascii_case(&self.code))
    }
}

// 说明：GEOIP 国家匹配依赖真实 mmdb 数据文件，集成测试在 vp-app 层进行。

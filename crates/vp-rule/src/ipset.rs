//! IP-CIDR 集合：构建期合并为有序区间数组，查询二分，热路径零分配。
//! IPv4 与 IPv6 分表；IPv4-mapped IPv6 地址按 IPv4 处理。

use std::net::IpAddr;

#[derive(Debug, Default, Clone)]
pub struct IpIntervalSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

#[derive(Debug, Default)]
pub struct IpIntervalSetBuilder {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl IpIntervalSetBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// 插入 CIDR（如 "10.0.0.0/8"、"2001:db8::/32"、裸 IP 视为 /32|/128）
    pub fn insert_cidr(&mut self, cidr: &str) -> Result<(), String> {
        let (ip, plen) = match cidr.split_once('/') {
            Some((ip, plen)) => (
                ip.parse::<IpAddr>()
                    .map_err(|e| format!("非法 IP {ip:?}: {e}"))?,
                plen.parse::<u8>()
                    .map_err(|_| format!("非法前缀长度 {plen:?}"))?,
            ),
            None => (
                cidr.parse::<IpAddr>()
                    .map_err(|e| format!("非法 IP {cidr:?}: {e}"))?,
                match cidr.parse::<IpAddr>() {
                    Ok(IpAddr::V4(_)) => 32,
                    _ => 128,
                },
            ),
        };
        match (ip, normalize(ip)) {
            (IpAddr::V4(_), NormIp::V4(v)) => {
                if plen > 32 {
                    return Err(format!("IPv4 前缀长度超限: {cidr}"));
                }
                self.push_v4(v, plen);
            }
            // IPv4-mapped IPv6：前缀长度换算到 v4 空间
            (IpAddr::V6(_), NormIp::V4(v)) => {
                if plen > 128 {
                    return Err(format!("前缀长度超限: {cidr}"));
                }
                let v4plen = plen.saturating_sub(96).min(32);
                self.push_v4(v, v4plen);
            }
            (IpAddr::V6(_), NormIp::V6(v)) => {
                if plen > 128 {
                    return Err(format!("前缀长度超限: {cidr}"));
                }
                let mask = if plen == 0 {
                    0
                } else {
                    u128::MAX << (128 - plen)
                };
                let base = v & mask;
                self.v6.push((base, base | !mask));
            }
            (IpAddr::V4(_), NormIp::V6(_)) => unreachable!(),
        }
        Ok(())
    }

    fn push_v4(&mut self, v: u32, plen: u8) {
        let mask = if plen == 0 {
            0
        } else {
            u32::MAX << (32 - plen)
        };
        let base = v & mask;
        self.v4.push((base, base | !mask));
    }

    pub fn build(mut self) -> IpIntervalSet {
        self.v4.sort_unstable();
        self.v6.sort_unstable();
        IpIntervalSet {
            v4: merge(&self.v4),
            v6: merge(&self.v6),
        }
    }
}

fn merge<T: Copy + Ord>(sorted: &[(T, T)]) -> Vec<(T, T)> {
    let mut out: Vec<(T, T)> = Vec::with_capacity(sorted.len());
    for &(lo, hi) in sorted.iter() {
        match out.last_mut() {
            Some(last) if lo <= last.1 && hi >= last.1 => last.1 = hi,
            Some(last) if lo <= last.1 => {} // 完全包含，跳过
            _ => out.push((lo, hi)),
        }
    }
    out
}

enum NormIp {
    V4(u32),
    V6(u128),
}

fn normalize(ip: IpAddr) -> NormIp {
    match ip {
        IpAddr::V4(v4) => NormIp::V4(u32::from_be_bytes(v4.octets())),
        IpAddr::V6(v6) => {
            let o = v6.octets();
            // IPv4-mapped ::ffff:a.b.c.d
            if o[..10].iter().all(|&b| b == 0) && o[10] == 0xff && o[11] == 0xff {
                NormIp::V4(u32::from_be_bytes([o[12], o[13], o[14], o[15]]))
            } else {
                let mut buf = [0u8; 16];
                buf.copy_from_slice(&o);
                NormIp::V6(u128::from_be_bytes(buf))
            }
        }
    }
}

impl IpIntervalSet {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match normalize(ip) {
            NormIp::V4(n) => contains_in(&self.v4, n),
            NormIp::V6(n) => contains_in(&self.v6, n),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

fn contains_in<T: Copy + Ord>(set: &[(T, T)], n: T) -> bool {
    set.binary_search_by(|&(lo, hi)| {
        if n < lo {
            std::cmp::Ordering::Greater
        } else if n > hi {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Equal
        }
    })
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(cidrs: &[&str]) -> IpIntervalSet {
        let mut b = IpIntervalSetBuilder::new();
        for c in cidrs {
            b.insert_cidr(c).unwrap();
        }
        b.build()
    }

    #[test]
    fn cidr_membership() {
        let s = set(&["10.0.0.0/8", "192.168.1.0/24"]);
        assert!(s.contains("10.20.30.40".parse().unwrap()));
        assert!(s.contains("10.0.0.0".parse().unwrap()));
        assert!(s.contains("10.255.255.255".parse().unwrap()));
        assert!(!s.contains("11.0.0.1".parse().unwrap()));
        assert!(s.contains("192.168.1.77".parse().unwrap()));
        assert!(!s.contains("192.168.2.1".parse().unwrap()));
    }

    #[test]
    fn merged_adjacent() {
        let s = set(&["10.0.0.0/24", "10.0.1.0/24"]);
        assert!(s.contains("10.0.1.200".parse().unwrap()));
    }

    #[test]
    fn v6_and_mapped_v4() {
        let s = set(&["2001:db8::/32", "1.2.3.4/32"]);
        assert!(s.contains("2001:db8:ffff::1".parse().unwrap()));
        assert!(!s.contains("2001:db9::1".parse().unwrap()));
        // v4-mapped 形式也按 v4 命中
        assert!(s.contains("::ffff:1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn bare_ip() {
        let s = set(&["8.8.8.8"]);
        assert!(s.contains("8.8.8.8".parse().unwrap()));
        assert!(!s.contains("8.8.8.9".parse().unwrap()));
    }

    #[test]
    fn invalid_input() {
        let mut b = IpIntervalSetBuilder::new();
        assert!(b.insert_cidr("nonsense").is_err());
        assert!(b.insert_cidr("10.0.0.0/99").is_err());
    }
}

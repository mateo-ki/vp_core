//! Mihomo MRS (.mrs) 二进制规则集解析器。
//!
//! 规范对齐 MetaCubeX/mihomo：
//! - 外层通常由 Zstandard (zstd) 压缩
//! - 魔数 Header: `MRS\x01` (4 字节)
//! - 行为 Behavior: 1 字节 (0: Domain, 1: IPCIDR, 2: Classical)
//! - 规则计数 Count: 8 字节 Big-Endian int64
//! - 额外保留字段 Extra: 8 字节 Big-Endian int64 长度 + 对应字节序列
//! - 载荷解码：
//!   - Domain: Version 1 + leaves uint64 数组 + labelBitmap uint64 数组 + labels 字节序列 (Succinct Trie)
//!   - IPCIDR: Version 1 + 范围总数 int64 + (16 字节 From, 16 字节 To) IP 范围数组

use crate::domain::DomainTrie;
use crate::ipset::IpIntervalSetBuilder;
use crate::provider::{DomainSet, ProviderPayload};

pub use crate::consts::{MRS_MAGIC, ZSTD_MAGIC};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MrsBehavior {
    Domain = 0,
    IpCidr = 1,
    Classical = 2,
}

impl MrsBehavior {
    pub fn from_u8(b: u8) -> Result<Self, String> {
        match b {
            0 => Ok(Self::Domain),
            1 => Ok(Self::IpCidr),
            2 => Ok(Self::Classical),
            other => Err(format!("未知的 MRS behavior 类型: {other}")),
        }
    }
}

/// 解析 MRS 二进制规则集。支持直接输入 Zstd 压缩流或已解压的裸数据。
pub fn parse_mrs(data: &[u8]) -> Result<ProviderPayload, String> {
    if data.len() < 4 {
        return Err("MRS 数据长度不足".into());
    }

    let decompressed = if data.starts_with(&ZSTD_MAGIC) {
        zstd::decode_all(data).map_err(|e| format!("zstd 解压 MRS 失败: {e}"))?
    } else if data.starts_with(&MRS_MAGIC) {
        data.to_vec()
    } else {
        // 尝试兜底用 zstd 解压
        match zstd::decode_all(data) {
            Ok(buf) if buf.starts_with(&MRS_MAGIC) => buf,
            _ => return Err("不是合法的 MRS 文件格式 (无效 Magic 标识)".into()),
        }
    };

    if decompressed.len() < 4 + 1 + 8 + 8 {
        return Err("解压后 MRS 数据头长度不足".into());
    }

    let mut cursor = 0;
    if decompressed[0..4] != MRS_MAGIC {
        return Err("无效的 MRS 魔数".into());
    }
    cursor += 4;

    let behavior = MrsBehavior::from_u8(decompressed[cursor])?;
    cursor += 1;

    let count = i64::from_be_bytes(
        decompressed[cursor..cursor + 8]
            .try_into()
            .map_err(|e| format!("{e}"))?,
    );
    cursor += 8;

    let extra_len = i64::from_be_bytes(
        decompressed[cursor..cursor + 8]
            .try_into()
            .map_err(|e| format!("{e}"))?,
    );
    cursor += 8;

    if extra_len < 0 {
        return Err("MRS extra 长度非法".into());
    }
    cursor += extra_len as usize;

    if cursor > decompressed.len() {
        return Err("MRS 载荷在读取 extra 字段后已越界".into());
    }

    let payload = &decompressed[cursor..];

    match behavior {
        MrsBehavior::Domain => {
            let (domains, suffixes) = parse_domain_set_bin(payload)?;
            let mut trie = DomainTrie::new();
            for d in domains {
                trie.insert_exact(&d);
            }
            for s in suffixes {
                trie.insert_suffix_all(&s);
            }
            Ok(ProviderPayload::Domain(Box::new(DomainSet {
                trie,
                keywords: Vec::new(),
            })))
        }
        MrsBehavior::IpCidr => {
            let mut builder = IpIntervalSetBuilder::new();
            parse_ipcidr_set_bin(payload, &mut builder)?;
            Ok(ProviderPayload::Ip(Box::new(builder.build())))
        }
        MrsBehavior::Classical => {
            // 对齐 mihomo 官方：暂无 classical mrs，若有则报错提示
            Err(format!(
                "MRS classical 格式当前未被生态正式采用 (规则数 {count})"
            ))
        }
    }
}

/// 解析 Mihomo DomainSetBin 结构
/// 返回 `(精确域名列表, 后缀域名列表)`
fn parse_domain_set_bin(data: &[u8]) -> Result<(Vec<String>, Vec<String>), String> {
    if data.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut cursor = 0;
    let version = data[cursor];
    cursor += 1;
    if version != 1 {
        return Err(format!("不支持的 DomainSetBin 版本: {version}"));
    }

    // leaves
    if cursor + 8 > data.len() {
        return Err("DomainSetBin leaves 长度不足".into());
    }
    let leaves_len = i64::from_be_bytes(data[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    if leaves_len < 0 {
        return Err("leaves_len 非法".into());
    }
    let leaves_count = leaves_len as usize;
    if cursor + leaves_count * 8 > data.len() {
        return Err("DomainSetBin leaves 数组截断".into());
    }
    let mut leaves = Vec::with_capacity(leaves_count);
    for _ in 0..leaves_count {
        leaves.push(u64::from_be_bytes(
            data[cursor..cursor + 8].try_into().unwrap(),
        ));
        cursor += 8;
    }

    // labelBitmap
    if cursor + 8 > data.len() {
        return Err("DomainSetBin labelBitmap 长度不足".into());
    }
    let bitmap_len = i64::from_be_bytes(data[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    if bitmap_len < 0 {
        return Err("bitmap_len 非法".into());
    }
    let bitmap_count = bitmap_len as usize;
    if cursor + bitmap_count * 8 > data.len() {
        return Err("DomainSetBin labelBitmap 数组截断".into());
    }
    let mut label_bitmap = Vec::with_capacity(bitmap_count);
    for _ in 0..bitmap_count {
        label_bitmap.push(u64::from_be_bytes(
            data[cursor..cursor + 8].try_into().unwrap(),
        ));
        cursor += 8;
    }

    // labels
    if cursor + 8 > data.len() {
        return Err("DomainSetBin labels 长度不足".into());
    }
    let labels_len = i64::from_be_bytes(data[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    if labels_len < 0 {
        return Err("labels_len 非法".into());
    }
    let labels_count = labels_len as usize;
    if cursor + labels_count > data.len() {
        return Err("DomainSetBin labels 数组截断".into());
    }
    let labels = &data[cursor..cursor + labels_count];

    // 从 Succinct Trie 提取出所有域名
    let keys = dump_succinct_keys(&leaves, &label_bitmap, labels);
    let mut exact_domains = Vec::new();
    let mut suffix_domains = Vec::new();

    for key in keys {
        // Mihomo 内部将域名倒序存储，若包含 '+' 后缀则表示通配/子域
        if let Some(prefix) = key.strip_suffix('+') {
            // 倒序恢复原域名
            let restored: String = prefix.chars().rev().collect();
            if !restored.is_empty() {
                suffix_domains.push(restored);
            }
        } else {
            let restored: String = key.chars().rev().collect();
            if !restored.is_empty() {
                exact_domains.push(restored);
            }
        }
    }

    Ok((exact_domains, suffix_domains))
}

/// 解析 Mihomo IpCidrSetBin 结构
fn parse_ipcidr_set_bin(data: &[u8], builder: &mut IpIntervalSetBuilder) -> Result<(), String> {
    if data.is_empty() {
        return Ok(());
    }
    let mut cursor = 0;
    let version = data[cursor];
    cursor += 1;
    if version != 1 {
        return Err(format!("不支持的 IpCidrSet 版本: {version}"));
    }

    if cursor + 8 > data.len() {
        return Err("IpCidrSet 长度不足".into());
    }
    let rr_len = i64::from_be_bytes(data[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    if rr_len < 0 {
        return Err("rr_len 非法".into());
    }

    let rr_count = rr_len as usize;
    let total_bytes = rr_count * 32;
    if cursor + total_bytes > data.len() {
        return Err("IpCidrSet 范围数据截断".into());
    }

    for _ in 0..rr_count {
        let from_raw: [u8; 16] = data[cursor..cursor + 16].try_into().unwrap();
        cursor += 16;
        let to_raw: [u8; 16] = data[cursor..cursor + 16].try_into().unwrap();
        cursor += 16;

        let from_ip = std::net::Ipv6Addr::from(from_raw);
        let to_ip = std::net::Ipv6Addr::from(to_raw);

        // 检测是否为 IPv4-mapped IPv6 地址 (::ffff:x.x.x.x)
        if let (Some(v4_from), Some(v4_to)) = (from_ip.to_ipv4_mapped(), to_ip.to_ipv4_mapped()) {
            builder.push_v4_range(u32::from(v4_from), u32::from(v4_to));
        } else {
            builder.push_v6_range(u128::from(from_ip), u128::from(to_ip));
        }
    }

    Ok(())
}

/// 从 Succinct Trie 的位图中提取所有有效键
pub fn dump_succinct_keys(leaves: &[u64], label_bitmap: &[u64], labels: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    let mut current_key = Vec::new();
    traverse_succinct(
        leaves,
        label_bitmap,
        labels,
        0,
        0,
        &mut current_key,
        &mut result,
        0,
    );
    result
}

#[allow(clippy::too_many_arguments)]
fn traverse_succinct(
    leaves: &[u64],
    label_bitmap: &[u64],
    labels: &[u8],
    node_id: usize,
    mut bm_idx: usize,
    current_key: &mut Vec<u8>,
    result: &mut Vec<String>,
    depth: usize,
) {
    if depth > 256 {
        return; // 防止异常环路
    }

    if get_bit(leaves, node_id) {
        if let Ok(s) = std::str::from_utf8(current_key) {
            result.push(s.to_string());
        }
    }

    loop {
        if get_bit(label_bitmap, bm_idx) {
            return;
        }
        if bm_idx < node_id || (bm_idx - node_id) >= labels.len() {
            return;
        }
        let next_label = labels[bm_idx - node_id];
        current_key.push(next_label);
        let next_node_id = count_zeros(label_bitmap, bm_idx + 1);
        let next_bm_idx = if next_node_id == 0 {
            0
        } else {
            select_ith_one(label_bitmap, next_node_id - 1) + 1
        };
        traverse_succinct(
            leaves,
            label_bitmap,
            labels,
            next_node_id,
            next_bm_idx,
            current_key,
            result,
            depth + 1,
        );
        current_key.pop();
        bm_idx += 1;
    }
}

#[inline(always)]
pub fn get_bit(bm: &[u64], i: usize) -> bool {
    let word = i >> 6;
    if word >= bm.len() {
        false
    } else {
        (bm[word] & (1u64 << (i & 63))) != 0
    }
}

/// 计算 label_bitmap 中在第 `i` 位之前的 0 的总个数 (不包含第 i 位)
pub fn count_zeros(bm: &[u64], i: usize) -> usize {
    let total_bits = i;
    let word = i >> 6;
    let mut ones = 0usize;

    for w in bm.iter().take(word.min(bm.len())) {
        ones += w.count_ones() as usize;
    }

    if word < bm.len() {
        let bit_offset = i & 63;
        if bit_offset > 0 {
            let mask = (1u64 << bit_offset) - 1;
            ones += (bm[word] & mask).count_ones() as usize;
        }
    }

    total_bits.saturating_sub(ones)
}

/// 找到位图中第 `target_one` (0-based) 个 1 的索引位置
pub fn select_ith_one(bm: &[u64], target_one: usize) -> usize {
    let mut rem = target_one;
    let mut base_idx = 0usize;

    for &word in bm {
        let ones = word.count_ones() as usize;
        if rem < ones {
            for b in 0..64 {
                if (word & (1u64 << b)) != 0 {
                    if rem == 0 {
                        return base_idx + b;
                    }
                    rem -= 1;
                }
            }
        } else {
            rem -= ones;
            base_idx += 64;
        }
    }

    base_idx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_zeros_and_select() {
        // "010010" -> bits: 0:0, 1:1, 2:0, 3:0, 4:1, 5:0
        let bm = vec![0b010010u64];
        assert_eq!(count_zeros(&bm, 4), 3); // 0, 2, 3 位是 0
        assert_eq!(select_ith_one(&bm, 0), 1); // 第 0 个 1 在 index 1
        assert_eq!(select_ith_one(&bm, 1), 4); // 第 1 个 1 在 index 4
    }

    #[test]
    fn test_mrs_domain_roundtrip() {
        // 构造一个模拟的 MRS Domain 二进制包
        let mut raw = Vec::new();
        raw.extend_from_slice(&MRS_MAGIC);
        raw.push(0); // Behavior: Domain
        raw.extend_from_slice(&2i64.to_be_bytes()); // Count: 2
        raw.extend_from_slice(&0i64.to_be_bytes()); // Extra: 0

        // DomainSet payload:
        let mut d_payload = Vec::new();
        d_payload.push(1); // Version: 1

        // 简易 single-node trie: "com.example+" (即 +.example.com)
        // leaves: 2 节点 (node 0, node 1)
        let leaves = [0b10u64];
        d_payload.extend_from_slice(&1i64.to_be_bytes());
        d_payload.extend_from_slice(&leaves[0].to_be_bytes());

        let label_bitmap = [0b110u64]; // bit 0: 'a', bit 1: end node 0, bit 2: end node 1
        d_payload.extend_from_slice(&1i64.to_be_bytes());
        d_payload.extend_from_slice(&label_bitmap[0].to_be_bytes());

        let labels = b"a";
        d_payload.extend_from_slice(&1i64.to_be_bytes());
        d_payload.extend_from_slice(labels);

        raw.extend_from_slice(&d_payload);

        let parsed = parse_mrs(&raw).expect("应当成功解析裸 MRS 字节流");
        if let ProviderPayload::Domain(d) = parsed {
            // key "a" 倒序仍然是 "a"
            assert!(d.matches("a"));
        } else {
            panic!("类型应当是 Domain");
        }
    }
}

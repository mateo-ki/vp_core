//! 反向标签压缩域名 trie：
//! - insert_suffix_all：自身 + 所有子域（DOMAIN-SUFFIX / "+.x" / geosite Root）
//! - insert_suffix_sub：仅子域（".x" 语义）
//! - insert_exact：仅自身（DOMAIN / geosite Full）
//! - insert_wildcard：mihomo 通配语法（rule-provider domain 行），`*` 恰好匹配一级标签
//!
//! 三种标记可共存于同一节点；哈希表索引子节点，插入与匹配均为 O(1)，启动构建零阻塞。

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitKind {
    Exact,
    SuffixAll,
    SuffixSub,
}

#[derive(Debug, Default, Clone)]
struct Node {
    children: HashMap<Box<str>, Node>,
    /// `*` 通配子节点（仅 insert_wildcard 产生）：匹配任意一级标签
    wild: Option<Box<Node>>,
    exact: bool,
    suffix_all: bool,
    suffix_sub: bool,
}

impl Node {
    fn merge(&mut self, other: Node) {
        if other.exact {
            self.exact = true;
        }
        if other.suffix_all {
            self.suffix_all = true;
        }
        if other.suffix_sub {
            self.suffix_sub = true;
        }
        if self.suffix_all {
            self.children.clear();
            self.children.shrink_to_fit();
            self.wild = None;
            return;
        }
        for (label, other_child) in other.children {
            self.children.entry(label).or_default().merge(other_child);
        }
        if let Some(w) = other.wild {
            self.wild.get_or_insert_default().merge(*w);
        }
    }

    /// 按反向标签下钻。存在 `*` 子节点时先走静态分支，走不通再回溯走通配
    /// （mihomo 同序：静态优先）；labels 克隆只复制游标，不分配。
    fn walk<'a>(&self, mut labels: impl Iterator<Item = &'a str> + Clone) -> Option<HitKind> {
        let mut node = self;
        while let Some(label) = labels.next() {
            // 即将下钻：本节点是任意后缀标记则命中（子域语义）
            if node.suffix_all {
                return Some(HitKind::SuffixAll);
            }
            if node.suffix_sub {
                return Some(HitKind::SuffixSub);
            }
            node = match node.wild.as_deref() {
                None => node.children.get(label)?,
                Some(wild) => {
                    let static_hit = node
                        .children
                        .get(label)
                        .and_then(|c| c.walk(labels.clone()));
                    if static_hit.is_some() {
                        return static_hit;
                    }
                    wild
                }
            };
        }
        if node.suffix_all {
            Some(HitKind::SuffixAll)
        } else if node.exact {
            Some(HitKind::Exact)
        } else {
            None
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct DomainTrie {
    root: Node,
    size: usize,
}

impl DomainTrie {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn merge(&mut self, other: DomainTrie) {
        self.size += other.size;
        self.root.merge(other.root);
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// 返回最深的可达节点（按反向标签）
    fn node_for(&self, domain: &str) -> Option<&Node> {
        let mut node = &self.root;
        for label in domain
            .to_ascii_lowercase()
            .rsplit('.')
            .filter(|l| !l.is_empty())
        {
            node = node.children.get(label)?;
        }
        Some(node)
    }

    /// wildcard=false 时 `*` 按字面标签存储（顶层 DOMAIN / DOMAIN-SUFFIX 不解析通配，与 mihomo 一致）
    fn insert(&mut self, domain: &str, wildcard: bool, f: impl FnOnce(&mut Node)) {
        let lowered = domain.to_ascii_lowercase();
        let mut node = &mut self.root;
        for label in lowered.rsplit('.').filter(|l| !l.is_empty()) {
            if node.suffix_all {
                // 父级根域已经是全子域匹配，子级规则完全冗余，直接剪枝跳过！
                return;
            }
            node = if wildcard && label == "*" {
                node.wild.get_or_insert_default().as_mut()
            } else {
                node.children.entry(label.into()).or_default()
            };
        }
        f(node);
        if node.suffix_all {
            // 当前节点是全子域匹配，清空所有子树节点，立即释放堆内存
            node.children.clear();
            node.children.shrink_to_fit();
            node.wild = None;
        }
        self.size += 1;
    }

    pub fn insert_exact(&mut self, domain: &str) {
        self.insert(domain, false, |n| n.exact = true);
    }

    pub fn insert_suffix_all(&mut self, domain: &str) {
        self.insert(domain, false, |n| n.suffix_all = true);
    }

    pub fn insert_suffix_sub(&mut self, domain: &str) {
        self.insert(domain, false, |n| n.suffix_sub = true);
    }

    /// mihomo 域名通配语法：`+.x` 自身及全部子域；`.x` 仅子域；`*` 恰好匹配一级标签，
    /// 可出现在任意位置（`*.x`、`a.*.x`、单独的 `*`）；其余为精确匹配。
    /// 没有域名部分的模式（`+.`、`.`）拒收并返回 false，否则会把整棵树变成全匹配。
    pub fn insert_wildcard(&mut self, pattern: &str) -> bool {
        let (domain, mark): (&str, fn(&mut Node)) = if let Some(rest) = pattern.strip_prefix("+.") {
            (rest, |n| n.suffix_all = true)
        } else if let Some(rest) = pattern.strip_prefix('.') {
            (rest, |n| n.suffix_sub = true)
        } else {
            (pattern, |n| n.exact = true)
        };
        if domain.split('.').all(str::is_empty) {
            return false;
        }
        self.insert(domain, true, mark);
        true
    }

    pub fn is_match(&self, domain: &str) -> bool {
        self.match_kind(domain).is_some()
    }

    pub fn is_exact_match(&self, domain: &str) -> bool {
        self.node_for(domain).is_some_and(|n| n.exact)
    }

    pub fn match_kind(&self, domain: &str) -> Option<HitKind> {
        let lowered = domain.to_ascii_lowercase();
        self.root
            .walk(lowered.rsplit('.').filter(|l| !l.is_empty()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_matches_self_and_sub() {
        let mut t = DomainTrie::new();
        t.insert_suffix_all("google.com");
        assert!(t.is_match("google.com"));
        assert!(t.is_match("www.google.com"));
        assert!(t.is_match("a.b.google.com"));
        assert!(!t.is_match("notgoogle.com"));
        assert!(!t.is_match("google.com.evil.io"));
    }

    #[test]
    fn exact_only_self() {
        let mut t = DomainTrie::new();
        t.insert_exact("example.com");
        assert!(t.is_match("example.com"));
        assert!(!t.is_match("www.example.com"));
    }

    #[test]
    fn coexisting_flags() {
        let mut t = DomainTrie::new();
        t.insert_exact("baidu.cn");
        t.insert_suffix_sub("baidu.cn");
        assert!(t.is_match("baidu.cn")); // exact
        assert!(t.is_match("a.baidu.cn")); // sub
        t.insert_suffix_all("baidu.cn");
        assert_eq!(t.match_kind("baidu.cn"), Some(HitKind::SuffixAll));
    }

    #[test]
    fn case_insensitive() {
        let mut t = DomainTrie::new();
        t.insert_suffix_all("GOOGLE.com");
        assert!(t.is_match("WWW.Google.COM"));
    }

    #[test]
    fn suffix_sub_excludes_self() {
        let mut t = DomainTrie::new();
        t.insert_suffix_sub("google.com");
        assert!(!t.is_match("google.com"));
        assert!(t.is_match("www.google.com"));
    }

    #[test]
    fn tld_rule() {
        let mut t = DomainTrie::new();
        t.insert_suffix_all("cn");
        assert!(t.is_match("baidu.cn"));
        assert!(t.is_match("x.y.cn"));
        assert!(!t.is_match("cn.com"));
    }

    #[test]
    fn wildcard_prefix_syntax_matches_mihomo() {
        let mut t = DomainTrie::new();
        t.insert_wildcard("+.google.com");
        t.insert_wildcard(".github.com");
        t.insert_wildcard("example.com");
        assert!(t.is_match("google.com") && t.is_match("a.b.google.com"));
        assert!(!t.is_match("github.com") && t.is_match("a.b.github.com"));
        assert!(t.is_match("example.com") && !t.is_match("www.example.com"));
    }

    #[test]
    fn wildcard_star_is_exactly_one_label() {
        let mut t = DomainTrie::new();
        t.insert_wildcard("*.qq.com");
        t.insert_wildcard("xbox.*.microsoft.com");
        t.insert_wildcard("*");
        assert!(t.is_match("a.qq.com"));
        assert!(!t.is_match("qq.com") && !t.is_match("a.b.qq.com"));
        assert!(t.is_match("xbox.live.microsoft.com"));
        assert!(!t.is_match("xbox.microsoft.com") && !t.is_match("xbox.a.b.microsoft.com"));
        // 单独的 `*` 只匹配不含点的主机名
        assert!(t.is_match("localhost") && !t.is_match("a.com"));
    }

    #[test]
    fn wildcard_backtracks_when_static_branch_dead_ends() {
        let mut t = DomainTrie::new();
        t.insert_exact("b.example.com");
        t.insert_wildcard("a.*.example.com");
        // 静态分支 b 存在但下面没有 a：必须回溯到 `*` 分支
        assert!(t.is_match("a.b.example.com"));
        assert!(t.is_match("b.example.com"));
        assert!(!t.is_match("c.b.example.com"));
    }

    #[test]
    fn star_is_literal_outside_wildcard_api() {
        // 顶层 DOMAIN-SUFFIX 不解析通配（与 mihomo 一致）
        let mut t = DomainTrie::new();
        t.insert_suffix_all("*.example.com");
        assert!(!t.is_match("a.example.com"));
    }

    #[test]
    fn wildcard_rejects_patterns_without_domain() {
        let mut t = DomainTrie::new();
        assert!(!t.insert_wildcard("+."));
        assert!(!t.insert_wildcard("."));
        assert!(t.is_empty());
        assert!(!t.is_match("anything.com"));
    }

    #[test]
    fn merge_keeps_wildcard_children() {
        let mut a = DomainTrie::new();
        a.insert_exact("x.com");
        let mut b = DomainTrie::new();
        b.insert_wildcard("*.y.com");
        a.merge(b);
        assert!(a.is_match("x.com") && a.is_match("m.y.com"));
    }
}

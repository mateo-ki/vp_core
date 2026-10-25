//! 反向标签压缩域名 trie：
//! - insert_suffix_all：自身 + 所有子域（DOMAIN-SUFFIX / "+.x" / geosite Root）
//! - insert_suffix_sub：仅子域（".x" 语义）
//! - insert_exact：仅自身（DOMAIN / geosite Full）
//! 三种标记可共存于同一节点；子节点按标签排序，查询二分，热路径零分配。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitKind {
    Exact,
    SuffixAll,
    SuffixSub,
}

#[derive(Debug, Default)]
struct Node {
    children: Vec<(Box<str>, Node)>,
    exact: bool,
    suffix_all: bool,
    suffix_sub: bool,
}

#[derive(Debug, Default)]
pub struct DomainTrie {
    root: Node,
    size: usize,
}

impl DomainTrie {
    pub fn new() -> Self {
        Self::default()
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
            let i = node
                .children
                .binary_search_by(|(k, _)| (**k).as_bytes().cmp(label.as_bytes()))
                .ok()?;
            node = &node.children[i].1;
        }
        Some(node)
    }

    fn insert(&mut self, domain: &str, f: impl FnOnce(&mut Node)) {
        let lowered = domain.to_ascii_lowercase();
        let mut node = &mut self.root;
        for label in lowered.rsplit('.').filter(|l| !l.is_empty()) {
            let i = match node
                .children
                .binary_search_by(|(k, _)| (**k).as_bytes().cmp(label.as_bytes()))
            {
                Ok(i) => i,
                Err(i) => {
                    node.children.insert(i, (label.into(), Node::default()));
                    i
                }
            };
            node = &mut node.children[i].1;
        }
        f(node);
        self.size += 1;
    }

    pub fn insert_exact(&mut self, domain: &str) {
        self.insert(domain, |n| n.exact = true);
    }

    pub fn insert_suffix_all(&mut self, domain: &str) {
        self.insert(domain, |n| n.suffix_all = true);
    }

    pub fn insert_suffix_sub(&mut self, domain: &str) {
        self.insert(domain, |n| n.suffix_sub = true);
    }

    pub fn is_match(&self, domain: &str) -> bool {
        self.match_kind(domain).is_some()
    }

    pub fn is_exact_match(&self, domain: &str) -> bool {
        self.node_for(domain).is_some_and(|n| n.exact)
    }

    pub fn match_kind(&self, domain: &str) -> Option<HitKind> {
        let mut node = &self.root;
        for label in domain
            .to_ascii_lowercase()
            .rsplit('.')
            .filter(|l| !l.is_empty())
        {
            // 即将下钻：本节点是任意后缀标记则命中（子域语义）
            if node.suffix_all {
                return Some(HitKind::SuffixAll);
            }
            if node.suffix_sub {
                return Some(HitKind::SuffixSub);
            }
            let i = node
                .children
                .binary_search_by(|(k, _)| (**k).as_bytes().cmp(label.as_bytes()))
                .ok()?;
            node = &node.children[i].1;
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
}

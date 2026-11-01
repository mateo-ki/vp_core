//! 多用户认证、流量配额管控与 QoS 限速状态管理 (User Accounting)

use crate::rate_limit::{BandwidthLimiter, BrutalPacer};
use sha2::{Digest, Sha224};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

fn sha224_hex(s: &str) -> String {
    let mut hasher = Sha224::new();
    hasher.update(s.as_bytes());
    let res = hasher.finalize();
    res.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_uuid_bytes(s: &str) -> Option<[u8; 16]> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// 用户账户及状态
#[derive(Debug)]
pub struct UserAccount {
    /// 用户标识名
    pub username: Arc<str>,
    /// 用户凭据（密码或 UUID）
    pub secret: Arc<str>,
    /// 已用上行流量（字节）
    pub upload: AtomicU64,
    /// 已用下行流量（字节）
    pub download: AtomicU64,
    /// 总流量配额限制（字节，达到后熔断；None 为不限）
    pub quota_bytes: Option<u64>,
    /// 当前活跃连接数
    pub active_conns: AtomicU32,
    /// 专属带宽限速器（QoS）
    pub limiter: Option<Arc<BandwidthLimiter>>,
    /// Brutal 恒速发包器
    pub brutal_pacer: Option<Arc<BrutalPacer>>,
}

impl UserAccount {
    pub fn new(
        username: impl Into<Arc<str>>,
        secret: impl Into<Arc<str>>,
        quota_bytes: Option<u64>,
        limiter: Option<Arc<BandwidthLimiter>>,
    ) -> Self {
        Self {
            username: username.into(),
            secret: secret.into(),
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            quota_bytes,
            active_conns: AtomicU32::new(0),
            limiter,
            brutal_pacer: None,
        }
    }

    pub fn with_brutal(mut self, brutal: Option<Arc<BrutalPacer>>) -> Self {
        self.brutal_pacer = brutal;
        self
    }

    /// 检查流量是否已耗尽
    pub fn is_quota_exceeded(&self) -> bool {
        if let Some(quota) = self.quota_bytes {
            self.upload.load(Ordering::Relaxed) + self.download.load(Ordering::Relaxed) >= quota
        } else {
            false
        }
    }

    /// 累加上行流量
    pub fn add_up(&self, bytes: u64) {
        self.upload.fetch_add(bytes, Ordering::Relaxed);
    }

    /// 累加下行流量
    pub fn add_down(&self, bytes: u64) {
        self.download.fetch_add(bytes, Ordering::Relaxed);
    }

    /// 进入活跃连接
    pub fn conn_open(&self) {
        self.active_conns.fetch_add(1, Ordering::Relaxed);
    }

    /// 退出活跃连接
    pub fn conn_close(&self) {
        self.active_conns.fetch_sub(1, Ordering::Relaxed);
    }

    /// 重置流量计数
    pub fn reset_traffic(&self) {
        self.upload.store(0, Ordering::Relaxed);
        self.download.store(0, Ordering::Relaxed);
    }

    /// 账户快照
    pub fn snapshot(&self) -> UserSnapshot {
        UserSnapshot {
            username: self.username.to_string(),
            upload: self.upload.load(Ordering::Relaxed),
            download: self.download.load(Ordering::Relaxed),
            quota_bytes: self.quota_bytes,
            active_conns: self.active_conns.load(Ordering::Relaxed),
            quota_exceeded: self.is_quota_exceeded(),
        }
    }
}

/// 用户状态快照
#[derive(Debug, Clone, serde::Serialize)]
pub struct UserSnapshot {
    pub username: String,
    pub upload: u64,
    pub download: u64,
    pub quota_bytes: Option<u64>,
    pub active_conns: u32,
    pub quota_exceeded: bool,
}

/// 入站监听器多用户管理器（线程安全容器）
#[derive(Debug, Default)]
pub struct UserManager {
    users_by_secret: std::sync::RwLock<HashMap<String, Arc<UserAccount>>>,
    users_by_name: std::sync::RwLock<HashMap<String, Arc<UserAccount>>>,
    users_by_trojan_hex: std::sync::RwLock<HashMap<String, Arc<UserAccount>>>,
    users_by_uuid: std::sync::RwLock<HashMap<[u8; 16], Arc<UserAccount>>>,
}

impl UserManager {
    pub fn new() -> Self {
        Self {
            users_by_secret: std::sync::RwLock::new(HashMap::new()),
            users_by_name: std::sync::RwLock::new(HashMap::new()),
            users_by_trojan_hex: std::sync::RwLock::new(HashMap::new()),
            users_by_uuid: std::sync::RwLock::new(HashMap::new()),
        }
    }

    pub fn add_user(&self, user: Arc<UserAccount>) {
        self.users_by_secret
            .write()
            .unwrap()
            .insert(user.secret.to_string(), user.clone());
        self.users_by_name
            .write()
            .unwrap()
            .insert(user.username.to_string(), user.clone());
        let hex = sha224_hex(&user.secret);
        self.users_by_trojan_hex
            .write()
            .unwrap()
            .insert(hex, user.clone());
        if let Some(uuid) = parse_uuid_bytes(&user.secret) {
            self.users_by_uuid.write().unwrap().insert(uuid, user);
        }
    }

    pub fn remove_user(&self, target: &str) -> Option<Arc<UserAccount>> {
        let mut by_sec = self.users_by_secret.write().unwrap();
        let mut by_name = self.users_by_name.write().unwrap();
        let mut by_trojan = self.users_by_trojan_hex.write().unwrap();
        let mut by_uuid = self.users_by_uuid.write().unwrap();

        let user = if let Some(user) = by_sec.remove(target) {
            by_name.remove(&*user.username);
            Some(user)
        } else if let Some(user) = by_name.remove(target) {
            by_sec.remove(&*user.secret);
            Some(user)
        } else {
            None
        };

        if let Some(ref u) = user {
            by_trojan.remove(&sha224_hex(&u.secret));
            if let Some(uuid) = parse_uuid_bytes(&u.secret) {
                by_uuid.remove(&uuid);
            }
        }
        user
    }

    pub fn get_user_by_target(&self, target: &str) -> Option<Arc<UserAccount>> {
        if let Some(u) = self.users_by_name.read().unwrap().get(target) {
            return Some(u.clone());
        }
        if let Some(u) = self.users_by_secret.read().unwrap().get(target) {
            return Some(u.clone());
        }
        None
    }

    pub fn reset_traffic(&self, target: &str) -> Option<Arc<UserAccount>> {
        let user = self.get_user_by_target(target)?;
        user.reset_traffic();
        Some(user)
    }

    /// 凭据认证并检查配额
    pub fn authenticate(&self, secret: &str) -> Option<Arc<UserAccount>> {
        let user = self.users_by_secret.read().unwrap().get(secret)?.clone();
        if user.is_quota_exceeded() {
            tracing::warn!(user = %user.username, "用户配额已超限，拒绝连接");
            return None;
        }
        Some(user)
    }

    /// 根据 SHA-224 Hex 凭据认证 Trojan 用户并检查配额
    pub fn authenticate_trojan_hex(&self, hex: &str) -> Option<Arc<UserAccount>> {
        let user = self.users_by_trojan_hex.read().unwrap().get(hex)?.clone();
        if user.is_quota_exceeded() {
            tracing::warn!(user = %user.username, "Trojan 用户配额已超限，拒绝连接");
            return None;
        }
        Some(user)
    }

    pub fn get_user_by_trojan_hex(&self, hex: &str) -> Option<Arc<UserAccount>> {
        self.users_by_trojan_hex.read().unwrap().get(hex).cloned()
    }

    /// 根据 16 字节 UUID 凭据认证 VLESS 用户并检查配额
    pub fn authenticate_uuid(&self, uuid: &[u8; 16]) -> Option<Arc<UserAccount>> {
        let user = self.users_by_uuid.read().unwrap().get(uuid)?.clone();
        if user.is_quota_exceeded() {
            tracing::warn!(user = %user.username, "VLESS 用户配额已超限，拒绝连接");
            return None;
        }
        Some(user)
    }

    pub fn get_user_by_uuid(&self, uuid: &[u8; 16]) -> Option<Arc<UserAccount>> {
        self.users_by_uuid.read().unwrap().get(uuid).cloned()
    }

    pub fn get_user(&self, secret: &str) -> Option<Arc<UserAccount>> {
        self.users_by_secret.read().unwrap().get(secret).cloned()
    }

    pub fn is_empty(&self) -> bool {
        self.users_by_secret.read().unwrap().is_empty()
    }

    pub fn all_users(&self) -> Vec<Arc<UserAccount>> {
        self.users_by_name
            .read()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_quota_accounting() {
        let user = Arc::new(UserAccount::new("alice", "secret123", Some(1000), None));
        let mgr = UserManager::new();
        mgr.add_user(user.clone());

        assert!(mgr.authenticate("secret123").is_some());
        assert!(mgr.authenticate("wrong").is_none());

        user.add_up(600);
        assert!(!user.is_quota_exceeded());
        assert!(mgr.authenticate("secret123").is_some());

        user.add_down(400);
        assert!(user.is_quota_exceeded());
        // 配额超额后认证拒绝
        assert!(mgr.authenticate("secret123").is_none());

        // 重置流量后重新允许
        mgr.reset_traffic("alice");
        assert!(!user.is_quota_exceeded());
        assert!(mgr.authenticate("secret123").is_some());

        // 移除用户
        assert!(mgr.remove_user("alice").is_some());
        assert!(mgr.authenticate("secret123").is_none());
    }
}

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// 1 SUI = 10^9 MIST, 1 SUI = 10000 chips → 1 chip = 10^5 MIST
pub const MIST_PER_CHIP: u64 = 100_000;

/// 将 MIST 余额转换为筹码数量（1 SUI = 10000 chips）
pub fn chips_from_mist(mist: u64) -> i64 {
    (mist / MIST_PER_CHIP) as i64
}

/// 将筹码数量转换为 MIST（用于显示兑换花费）
pub fn mist_from_chips(chips: i64) -> u64 {
    if chips <= 0 {
        return 0;
    }
    (chips as u64) * MIST_PER_CHIP
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub name: String,
    pub address: String,
    pub created: String,
    /// 已锁定筹码（入座时扣除，离开时返还）。实际余额由 SUI 链上余额决定。
    pub locked_chips: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserResponse {
    #[serde(rename = "_id")]
    pub id: String,
    pub name: String,
    pub address: String,
    /// 可用筹码 = SUI 余额 * 10000 - locked_chips
    pub chips_amount: i64,
    /// SUI 链上余额（MIST）
    pub sui_balance: u64,
    pub created: String,
}

#[derive(Clone)]
pub struct Database {
    users: Arc<RwLock<HashMap<String, User>>>,
}

impl Database {
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn find_user_by_id(&self, id: &str) -> Option<User> {
        self.users.read().await.get(id).cloned()
    }

    pub async fn find_user_by_address(&self, address: &str) -> Option<User> {
        self.users.read().await.values().find(|u| u.address == address).cloned()
    }

    pub async fn save_user(&self, user: &User) -> Result<(), String> {
        let mut users = self.users.write().await;
        users.insert(user.id.clone(), user.clone());
        Ok(())
    }

    pub async fn update_address(&self, id: &str, address: &str) -> bool {
        let mut users = self.users.write().await;
        if let Some(user) = users.get_mut(id) {
            user.address = address.to_string();
            true
        } else {
            false
        }
    }

    /// 锁定筹码（入座时调用）
    pub async fn lock_chips(&self, id: &str, amount: i64) -> Option<User> {
        let mut users = self.users.write().await;
        if let Some(user) = users.get_mut(id) {
            user.locked_chips += amount;
            return Some(user.clone());
        }
        None
    }

    /// 解锁筹码（离开时调用）
    pub async fn unlock_chips(&self, id: &str, amount: i64) -> Option<User> {
        let mut users = self.users.write().await;
        if let Some(user) = users.get_mut(id) {
            user.locked_chips = (user.locked_chips - amount).max(0);
            return Some(user.clone());
        }
        None
    }

    pub async fn get_locked_chips(&self, id: &str) -> i64 {
        self.users.read().await.get(id).map(|u| u.locked_chips).unwrap_or(0)
    }
}

impl Default for Database {
    fn default() -> Self {
        Self::new()
    }
}

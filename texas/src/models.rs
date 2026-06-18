use mongodb::{Collection, Database as MongoDatabase};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id")]
    pub id: String,
    pub name: String,
    pub email: String,
    pub password: String,
    pub chips_amount: i64,
    #[serde(rename = "type", default)]
    pub user_type: i32,
    pub created: String,
    pub address:String,
    #[serde(default)]
    pub last_free_chips_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserResponse {
    #[serde(rename = "_id")]
    pub id: String,
    pub name: String,
    pub email: String,
    pub chips_amount: i64,
    #[serde(rename = "type")]
    pub user_type: i32,
    pub created: String,
}

#[derive(Clone)]
pub struct Database {
    users: Arc<Collection<User>>,
}

impl Database {
    pub async fn new(mongo_db: &MongoDatabase) -> Self {
        let users = mongo_db.collection::<User>("users");
        Self { users: Arc::new(users) }
    }

    pub async fn find_user_by_id(&self, id: &str) -> Option<User> {
        self.users
            .find_one(mongodb::bson::doc! {"_id": id})
            .await
            .ok()
            .flatten()
    }



    pub async fn update_address(&self, id: &str, address: &str) -> bool {
        self.users
            .update_one(
                mongodb::bson::doc! {"_id": id},
                mongodb::bson::doc! {"$set": {"address": address}},
            )
            .await
            .is_ok()
    }

    pub async fn find_user_by_email(&self, email: &str) -> Option<User> {
        match self.users
            .find_one(mongodb::bson::doc! {"email": email})
            .await
        {
            Ok(opt) => opt,
            Err(e) => {
                tracing::error!("Failed to find user by email {}: {}", email, e);
                None
            }
        }
    }

    pub async fn find_user_by_name(&self, name: &str) -> Option<User> {
        self.users
            .find_one(mongodb::bson::doc! {"name": name})
            .await
            .ok()
            .flatten()
    }


    pub async fn save_user(&self, user: &User) -> mongodb::error::Result<mongodb::results::InsertOneResult> {
        self.users.insert_one(user).await
    }

    pub async fn update_chips(&self, id: &str, amount: i64) -> Option<User> {
        let result = self.users
            .update_one(
                mongodb::bson::doc! {"_id": id},
                mongodb::bson::doc! {"$inc": {"chips_amount": amount}},
            )
            .await;
        match result {
            Ok(_) => self.find_user_by_id(id).await,
            Err(e) => {
                tracing::error!("Failed to update chips for {}: {}", id, e);
                None
            }
        }
    }

    pub async fn set_chips(&self, id: &str, amount: i64) -> Option<User> {
        let result = self.users
            .update_one(
                mongodb::bson::doc! {"_id": id},
                mongodb::bson::doc! {"$set": {"chips_amount": amount}},
            )
            .await;
        match result {
            Ok(_) => self.find_user_by_id(id).await,
            Err(e) => {
                tracing::error!("Failed to set chips for {}: {}", id, e);
                None
            }
        }
    }

    pub async fn set_chips_with_cooldown(&self, id: &str, amount: i64) -> Option<User> {
        let now = chrono::Utc::now();
        let one_hour_ago = now - chrono::Duration::hours(1);
        let now_str = now.to_rfc3339();
        let one_hour_ago_str = one_hour_ago.to_rfc3339();

        // F12: 原子操作 —— 在 filter 中加入冷却时间检查，避免 check-then-update 竞态
        let filter = mongodb::bson::doc! {
            "_id": id,
            "$or": [
                {"last_free_chips_at": {"$exists": false}},
                {"last_free_chips_at": null},
                {"last_free_chips_at": {"$lt": &one_hour_ago_str}}
            ]
        };
        let update = mongodb::bson::doc! {
            "$set": {"chips_amount": amount, "last_free_chips_at": &now_str}
        };

        let result = self.users
            .update_one(filter, update)
            .await;
        match result {
            Ok(update_result) if update_result.matched_count > 0 => {
                // 冷却已过，更新成功，重新查询返回最新用户
                self.find_user_by_id(id).await
            }
            Ok(_) => {
                // matched_count == 0，冷却未过
                tracing::debug!("Cooldown not elapsed for {}", id);
                None
            }
            Err(e) => {
                tracing::error!("Failed to set chips for {}: {}", id, e);
                None
            }
        }
    }
}

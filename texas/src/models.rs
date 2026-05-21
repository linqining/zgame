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
    pub pk_hex:String,
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

    pub async fn update_user_pk(&self, id: &str, pk_hex: &str) -> bool {
        self.users
            .update_one(
                mongodb::bson::doc! {"_id": id},
                mongodb::bson::doc! {"$set": {"pk_hex": pk_hex}},
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

    pub async fn find_user_by_pk_hex(&self, pk_hex: &str) -> Option<User> {
        self.users
            .find_one(mongodb::bson::doc! {"pk_hex": pk_hex})
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
}

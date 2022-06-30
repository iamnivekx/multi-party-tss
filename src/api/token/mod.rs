use rocket::serde::json::{json, Value};
use uuid::Uuid;

#[post("/token")]
pub async fn gen_token() -> Value {
    json!({
        "token": Uuid::new_v4().to_string(),
    })
}

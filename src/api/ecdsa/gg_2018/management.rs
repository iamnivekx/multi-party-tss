use rocket::http::Status;
use rocket::response::status;
use rocket::serde::json::{json, Json, Value};
use rocket::State;

use std::collections::HashMap;
use std::sync::RwLock;

use crate::api::ecdsa::adapter::{get_store_adapter, Entry, Index, PartySignupReq};

#[post("/get-entry", format = "json", data = "<request>")]
pub async fn get_entry(
    state: &State<RwLock<HashMap<String, String>>>,
    request: Json<Index>,
) -> status::Custom<Value> {
    let key = request.0.key;
    let adapter = get_store_adapter(&state);
    let result = adapter.get_entry(&key).await;
    match result {
        Ok(v) => status::Custom(Status::Ok, json!(v)),
        Err(_) => status::Custom(
            Status::BadRequest,
            json!({
                "status": "error",
                "reason":  "get signup party failed",
            }),
        ),
    }
}

#[post("/set-entry", format = "json", data = "<request>")]
pub async fn set_entry(
    state: &State<RwLock<HashMap<String, String>>>,
    request: Json<Entry>,
) -> (Status, Value) {
    let entry = request.0;
    let adapter = get_store_adapter(&state);
    let result = adapter.set_entry(&entry).await;
    match result {
        Ok(v) => (Status::Ok, json!(v)),
        Err(_) => (
            Status::BadRequest,
            json!({
                "status": "error",
                "reason":  "set entry failed",
            }),
        ),
    }
}

#[post("/signup-party", format = "json", data = "<request>")]
pub async fn signup_party(
    state: &State<RwLock<HashMap<String, String>>>,
    request: Json<PartySignupReq<'_>>,
) -> (Status, Value) {
    let num = request.num;
    let room_id = request.key.to_string();
    let adapter = get_store_adapter(&state);
    let party_signup = adapter.get_party_signup(num, &room_id).await;
    match party_signup {
        Ok(v) => (Status::Ok, json!(v)),
        Err(_) => (
            Status::BadRequest,
            json!({
                "status": "error",
                "reason":  "signup party failed",
            }),
        ),
    }
}

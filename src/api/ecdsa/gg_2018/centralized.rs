use rocket::http::Status;
use rocket::response::status;
use rocket::serde::json::{json, Json, Value};
use rocket::serde::{Deserialize, Serialize};

use std::collections::HashMap;
use std::sync::RwLock;

use futures::future;
use uuid::Uuid;

use crate::ecdsa::gg_2018::common::party_key_pub_hex;
use crate::ecdsa::gg_2018::keygen::keygen;
use crate::ecdsa::gg_2018::sign::sign;

use crate::api::ecdsa::gg_2018::adapter::get_adapter;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct GenKeysReq {
    parties: u16,
    threshold: u16,
}
#[post("/keys", data = "<request>")]
pub async fn gen_keys(request: Json<GenKeysReq>) -> Value {
    let parties = request.parties;
    let threshold = request.threshold;
    let room_id = Uuid::new_v4().to_string();
    let db: HashMap<String, String> = HashMap::new();
    let store = RwLock::new(db);
    let adapter = get_adapter(&store);
    let futures = (0..parties).map(|_| keygen(parties, threshold, &room_id, &adapter));
    let keys = future::join_all(futures).await;

    let pub_hex = party_key_pub_hex(&keys[0]);
    json!({
        "keys": keys,
        "pub_key": pub_hex,
        "threshold": threshold,
        "parties": parties,
    })
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SignReq<'r> {
    keys: Vec<String>,
    message: &'r str,
    parties: u16,
    threshold: u16,
}
#[post("/sign", data = "<request>")]
pub async fn signatures(request: Json<SignReq<'_>>) -> status::Custom<Value> {
    let parties = request.parties;
    let threshold = request.threshold;
    let threshold_usize = usize::from(threshold);
    let keys = request
        .keys
        .clone()
        .into_iter()
        .map(|v| v.to_string())
        .collect::<Vec<String>>();
    let message = request.message.to_string();
    let room_id = Uuid::new_v4().to_string();
    let db: HashMap<String, String> = HashMap::new();
    let store = RwLock::new(db);
    let adapter = get_adapter(&store);
    if keys.len() < threshold_usize {
        return status::Custom(
            Status::BadRequest,
            json!({
                "status": "error",
                "reason":  format!("should provide {} keys", threshold_usize + 1),
            }),
        );
    }

    let futures = keys
        .iter()
        .map(|key| sign(parties, threshold, key, &room_id, &message, &adapter));
    let signatures = future::join_all(futures).await;
    status::Custom(
        Status::Ok,
        json!({
            "signatures": signatures,
        }),
    )
}

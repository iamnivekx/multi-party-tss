use rocket::http::Status;
use rocket::response::status;
use rocket::serde::json::{json, Json, Value};
use rocket::serde::{Deserialize, Serialize};
use rocket::State;

use std::collections::HashMap;
use std::sync::RwLock;

use crate::ecdsa::gg_2018::common::party_key_pub_hex;
use crate::ecdsa::gg_2018::keygen::keygen_key;
use crate::ecdsa::gg_2018::sign::sign;

use crate::api::ecdsa::adapter::get_adapter;
use crate::api::from_request::token::Token;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct KeyGenReq {
    parties: u16,
    threshold: u16,
}
#[post("/keys", data = "<request>")]
pub async fn gen_key(
    token: Token,
    store: &State<RwLock<HashMap<String, String>>>,
    request: Json<KeyGenReq>,
) -> status::Custom<Value> {
    let room_id = token.0.to_string();
    let parties = request.parties;
    let threshold = request.threshold;
    let adapter = get_adapter(store);
    let gen_key = keygen_key(parties, threshold, &room_id, &adapter).await;
    let pub_hex = party_key_pub_hex(&gen_key);
    status::Custom(
        Status::Ok,
        json!({
            "key": gen_key,
            "pub_key": pub_hex,
            "threshold": threshold,
            "parties": parties,
        }),
    )
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct KeySignReq<'r> {
    key: String,
    message: &'r str,
    parties: u16,
    threshold: u16,
}
#[post("/sign", data = "<request>")]
pub async fn sign_message(
    token: Token,
    store: &State<RwLock<HashMap<String, String>>>,
    request: Json<KeySignReq<'_>>,
) -> status::Custom<Value> {
    let room_id = token.0.to_string();
    let key = request.key.to_string();
    let parties = request.parties;
    let threshold = request.threshold;
    let message = request.message.to_string();
    let adapter = get_adapter(store);
    let signature = sign(parties, threshold, &key, &room_id, &message, &adapter).await;
    status::Custom(
        Status::Ok,
        json!({
            "signature": signature,
        }),
    )
}

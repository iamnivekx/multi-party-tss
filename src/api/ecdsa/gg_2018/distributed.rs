use anyhow::anyhow;
use rocket::serde::json::{json, Json, Value};
use rocket::serde::{Deserialize, Serialize};
use rocket::State;
use std::collections::HashMap;
use std::sync::RwLock;

use crate::api::{
    ecdsa::gg_2018::adapter::get_adapter, from_request::token::Token, response::error::ApiError,
};
use crate::config::Config;
use crate::ecdsa::gg_2018::{common::party_key_pub_hex, keygen::keygen, sign::sign};

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct KeyGenReq {
    parties: u16,
    threshold: u16,
}
#[post("/keys", data = "<request>")]
pub async fn gen_key(
    token: Token,
    store: &State<RwLock<HashMap<String, String>>>,
    config: &State<Config>,
    request: Json<KeyGenReq>,
) -> Result<Value, ApiError> {
    let room_id = token.0.to_string();
    let parties = request.parties;
    let threshold = request.threshold;
    let addr = config.gg18_communicate_endpoint.clone();
    let addr = addr.ok_or(ApiError::BadRequest(anyhow!(
        "please set the gg18_communicate_endpoint."
    )))?;
    let adapter = get_adapter(addr.as_str(), store);
    let gen_key = keygen(parties, threshold, &room_id, &adapter).await;
    let pub_hex = party_key_pub_hex(&gen_key);
    Ok(json!({
        "key": gen_key,
        "pub_key": pub_hex,
        "threshold": threshold,
        "parties": parties,
    }))
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
    config: &State<Config>,
    request: Json<KeySignReq<'_>>,
) -> Result<Value, ApiError> {
    let room_id = token.0.to_string();
    let key = request.key.to_string();
    let parties = request.parties;
    let threshold = request.threshold;
    let message = request.message.to_string();
    let addr = config.gg18_communicate_endpoint.clone();

    let addr = addr.ok_or(ApiError::BadRequest(anyhow!(
        "please set the gg18_communicate_endpoint."
    )))?;
    let adapter = get_adapter(addr.as_str(), store);
    let signature = sign(parties, threshold, &key, &room_id, &message, &adapter).await;
    Ok(json!({
        "signature": signature,
    }))
}

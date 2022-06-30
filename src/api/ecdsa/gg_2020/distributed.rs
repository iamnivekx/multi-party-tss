use anyhow::Context;
use rocket::serde::json::{json, Json, Value};
use rocket::serde::{Deserialize, Serialize};
use rocket::State;

use crate::api::from_request::token::Token;
use crate::api::response::error::ApiError;
use crate::config::Config;
use crate::ecdsa::gg_2020::{keygen::keygen, sign::sign};

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct KeyGenReq {
    index: u16,
    parties: u16,
    threshold: u16,
}
#[post("/keys", data = "<request>")]
pub async fn gen_key(
    token: Token,
    request: Json<KeyGenReq>,
    config: &State<Config>,
) -> Result<Value, ApiError> {
    let addr = config
        .gg20_communicate_endpoint()
        .map_err(|e| ApiError::BadRequest(e.into()))?;
    let address = surf::Url::parse(addr.as_str()).unwrap();
    let room_id = token.0.to_string();
    let index = request.index;
    let parties = request.parties;
    let threshold = request.threshold;
    let (public_key, local_key) = keygen(index, threshold, parties, address, &room_id)
        .await
        .context("failed to generate key")?;

    Ok(json!({
        "key": local_key,
        "pub_key": public_key,
        "threshold": threshold,
        "parties": parties,
    }))
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct KeySignReq<'r> {
    key: String,
    message: &'r str,
    parties: Vec<u16>,
}
#[post("/sign", data = "<request>")]
pub async fn sign_message(
    token: Token,
    request: Json<KeySignReq<'_>>,
    config: &State<Config>,
) -> Result<Value, ApiError> {
    let addr = config
        .gg20_communicate_endpoint()
        .map_err(|e| ApiError::BadRequest(e.into()))?;
    let address = surf::Url::parse(addr.as_str()).unwrap();
    let room_id = token.0.to_string();
    let key = request.key.as_str();
    let parties = request.parties.clone();
    let message = request.message;
    let signature = sign(key, parties.clone(), message, address, &room_id).await?;
    Ok(json!({
        "signature": signature,
        "parties": parties,
    }))
}

use anyhow::Context;
use lazy_static::lazy_static;

use rocket::serde::json::{json, Json, Value};
use rocket::serde::{Deserialize, Serialize};
use std::env;
use std::result::Result;

use crate::api::from_request::token::Token;
use crate::api::response::error::ApiError;
use crate::ecdsa::gg_2020::{keygen::keygen, sign::sign};
use crate::lib::establish_connection;
use crate::models::keys::Key;

lazy_static! {
    pub static ref COMMUNICATE_API: String = {
        match env::var("COMMUNICATE_API") {
            Result::Ok(v) => v,
            Result::Err(_) => "".to_string(),
        }
    };
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct KeyGenReq {
    index: u16,
    parties: u16,
    threshold: u16,
}
#[post("/keys", data = "<request>")]
pub async fn key_gen_key(token: Token, request: Json<KeyGenReq>) -> Result<Value, ApiError> {
    let input = format!("{}", *COMMUNICATE_API);
    let address = surf::Url::parse(input.as_str()).context("failed to parse url")?;
    let room_id = token.0.to_string();
    let index = request.index;
    let parties = request.parties;
    let threshold = request.threshold;
    let (pub_key, local_key) = keygen(
        index.clone(),
        threshold.clone(),
        parties.clone(),
        address,
        &room_id,
    )
    .await
    .context("failed to generate key")
    .map_err(|e| ApiError::Unknown(e))?;

    let conn = establish_connection().map_err(|e| ApiError::Unknown(e))?;

    let _id = Key::create_key(
        &conn,
        i32::from(index),
        i32::from(threshold.clone()),
        i32::from(parties.clone()),
        pub_key.clone().as_str(),
        local_key.as_str().clone(),
    )
    .context("failed to store key")?;

    Ok(json!({
        "key": local_key,
        "pub_key": pub_key,
        "index": index,
        "threshold": threshold,
        "parties": parties,
    }))
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PubKeySignReq<'r> {
    index: Option<u16>,
    pub_key: &'r str,
    message: &'r str,
    parties: Vec<u16>,
}
#[post("/sign", data = "<request>")]
pub async fn key_sign_message(
    token: Token,
    request: Json<PubKeySignReq<'_>>,
) -> Result<Value, ApiError> {
    let input = format!("{}", *COMMUNICATE_API);
    let address = surf::Url::parse(input.as_str()).unwrap();
    let room_id = token.0.to_string();
    let index = request.index;
    let conn = establish_connection()?;
    let pub_key = request.pub_key.to_string();
    let key = Key::find_by_pub_key(&conn, pub_key.clone(), index.map(|v| i32::from(v)))
        .context("failed to find key")
        .map_err(|e| ApiError::BadRequest(anyhow::anyhow!("{}", e)))?;
    let body = key.body.clone();
    let message = request.message;
    let parties = request.parties.clone();
    let signature = sign(body.as_str(), parties.clone(), message, address, &room_id).await?;
    Ok(json!({
        "pub_key": pub_key.clone(),
        "signature": signature,
        "parties": parties,
    }))
}

use anyhow::Context;
use lazy_static::lazy_static;
use std::env;

use rocket::http::Status;
use rocket::response::status;
use rocket::serde::json::{json, Json, Value};
use rocket::serde::{Deserialize, Serialize};

use crate::api::from_request::token::Token;
use crate::ecdsa::gg_2020::{keygen::keygen, sign::sign};

lazy_static! {
    pub static ref COMMUNICATE_API: String = {
        match env::var("COMMUNICATE_API") {
            Ok(v) => v,
            Err(_) => "".to_string(),
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
pub async fn gen_key(token: Token, request: Json<KeyGenReq>) -> status::Custom<Value> {
    let input = format!("{}", *COMMUNICATE_API);
    let address = surf::Url::parse(input.as_str()).unwrap();
    let room_id = token.0.to_string();
    let index = request.index;
    let parties = request.parties;
    let threshold = request.threshold;
    let key = keygen(index, threshold, parties, address, &room_id)
        .await
        .context("failed to generate key");
    match key {
        Ok((public_key, local_key)) => status::Custom(
            Status::Ok,
            json!({
                "key": local_key,
                "pub_key": public_key,
                "threshold": threshold,
                "parties": parties,
            }),
        ),
        Err(e) => {
            error!("gen_key failed {:?}", e);
            status::Custom(Status::InternalServerError, json!({"error": e.to_string()}))
        }
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct KeySignReq<'r> {
    key: String,
    message: &'r str,
    parties: Vec<u16>,
}
#[post("/sign", data = "<request>")]
pub async fn sign_message(token: Token, request: Json<KeySignReq<'_>>) -> status::Custom<Value> {
    let input = format!("{}", *COMMUNICATE_API);
    let address = surf::Url::parse(input.as_str()).unwrap();
    let room_id = token.0.to_string();
    let key = request.key.as_str();
    let parties = request.parties.clone();
    let message = request.message;
    let signature = sign(key, parties.clone(), message, address, &room_id).await;
    match signature {
        Ok(sig) => status::Custom(
            Status::Ok,
            json!({
                "signature": sig,
                "parties": parties,
            }),
        ),
        Err(e) => {
            error!("sign_message failed {:?}", e);
            status::Custom(Status::InternalServerError, json!({"error": e.to_string()}))
        }
    }
}

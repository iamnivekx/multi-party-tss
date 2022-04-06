use anyhow::Context;
use curv::elliptic::curves::Secp256k1;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;

use rocket::http::Status;
use rocket::response::status;
use rocket::serde::json::{json, Json, Value};
use rocket::serde::{Deserialize, Serialize};

use crate::api::from_request::token::Token;
use crate::ecdsa::gg_2020::keygen::keygen;
use crate::ecdsa::gg_2020::sign::sign;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct KeyGenReq {
    index: u16,
    parties: u16,
    threshold: u16,
}
#[post("/key", data = "<request>")]
pub async fn gen_key(token: Token, request: Json<KeyGenReq>) -> status::Custom<Value> {
    let address = surf::Url::parse("http://127.0.0.1:8000").unwrap();
    let room_id = token.0.to_string();
    let index = request.index;
    let parties = request.parties;
    let threshold = request.threshold;
    let key = keygen(index, threshold, parties, address, &room_id)
        .await
        .context("failed to generate key")
        .unwrap();

    let local_key: LocalKey<Secp256k1> = serde_json::from_str(&key).unwrap();
    let public_key = local_key.public_key().to_bytes(true).to_vec();
    let public_key_hex = hex::encode(&public_key);
    status::Custom(
        Status::Ok,
        json!({
            "key": key,
            "pub_key": public_key_hex,
            "threshold": threshold,
            "parties": parties,
        }),
    )
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct KeySignReq<'r> {
    key: String,
    message: &'r str,
    parties: Vec<u16>,
}
#[post("/sign", data = "<request>")]
pub async fn sign_message(token: Token, request: Json<KeySignReq<'_>>) -> status::Custom<Value> {
    let address = surf::Url::parse("http://127.0.0.1:8000").unwrap();
    let room_id = token.0.to_string();
    let key = request.key.as_str();
    let parties = request.parties.clone();
    let message = request.message;
    let signature = sign(key, parties, message, address, &room_id)
        .await
        .unwrap();
    status::Custom(
        Status::Ok,
        json!({
            "signature": signature,
        }),
    )
}

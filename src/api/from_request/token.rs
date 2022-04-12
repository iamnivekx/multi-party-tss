use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use thiserror::Error;
use uuid::Uuid;

pub struct Token(pub String);

#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum ApiTokenError {
    #[error("Api token missing")]
    Missing,
    #[error("Api token invalid")]
    Invalid,
}

/// Returns true if `key` is a valid API key string.
fn is_valid(key: &str) -> bool {
    match Uuid::parse_str(key) {
        Ok(_) => true,
        Err(_) => false,
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Token {
    type Error = ApiTokenError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let token = req.headers().get_one("token");
        match token {
            None => Outcome::Failure((Status::BadRequest, ApiTokenError::Missing)),
            Some(key) if is_valid(key) => Outcome::Success(Token(key.to_string())),
            Some(_) => Outcome::Failure((Status::BadRequest, ApiTokenError::Invalid)),
        }
    }
}

use diesel;
use rocket::http::ContentType;
use rocket::http::Status;
use rocket::request::Request;
use rocket::response::{self, Responder, Response};
use serde_json::json;
use std::io::Cursor;
use thiserror::Error;

use crate::util::store::StoreError;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("{1:#}")]
    Custom(Status, String),
    #[error("{0:#}")]
    BadRequest(anyhow::Error),
    #[error("{0:#}")]
    Unknown(anyhow::Error),
    #[error("{0}")]
    DatabaseError(diesel::result::Error),
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::Unknown(e)
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        ApiError::Custom(Status::InternalServerError, e.to_string())
    }
}

impl From<(Status, String)> for ApiError {
    fn from((status, message): (Status, String)) -> Self {
        ApiError::Custom(status, message)
    }
}

impl From<diesel::result::Error> for ApiError {
    fn from(e: diesel::result::Error) -> Self {
        ApiError::DatabaseError(e)
    }
}

impl<'r, 'o: 'r> Responder<'r, 'o> for ApiError {
    fn respond_to(self, req: &'r Request<'_>) -> response::Result<'o> {
        let description = self.to_string();
        let desc = json!({ "error": description.to_string() });
        let body = Cursor::new(format!("{}", desc.to_string()));
        let status = match self {
            ApiError::Custom(status, _) => status,
            ApiError::BadRequest(_) => Status::BadRequest,
            _ => Status::InternalServerError,
        };
        error!(
            "Request status {}, uri {}, method {}, response {}",
            status.clone(),
            req.uri(),
            req.method(),
            description
        );
        Response::build()
            .header(ContentType::JSON)
            .streamed_body(body)
            .status(status)
            .ok()
    }
}

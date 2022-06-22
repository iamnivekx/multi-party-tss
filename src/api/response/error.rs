use diesel;
use rocket::http::ContentType;
use rocket::http::Status;
use rocket::request::Request;
use rocket::response::{self, Responder, Response};
use serde_json::json;
use std::io::Cursor;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
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

impl From<diesel::result::Error> for ApiError {
    fn from(e: diesel::result::Error) -> Self {
        ApiError::DatabaseError(e)
    }
}

impl<'r, 'o: 'r> Responder<'r, 'o> for ApiError {
    fn respond_to(self, req: &'r Request<'_>) -> response::Result<'o> {
        let description = self.to_string();
        error!(
            "Request uri {} ,method {}, response {} ",
            req.uri(),
            req.method(),
            description
        );
        let desc = json!({ "error": description.to_string() });
        let body = Cursor::new(format!("{}", desc.to_string()));
        Response::build()
            .header(ContentType::JSON)
            .streamed_body(body)
            .status(Status::InternalServerError)
            .ok()
    }
}

use thiserror;

#[derive(thiserror::Error, Debug)]
enum ApiError {
    #[error("page not found")]
    NotFound(String),
    #[error("{0}")]
    JsonError(#[from] JsonError),
}

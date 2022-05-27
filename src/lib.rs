use anyhow::anyhow;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use dotenv::dotenv;
use lazy_static::lazy_static;
use std::env;

lazy_static! {
    pub static ref DATABASE_URL: String = {
        match env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => "".to_string(),
        }
    };
}

pub fn establish_connection() -> anyhow::Result<PgConnection, anyhow::Error> {
    dotenv().ok();
    PgConnection::establish(&DATABASE_URL)
        .map_err(|_| anyhow!("Connecting to Database failed".to_string()))
}

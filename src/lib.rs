use anyhow::anyhow;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use dotenv::dotenv;

pub fn establish_connection(database_url: &str) -> Result<PgConnection, anyhow::Error> {
    dotenv().ok();
    PgConnection::establish(database_url)
        .map_err(|_| anyhow!("Connecting to Database failed".to_string()))
}

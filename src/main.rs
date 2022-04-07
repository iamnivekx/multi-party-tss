#[macro_use]
extern crate rocket;
extern crate dotenv;

use dotenv::dotenv;

use rocket::fairing::AdHoc;
use rocket::Config;

// use std::collections::HashMap;
// use std::sync::RwLock;

mod api;
mod ecdsa;
mod state;

use crate::state::db::Db;

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    dotenv().ok();
    // let db: HashMap<String, String> = HashMap::new();
    // let state = RwLock::new(db);
    let state = Db::empty();
    rocket::build()
        .manage(state)
        .attach(AdHoc::config::<Config>())
        .attach(api::stage())
        .ignite()
        .await?
        .launch()
        .await
}

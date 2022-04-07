#[macro_use]
extern crate rocket;

use dotenv::dotenv;

use rocket::fairing::AdHoc;
use rocket::Config;

use std::collections::HashMap;
use std::sync::RwLock;

mod api;
mod ecdsa;
mod state;

use crate::state::db::Db;

#[allow(dead_code)]
async fn gg18() -> Result<(), rocket::Error> {
    let db: HashMap<String, String> = HashMap::new();
    let state = RwLock::new(db);
    rocket::build()
        .manage(state)
        .attach(AdHoc::config::<Config>())
        .attach(api::stage())
        .ignite()
        .await?
        .launch()
        .await
}

#[allow(dead_code)]
async fn gg20() -> Result<(), rocket::Error> {
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

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    dotenv().ok();

    match *api::GG_18 {
        true => gg18().await,
        false => gg20().await,
    }
}

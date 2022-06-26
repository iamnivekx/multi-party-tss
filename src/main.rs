#[macro_use]
extern crate rocket;
extern crate dotenv;

#[macro_use]
extern crate diesel;

use dotenv::dotenv;

use rocket::{
    data::{Limits, ToByteUnit},
    fairing::AdHoc,
    Config,
};
use std::collections::HashMap;
use std::sync::RwLock;
use structopt::StructOpt;

pub mod api;
pub mod config;
pub mod connection_pool;
pub mod ecdsa;
pub mod lib;
pub mod models;
pub mod opt;
pub mod schema;
pub mod state;
pub mod store_builder;
pub mod util;

use crate::config::Config as AppConfig;
use crate::state::db::Db;
use crate::store_builder::StoreBuilder;

#[rocket::main]
async fn main() -> Result<(), anyhow::Error> {
    dotenv().ok();

    let opt = opt::Opt::from_args();
    let config = match AppConfig::load(&opt.clone().into()) {
        Err(e) => {
            eprintln!("configuration error: {}", e);
            std::process::exit(1);
        }
        Ok(config) => config,
    };

    let mut store = StoreBuilder::new(&config);
    let _ = store.try_connected().await?;

    let db = Db::empty();
    let map: HashMap<String, String> = HashMap::new();
    let map = RwLock::new(map);
    let figment = rocket::Config::figment()
        .merge(("limits", Limits::new().limit("string", 100_i32.megabytes())));
    let _ = rocket::custom(figment)
        .manage(db)
        .manage(map)
        .manage(config)
        .manage(store)
        .attach(AdHoc::config::<Config>())
        .attach(api::stage())
        .ignite()
        .await?
        .launch()
        .await?;
    Ok(())
}

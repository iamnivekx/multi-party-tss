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
use tracing_subscriber::{filter::EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

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

    // log to console
    let std_layer = fmt::layer().with_writer(std::io::stderr);
    let file_appended = tracing_appender::rolling::daily(
        config.file_log_opt.directory.clone(),
        config.file_log_opt.file_prefix_name.clone(),
    );
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appended);
    // log to file
    let file_layer = fmt::Layer::new().pretty().with_writer(non_blocking);

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(env_filter)
        .with(file_layer)
        .with(std_layer)
        .init();

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

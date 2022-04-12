use lazy_static::lazy_static;
use rocket::http::Status;
use rocket::response::status::Custom;
use rocket::serde::json::{json, Value};
use rocket::Request;
use std::env;

use ecdsa::gg_2018::centralized::{gen_keys, signatures};
use ecdsa::gg_2018::distributed::{gen_key, sign_message};
use ecdsa::gg_2018::management::{get_entry, set_entry, signup_party};
use ecdsa::gg_2020::{
    distributed::{gen_key as gg20_gen_key, sign_message as gg20_sign_message},
    management::{broadcast, issue_idx, subscribe},
};

mod ecdsa;
mod from_request;
mod response;
mod token;

use token::gen_token;

lazy_static! {
    pub static ref GG_18: bool = {
        match env::var("GG_18") {
            Ok(v) => v.eq("true"),
            Err(_) => false,
        }
    };
}

#[catch(404)]
fn not_found() -> Value {
    json!({
        "code": 400,
        "message": "source not found"
    })
}

#[catch(default)]
fn default_catcher(status: Status, req: &Request<'_>) -> Custom<Value> {
    Custom(
        status,
        json!({
            "uri": req.uri(),
            "code": status.code,
            "reason": format!("{}", status.clone()),
            "message": status.reason_lossy(),
        }),
    )
}

pub fn stage() -> rocket::fairing::AdHoc {
    rocket::fairing::AdHoc::on_ignite("JSON", |rocket| async {
        let rocket_build = rocket
            .mount("/", routes![gen_token,])
            .register("/", catchers![not_found, default_catcher]);

        match *GG_18 {
            true => rocket_build
                .mount("/ecdsa/gg_18/distributed", routes![gen_key, sign_message])
                .mount("/ecdsa/gg_18/centralized", routes![gen_keys, signatures])
                .mount(
                    "/ecdsa/gg_18/management/",
                    routes![get_entry, set_entry, signup_party],
                ),
            false => rocket_build
                .mount(
                    "/ecdsa/gg_20/management/",
                    routes![broadcast, issue_idx, subscribe],
                )
                .mount(
                    "/ecdsa/gg_20/distributed/",
                    routes![gg20_gen_key, gg20_sign_message],
                ),
        }
    })
}

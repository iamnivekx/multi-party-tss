use rocket::http::Status;
use rocket::response::status::Custom;
use rocket::serde::json::{json, Value};
use rocket::Request;

use ecdsa::gg_2018::{
    centralized::{gen_keys, signatures},
    distributed::{gen_key, sign_message},
    management::{get_entry, set_entry, signup_party},
};
use ecdsa::gg_2020::{
    distributed::{gen_key as gg20_gen_key, sign_message as gg20_sign_message},
    gateway::{gen_keys as gg_20_gateway_key_gen_key, sign_message as gg_20_gateway_sign_message},
    key::{key_gen_key as gg_20_key_gen_key, key_sign_message as gg_20_key_sign_message},
    management::{broadcast, issue_idx, subscribe},
};

mod ecdsa;
mod from_request;
mod response;
mod token;

use token::gen_token;

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
    rocket::fairing::AdHoc::on_ignite("JSON", move |rocket| async move {
        let rocket_build = rocket
            .mount("/", routes![gen_token,])
            .register("/", catchers![not_found, default_catcher]);

        rocket_build
            .mount("/ecdsa/gg_18/distributed", routes![gen_key, sign_message])
            .mount("/ecdsa/gg_18/centralized", routes![gen_keys, signatures])
            .mount(
                "/ecdsa/gg_18/management/",
                routes![get_entry, set_entry, signup_party],
            )
            .mount(
                "/ecdsa/gg_20/management/",
                routes![broadcast, issue_idx, subscribe],
            )
            .mount(
                "/ecdsa/gg_20/distributed/",
                routes![gg20_gen_key, gg20_sign_message],
            )
            .mount(
                "/ecdsa/gg_20/pub_key/",
                routes![gg_20_key_gen_key, gg_20_key_sign_message],
            )
            .mount(
                "/ecdsa/gg_20/gateway/",
                routes![gg_20_gateway_key_gen_key, gg_20_gateway_sign_message],
            )
    })
}

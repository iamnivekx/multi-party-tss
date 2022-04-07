use rocket::http::Status;
use rocket::response::status::Custom;
use rocket::serde::json::{json, Value};
use rocket::Request;

mod ecdsa;
mod from_request;
mod token;

// use ecdsa::gg_2018::centralized::{gen_keys, signatures};
// use ecdsa::gg_2018::distributed::{gen_key, sign_message};
// use ecdsa::gg_2018::management::{get_entry, set_entry, signup_party};
use ecdsa::gg_2020::{
    distributed::{gen_key as gg20_gen_key, sign_message as gg20_sign_message},
    management::{broadcast, issue_idx, subscribe},
};
use token::gen_token;

#[catch(404)]
fn not_found() -> Value {
    json!({
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
            "reason": status.reason_lossy(),
        }),
    )
}

pub fn stage() -> rocket::fairing::AdHoc {
    rocket::fairing::AdHoc::on_ignite("JSON", |rocket| async {
        rocket
            .mount("/", routes![gen_token])
            // .mount("/ecdsa/gg_18/distributed", routes![gen_key, sign_message])
            // .mount("/ecdsa/gg_18/centralized", routes![gen_keys, signatures])
            // .mount(
            //     "/ecdsa/gg_18/management/",
            //     routes![get_entry, set_entry, signup_party],
            // )
            .mount(
                "/ecdsa/gg_20/management",
                routes![broadcast, issue_idx, subscribe],
            )
            .mount(
                "/ecdsa/gg_20/distributed",
                routes![gg20_gen_key, gg20_sign_message],
            )
            .register("/", catchers![not_found, default_catcher])
    })
}

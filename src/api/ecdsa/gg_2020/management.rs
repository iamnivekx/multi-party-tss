use futures::Stream;
use rocket::http::Status;
use rocket::response::stream::{stream, Event, EventStream};
use rocket::serde::json::Json;
use rocket::serde::{Deserialize, Serialize};
use rocket::State;

use crate::api::from_request::last_event_id::LastEventId;
use crate::state::db::Db;

#[derive(Serialize, Deserialize, Debug)]
pub struct IssuedUniqueIdx {
    unique_idx: u16,
}

#[get("/rooms/<room_id>/subscribe")]
pub async fn subscribe(
    db: &State<Db>,
    mut shutdown: rocket::Shutdown,
    last_seen_msg: LastEventId,
    room_id: &str,
) -> EventStream<impl Stream<Item = Event>> {
    let room = db.get_room_or_create_empty(room_id).await;
    let last_seen_msg_id = last_seen_msg.id();
    let mut subscription = room.subscribe(last_seen_msg_id);
    EventStream::from(stream! {
        loop {
            let (id, msg) = tokio::select! {
                message = subscription.next() => message,
                _ = &mut shutdown => return,
            };
            yield Event::data(msg)
                .event("new-message")
                .id(id.to_string())
        }
    })
}

#[post("/rooms/<room_id>/issue_unique_idx")]
pub async fn issue_idx(db: &State<Db>, room_id: &str) -> Json<IssuedUniqueIdx> {
    let room = db.get_room_or_create_empty(room_id).await;
    let idx = room.issue_unique_idx();
    Json::from(IssuedUniqueIdx { unique_idx: idx })
}

#[post("/rooms/<room_id>/broadcast", data = "<message>")]
pub async fn broadcast(db: &State<Db>, room_id: &str, message: String) -> Status {
    let room = db.get_room_or_create_empty(room_id).await;
    room.publish(message).await;
    Status::Ok
}

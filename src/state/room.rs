use std::collections::hash_map::{Entry, HashMap};
use std::sync::{
    atomic::{AtomicU16, Ordering},
    Arc,
};

use tokio::sync::{Notify, RwLock};

pub struct Db {
    rooms: RwLock<HashMap<String, Arc<Room>>>,
}

pub struct Room {
    messages: RwLock<Vec<String>>,
    message_appeared: Notify,
    subscribers: AtomicU16,
    next_idx: AtomicU16,
}

impl Db {
    pub fn empty() -> Self {
        Self {
            rooms: RwLock::new(HashMap::new()),
        }
    }

    pub async fn get_room_or_create_empty(&self, room_id: &str) -> Arc<Room> {
        let rooms = self.rooms.read().await;
        if let Some(room) = rooms.get(room_id) {
            // If no one is watching this room - we need to clean it up first
            if !room.is_abandoned() {
                return room.clone();
            }
        }
        drop(rooms);

        let mut rooms = self.rooms.write().await;
        match rooms.entry(room_id.to_owned()) {
            Entry::Occupied(entry) if !entry.get().is_abandoned() => entry.get().clone(),
            Entry::Occupied(entry) => {
                let room = Arc::new(Room::empty());
                *entry.into_mut() = room.clone();
                room
            }
            Entry::Vacant(entry) => entry.insert(Arc::new(Room::empty())).clone(),
        }
    }
}

impl Room {
    pub fn empty() -> Self {
        Self {
            messages: RwLock::new(vec![]),
            message_appeared: Notify::new(),
            subscribers: AtomicU16::new(0),
            next_idx: AtomicU16::new(1),
        }
    }

    pub async fn publish(self: &Arc<Self>, message: String) {
        let mut messages = self.messages.write().await;
        messages.push(message);
        self.message_appeared.notify_waiters();
    }

    pub fn subscribe(self: Arc<Self>, last_seen_msg: Option<u16>) -> Subscription {
        self.subscribers.fetch_add(1, Ordering::SeqCst);
        Subscription {
            room: self,
            next_event: last_seen_msg.map(|i| i + 1).unwrap_or(0),
        }
    }

    pub fn is_abandoned(&self) -> bool {
        self.subscribers.load(Ordering::SeqCst) == 0
    }

    pub fn issue_unique_idx(&self) -> u16 {
        self.next_idx.fetch_add(1, Ordering::Relaxed)
    }
}

pub struct Subscription {
    room: Arc<Room>,
    next_event: u16,
}

impl Subscription {
    pub async fn next(&mut self) -> (u16, String) {
        loop {
            let history = self.room.messages.read().await;
            if let Some(msg) = history.get(usize::from(self.next_event)) {
                let event_id = self.next_event;
                self.next_event = event_id + 1;
                return (event_id, msg.clone());
            }
            let notification = self.room.message_appeared.notified();
            drop(history);
            notification.await;
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.room.subscribers.fetch_sub(1, Ordering::SeqCst);
    }
}

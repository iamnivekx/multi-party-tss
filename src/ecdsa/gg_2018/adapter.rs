use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub key: String,
    pub value: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PartySignup {
    pub number: u16,
    pub uuid: String,
}

#[async_trait]
pub trait Community {
    async fn get_entry(&self, key: &String) -> Result<Entry, ()>;
    async fn set_entry(&self, entry: &Entry) -> Result<Entry, ()>;
    async fn get_party_signup(
        &self,
        parties: u16,
        room_id: &String,
    ) -> Result<PartySignup, ()>;
}

pub struct StoreCommunity<'a> {
    store: &'a RwLock<HashMap<String, String>>,
}

impl<'a> StoreCommunity<'a> {
    pub fn new(store: &'a RwLock<HashMap<String, String>>) -> StoreCommunity<'a> {
        StoreCommunity { store }
    }
}

#[async_trait]
impl<'a> Community for StoreCommunity<'a> {
    async fn get_entry(&self, key: &String) -> Result<Entry, ()> {
        let hm = self.store.read().unwrap();
        match hm.get(key) {
            Some(v) => Ok(Entry {
                key: key.clone().to_string(),
                value: v.clone().to_string(),
            }),
            None => Err(()),
        }
    }

    async fn set_entry(&self, entry: &Entry) -> Result<Entry, ()> {
        let mut hm = self.store.write().unwrap();
        hm.insert(entry.key.clone(), entry.value.clone());
        Ok(entry.clone())
    }

    async fn get_party_signup(&self, num: u16, key: &String) -> Result<PartySignup, ()> {
        let party_signup_result = {
            let hm = self.store.read().unwrap();
            match hm.get(key) {
                Some(value) => {
                    let client_signup: PartySignup = serde_json::from_str(&value).unwrap();
                    if client_signup.number < num {
                        Ok(PartySignup {
                            number: client_signup.number + 1,
                            uuid: client_signup.uuid,
                        })
                    } else {
                        Err(())
                    }
                }
                None => Ok(PartySignup {
                    number: 1,
                    uuid: Uuid::new_v4().to_string(),
                }),
            }
        };
        let party_signup = party_signup_result?;
        let mut hm = self.store.write().unwrap();
        hm.insert(key.clone(), serde_json::to_string(&party_signup).unwrap());
        Ok(party_signup)
    }
}

#[cfg(test)]
pub mod test {
    use super::StoreCommunity;
    use crate::ecdsa::gg_2018::common::Community;
    use std::collections::HashMap;
    use std::sync::RwLock;

    #[tokio::test]
    async fn test_signup_set_multi() {
        let parties = 3;
        let key = "key".to_string();
        let db: HashMap<String, String> = HashMap::new();
        let store = RwLock::new(db);
        let adapter = StoreCommunity::new(&store);
        let party_signup1 = adapter.get_party_signup(parties, &key).await.unwrap();
        let party_signup2 = adapter.get_party_signup(parties, &key).await.unwrap();

        assert_eq!(party_signup1.uuid, party_signup2.uuid);
        assert_eq!(party_signup1.number, party_signup2.number - 1);
    }
}

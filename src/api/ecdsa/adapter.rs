use async_trait::async_trait;
use std::collections::HashMap;
use std::env;
use std::sync::RwLock;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::time::sleep;

pub use crate::ecdsa::gg_2018::adapter::{Community, Entry, PartySignup, StoreCommunity};
use std::option::Option::Some;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Index {
    pub key: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PartySignupReq<'r> {
    pub(crate) num: u16,
    pub(crate) key: &'r str,
}

pub struct ApiCommunity {
    addr: String,
    client: Client,
}

impl ApiCommunity {
    fn new(addr: String) -> Self {
        Self {
            addr: addr.clone(),
            client: Client::new(),
        }
    }

    async fn post<T>(&self, path: &str, body: T) -> Option<String>
    where
        T: serde::ser::Serialize,
    {
        let retries = 10;
        let retry_delay = Duration::from_millis(250);
        let url = format!("{}/{}", self.addr.clone(), path);
        for _i in 1..retries {
            let res: Result<Value, _> = self
                .client
                .post(&url)
                .json(&body)
                .send()
                .await
                .unwrap()
                .json()
                .await;

            if let Ok(res) = res {
                return Some(serde_json::to_string(&res).unwrap());
            }
            sleep(retry_delay).await;
        }
        None
    }
}

#[async_trait]
impl Community for ApiCommunity {
    async fn get_entry(&self, key: &String) -> Result<Entry, ()> {
        let index = Entry {
            key: key.clone(),
            value: "".to_string(),
        };
        let res_body = self
            .post("ecdsa/management/get-entry", &index)
            .await
            .unwrap();
        match serde_json::from_str(&res_body) {
            Ok(v) => Ok(v),
            Err(_e) => Err(()),
        }
    }

    async fn set_entry(&self, entry: &Entry) -> Result<Entry, ()> {
        let res_body = self
            .post("ecdsa/management/set-entry", entry.clone())
            .await
            .unwrap();
        match serde_json::from_str(&res_body) {
            Ok(v) => Ok(v),
            Err(_e) => Err(()),
        }
    }

    async fn get_party_signup(&self, num: u16, key: &String) -> Result<PartySignup, ()> {
        let key_str = key.clone();
        let req = PartySignupReq {
            num,
            key: key_str.as_str(),
        };
        let res_body = self
            .post("ecdsa/management/signup-party", req)
            .await
            .unwrap();
        match serde_json::from_str(&res_body) {
            Ok(v) => Ok(v),
            Err(_e) => Err(()),
        }
    }
}

pub fn get_adapter<'a>(
    store: &'a RwLock<HashMap<String, String>>,
) -> Box<dyn Community + Sync + Send + 'a> {
    match env::var("COMMUNICATE_API") {
        Ok(v) => Box::new(ApiCommunity::new(v.clone())),
        Err(_) => Box::new(StoreCommunity::new(&store)),
    }
}

pub fn get_store_adapter<'a>(
    store: &'a RwLock<HashMap<String, String>>,
) -> Box<dyn Community + Sync + Send + 'a> {
    Box::new(StoreCommunity::new(&store))
}

#[cfg(test)]
pub mod test {
    use super::get_adapter;
    use crate::api::ecdsa::adapter::Entry;
    use dotenv::dotenv;
    use std::collections::HashMap;
    use std::sync::RwLock;

    #[test]
    fn test_get_adapter() {
        dotenv().ok();
        let db: HashMap<String, String> = HashMap::new();
        let store = RwLock::new(db);

        let _adapter = get_adapter(&store);
    }

    #[tokio::test]
    async fn test_api_adapter() {
        dotenv().ok();
        let db: HashMap<String, String> = HashMap::new();
        let store = RwLock::new(db);

        let adapter = get_adapter(&store);
        let num = 3;
        let key = "key".to_string();
        let result = adapter.get_party_signup(num, &key).await;
        assert_eq!(result.is_ok(), true);

        let key = "k".to_string();
        let entry = Entry {
            key: key.clone(),
            value: "v".to_string(),
        };
        let result = adapter.set_entry(&entry).await;
        assert_eq!(result.is_ok(), true);

        let result = adapter.get_entry(&key).await;
        assert_eq!(result.is_ok(), true);

        let invalid_key = "invalid".to_string();
        let result = adapter.get_entry(&invalid_key).await;
        assert_eq!(result.is_ok(), false);
    }
}

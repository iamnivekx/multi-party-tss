use anyhow::{anyhow, Context};
use uuid::Uuid;
use tokio::time::{sleep, Duration};
use std::sync::Arc;
use rocket::serde::json::{json, Json, Value};
use rocket::serde::{Deserialize, Serialize};
use futures::future;

use crate::api::response::error::ApiError;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ErrorMsg {
    error: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct KeyGenReq {
    threshold: u16,
    nodes: Vec<String>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PubKey {
    index: u16,
    key: String,
    pub_key: String,
    parties: u16,
    threshold: u16
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PubKeyIndex {
    index: u16,
    parties: u16,
    threshold: u16,
    node: String,
}

#[post("/keys", data = "<request>")]
pub async fn gen_keys(request: Json<KeyGenReq>) -> Result<Value, ApiError>  {
    let nodes = request.nodes.to_vec();
    let nodes = Arc::new(nodes);

    let parties = nodes.len() as u16;

    let threshold = request.threshold;
    let room_id = Uuid::new_v4().to_string();
    let room_id = Arc::new(room_id);

    let futures = (1..=parties).into_iter().map(|index| (index, nodes.clone(), room_id.clone())).map(|(index, nodes, room_id)| async move {
        let parties = nodes.len() as u16;
        let node = nodes[index as usize - 1].clone();
        let mut url = surf::Url::parse(node.as_str()).context("url parse failed")?;
        url.set_path("/ecdsa/gg_20/pub_key/keys");
        
        let body = json!({ "index": index, "threshold": threshold, "parties": parties });
        sleep(Duration::from_millis(u64::from(index * 200))).await;
        let mut res = surf::post(url).header("token", room_id.to_string()).body_json(&body).map_err(|e| anyhow!(e.to_string()))?.await.map_err(|e| anyhow!(e.to_string()))?;
    
        let body = res.body_string().await.map_err(|e| e.into_inner())?;
        let result = if res.status() == 200 {
            let pub_key: PubKey = serde_json::from_str(body.as_str()).map_err(|e|anyhow!("failed to decode the body {}", e))?;
            anyhow::Ok((pub_key, node))
        } else {
            let error: ErrorMsg = serde_json::from_str(body.as_str()).context("failed to decode the error body")?;
            Err(anyhow!("failed to compute the key {}", error.error).into())
        };
        result
    });
    let keys: Vec<anyhow::Result<(PubKey, String), anyhow::Error>>  = future::join_all(futures).await;
    let mut pub_keys: Vec<PubKeyIndex> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut pub_key = "".to_string();
    keys.into_iter().for_each(|key| {
        if let Ok(key) = key {
            pub_key = key.0.pub_key.clone();
            pub_keys.push(PubKeyIndex { index: key.0.index, parties: key.0.parties, threshold: key.0.threshold, node: key.1.clone() });
        } else {
            errors.push(key.unwrap_err().to_string());
        }
    });
    if errors.len() > 0 {
        return Err(anyhow!("{}", errors.join("\n"))
            .context("failed to generate key")
            .into());
    }
    Ok(json!({
        "pub_key": pub_key,
        "keys": pub_keys,
    }))
    
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct KeySignReq {
    pub_key: String,
    message: String,
    nodes:Vec<PubKeyIndex>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Sig {
    pub_key: String,
    parties: Vec<u16>,
    signature: String,
}
#[post("/sign", data = "<request>")]
pub async fn sign_message(request: Json<KeySignReq>) -> Result<Value, ApiError> {
    let room_id = Uuid::new_v4().to_string();
    let room_id = Arc::new(room_id);

    let pub_key = request.pub_key.to_string();
    let pub_key = Arc::new(pub_key);

    let message = request.message.to_string();
    let message = Arc::new(message);

    let mut nodes: Vec<PubKeyIndex> = request.nodes.to_vec();
    nodes.sort_by(|a, b| a.index.cmp(&b.index));

    let parties: Vec<u16> = nodes.iter().map(|i| i.index).collect::<Vec<u16>>();
    let parties = Arc::new(parties);

    let futures = nodes.into_iter().map(|key| (key, pub_key.clone(), message.clone(), parties.clone(), room_id.clone())).map(|(key, pub_key, message ,parties, room_id)| async move {
        let pub_key = pub_key.to_string();
        let message = message.to_string();
        let parties = parties.to_vec();
        let index = key.index;
        let node = key.node;

        let mut url = surf::Url::parse(node.as_str().clone()).context("build url failed")?;
        url.set_path("/ecdsa/gg_20/pub_key/sign");

        let body = json!({ "index": index, "pub_key": pub_key, "parties": parties, "message": message });
        sleep(Duration::from_millis(u64::from(index * 200))).await;
        let mut res = surf::post(url).header("token", room_id.to_string()).body_json(&body).map_err(|e| anyhow!(e.into_inner()))?.await.map_err(|e| anyhow!("fetch from node {} {}", node, e.into_inner()))?;
        let body = res.body_string().await.map_err(|e| e.into_inner())?;
        let result = if res.status() == 200 {
            let sig: Sig = serde_json::from_str(body.as_str()).map_err(|e|anyhow!("failed to decode the body {} {}", node, e))?;
            anyhow::Ok((sig, node.to_string()))
        } else {
            let error: ErrorMsg = serde_json::from_str(body.as_str()).context("failed to decode the error body")?;
            Err(anyhow!("failed to compute the signature {} {}",  node, error.error).into())
        };
        result
    });
    
    let result: Vec<anyhow::Result<(Sig, String), anyhow::Error>>  = future::join_all(futures).await;

    let mut signatures: Vec<Sig> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    result.into_iter().for_each(|item| {
        if let Ok(item) = item {
            signatures.push(item.0);
        } else {
            let e = item.unwrap_err().to_string();
            errors.push(e);
        }
    });
    if errors.len() > 0 {
        return Err(anyhow!("{:?}", errors).into());
    }
    Ok(json!({
        "pub_key": pub_key.to_string(),
        "message": message.to_string(),
        "signature": signatures[0].signature,
    }))
}




#[cfg(test)]
pub mod test {
    use uuid::Uuid;
    use anyhow::{anyhow, Context, Result};
    use std::sync::Arc;
    use tokio::time::{sleep, Duration};
    use rocket::serde::json::json;
    use futures::future;

    use super::PubKeyIndex;

    #[tokio::test]
    async fn test_async_keygen() -> Result<()> {
        let parties: u16 = 3;
        let threshold = 1;
        let nodes = vec![ "http://localhost:8000",  "http://localhost:8000",  "http://localhost:8000"];
        let nodes = Arc::new(nodes);
        let room_id = Uuid::new_v4().to_string();
        let room_id = Arc::new(room_id);

        let futures = (1..=parties).into_iter().map(|idx| (idx, room_id.clone(), nodes.clone())).map(|(index, room_id, nodes)| async move {
            let node = nodes[usize::from(index) - 1];
            let mut url = surf::Url::parse(node).context("build url failed")?;
            url.set_path("/ecdsa/gg_20/pub_key/keys");
            let body = json!({ "index": index.clone(), "threshold": threshold.clone(), "parties": parties.clone() });
            sleep(Duration::from_millis(u64::from(index * 200))).await;
            let mut res = surf::post(url).header("token", room_id.to_string()).body_json(&body).map_err(|e| anyhow!(e.to_string())).context("Build request failed")?.await.map_err(|e| anyhow!(e.to_string())).context("Failed to fetch from nodes")?;
            let body = res.body_string().await.map_err(|e| anyhow!(e.to_string())).context("failed to get body")?;
            anyhow::Ok(body)
        });
        let keys: Vec<anyhow::Result<String, anyhow::Error>> = future::join_all(futures).await;
        println!("{:?}", keys.into_iter().map(|res| res.unwrap_or_else(|e| e.to_string())).collect::<Vec<String>>());
        Ok(())
    }

    #[tokio::test]
    async fn test_async_key_sign() -> Result<()> {
        let threshold = 1;
        let parties = 3;
        let pub_key = "03c7f4ce41ac65c6c779c57395811fa4a04a27ccad5f7f94d0e4272da599ccfe17";
        let pub_key = Arc::new(pub_key);

        let message = "68656c6c6f20776f726c64".to_string();
        let message = Arc::new(message);

        let room_id = Uuid::new_v4().to_string();
        let room_id = Arc::new(room_id);


        let keys = vec![
            PubKeyIndex{ index: 1, parties: parties, threshold: threshold, node: "http://localhost:8000".to_string() },
            PubKeyIndex{ index: 2, parties: parties, threshold: threshold, node: "http://localhost:8000".to_string() },
        ];
        let keys = Arc::new(keys);

        let parties: Vec<u16> = keys.iter().map(|i| i.index).collect::<Vec<u16>>();
        let parties = Arc::new(parties);

        let futures = keys.iter().map(|key| (key, pub_key.clone(), message.clone(), parties.clone(), room_id.clone())).map(|(key, pub_key, message ,parties, room_id)| async move {
            let pub_key = pub_key.to_string();
            let message = message.to_string();
            let parties = parties.to_vec();
            let index = key.index;
            let node = key.node.clone();
            let mut url = surf::Url::parse(node.as_str()).context("build url failed")?;
            url.set_path("/ecdsa/gg_20/pub_key/sign");
            let body = json!({ "index": index, "pub_key": pub_key, "parties": parties, "message": message });
            sleep(Duration::from_millis(u64::from(index * 200))).await;
            let mut res = surf::post(url).header("token", room_id.to_string()).body_json(&body).map_err(|e| anyhow!(e.to_string())).context("Build request failed")?.await.map_err(|e| anyhow!(e.to_string())).context("Failed to fetch from nodes")?;
            let body = res.body_string().await.map_err(|e| anyhow!(e.to_string())).context("failed to get body")?;
            anyhow::Ok(body)
        });
        let keys: Vec<anyhow::Result<String, anyhow::Error>> = future::join_all(futures).await;
        println!("{:?}", keys.into_iter().map(|res| res.unwrap_or_else(|e| e.to_string())).collect::<Vec<String>>());
        Ok(())
    }
}

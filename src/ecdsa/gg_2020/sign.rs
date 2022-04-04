use crate::ecdsa::gg_2020::sm_client::join_computation;
use anyhow::{anyhow, Context, Ok, Result};
use curv::arithmetic::Converter;
use curv::BigInt;
use futures::{SinkExt, StreamExt, TryStreamExt};

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::sign::{
    OfflineStage, SignManual,
};
use round_based::async_runtime::AsyncProtocol;
use round_based::Msg;

#[allow(dead_code)]
async fn sign(
    key: &Vec<u8>,
    parties: Vec<u16>,
    message: String,
    url: &str,
    room_id: &str,
) -> Result<String, anyhow::Error> {
    let address = surf::Url::parse(url.clone()).unwrap();
    let number_of_parties = parties.len();

    println!(
        "number_of_parties {}, room_id {}, host {:?} path {:?}, parties {:?} message {:?}",
        number_of_parties.clone(),
        room_id.clone(),
        address.host_str(),
        address.path(),
        parties.clone(),
        message.clone()
    );

    let local_share = serde_json::from_slice(&key).context("parse local share")?;

    let (i, incoming, outgoing) = join_computation(address.clone(), room_id.clone())
        .await
        .context("join offline computation")?;

    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let signing = OfflineStage::new(i, parties.clone(), local_share)?;
    let completed_offline_stage = AsyncProtocol::new(signing, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("protocol execution terminated with error: {}", e))?;

    let (_i, incoming, outgoing) = join_computation(address.clone(), room_id.clone())
        .await
        .context("join online computation")?;

    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let (signing, partial_signature) = SignManual::new(
        BigInt::from_bytes(message.as_bytes()),
        completed_offline_stage,
    )?;

    outgoing
        .send(Msg {
            sender: i,
            receiver: None,
            body: partial_signature,
        })
        .await?;

    let partial_signatures: Vec<_> = incoming
        .take(number_of_parties - 1)
        .map_ok(|msg| msg.body)
        .try_collect()
        .await?;
    let signature = signing
        .complete(&partial_signatures)
        .context("online stage failed")?;
    let signature = serde_json::to_string(&signature).context("serialize signature")?;
    Ok(signature)
}

#[cfg(test)]
pub mod test {
    use anyhow::{Context, Result};

    use std::env;
    use std::path::PathBuf;

    use super::sign;

    #[tokio::test]
    async fn tets_cli() -> Result<()> {
        let url = "http://localhost:8000/";
        let parties = vec![1, 2];
        let message = "hello".to_string();
        let room_id = "default-signing";
        let path = env::current_dir()?;
        let path = format!(
            "{}/local-share{}.json",
            path.as_os_str().to_str().unwrap(),
            2
        );
        let key = tokio::fs::read(&PathBuf::from(path.clone()))
            .await
            .context("cannot read local share")
            .unwrap();

        let signature = sign(&key, parties, message, url, room_id).await.unwrap();
        println!("signature {} ", signature);
        Ok(())
    }
}

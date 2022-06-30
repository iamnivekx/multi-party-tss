use anyhow::{anyhow, Context, Ok, Result};
use futures::StreamExt;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::Keygen;
use round_based::async_runtime::AsyncProtocol;
use tracing::instrument;

use crate::ecdsa::{common::party_key_compress_pub_hex, gg_2020::sm_client::join_computation};

#[instrument]
pub async fn keygen(
    index: u16,
    threshold: u16,
    parties: u16,
    address: surf::Url,
    room_id: &str,
) -> Result<(String, String), anyhow::Error> {
    let (_i, incoming, outgoing) = join_computation(address, room_id)
        .await
        .context("join computation")?;

    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);
    let keygen = Keygen::new(index, threshold, parties)?;
    let local_key = AsyncProtocol::new(keygen, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("protocol execution terminated with error: {}", e))?;
    let pk = local_key.public_key();
    let pk_hex = party_key_compress_pub_hex(&pk);
    let serialize_output = serde_json::to_string(&local_key).context("serialize output")?;

    Ok((pk_hex, serialize_output))
}

#[cfg(test)]
pub mod test {
    use super::keygen;

    use anyhow::{Context, Result};
    use futures::future;

    #[tokio::test]
    async fn test_async_keygen() -> Result<()> {
        let parties: u16 = 3;
        let threshold = 1;
        let room_id = "room_id_1_3";

        let futures = vec![1, 2, 3].into_iter().map(|i| async move {
            let address = surf::Url::parse("http://127.0.0.1:8000").unwrap();
            let output = keygen(i, threshold, parties, address.clone(), room_id)
                .await
                .context("failed to generate key")
                .unwrap();

            output
        });
        let keys = future::join_all(futures).await;
        println!("{:?}", keys);
        Ok(())
    }
}

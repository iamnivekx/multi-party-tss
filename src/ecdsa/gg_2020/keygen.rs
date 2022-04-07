use crate::ecdsa::gg_2020::sm_client::join_computation;
use anyhow::{anyhow, Context, Ok, Result};

use futures::StreamExt;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::Keygen;
use round_based::async_runtime::AsyncProtocol;

pub async fn keygen(
    index: u16,
    threshold: u16,
    parties: u16,
    address: surf::Url,
    room_id: &str,
) -> Result<String, anyhow::Error> {
    let (_i, incoming, outgoing) = join_computation(address, room_id)
        .await
        .context("join computation")?;

    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);
    let keygen = Keygen::new(index, threshold, parties)?;
    let output = AsyncProtocol::new(keygen, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("protocol execution terminated with error: {}", e))?;
    let output = serde_json::to_string(&output).context("serialize output")?;

    Ok(output)
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

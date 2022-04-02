#[cfg(test)]
pub mod test {
    use crate::ecdsa::gg_2020::sm_client::join_computation;
    use anyhow::{anyhow, Context, Result};
    use futures::future;
    use futures::StreamExt;
    use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::Keygen;
    use round_based::async_runtime::AsyncProtocol;

    #[tokio::test]
    async fn test_async_keygen() -> Result<()> {
        let futures = vec![1, 2, 3].into_iter().map(|i| async move {
            let address = surf::Url::parse("http://127.0.0.1:8000").unwrap();
            let index = i;
            let parties: u16 = 3;
            let threshold = 1;
            let room_id = "room_id_3";
            let (_i, incoming, outgoing) = join_computation(address, room_id)
                .await
                .context("join computation")
                .unwrap();

            let incoming = incoming.fuse();
            tokio::pin!(incoming);
            tokio::pin!(outgoing);

            let keygen = Keygen::new(index, threshold, parties).unwrap();
            let output = AsyncProtocol::new(keygen, incoming, outgoing)
                .run()
                .await
                .map_err(|e| anyhow!("protocol execution terminated with error: {}", e))
                .unwrap();
            let output = serde_json::to_string(&output)
                .context("serialize output")
                .unwrap();

            output
        });
        let keys = future::join_all(futures).await;
        println!("{:?}", keys);
        Ok(())
    }
}

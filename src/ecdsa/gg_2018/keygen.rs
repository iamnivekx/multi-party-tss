#![allow(unused_imports)]
use std::collections::HashMap;
use std::sync::RwLock;
use std::{env, fs, thread, time, time::Duration};
use uuid::Uuid;

use curv::{
    arithmetic::traits::*,
    cryptographic_primitives::{
        proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof,
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};

use super::adapter::Community;
use super::common::{
    aes_decrypt, aes_encrypt, broadcast, poll_for_broadcasts, poll_for_p2p, sendp2p, ECDSAError,
    Entry, Index, Key, PartySignup, AEAD, AES_KEY_BYTES_LEN,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, Parameters,
};
use paillier::EncryptionKey;
use sha2::Sha256;

pub async fn keygen_key<'a>(
    parties: u16,
    threshold: u16,
    room_id: &String,
    adapter: &Box<dyn Community + Send + Sync + 'a>,
) -> String {
    let delay = time::Duration::from_millis(25);
    let params = Parameters {
        threshold,
        share_count: parties,
    };

    //signup:
    let party_signup = adapter.get_party_signup(parties, room_id).await.unwrap();
    let party_num_int = party_signup.number;
    let uuid = party_signup.uuid;

    let party_keys = Keys::create(party_num_int);
    let (bc_i, decom_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();

    // send commitment to ephemeral public keys, get round 1 commitments of other parties
    assert!(broadcast(
        adapter,
        party_num_int,
        "round1",
        serde_json::to_string(&bc_i).unwrap(),
        uuid.clone(),
    )
    .await
    .is_ok());

    let round1_ans_vec = poll_for_broadcasts(
        adapter,
        party_num_int,
        parties,
        delay,
        "round1",
        uuid.clone(),
    )
    .await;

    let mut bc1_vec = round1_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenBroadcastMessage1>(m).unwrap())
        .collect::<Vec<_>>();

    bc1_vec.insert(party_num_int as usize - 1, bc_i);

    // send ephemeral public keys and check commitments correctness
    assert!(broadcast(
        adapter,
        party_num_int,
        "round2",
        serde_json::to_string(&decom_i).unwrap(),
        uuid.clone(),
    )
    .await
    .is_ok());

    let round2_ans_vec = poll_for_broadcasts(
        adapter,
        party_num_int,
        parties,
        delay,
        "round2",
        uuid.clone(),
    )
    .await;

    let mut j = 0;
    let mut point_vec: Vec<Point<Secp256k1>> = Vec::new();
    let mut decom_vec: Vec<KeyGenDecommitMessage1> = Vec::new();
    let mut enc_keys: Vec<Vec<u8>> = Vec::new();
    for i in 1..=parties {
        if i == party_num_int {
            point_vec.push(decom_i.y_i.clone());
            decom_vec.push(decom_i.clone());
        } else {
            let decom_j: KeyGenDecommitMessage1 = serde_json::from_str(&round2_ans_vec[j]).unwrap();
            point_vec.push(decom_j.y_i.clone());
            decom_vec.push(decom_j.clone());
            let key_bn: BigInt = (decom_j.y_i.clone() * (party_keys.u_i.clone()))
                .x_coord()
                .unwrap();
            let key_bytes = BigInt::to_bytes(&key_bn);
            let mut template: Vec<u8> = vec![0u8; AES_KEY_BYTES_LEN - key_bytes.len()];
            template.extend_from_slice(&key_bytes[..]);
            enc_keys.push(template);
            j = j + 1;
        }
    }

    let (head, tail) = point_vec.split_at(1);
    let y_sum = tail.iter().fold(head[0].clone(), |acc, x| acc + x);

    let (vss_scheme, secret_shares, _index) = party_keys
        .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
            &params, &decom_vec, &bc1_vec,
        )
        .expect("invalid key");

    //////////////////////////////////////////////////////////////////////////////

    let mut j = 0;
    for (k, i) in (1..=parties).enumerate() {
        if i != party_num_int {
            // prepare encrypted ss for party i:
            let key_i = &enc_keys[j];
            let plaintext = BigInt::to_bytes(&secret_shares[k].to_bigint());
            let aead_pack_i = aes_encrypt(key_i, &plaintext);
            assert!(sendp2p(
                adapter,
                party_num_int,
                i,
                "round3",
                serde_json::to_string(&aead_pack_i).unwrap(),
                uuid.clone(),
            )
            .await
            .is_ok());
            j += 1;
        }
    }

    let round3_ans_vec = poll_for_p2p(
        adapter,
        party_num_int,
        parties,
        delay,
        "round3",
        uuid.clone(),
    )
    .await;

    let mut j = 0;
    let mut party_shares: Vec<Scalar<Secp256k1>> = Vec::new();
    for i in 1..=parties {
        if i == party_num_int {
            party_shares.push(secret_shares[usize::from(i - 1)].clone());
        } else {
            let aead_pack: AEAD = serde_json::from_str(&round3_ans_vec[j]).unwrap();
            let key_i = &enc_keys[j];
            let out = aes_decrypt(key_i, aead_pack);
            let out_bn = BigInt::from_bytes(&out[..]);
            let out_fe = Scalar::<Secp256k1>::from(&out_bn);
            party_shares.push(out_fe);

            j += 1;
        }
    }

    // round 4: send vss commitments
    assert!(broadcast(
        adapter,
        party_num_int,
        "round4",
        serde_json::to_string(&vss_scheme).unwrap(),
        uuid.clone(),
    )
    .await
    .is_ok());
    let round4_ans_vec = poll_for_broadcasts(
        adapter,
        party_num_int,
        parties,
        delay,
        "round4",
        uuid.clone(),
    )
    .await;

    let mut j = 0;
    let mut vss_scheme_vec: Vec<VerifiableSS<Secp256k1>> = Vec::new();
    for i in 1..=parties {
        if i == party_num_int {
            vss_scheme_vec.push(vss_scheme.clone());
        } else {
            let vss_scheme_j: VerifiableSS<Secp256k1> =
                serde_json::from_str(&round4_ans_vec[j]).unwrap();
            vss_scheme_vec.push(vss_scheme_j);
            j += 1;
        }
    }

    let (shared_keys, dlog_proof) = party_keys
        .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
            &params,
            &point_vec,
            &party_shares,
            &vss_scheme_vec,
            party_num_int,
        )
        .expect("invalid vss");

    // round 5: send dlog proof
    assert!(broadcast(
        adapter,
        party_num_int,
        "round5",
        serde_json::to_string(&dlog_proof).unwrap(),
        uuid.clone(),
    )
    .await
    .is_ok());

    let round5_ans_vec = poll_for_broadcasts(
        adapter,
        party_num_int,
        parties,
        delay,
        "round5",
        uuid.clone(),
    )
    .await;

    let mut j = 0;
    let mut dlog_proof_vec: Vec<DLogProof<Secp256k1, Sha256>> = Vec::new();
    for i in 1..=parties {
        if i == party_num_int {
            dlog_proof_vec.push(dlog_proof.clone());
        } else {
            let dlog_proof_j: DLogProof<Secp256k1, Sha256> =
                serde_json::from_str(&round5_ans_vec[j]).unwrap();
            dlog_proof_vec.push(dlog_proof_j);
            j += 1;
        }
    }
    Keys::verify_dlog_proofs(&params, &dlog_proof_vec, &point_vec).expect("bad dlog proof");

    //save key to file:
    let paillier_key_vec = (0..parties)
        .map(|i| bc1_vec[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();

    let keygen_json = serde_json::to_string(&(
        party_keys,
        shared_keys,
        party_num_int,
        vss_scheme_vec,
        paillier_key_vec,
        y_sum,
    ))
    .unwrap();
    keygen_json
}

#[cfg(test)]
pub mod test {
    use super::keygen_key;
    use crate::ecdsa::gg_2018::common::Community;
    use crate::ecdsa::gg_2018::{adapter::StoreCommunity, common::party_key_pub_hex};
    use futures::future;
    use std::collections::HashMap;
    use std::io::Read;
    use std::sync::RwLock;

    #[tokio::test]
    async fn test_keygen_key_async() {
        use futures::future;
        let db: HashMap<String, String> = HashMap::new();
        let store = RwLock::new(db);
        let adapter: Box<dyn Community + Send + Sync> = Box::new(StoreCommunity::new(&store));
        let parties: u16 = 3;
        let threshold = 1;
        let room_id = "room_id".to_string();
        // let adapter =
        let futures = (0..parties).map(|_| keygen_key(parties, threshold, &room_id, &adapter));
        let results = future::join_all(futures).await;

        let pub_key1 = &results[0];
        let pub_key2 = &results[1];
        let pub_key3 = &results[2];
        let pub_hex = party_key_pub_hex(&pub_key1);
        println!("pub_hex : {}", pub_hex.clone());
        println!("pub_key1 : {}", pub_key1.clone());
        println!("pub_key2 : {}", pub_key2.clone());
        println!("pub_key3 : {}", pub_key3.clone());
        assert_eq!(pub_hex, party_key_pub_hex(&pub_key2));
        assert_eq!(pub_hex, party_key_pub_hex(&pub_key3));
    }
}

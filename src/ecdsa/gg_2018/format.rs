#![allow(unused_imports)]

use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::{time, time::Duration};

use curv::{
    arithmetic::traits::*,
    cryptographic_primitives::{
        proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof,
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    Keys, LocalSignature, PartyPrivate, Phase5ADecom1, Phase5Com1, Phase5Com2, Phase5DDecom2,
    SharedKeys, SignBroadcastPhase1, SignDecommitPhase1, SignKeys,
};
use multi_party_ecdsa::utilities::mta::*;
use paillier::EncryptionKey;

use super::common::{
    aes_decrypt, aes_encrypt, broadcast, check_sig, poll_for_broadcasts, poll_for_p2p, send_p2p,
    ECDSAError, Entry, Index, Key, PartySignup, AEAD,
};

pub fn format_vec_from_reads<'a, T: serde::Deserialize<'a> + Clone>(
    ans_vec: &'a [String],
    party_num: usize,
    value_i: T,
    new_vec: &'a mut Vec<T>,
) {
    let mut j = 0;
    for i in 1..ans_vec.len() + 2 {
        if i == party_num {
            new_vec.push(value_i.clone());
        } else {
            let value_j: T = serde_json::from_str(&ans_vec[j]).unwrap();
            new_vec.push(value_j);
            j += 1;
        }
    }
}

pub fn format_signers(
    threshold: u16,
    party_num_int: u16,
    party_id: u16,
    round0_ans_vec: Vec<String>,
) -> Vec<u16> {
    let mut j = 0;
    let mut signers_vec: Vec<u16> = Vec::new();
    for i in 1..=threshold + 1 {
        if i == party_num_int {
            signers_vec.push(party_id - 1);
        } else {
            let signer_j: u16 = serde_json::from_str(&round0_ans_vec[j]).unwrap();
            signers_vec.push(signer_j - 1);
            j += 1;
        }
    }
    signers_vec
}

pub fn format_broadcast_phase1_and_message_a_vec(
    threshold: u16,
    party_num_int: u16,
    com: &SignBroadcastPhase1,
    round1_ans_vec: Vec<String>,
) -> (Vec<SignBroadcastPhase1>, Vec<MessageA>) {
    let mut bc1_vec: Vec<SignBroadcastPhase1> = Vec::new();
    let mut m_a_vec: Vec<MessageA> = Vec::new();
    let mut j = 0;
    for i in 1..=threshold + 1 {
        if i == party_num_int {
            bc1_vec.push(com.clone());
        } else {
            let (bc1_j, m_a_party_j): (SignBroadcastPhase1, MessageA) =
                serde_json::from_str(&round1_ans_vec[j]).unwrap();
            bc1_vec.push(bc1_j);
            m_a_vec.push(m_a_party_j);
            j += 1;
        }
    }
    (bc1_vec, m_a_vec)
}

pub fn format_message_b_and_ni_vec(
    threshold: u16,
    party_num_int: u16,
    sign_keys: &SignKeys,
    pallier_key_vector: &Vec<EncryptionKey>,
    m_a_vec: &Vec<MessageA>,
    signers_vec: &Vec<u16>,
) -> (
    Vec<MessageB>,
    Vec<Scalar<Secp256k1>>,
    Vec<MessageB>,
    Vec<Scalar<Secp256k1>>,
) {
    let mut m_b_gamma_send_vec: Vec<MessageB> = Vec::new();
    let mut beta_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    let mut m_b_w_send_vec: Vec<MessageB> = Vec::new();
    let mut ni_vec: Vec<Scalar<Secp256k1>> = Vec::new();

    let mut j = 0;
    for i in 1..=threshold + 1 {
        if i == party_num_int {
            continue;
        }
        let message_a = m_a_vec[j].clone();
        let (m_b_gamma, beta_gamma, _, _) = MessageB::b(
            &sign_keys.gamma_i,
            &pallier_key_vector[usize::from(signers_vec[usize::from(i - 1)])],
            message_a.clone(),
            &[],
        )
        .unwrap();
        let (m_b_w, beta_wi, _, _) = MessageB::b(
            &sign_keys.w_i,
            &pallier_key_vector[usize::from(signers_vec[usize::from(i - 1)])],
            message_a.clone(),
            &[],
        )
        .unwrap();
        m_b_gamma_send_vec.push(m_b_gamma);
        m_b_w_send_vec.push(m_b_w);
        beta_vec.push(beta_gamma);
        ni_vec.push(beta_wi);
        j += 1;
    }
    (m_b_gamma_send_vec, beta_vec, m_b_w_send_vec, ni_vec)
}

pub fn format_round2_rec_gamma_and_w_vec(
    threshold: u16,
    round2_ans_vec: Vec<String>,
) -> (Vec<MessageB>, Vec<MessageB>) {
    let mut m_b_gamma_rec_vec: Vec<MessageB> = Vec::new();
    let mut m_b_w_rec_vec: Vec<MessageB> = Vec::new();
    for i in 0..threshold {
        let (m_b_gamma_i, m_b_w_i): (MessageB, MessageB) =
            serde_json::from_str(&round2_ans_vec[i as usize]).unwrap();
        m_b_gamma_rec_vec.push(m_b_gamma_i);
        m_b_w_rec_vec.push(m_b_w_i);
    }
    (m_b_gamma_rec_vec, m_b_w_rec_vec)
}

pub fn format_round2_alpha_and_miu_vec(
    threshold: u16,
    party_num_int: u16,
    m_b_gamma_rec_vec: &Vec<MessageB>,
    m_b_w_rec_vec: &Vec<MessageB>,
    xi_com_vec: &Vec<Point<Secp256k1>>,
    vss_scheme_vec: &Vec<VerifiableSS<Secp256k1>>,
    party_keys: &Keys,
    sign_keys: &SignKeys,
    signers_vec: &Vec<u16>,
) -> (Vec<Scalar<Secp256k1>>, Vec<Scalar<Secp256k1>>) {
    let mut alpha_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    let mut miu_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    let mut j = 0;
    for i in 1..threshold + 2 {
        if i != party_num_int {
            let m_b = m_b_gamma_rec_vec[j].clone();

            let alpha_ij_gamma = m_b
                .verify_proofs_get_alpha(&party_keys.dk, &sign_keys.k_i)
                .expect("wrong dlog or m_b");
            let m_b = m_b_w_rec_vec[j].clone();
            let alpha_ij_wi = m_b
                .verify_proofs_get_alpha(&party_keys.dk, &sign_keys.k_i)
                .expect("wrong dlog or m_b");
            alpha_vec.push(alpha_ij_gamma.0);
            miu_vec.push(alpha_ij_wi.0);
            let g_w_i = Keys::update_commitments_to_xi(
                &xi_com_vec[usize::from(signers_vec[usize::from(i - 1)])],
                &vss_scheme_vec[usize::from(signers_vec[usize::from(i - 1)])],
                signers_vec[usize::from(i - 1)],
                &signers_vec,
            );
            assert_eq!(m_b.b_proof.pk, g_w_i);
            j += 1;
        }
    }
    (alpha_vec, miu_vec)
}

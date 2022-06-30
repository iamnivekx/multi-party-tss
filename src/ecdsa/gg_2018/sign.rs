#![allow(non_snake_case)]
use curv::{
    arithmetic::traits::*,
    cryptographic_primitives::{
        proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof,
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};
use serde_json::json;
use std::time;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    Keys, LocalSignature, PartyPrivate, Phase5ADecom1, Phase5Com1, Phase5Com2, Phase5DDecom2,
    SharedKeys, SignDecommitPhase1, SignKeys,
};
use multi_party_ecdsa::utilities::mta::*;
use paillier::EncryptionKey;
use sha2::Sha256;

use super::common::{broadcast, check_sig, poll_for_broadcasts, poll_for_p2p, send_p2p};
use super::format::{
    format_broadcast_phase1_and_message_a_vec, format_message_b_and_ni_vec,
    format_round2_alpha_and_miu_vec, format_round2_rec_gamma_and_w_vec, format_signers,
    format_vec_from_reads,
};

use super::adapter::Community;

pub async fn sign<'a>(
    parties: u16,
    threshold: u16,
    key: &String,
    room_id: &String,
    msg: &String,
    adapter: &Box<dyn Community + Send + Sync + 'a>,
) -> String {
    let message = match hex::decode(msg.clone()) {
        Ok(x) => x,
        Err(_e) => msg.as_bytes().to_vec(),
    };
    let message = &message[..];
    // delay:
    let delay = time::Duration::from_millis(25);
    // read key file
    let (party_keys, shared_keys, party_id, vss_scheme_vec, paillier_key_vector, y_sum): (
        Keys,
        SharedKeys,
        u16,
        Vec<VerifiableSS<Secp256k1>>,
        Vec<EncryptionKey>,
        Point<Secp256k1>,
    ) = serde_json::from_str(&key).unwrap();

    //signup:
    let party_signup = adapter.get_party_signup(parties, room_id).await.unwrap();
    let party_num_int = party_signup.number;
    let uuid = party_signup.uuid;

    // round 0: collect signers IDs
    assert!(broadcast(
        adapter,
        party_num_int,
        "round0",
        serde_json::to_string(&party_id).unwrap(),
        uuid.clone(),
    )
    .await
    .is_ok());
    let round0_ans_vec = poll_for_broadcasts(
        adapter,
        party_num_int,
        threshold + 1,
        delay,
        "round0",
        uuid.clone(),
    )
    .await;

    let signers_vec = format_signers(threshold, party_num_int, party_id, round0_ans_vec);

    let private = PartyPrivate::set_private(party_keys.clone(), shared_keys);

    let sign_keys = SignKeys::create(
        &private,
        &vss_scheme_vec[usize::from(signers_vec[usize::from(party_num_int - 1)])],
        signers_vec[usize::from(party_num_int - 1)],
        &signers_vec,
    );

    let xi_com_vec = Keys::get_commitments_to_xi(&vss_scheme_vec);
    //////////////////////////////////////////////////////////////////////////////
    let (com, decommit) = sign_keys.phase1_broadcast();
    let (m_a_k, _) = MessageA::a(&sign_keys.k_i, &party_keys.ek, &[]);
    assert!(broadcast(
        adapter,
        party_num_int,
        "round1",
        serde_json::to_string(&(com.clone(), m_a_k.clone())).unwrap(),
        uuid.clone(),
    )
    .await
    .is_ok());

    let round1_ans_vec = poll_for_broadcasts(
        adapter,
        party_num_int,
        threshold + 1,
        delay,
        "round1",
        uuid.clone(),
    )
    .await;
    let (mut bc1_vec, m_a_vec) =
        format_broadcast_phase1_and_message_a_vec(threshold, party_num_int, &com, round1_ans_vec);
    assert_eq!(signers_vec.len(), bc1_vec.len());

    //////////////////////////////////////////////////////////////////////////////
    let (m_b_gamma_send_vec, beta_vec, m_b_w_send_vec, ni_vec) = format_message_b_and_ni_vec(
        threshold,
        party_num_int,
        &sign_keys,
        &paillier_key_vector,
        &m_a_vec,
        &signers_vec,
    );

    let mut j = 0;
    for i in 1..=threshold + 1 {
        if i != party_num_int {
            assert!(send_p2p(
                adapter,
                party_num_int,
                i,
                "round2",
                serde_json::to_string(&(m_b_gamma_send_vec[j].clone(), m_b_w_send_vec[j].clone(),))
                    .unwrap(),
                uuid.clone(),
            )
            .await
            .is_ok());
            j += 1;
        }
    }

    let round2_ans_vec = poll_for_p2p(
        adapter,
        party_num_int,
        threshold + 1,
        delay,
        "round2",
        uuid.clone(),
    )
    .await;

    let (m_b_gamma_rec_vec, m_b_w_rec_vec) =
        format_round2_rec_gamma_and_w_vec(threshold, round2_ans_vec);
    let (alpha_vec, miu_vec) = format_round2_alpha_and_miu_vec(
        threshold,
        party_num_int,
        &m_b_gamma_rec_vec,
        &m_b_w_rec_vec,
        &xi_com_vec,
        &vss_scheme_vec,
        &party_keys,
        &sign_keys,
        &signers_vec,
    );

    //////////////////////////////////////////////////////////////////////////////
    let delta_i = sign_keys.phase2_delta_i(&alpha_vec, &beta_vec);
    let sigma = sign_keys.phase2_sigma_i(&miu_vec, &ni_vec);

    assert!(broadcast(
        adapter,
        party_num_int,
        "round3",
        serde_json::to_string(&delta_i).unwrap(),
        uuid.clone(),
    )
    .await
    .is_ok());
    let round3_ans_vec = poll_for_broadcasts(
        adapter,
        party_num_int,
        threshold + 1,
        delay,
        "round3",
        uuid.clone(),
    )
    .await;
    let mut delta_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    format_vec_from_reads(
        &round3_ans_vec,
        party_num_int as usize,
        delta_i,
        &mut delta_vec,
    );
    let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);

    //////////////////////////////////////////////////////////////////////////////
    // decommit to gamma_i
    assert!(broadcast(
        adapter,
        party_num_int,
        "round4",
        serde_json::to_string(&decommit).unwrap(),
        uuid.clone(),
    )
    .await
    .is_ok());
    let round4_ans_vec = poll_for_broadcasts(
        adapter,
        party_num_int,
        threshold + 1,
        delay,
        "round4",
        uuid.clone(),
    )
    .await;

    let mut decommit_vec: Vec<SignDecommitPhase1> = Vec::new();
    format_vec_from_reads(
        &round4_ans_vec,
        party_num_int as usize,
        decommit,
        &mut decommit_vec,
    );
    let decomm_i = decommit_vec.remove((party_num_int - 1) as usize);
    bc1_vec.remove((party_num_int - 1) as usize);
    let b_proof_vec = (0..m_b_gamma_rec_vec.len())
        .map(|i| &m_b_gamma_rec_vec[i].b_proof)
        .collect::<Vec<&DLogProof<Secp256k1, Sha256>>>();
    let R = SignKeys::phase4(&delta_inv, &b_proof_vec, decommit_vec, &bc1_vec)
        .expect("bad gamma_i decommit");

    // adding local g_gamma_i
    let R = R + decomm_i.g_gamma_i * delta_inv;

    // we assume the message is already hashed (by the signer).
    let message_bn = BigInt::from_bytes(message);
    let local_sig =
        LocalSignature::phase5_local_sig(&sign_keys.k_i, &message_bn, &R, &sigma, &y_sum);

    let (phase5_com, phase_5a_decom, helgamal_proof, dlog_proof_rho) =
        local_sig.phase5a_broadcast_5b_zkproof();

    //phase (5A)  broadcast commit
    assert!(broadcast(
        adapter,
        party_num_int,
        "round5",
        serde_json::to_string(&phase5_com).unwrap(),
        uuid.clone(),
    )
    .await
    .is_ok());
    let round5_ans_vec = poll_for_broadcasts(
        adapter,
        party_num_int,
        threshold + 1,
        delay,
        "round5",
        uuid.clone(),
    )
    .await;

    let mut commit5a_vec: Vec<Phase5Com1> = Vec::new();
    format_vec_from_reads(
        &round5_ans_vec,
        party_num_int as usize,
        phase5_com,
        &mut commit5a_vec,
    );

    //phase (5B)  broadcast decommit and (5B) ZK proof
    assert!(broadcast(
        adapter,
        party_num_int,
        "round6",
        serde_json::to_string(&(
            phase_5a_decom.clone(),
            helgamal_proof.clone(),
            dlog_proof_rho.clone(),
        ))
        .unwrap(),
        uuid.clone(),
    )
    .await
    .is_ok());
    let round6_ans_vec = poll_for_broadcasts(
        adapter,
        party_num_int,
        threshold + 1,
        delay,
        "round6",
        uuid.clone(),
    )
    .await;

    let mut decommit5a_and_elgamal_and_dlog_vec: Vec<(
        Phase5ADecom1,
        HomoELGamalProof<Secp256k1, Sha256>,
        DLogProof<Secp256k1, Sha256>,
    )> = Vec::new();
    format_vec_from_reads(
        &round6_ans_vec,
        party_num_int as usize,
        (
            phase_5a_decom.clone(),
            helgamal_proof.clone(),
            dlog_proof_rho.clone(),
        ),
        &mut decommit5a_and_elgamal_and_dlog_vec,
    );
    let decommit5a_and_elgamal_and_dlog_vec_includes_i =
        decommit5a_and_elgamal_and_dlog_vec.clone();
    decommit5a_and_elgamal_and_dlog_vec.remove((party_num_int - 1) as usize);
    commit5a_vec.remove((party_num_int - 1) as usize);
    let phase_5a_decomm_vec = (0..threshold)
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].0.clone())
        .collect::<Vec<Phase5ADecom1>>();
    let phase_5a_elgamal_vec = (0..threshold)
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].1.clone())
        .collect::<Vec<HomoELGamalProof<Secp256k1, Sha256>>>();
    let phase_5a_dlog_vec = (0..threshold)
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].2.clone())
        .collect::<Vec<DLogProof<Secp256k1, Sha256>>>();
    let (phase5_com2, phase_5d_decom2) = local_sig
        .phase5c(
            &phase_5a_decomm_vec,
            &commit5a_vec,
            &phase_5a_elgamal_vec,
            &phase_5a_dlog_vec,
            &phase_5a_decom.V_i,
            &R,
        )
        .expect("error phase5");

    //////////////////////////////////////////////////////////////////////////////
    assert!(broadcast(
        adapter,
        party_num_int,
        "round7",
        serde_json::to_string(&phase5_com2).unwrap(),
        uuid.clone(),
    )
    .await
    .is_ok());
    let round7_ans_vec = poll_for_broadcasts(
        adapter,
        party_num_int,
        threshold + 1,
        delay,
        "round7",
        uuid.clone(),
    )
    .await;

    let mut commit5c_vec: Vec<Phase5Com2> = Vec::new();
    format_vec_from_reads(
        &round7_ans_vec,
        party_num_int as usize,
        phase5_com2,
        &mut commit5c_vec,
    );

    //phase (5B)  broadcast decommit and (5B) ZK proof
    assert!(broadcast(
        adapter,
        party_num_int,
        "round8",
        serde_json::to_string(&phase_5d_decom2).unwrap(),
        uuid.clone(),
    )
    .await
    .is_ok());
    let round8_ans_vec = poll_for_broadcasts(
        adapter,
        party_num_int,
        threshold + 1,
        delay,
        "round8",
        uuid.clone(),
    )
    .await;

    let mut decommit5d_vec: Vec<Phase5DDecom2> = Vec::new();
    format_vec_from_reads(
        &round8_ans_vec,
        party_num_int as usize,
        phase_5d_decom2.clone(),
        &mut decommit5d_vec,
    );

    let phase_5a_decomm_vec_includes_i = (0..=threshold)
        .map(|i| {
            decommit5a_and_elgamal_and_dlog_vec_includes_i[i as usize]
                .0
                .clone()
        })
        .collect::<Vec<Phase5ADecom1>>();
    let s_i = local_sig
        .phase5d(
            &decommit5d_vec,
            &commit5c_vec,
            &phase_5a_decomm_vec_includes_i,
        )
        .expect("bad com 5d");

    //////////////////////////////////////////////////////////////////////////////
    assert!(broadcast(
        adapter,
        party_num_int,
        "round9",
        serde_json::to_string(&s_i).unwrap(),
        uuid.clone(),
    )
    .await
    .is_ok());
    let round9_ans_vec = poll_for_broadcasts(
        adapter,
        party_num_int,
        threshold + 1,
        delay,
        "round9",
        uuid.clone(),
    )
    .await;

    let mut s_i_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    format_vec_from_reads(&round9_ans_vec, party_num_int as usize, s_i, &mut s_i_vec);

    s_i_vec.remove((party_num_int - 1) as usize);
    let sig = local_sig
        .output_signature(&s_i_vec)
        .expect("verification failed");

    let sign_json = json!({
        "r": BigInt::from_bytes(sig.r.to_bytes().as_ref()).to_str_radix(16),
        "s":  BigInt::from_bytes(sig.s.to_bytes().as_ref()).to_str_radix(16),
        "v":sig.recid.clone(),
    });
    // check sig against secp256k1
    check_sig(&sig.r, &sig.s, &message_bn, &y_sum);
    sign_json.to_string()
}

#[cfg(test)]
pub mod test {
    use super::sign;
    use crate::ecdsa::gg_2018::adapter::StoreCommunity;
    use crate::ecdsa::gg_2018::common::Community;
    use std::collections::HashMap;
    use std::sync::RwLock;

    #[tokio::test]
    async fn test_sign_async() {
        use futures::future;

        let db: HashMap<String, String> = HashMap::new();
        let store = RwLock::new(db);
        let adapter: Box<dyn Community + Send + Sync> = Box::new(StoreCommunity::new(&store));

        let parties: u16 = 3;
        let threshold = 1;
        let room_id = "signup_".to_string();
        let message = "68656c6c6f20776f726c64".to_string();

        let keys = [
            r#"[{"u_i":{"curve":"secp256k1","scalar":[168,103,16,161,20,54,2,80,17,100,11,166,20,120,82,115,68,31,70,24,36,167,171,162,67,203,179,151,13,130,35,120]},"y_i":{"curve":"secp256k1","point":[2,208,91,104,3,89,40,129,170,58,201,234,36,140,113,186,218,107,174,141,229,121,4,128,119,43,225,144,60,118,219,112,11]},"dk":{"p":"89946124294230763161866437910149020596410526829370893582310694443404118736264496394493125529687651537921025287318328409909707318368729219975611445656145390687970888942820132063475495245937654250001532528264574273889262914810353302804392488545936979047221495497124131990739275600413915398270266816766585618451","q":"149313575310042793176769239547461262109620289949804026504525231446476127044311502170849218844132485753775470793144586941856136954964509150660533262170369190502995948793098621971684745991660626479373691405263541240762105369273059610818343423996820055655144801929848793607994362329986788427183957673855465777163"},"ek":{"n":"13430177403653094734284749105839063373123090514283420069287822514799171673891423664451345877476898674596363542265880878290868522191770304062093002284820197165581711699437091381538833183901171347337446279747150955986572720492947594557938334062499775668714281856334605192956069553352509122333182837281433980046649627743031398376901998870460579475468751333595108042612837225772027315805734527352679955155986378698049646020128805543661152488050652797414142932074223324742684702999835560971666087625805823941197882283558025996160918433591669443101411726516727413648649578377369914585638070333589409423109109381163707234513"},"party_index":1},{"y":{"curve":"secp256k1","point":[3,58,77,219,150,151,252,204,142,255,45,75,48,15,101,45,24,4,95,107,41,195,119,235,149,50,100,31,163,196,5,55,104]},"x_i":{"curve":"secp256k1","scalar":[22,145,64,113,168,47,8,25,212,36,243,89,205,85,123,107,74,241,144,100,216,218,53,205,117,160,21,247,186,139,43,251]}},1,[{"parameters":{"threshold":1,"share_count":3},"commitments":[{"curve":"secp256k1","point":[2,208,91,104,3,89,40,129,170,58,201,234,36,140,113,186,218,107,174,141,229,121,4,128,119,43,225,144,60,118,219,112,11]},{"curve":"secp256k1","point":[3,151,12,253,186,175,117,232,205,14,23,232,241,51,155,86,204,42,71,222,187,250,157,146,203,138,30,240,111,158,42,90,49]}]},{"parameters":{"threshold":1,"share_count":3},"commitments":[{"curve":"secp256k1","point":[2,108,238,193,117,74,96,237,226,114,87,173,116,34,99,207,243,77,164,105,70,254,60,99,225,23,106,33,209,84,56,26,64]},{"curve":"secp256k1","point":[3,248,196,38,65,178,140,75,251,152,237,12,76,191,61,184,19,223,9,23,126,42,221,3,242,6,254,100,184,212,0,92,146]}]},{"parameters":{"threshold":1,"share_count":3},"commitments":[{"curve":"secp256k1","point":[3,227,156,84,207,62,244,112,117,199,130,205,230,143,6,101,29,113,135,82,20,46,130,113,185,209,136,163,227,151,105,4,102]},{"curve":"secp256k1","point":[3,51,139,74,209,54,45,235,40,192,228,34,13,130,84,190,83,206,140,225,244,32,131,95,225,237,134,118,82,76,9,217,235]}]}],[{"n":"13430177403653094734284749105839063373123090514283420069287822514799171673891423664451345877476898674596363542265880878290868522191770304062093002284820197165581711699437091381538833183901171347337446279747150955986572720492947594557938334062499775668714281856334605192956069553352509122333182837281433980046649627743031398376901998870460579475468751333595108042612837225772027315805734527352679955155986378698049646020128805543661152488050652797414142932074223324742684702999835560971666087625805823941197882283558025996160918433591669443101411726516727413648649578377369914585638070333589409423109109381163707234513"},{"n":"15200378547566505087063668898382604439912637712665137709638489070195262543627015653618149623835131369698156874919992319946446826420531832724980063843832189151944987449936090500748855948294353425509484626552048238720135439820139908160348893053189853050297651158692361474514274606305768156515885449165628801333069650617228781461198341901992699367594834480149579812272716933410841255490975792900225149100585086446829249417408448853835365228949562645492166624085522593122746471185849361944326002601987767873566532301026425950795548801195819842818665757503717769637341137007584814517820779590611538309558850821471851701413"},{"n":"19012870963126585215010502377022930737435240499120684216852501732272451758139596835171693631359128710199900925400018214950332993124452026525719848404334036936171597959259597756015203372360386624808866170560892289421705564851150348707217373558230172836701856614016550349649019833393150651309049713863980506136977764811141854367199547068130866988285108077491813878122378242474462919386678564007269848943776698530135128426004578399874425752593995681923869655734971605311862899903348502691925242668321073688411173197725040539716953758523940991563982349016166572865989706834029783646627583165092208571877800675291555028863"}],{"curve":"secp256k1","point":[3,58,77,219,150,151,252,204,142,255,45,75,48,15,101,45,24,4,95,107,41,195,119,235,149,50,100,31,163,196,5,55,104]}]"#,
            r#"[{"u_i":{"curve":"secp256k1","scalar":[8,17,105,249,128,167,175,82,65,222,103,211,33,44,51,13,224,61,79,113,236,128,192,140,20,235,15,18,27,244,109,107]},"y_i":{"curve":"secp256k1","point":[2,108,238,193,117,74,96,237,226,114,87,173,116,34,99,207,243,77,164,105,70,254,60,99,225,23,106,33,209,84,56,26,64]},"dk":{"p":"117632038910001151072469744424481901181270582594959937106123234801158925935473224478003827101921213319910526977465580185106108241684900066589851449822614822665451244325927001300511926878436142363542100478425893398455711756666512490402536416366700660254385262721105331649708145071929871608129364553363749020717","q":"129219715040356740729787438181496292103813946718060775096346433000395571841867094038682468518822744556424860014131450568080852978618718343661097951819293695502077690595207681339504743157930699958222082095492887709199544763469364290319090738316506810492732127511130678065394644744479467698069347761314435052889"},"ek":{"n":"15200378547566505087063668898382604439912637712665137709638489070195262543627015653618149623835131369698156874919992319946446826420531832724980063843832189151944987449936090500748855948294353425509484626552048238720135439820139908160348893053189853050297651158692361474514274606305768156515885449165628801333069650617228781461198341901992699367594834480149579812272716933410841255490975792900225149100585086446829249417408448853835365228949562645492166624085522593122746471185849361944326002601987767873566532301026425950795548801195819842818665757503717769637341137007584814517820779590611538309558850821471851701413"},"party_index":2},{"y":{"curve":"secp256k1","point":[3,58,77,219,150,151,252,204,142,255,45,75,48,15,101,45,24,4,95,107,41,195,119,235,149,50,100,31,163,196,5,55,104]},"x_i":{"curve":"secp256k1","scalar":[78,83,31,35,110,167,33,56,95,201,114,90,236,225,242,249,138,69,122,199,38,53,69,96,0,109,123,39,139,109,163,69]}},2,[{"parameters":{"threshold":1,"share_count":3},"commitments":[{"curve":"secp256k1","point":[2,208,91,104,3,89,40,129,170,58,201,234,36,140,113,186,218,107,174,141,229,121,4,128,119,43,225,144,60,118,219,112,11]},{"curve":"secp256k1","point":[3,151,12,253,186,175,117,232,205,14,23,232,241,51,155,86,204,42,71,222,187,250,157,146,203,138,30,240,111,158,42,90,49]}]},{"parameters":{"threshold":1,"share_count":3},"commitments":[{"curve":"secp256k1","point":[2,108,238,193,117,74,96,237,226,114,87,173,116,34,99,207,243,77,164,105,70,254,60,99,225,23,106,33,209,84,56,26,64]},{"curve":"secp256k1","point":[3,248,196,38,65,178,140,75,251,152,237,12,76,191,61,184,19,223,9,23,126,42,221,3,242,6,254,100,184,212,0,92,146]}]},{"parameters":{"threshold":1,"share_count":3},"commitments":[{"curve":"secp256k1","point":[3,227,156,84,207,62,244,112,117,199,130,205,230,143,6,101,29,113,135,82,20,46,130,113,185,209,136,163,227,151,105,4,102]},{"curve":"secp256k1","point":[3,51,139,74,209,54,45,235,40,192,228,34,13,130,84,190,83,206,140,225,244,32,131,95,225,237,134,118,82,76,9,217,235]}]}],[{"n":"13430177403653094734284749105839063373123090514283420069287822514799171673891423664451345877476898674596363542265880878290868522191770304062093002284820197165581711699437091381538833183901171347337446279747150955986572720492947594557938334062499775668714281856334605192956069553352509122333182837281433980046649627743031398376901998870460579475468751333595108042612837225772027315805734527352679955155986378698049646020128805543661152488050652797414142932074223324742684702999835560971666087625805823941197882283558025996160918433591669443101411726516727413648649578377369914585638070333589409423109109381163707234513"},{"n":"15200378547566505087063668898382604439912637712665137709638489070195262543627015653618149623835131369698156874919992319946446826420531832724980063843832189151944987449936090500748855948294353425509484626552048238720135439820139908160348893053189853050297651158692361474514274606305768156515885449165628801333069650617228781461198341901992699367594834480149579812272716933410841255490975792900225149100585086446829249417408448853835365228949562645492166624085522593122746471185849361944326002601987767873566532301026425950795548801195819842818665757503717769637341137007584814517820779590611538309558850821471851701413"},{"n":"19012870963126585215010502377022930737435240499120684216852501732272451758139596835171693631359128710199900925400018214950332993124452026525719848404334036936171597959259597756015203372360386624808866170560892289421705564851150348707217373558230172836701856614016550349649019833393150651309049713863980506136977764811141854367199547068130866988285108077491813878122378242474462919386678564007269848943776698530135128426004578399874425752593995681923869655734971605311862899903348502691925242668321073688411173197725040539716953758523940991563982349016166572865989706834029783646627583165092208571877800675291555028863"}],{"curve":"secp256k1","point":[3,58,77,219,150,151,252,204,142,255,45,75,48,15,101,45,24,4,95,107,41,195,119,235,149,50,100,31,163,196,5,55,104]}]"#,
            // r#"[{"u_i":{"curve":"secp256k1","scalar":[46,86,231,37,76,217,61,88,245,62,0,223,120,36,126,90,161,239,237,95,41,159,90,72,81,238,76,171,144,104,101,15]},"y_i":{"curve":"secp256k1","point":[3,227,156,84,207,62,244,112,117,199,130,205,230,143,6,101,29,113,135,82,20,46,130,113,185,209,136,163,227,151,105,4,102]},"dk":{"p":"131015113375929744012820180167527541494824829813999924851454585846154120050557446502149268963198738298292008237205353863019893338362960299203137994519634916986722421530644006949181393644854801353407932094273652787740516302904187825503058365298633033040277471637712274822020839485668345778200600622606500960523","q":"145119677212901248340269280105587821035047043455677303026614780430898102943956503303094490903652930840018560007451819513621653299591445105991895374112762631334399118746515916744824028964150210179586049047221013318928370984838147593274174037817697426562483891871145319170316492891621747912229377491677433455581"},"ek":{"n":"19012870963126585215010502377022930737435240499120684216852501732272451758139596835171693631359128710199900925400018214950332993124452026525719848404334036936171597959259597756015203372360386624808866170560892289421705564851150348707217373558230172836701856614016550349649019833393150651309049713863980506136977764811141854367199547068130866988285108077491813878122378242474462919386678564007269848943776698530135128426004578399874425752593995681923869655734971605311862899903348502691925242668321073688411173197725040539716953758523940991563982349016166572865989706834029783646627583165092208571877800675291555028863"},"party_index":3},{"y":{"curve":"secp256k1","point":[3,58,77,219,150,151,252,204,142,255,45,75,48,15,101,45,24,4,95,107,41,195,119,235,149,50,100,31,163,196,5,55,104]},"x_i":{"curve":"secp256k1","scalar":[134,20,253,213,53,31,58,86,235,109,241,92,12,110,106,135,201,153,101,41,115,144,84,242,139,58,224,87,92,80,26,143]}},3,[{"parameters":{"threshold":1,"share_count":3},"commitments":[{"curve":"secp256k1","point":[2,208,91,104,3,89,40,129,170,58,201,234,36,140,113,186,218,107,174,141,229,121,4,128,119,43,225,144,60,118,219,112,11]},{"curve":"secp256k1","point":[3,151,12,253,186,175,117,232,205,14,23,232,241,51,155,86,204,42,71,222,187,250,157,146,203,138,30,240,111,158,42,90,49]}]},{"parameters":{"threshold":1,"share_count":3},"commitments":[{"curve":"secp256k1","point":[2,108,238,193,117,74,96,237,226,114,87,173,116,34,99,207,243,77,164,105,70,254,60,99,225,23,106,33,209,84,56,26,64]},{"curve":"secp256k1","point":[3,248,196,38,65,178,140,75,251,152,237,12,76,191,61,184,19,223,9,23,126,42,221,3,242,6,254,100,184,212,0,92,146]}]},{"parameters":{"threshold":1,"share_count":3},"commitments":[{"curve":"secp256k1","point":[3,227,156,84,207,62,244,112,117,199,130,205,230,143,6,101,29,113,135,82,20,46,130,113,185,209,136,163,227,151,105,4,102]},{"curve":"secp256k1","point":[3,51,139,74,209,54,45,235,40,192,228,34,13,130,84,190,83,206,140,225,244,32,131,95,225,237,134,118,82,76,9,217,235]}]}],[{"n":"13430177403653094734284749105839063373123090514283420069287822514799171673891423664451345877476898674596363542265880878290868522191770304062093002284820197165581711699437091381538833183901171347337446279747150955986572720492947594557938334062499775668714281856334605192956069553352509122333182837281433980046649627743031398376901998870460579475468751333595108042612837225772027315805734527352679955155986378698049646020128805543661152488050652797414142932074223324742684702999835560971666087625805823941197882283558025996160918433591669443101411726516727413648649578377369914585638070333589409423109109381163707234513"},{"n":"15200378547566505087063668898382604439912637712665137709638489070195262543627015653618149623835131369698156874919992319946446826420531832724980063843832189151944987449936090500748855948294353425509484626552048238720135439820139908160348893053189853050297651158692361474514274606305768156515885449165628801333069650617228781461198341901992699367594834480149579812272716933410841255490975792900225149100585086446829249417408448853835365228949562645492166624085522593122746471185849361944326002601987767873566532301026425950795548801195819842818665757503717769637341137007584814517820779590611538309558850821471851701413"},{"n":"19012870963126585215010502377022930737435240499120684216852501732272451758139596835171693631359128710199900925400018214950332993124452026525719848404334036936171597959259597756015203372360386624808866170560892289421705564851150348707217373558230172836701856614016550349649019833393150651309049713863980506136977764811141854367199547068130866988285108077491813878122378242474462919386678564007269848943776698530135128426004578399874425752593995681923869655734971605311862899903348502691925242668321073688411173197725040539716953758523940991563982349016166572865989706834029783646627583165092208571877800675291555028863"}],{"curve":"secp256k1","point":[3,58,77,219,150,151,252,204,142,255,45,75,48,15,101,45,24,4,95,107,41,195,119,235,149,50,100,31,163,196,5,55,104]}]"#,
        ];
        let keys = keys.map(|v| String::from(v));

        let futures = keys
            .iter()
            .map(|key| sign(parties, threshold, key, &room_id, &message, &adapter));
        let signatures = future::join_all(futures).await;
        println!("signatures : {:?}", signatures);
    }
}

#![allow(unused_imports)]

use std::collections::HashMap;
use std::sync::RwLock;
use std::{iter::repeat, time::Duration};
use tokio::time::sleep;
use uuid::Uuid;

use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Nonce};
use curv::{
    arithmetic::traits::Converter,
    cryptographic_primitives::{
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{Keys, SharedKeys};

use secp256k1::{verify, Message, PublicKey, PublicKeyFormat, Signature};

use paillier::{Decrypt, EncryptionKey};
use serde::{Deserialize, Serialize};

pub use crate::ecdsa::gg_2018::adapter::{Community, Entry, PartySignup};

pub type Key = String;

#[allow(dead_code)]
#[derive(Debug)]
pub enum ECDSAError {
    ReachMaxParties,
}

#[allow(dead_code)]
pub const AES_KEY_BYTES_LEN: usize = 32;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Index {
    pub key: Key,
}

#[derive(Serialize, Deserialize)]
pub struct Params {
    pub parties: String,
    pub threshold: String,
}

#[allow(dead_code)]
pub fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> AEAD {
    let aes_key = aes_gcm::Key::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce = Nonce::from_slice(&nonce);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("encryption failure!");

    AEAD {
        ciphertext: ciphertext,
        tag: nonce.to_vec(),
    }
}

#[allow(dead_code)]
pub fn aes_decrypt(key: &[u8], aead_pack: AEAD) -> Vec<u8> {
    let aes_key = aes_gcm::Key::from_slice(key);
    let nonce = Nonce::from_slice(&aead_pack.tag);
    let gcm = Aes256Gcm::new(aes_key);

    let out = gcm.decrypt(nonce, aead_pack.ciphertext.as_slice());
    out.unwrap()
}

pub async fn broadcast<'a>(
    adapter: &Box<dyn Community + Send + Sync + 'a>,
    party_num: u16,
    round: &str,
    data: String,
    sender_uuid: String,
) -> Result<Entry, ()> {
    let key = format!("{}-{}-{}", party_num, round, sender_uuid);
    let entry = Entry {
        key: key.clone(),
        value: data,
    };
    adapter.set_entry(&entry).await
}

pub async fn poll_for_broadcasts<'a>(
    adapter: &Box<dyn Community + Send + Sync + 'a>,
    party_num: u16,
    n: u16,
    delay: Duration,
    round: &str,
    sender_uuid: String,
) -> Vec<String> {
    let mut ans_vec = Vec::new();
    for i in 1..=n {
        if i != party_num {
            let key = format!("{}-{}-{}", i, round, sender_uuid);
            loop {
                // add delay to allow the server to process request:
                sleep(delay).await;
                let answer = adapter.get_entry(&key).await;
                if let Ok(answer) = answer {
                    ans_vec.push(answer.value);
                    println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                    break;
                }
            }
        }
    }
    ans_vec
}

pub async fn sendp2p<'a>(
    adapter: &Box<dyn Community + Send + Sync + 'a>,
    party_from: u16,
    party_to: u16,
    round: &str,
    data: String,
    sender_uuid: String,
) -> Result<Entry, ()> {
    let key = format!("{}-{}-{}-{}", party_from, party_to, round, sender_uuid);

    let entry = Entry {
        key: key.clone(),
        value: data,
    };
    adapter.set_entry(&entry).await
}

pub async fn poll_for_p2p<'a>(
    adapter: &Box<dyn Community + Send + Sync + 'a>,
    party_num: u16,
    n: u16,
    delay: Duration,
    round: &str,
    sender_uuid: String,
) -> Vec<String> {
    let mut ans_vec = Vec::new();
    for i in 1..=n {
        if i != party_num {
            let key = format!("{}-{}-{}-{}", i, party_num, round, sender_uuid);
            loop {
                // add delay to allow the server to process request:
                sleep(delay).await;
                let answer = adapter.get_entry(&key).await;
                if let Ok(answer) = answer {
                    ans_vec.push(answer.value);
                    println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                    break;
                }
            }
        }
    }
    ans_vec
}

pub fn party_key_pub_hex(data: &String) -> String {
    let (_party_keys, _shared_keys, _party_id, _vss_scheme_vec, _paillier_key_vector, y_sum): (
        Keys,
        SharedKeys,
        u16,
        Vec<VerifiableSS<Secp256k1>>,
        Vec<EncryptionKey>,
        Point<Secp256k1>,
    ) = serde_json::from_str(&data).unwrap();
    let mut raw_pk = y_sum.to_bytes(false).to_vec();
    if raw_pk.len() == 64 {
        raw_pk.insert(0, 4u8);
    }
    let pk = PublicKey::parse_slice(&raw_pk, Some(PublicKeyFormat::Full)).unwrap();
    hex::encode(pk.serialize())
}

#[allow(dead_code)]
pub fn check_sig(
    r: &Scalar<Secp256k1>,
    s: &Scalar<Secp256k1>,
    msg: &BigInt,
    pk: &Point<Secp256k1>,
) {
    use secp256k1::{verify, Message, PublicKey, PublicKeyFormat, Signature};

    let raw_msg = BigInt::to_bytes(msg);
    let mut msg: Vec<u8> = Vec::new(); // padding
    msg.extend(vec![0u8; 32 - raw_msg.len()]);
    msg.extend(raw_msg.iter());

    let msg = Message::parse_slice(msg.as_slice()).unwrap();
    let mut raw_pk = pk.to_bytes(false).to_vec();
    if raw_pk.len() == 64 {
        raw_pk.insert(0, 4u8);
    }
    let pk = PublicKey::parse_slice(&raw_pk, Some(PublicKeyFormat::Full)).unwrap();

    let mut compact: Vec<u8> = Vec::new();
    let bytes_r = &r.to_bytes().to_vec();
    compact.extend(vec![0u8; 32 - bytes_r.len()]);
    compact.extend(bytes_r.iter());

    let bytes_s = &s.to_bytes().to_vec();
    compact.extend(vec![0u8; 32 - bytes_s.len()]);
    compact.extend(bytes_s.iter());

    let secp_sig = Signature::parse_slice(compact.as_slice()).unwrap();

    let is_correct = verify(&msg, &secp_sig, &pk);
    assert!(is_correct);
}

#[cfg(test)]
pub mod test {
    use super::{party_key_pub_hex, Entry};
    use futures::{executor, future, FutureExt};
    use std::collections::HashMap;
    use std::sync::RwLock;

    #[test]
    fn test_party_key_pub_hex() {
        let party_str = String::from(
            r#"[{"u_i":{"curve":"secp256k1","scalar":[117,182,42,84,233,175,53,161,77,221,78,116,89,104,84,218,245,10,71,92,94,125,52,76,71,185,88,15,68,135,115,234]},"y_i":{"curve":"secp256k1","point":[2,164,58,242,107,235,115,221,210,246,143,120,195,252,26,45,83,226,104,114,227,44,11,25,31,223,22,93,117,230,83,11,117]},"dk":{"p":"107430399500028687503947323721910779785667707796529005617831133184438674423854224958254526580050124997882201748982424934287745794218586080230943447250697910723503762473349103504428314181599483592335597829731862520505549315573382547138930518113056268828830690117566050401609364529741688447991186695291382196343","q":"139902795768796603972620859981949665707004391625747053588197369799120128029719607206749749243811126931123509276232525784494469760723003564414710761438631528377990558480864092750404514587787109281483866003259582031032318880708793262117022651721781325884911667534333004271386643304327338187989476853537294075353"},"ek":{"n":"15029813240612742261027805026970689841545650744955544132349688044050860534395147030820357834363911650727598220248034051205048680665130916398115519684008147879861825539698906684037590551993095564988532631037098575779410305340076190715041762700376193599858213930484575151686305151698764815053406455725731628048194289463339529290461362316591411036159987945560268190046749550386662855489195278732487162970409105226777176852032768483567120113149183168286466002789131088157178600000815335904397475817801682072645735590872017142232430996800931686723640511532287801881975014325688287427286467739808709538478704672438483034079"},"party_index":1},{"y":{"curve":"secp256k1","point":[3,73,156,248,241,137,33,19,63,22,124,165,148,165,19,55,194,38,233,60,36,168,248,253,132,62,168,108,250,40,200,167,214]},"x_i":{"curve":"secp256k1","scalar":[126,23,246,107,247,138,166,69,102,243,242,2,108,62,105,19,152,121,73,201,178,148,82,174,231,203,30,157,57,15,92,191]}},1,[{"parameters":{"threshold":1,"share_count":3},"commitments":[{"curve":"secp256k1","point":[2,164,58,242,107,235,115,221,210,246,143,120,195,252,26,45,83,226,104,114,227,44,11,25,31,223,22,93,117,230,83,11,117]},{"curve":"secp256k1","point":[3,90,174,192,194,131,120,135,173,29,201,5,69,212,34,203,33,99,228,63,139,154,251,152,74,184,38,206,191,251,6,87,221]}]},{"parameters":{"threshold":1,"share_count":3},"commitments":[{"curve":"secp256k1","point":[3,209,222,218,88,255,131,45,146,185,12,213,53,191,5,179,112,7,44,80,128,95,96,6,232,252,239,0,184,116,76,42,165]},{"curve":"secp256k1","point":[3,2,29,88,29,154,121,217,244,137,2,159,141,129,96,229,152,141,197,210,64,55,187,87,183,91,241,83,227,145,191,128,177]}]},{"parameters":{"threshold":1,"share_count":3},"commitments":[{"curve":"secp256k1","point":[2,115,91,1,40,47,14,216,157,253,81,138,38,208,3,90,162,180,82,245,160,79,111,155,116,15,128,117,70,233,103,135,206]},{"curve":"secp256k1","point":[3,7,136,206,247,46,43,243,45,26,156,110,141,27,190,230,134,209,141,190,89,49,200,182,141,87,246,94,94,207,222,30,238]}]}],[{"n":"15029813240612742261027805026970689841545650744955544132349688044050860534395147030820357834363911650727598220248034051205048680665130916398115519684008147879861825539698906684037590551993095564988532631037098575779410305340076190715041762700376193599858213930484575151686305151698764815053406455725731628048194289463339529290461362316591411036159987945560268190046749550386662855489195278732487162970409105226777176852032768483567120113149183168286466002789131088157178600000815335904397475817801682072645735590872017142232430996800931686723640511532287801881975014325688287427286467739808709538478704672438483034079"},{"n":"20061913469968490195111418563414539036482609345204623380074213655937451475312094930066579592008604188794779898281785808283084153502231812584043007154894142002742864813243549340459026398801183222320407511316527665908258043194803980142699336484289656057392891771567661682019882383362017015561028666775313946644071887945579195269384830887472374716194488317599589514075550592909396396089569646278929155835316466557169413125150738373134220887926313682508178366631910902108108839194900142328918643451369809933230947463470646243786103673585198130899449991625883106535585559845937941983006689214854637817491820116760990624157"},{"n":"16128421079878930609020245351864657761212896502123868936416201635099680785699248923429680518695388018754225998114986144553573009975472733240266391090227723765047126576676519597210193766462369229016879281630914662657800124290387550992541041878215046280571226473210378294931265864805484085705265468781805529494774316392309820801134919698382802789922684379002158209344448213703467959990018748223913429414920202830415215527071984586709365823780420053831822551609829513130114062083830847629416710673556019992889290377850859267524578948954086789074725631650253650842853472597987231179480824231327827725920765267486509157499"}],{"curve":"secp256k1","point":[3,73,156,248,241,137,33,19,63,22,124,165,148,165,19,55,194,38,233,60,36,168,248,253,132,62,168,108,250,40,200,167,214]}]"#,
        );
        let expected = "04499cf8f18921133f167ca594a51337c226e93c24a8f8fd843ea86cfa28c8a7d697b5b0860fa1c6686170983ab3ec9856ae8007689d21be7f497180b147858651".to_string();
        let pub_hex = party_key_pub_hex(&party_str);
        assert_eq!(pub_hex, expected);
    }
}

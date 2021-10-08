#![allow(unused_imports)]

use std::collections::HashMap;
use std::sync::RwLock;
use std::{iter::repeat, time::Duration};
use tokio::time::sleep;
use uuid::Uuid;

use crypto::{
    aead::{AeadDecryptor, AeadEncryptor},
    aes::KeySize::KeySize256,
    aes_gcm::AesGcm,
};
use curv::{
    arithmetic::traits::*,
    cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS,
    elliptic::curves::secp256_k1::{FE, GE},
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt,
};

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
    let nonce: Vec<u8> = repeat(3).take(12).collect();
    let aad: [u8; 0] = [];
    let mut gcm = AesGcm::new(KeySize256, key, &nonce[..], &aad);
    let mut out: Vec<u8> = repeat(0).take(plaintext.len()).collect();
    let mut out_tag: Vec<u8> = repeat(0).take(16).collect();
    gcm.encrypt(&plaintext[..], &mut out[..], &mut out_tag[..]);
    AEAD {
        ciphertext: out.to_vec(),
        tag: out_tag.to_vec(),
    }
}

#[allow(dead_code)]
pub fn aes_decrypt(key: &[u8], aead_pack: AEAD) -> Vec<u8> {
    let mut out: Vec<u8> = repeat(0).take(aead_pack.ciphertext.len()).collect();
    let nonce: Vec<u8> = repeat(3).take(12).collect();
    let aad: [u8; 0] = [];
    let mut gcm = AesGcm::new(KeySize256, key, &nonce[..], &aad);
    gcm.decrypt(&aead_pack.ciphertext[..], &mut out, &aead_pack.tag[..]);
    out
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
        Vec<VerifiableSS<GE>>,
        Vec<EncryptionKey>,
        GE,
    ) = serde_json::from_str(&data).unwrap();
    let mut raw_pk = y_sum.pk_to_key_slice();
    if raw_pk.len() == 64 {
        raw_pk.insert(0, 4u8);
    }
    let pk = PublicKey::parse_slice(&raw_pk, Some(PublicKeyFormat::Full)).unwrap();
    hex::encode(pk.serialize())
}

#[allow(dead_code)]
pub fn check_sig(r: &FE, s: &FE, msg: &BigInt, pk: &GE) {
    let raw_msg = BigInt::to_bytes(&msg);
    let mut msg: Vec<u8> = Vec::new(); // padding
    msg.extend(vec![0u8; 32 - raw_msg.len()]);
    msg.extend(raw_msg.iter());

    let msg = Message::parse_slice(msg.as_slice()).unwrap();
    let mut raw_pk = pk.pk_to_key_slice();
    if raw_pk.len() == 64 {
        raw_pk.insert(0, 4u8);
    }
    let pk = PublicKey::parse_slice(&raw_pk, Some(PublicKeyFormat::Full)).unwrap();

    let mut compact: Vec<u8> = Vec::new();
    let bytes_r = &r.get_element()[..];
    compact.extend(vec![0u8; 32 - bytes_r.len()]);
    compact.extend(bytes_r.iter());

    let bytes_s = &s.get_element()[..];
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
            r#"[{"u_i":"ace8c896f24c9620a288e47dd218bb98a74d3d1e4b1da88d70524f1373aaa124","y_i":{"x":"6d86697455046c730a063974bf0f9d4dbddaec9a7c68e75081b8c92b4c660bb1","y":"1c6861d5f2c97dd701d37ffd6cc69dec1386072e051740561c78178f3cd2c58c"},"dk":{"p":"112386505787263372019669498553109025657194331944814473057214316830369856261357701997003987362788373615285188458038732402891620917081880058220912875408926532126895209663411883641169274211096049055375962782173487904551081874244948820657685328934681058070902191905756393783333737077947001189597651817953520317009","q":"97577720000977409259966773922493917194638289542493983487051643773689138633860121405117307014402420341560036100429840490428188459582917085793988740300723979958029164550511731460150239098900151576256754444349465152440787556886056275268373737282032874819335461585107651414302440982847033100480962764893354415757"},"ek":{"n":"10966418993597812492642925469474602068524266332280317978676679355598656939839094179795337559509381104358907194006801298928938127515613527518220493666236823513055513656608913049404680025169262815841025455242328612044591042591326957802931079118134563289554567317896110660501416880230724196314905100390167933743195889200524766231052766999023328215338183033265698592491918343108170336455493421372617866632318716583251404515316119667292857644728574282314221612607935470781713242383475741753389998688003695192456201215060372760519476124232042666723388434039627219544689594649292456517925515882860178825780919059004624710813"},"party_index":1},{"y":{"x":"4429a3eb9f9f87d43599a77a0246240a38cab5340c2902248d38ab3a6df268d5","y":"3e56760bcf711aedf6f7cdd30969aa2b0a7f9a21e5f4659897caae0c27e769b7"},"x_i":"464fe585745cc0a58159a5ee42ad41502b00047bfaff723e8f5c2e8f09c8d34"},1,[{"parameters":{"threshold":1,"share_count":3},"commitments":[{"x":"6d86697455046c730a063974bf0f9d4dbddaec9a7c68e75081b8c92b4c660bb1","y":"1c6861d5f2c97dd701d37ffd6cc69dec1386072e051740561c78178f3cd2c58c"},{"x":"5014a7c1e0b0f2001b65999779d1fdb8a1fff377c9f9ef350c4af03c90794ba2","y":"88d40883f6616f6532dc53bd18ddc62d174a0101b31b8e607cd942090709ec14"}]},{"parameters":{"threshold":1,"share_count":3},"commitments":[{"x":"e783690b270f758e6281941eada8d22c864787cd5042139e56e281d79eea387f","y":"d748579d9b817f70d937bb34471aed76cd444783151a66f554bc2367f042f42d"},{"x":"c6ae2c97e311cc905e0ebb1e056792a682dd45462110c2e0e60bc8a590ddff58","y":"bd97cae4ad0b2afbc02ee81b059429387a7ced4be407f8515e1c2bc6cfefce52"}]},{"parameters":{"threshold":1,"share_count":3},"commitments":[{"x":"c1a468ba55b36761adfb0f8590dced32ef202e4f89444cf0ba536f8d4682b929","y":"813a114d527557bec93c1b179b05a97cc99cfaf86a92c55fed1735a7207f45f9"},{"x":"6a57bbac920d61eec4ce5978aecc83b8c8e35d94c25600e4166488bafba23b82","y":"ea1b5bc8650681803339f9a969f39af01839f10b3ac2204595ea3f5085c98a2a"}]}],[{"n":"10966418993597812492642925469474602068524266332280317978676679355598656939839094179795337559509381104358907194006801298928938127515613527518220493666236823513055513656608913049404680025169262815841025455242328612044591042591326957802931079118134563289554567317896110660501416880230724196314905100390167933743195889200524766231052766999023328215338183033265698592491918343108170336455493421372617866632318716583251404515316119667292857644728574282314221612607935470781713242383475741753389998688003695192456201215060372760519476124232042666723388434039627219544689594649292456517925515882860178825780919059004624710813"},{"n":"24746791525704225717881822172748872354045667483925506611166571158253199831821188228213981881397219391826411635547196112063148245241006212383472705133986360722796894655167648198064065620214487883171141853757910861749928650813853743125157086322681538773123203756857672486027178964619316300112812367963077902464115678595933540176230612835335783170587329332050463826094976241381847411508283855980308820323982822771537511079794261203612301289371621749841595613155179070244110200869253008828618230166095642400586120536617713506320426066986303642307746822722585628386881226679447575402258112729688334465453208011250015011263"},{"n":"15187308640777630071409359629770712246981555888009086456705206923357300051501058597805805665328086795253846909333281919539926928846884884822298505026107195641952451500774105972998411277128577123235192973080121107947129002025571869991402489673250106998663287988941343685549494300744393050935919016208970682824413995221579323664593680113163928212734890045118569243095449636884165753285837478178604030296441550509436608904189872518554930815065608114037169811208471594400411030942990946039103508853166203097271274269585396764395606566299502810984942049474193459864571841013437170463471340449623187393866109937045699437863"}],{"x":"4429a3eb9f9f87d43599a77a0246240a38cab5340c2902248d38ab3a6df268d5","y":"3e56760bcf711aedf6f7cdd30969aa2b0a7f9a21e5f4659897caae0c27e769b7"}]"#,
        );
        let expected = "044429a3eb9f9f87d43599a77a0246240a38cab5340c2902248d38ab3a6df268d53e56760bcf711aedf6f7cdd30969aa2b0a7f9a21e5f4659897caae0c27e769b7".to_string();
        let pub_hex = party_key_pub_hex(&party_str);
        assert_eq!(pub_hex, expected);
    }
}

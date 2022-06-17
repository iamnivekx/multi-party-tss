use curv::{
    arithmetic::traits::Converter,
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};
use secp256k1::{verify, Message, PublicKey, PublicKeyFormat, Signature};

pub fn party_key_pub_hex(y_sum: &Point<Secp256k1>) -> String {
    let mut raw_pk = y_sum.to_bytes(false).to_vec();
    if raw_pk.len() == 64 {
        raw_pk.insert(0, 4u8);
    }
    let pk = PublicKey::parse_slice(&raw_pk, Some(PublicKeyFormat::Full)).unwrap();
    hex::encode(pk.serialize())
}

pub fn party_key_compress_pub_hex(y_sum: &Point<Secp256k1>) -> String {
    let raw_pk = y_sum.to_bytes(true).to_vec();
    let pk = PublicKey::parse_slice(&raw_pk, Some(PublicKeyFormat::Compressed)).unwrap();
    hex::encode(pk.serialize_compressed())
}

#[allow(dead_code)]
pub fn check_sig(
    r: &Scalar<Secp256k1>,
    s: &Scalar<Secp256k1>,
    msg: &BigInt,
    pk: &Point<Secp256k1>,
) -> bool {
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

    verify(&msg, &secp_sig, &pk)
}

#[cfg(test)]
pub mod test {
    use super::{party_key_compress_pub_hex, party_key_pub_hex};

    #[test]
    fn test_party_key_pub_hex() {
        let key_str = String::from(
            r#"{"curve":"secp256k1","point":[3,73,156,248,241,137,33,19,63,22,124,165,148,165,19,55,194,38,233,60,36,168,248,253,132,62,168,108,250,40,200,167,214]}"#,
        );
        let pk = serde_json::from_str(&key_str).unwrap();
        let pub_hex = party_key_pub_hex(&pk);
        assert_eq!(pub_hex,  "04499cf8f18921133f167ca594a51337c226e93c24a8f8fd843ea86cfa28c8a7d697b5b0860fa1c6686170983ab3ec9856ae8007689d21be7f497180b147858651");

        let compress_pub_hex = party_key_compress_pub_hex(&pk);
        assert_eq!(
            compress_pub_hex,
            "03499cf8f18921133f167ca594a51337c226e93c24a8f8fd843ea86cfa28c8a7d6"
        );
    }
}

use alloy_rlp::{Encodable, RlpDecodable, RlpEncodable};
use bytes::{BufMut, BytesMut};
use secp256k1::{PublicKey, SECP256K1, SecretKey};
use crate::ecies_crypto::Ecies;
use crate::handshake_protocol::ecdh_x;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, RlpDecodable, RlpEncodable)]
pub struct AuthBody {
    pub sig: [u8; 65],
    pub initiator_pubk: [u8; 64],
    pub initiator_nonce: [u8; 32],
    pub auth_vsn: u8
}

pub struct Rlpx;

impl Rlpx {

    pub fn build_auth(encrypted: BytesMut) -> BytesMut {
        let mut buf = BytesMut::new();
        let len: [u8;2] = (encrypted.len() as u16).to_be_bytes();
        buf.extend_from_slice(&len);
        buf.extend_from_slice(&encrypted);
        buf
    }

    pub fn encrypt_auth_body(auth_body: AuthBody, padding: &[u8], peer_public_key: &PublicKey) -> BytesMut {
        let mut bytes = BytesMut::new();
        auth_body.encode(&mut bytes);
        bytes.extend_from_slice(padding);

        Ecies::encrypt(bytes,peer_public_key )
    }


    pub fn get_auth_body(secret_key: &SecretKey, id: [u8; 64], nonce: [u8; 32], ephemeral_secret_key: &SecretKey, peer_public_key: &PublicKey) -> AuthBody {
        let mut x = ecdh_x(&peer_public_key, &secret_key);

        //x ^= nonce
        x.iter_mut().zip(nonce).for_each(|(a, b)| *a ^= b);

        let (rec_id, sig) = SECP256K1
            .sign_ecdsa_recoverable(
                &secp256k1::Message::from_digest_slice(x.as_slice()).unwrap(),
                &ephemeral_secret_key
            )
            .serialize_compact();

        println!("sig: {:?}", sig);
        println!("recover: {:?}", rec_id);

        let mut signature = BytesMut::with_capacity(65);
        signature.put_slice(&sig);
        signature.put_u8(rec_id.to_i32() as u8);

        let auth_body = AuthBody {
            sig: signature[..].try_into().expect("signature should fit"),
            initiator_pubk: id,
            initiator_nonce: nonce,
            auth_vsn: 4,
        };

        auth_body
    }
}
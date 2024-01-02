use std::borrow::Cow;
use std::mem;
use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};
use bytes::{BufMut, BytesMut};
use cipher::StreamCipher;
use cipher::KeyIvInit;
use secp256k1::{PublicKey, SECP256K1, SecretKey};
use crate::crypto::{keccak256_vec, KeccakStream};
use crate::handshake::session::Session;
use crate::util::ecdh_x;
use super::ecies_crypto::{Aes256Ctr64BE, Ecies};

pub const RLP_ZERO: u8 = 0x80;
pub const RLP_EMPTY: u8 = 0xC0;


#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, RlpDecodable, RlpEncodable)]
pub struct AuthBody {
    pub sig: [u8; 65],
    pub initiator_pubk: [u8; 64],
    pub initiator_nonce: [u8; 32],
    pub auth_vsn: u8
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, RlpDecodable, RlpEncodable)]
pub struct AckBody {
    pub recipient_ephemeral_public_key: [u8; 64],
    pub recipient_nonce: [u8; 32],
    pub ack_vsn: u8
}

#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable, Default, Hash)]
pub struct Capability {
    pub name: Cow<'static, str>,
    pub version: usize,
}


#[derive(Clone, Debug, PartialEq, Eq, Hash, RlpDecodable, RlpEncodable)]
pub struct Hello {
    pub protocol_version: u8,
    pub client_version: String,
    pub capabilities: Vec<Capability>,
    pub port: u16,
    pub id: [u8;64],
}

pub struct Rlpx;


#[derive(Debug)]
pub struct RlpxError(pub String);

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

        Ecies::encrypt(bytes, peer_public_key)
    }

    pub fn build_auth_body(secret_key: &SecretKey, id: &[u8; 64], nonce: &[u8; 32], ephemeral_secret_key: &SecretKey, peer_public_key: &PublicKey) -> AuthBody {
        let mut x = ecdh_x(&peer_public_key, &secret_key);

        //x ^= nonce
        x.iter_mut().zip(nonce).for_each(|(a, b)| *a ^= b);

        let (rec_id, sig) = SECP256K1
            .sign_ecdsa_recoverable(
                &secp256k1::Message::from_digest_slice(x.as_slice()).unwrap(),
                &ephemeral_secret_key
            )
            .serialize_compact();

        let mut signature = BytesMut::with_capacity(65);
        signature.put_slice(&sig);
        signature.put_u8(rec_id.to_i32() as u8);

        let auth_body = AuthBody {
            sig: signature[..].try_into().expect("signature should fit"),
            initiator_pubk: id.clone(),
            initiator_nonce: nonce.clone(),
            auth_vsn: 4,
        };

        auth_body
    }

    pub async fn decrypt_ack(buf: BytesMut, secret_key: &SecretKey) -> Result<AckBody, RlpxError> {
        if buf.len() < 2 {
            return Err(RlpxError("Ack too small".to_string()));
        }

        if let Ok(ack_body_bytes) = Ecies::decrypt(buf, secret_key) {
            if let Ok(ack_body) = Self::build_ack_body(ack_body_bytes) {
                return Ok(ack_body);
            }
        }
        Err(RlpxError("Failed to decrypt Ack".to_string()))
    }

    fn build_ack_body(bytes: BytesMut) -> Result<AckBody, RlpxError> {
        let ack: AckBody = Decodable::decode(&mut &*bytes).map_err(|_| RlpxError("failed to decode from".to_string()))?;
        Ok(ack)
    }

    pub fn egress_hashers(nonce: &[u8; 32], auth_message: &BytesMut, ack: &AckBody, ephemeral_shared_secret: &[u8; 32]) -> (Aes256Ctr64BE, KeccakStream) {
        let aes_secret: [u8; 32] = {
            let h_nonce = keccak256_vec(vec![&ack.recipient_nonce, nonce]);
            let shared_secret = keccak256_vec(vec![ephemeral_shared_secret, &h_nonce]);
            keccak256_vec(vec![ephemeral_shared_secret, &shared_secret])
        };
        let mac_secret = keccak256_vec(vec![ephemeral_shared_secret, &aes_secret]);

        let iv = [0u8; 16];
        let egress_aes = Aes256Ctr64BE::new(aes_secret.as_ref().into(), iv.as_ref().into());
        let mut egress_mac = KeccakStream::new(mac_secret);

        let mac_xor_nonce = {
            let mut xor = mac_secret.clone();
            xor.iter_mut().zip(ack.recipient_nonce).for_each(|(a, b)| *a ^= b);
            xor
        };
        egress_mac.update(&mac_xor_nonce);
        egress_mac.update(&auth_message);
        (egress_aes, egress_mac)
    }

    pub fn ingress_hashers(nonce: &[u8; 32], ack_message: &BytesMut, ack: &AckBody, ephemeral_shared_secret: &[u8; 32]) -> (Aes256Ctr64BE, KeccakStream) {
        let aes_secret: [u8; 32] = {
            let h_nonce = keccak256_vec(vec![&ack.recipient_nonce, nonce]);
            let shared_secret = keccak256_vec(vec![ephemeral_shared_secret, &h_nonce]);
            keccak256_vec(vec![ephemeral_shared_secret, &shared_secret])
        };
        let mac_secret = keccak256_vec(vec![ephemeral_shared_secret, &aes_secret]);

        let iv = [0u8; 16];
        let ingress_aes = Aes256Ctr64BE::new(aes_secret.as_ref().into(), iv.as_ref().into());
        let mut ingress_mac = KeccakStream::new(mac_secret);

        let mac_xor_nonce = {
            let mut xor = mac_secret.clone();
            xor.iter_mut().zip(nonce).for_each(|(a, b)| *a ^= b);
            xor
        };
        ingress_mac.update(&mac_xor_nonce);
        ingress_mac.update(&ack_message);
        (ingress_aes, ingress_mac)
    }

    pub fn build_hello(id: [u8;64]) -> BytesMut {
        let mut hello_bytes = BytesMut::new();
        hello_bytes.put_u8(RLP_ZERO); //hello message 0x00
        Hello {
            protocol_version: 5,
            client_version: "shake-that-hand/0.1".to_string(),
            capabilities: vec![
                Capability {
                    name: Cow::from("eth"),
                    version: 66,
                },
                Capability {
                    name: Cow::from("eth"),
                    version: 67,
                },
                Capability {
                    name: Cow::from("eth"),
                    version: 68,
                }
            ],
            port: 0,
            id,
        }.encode(&mut hello_bytes);
        hello_bytes
    }

    pub fn encrypt_frame(bytes: BytesMut, session: &mut Session) -> BytesMut {
        let size = bytes.len();
        let size_bytes = size.to_be_bytes();
        let mut header = [0u8; 16];
        header[0..3].copy_from_slice(&size_bytes[mem::size_of_val(&size)-3..mem::size_of_val(&size)]);
        header[3..6].copy_from_slice(&[RLP_EMPTY+2, RLP_ZERO, RLP_ZERO]); // rlp encoded 2 element array with zeros

        session.egress_aes.apply_keystream(&mut header);
        session.egress_mac.accumulate_with_xor(&header);
        let mac_digest = session.egress_mac.digest();

        let mut output = BytesMut::new();
        output.extend_from_slice(&header);
        output.extend_from_slice(&mac_digest);

        let initial_len = output.len();
        //round up to 16 multiplication
        let padding_len = ((bytes.len() + 15) & !15) - bytes.len();
        let padding = vec![0u8; padding_len];

        output.extend_from_slice(&bytes);
        output.extend_from_slice(padding.as_slice());
        let mut padded_bytes = &mut output[initial_len..];

        session.egress_aes.apply_keystream(&mut padded_bytes);
        session.egress_mac.update_accumulate_with_xor(&padded_bytes);
        let digest = session.egress_mac.digest();

        output.extend_from_slice(&digest);
        output
    }

    pub(crate) fn read_hello_frame(mut bytes: BytesMut, ingress_aes: &mut Aes256Ctr64BE, ingress_mac: &mut KeccakStream) -> Result<BytesMut, RlpxError> {
        let (header_bytes, mac_bytes) = bytes.split_at_mut(16);
        let (mac_bytes, body) = mac_bytes.split_at_mut(16);

        ingress_mac.accumulate_with_xor(header_bytes);
        let digest = ingress_mac.digest();
        if mac_bytes != digest {
            return Err(RlpxError("digest mismatch".to_string()));
        }

        ingress_aes.apply_keystream(header_bytes);

        let mut size_bytes = [0u8; 8];
        size_bytes[5..8].clone_from_slice(&header_bytes[0..3]);
        let size = usize::from_be_bytes(size_bytes);
        let padded_size = (size + 15) & !15;

        let (body, _) = body.split_at_mut(padded_size + 16);
        let (body, mac_bytes) = body.split_at_mut( body.len() - 16);
        ingress_mac.update_accumulate_with_xor(body);
        let digest = ingress_mac.digest();
        if mac_bytes != digest {
            return Err(RlpxError("digest mismatch".to_string()));
        }

        ingress_aes.apply_keystream(body);

        let bytes = {
            let mut b = BytesMut::new();
            b.extend_from_slice(&body[0..size]);
            b
        };
        Ok(bytes)
    }
}
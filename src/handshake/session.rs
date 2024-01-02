use bytes::BytesMut;
use secp256k1::SecretKey;
use crate::crypto::KeccakStream;
use crate::handshake::ecies_crypto::Aes256Ctr64BE;
use crate::handshake::rlpx::{AckBody, Rlpx};
use crate::util::{ecdh_x, public_key_from_node_id};

pub struct Session {
    pub ingress_mac: KeccakStream,
    pub ingress_aes: Aes256Ctr64BE,
    pub egress_mac: KeccakStream,
    pub egress_aes: Aes256Ctr64BE
}


impl Session {
    pub fn new(ack: AckBody, ephemeral_secret_key: &SecretKey, nonce: &[u8; 32], auth_message: &BytesMut, ack_message: &BytesMut) ->Self {
        let recipient_ephemeral_public_key = public_key_from_node_id(&ack.recipient_ephemeral_public_key).unwrap();
        let ephemeral_shared_secret = ecdh_x(&recipient_ephemeral_public_key, ephemeral_secret_key);

        let (egress_aes, egress_mac) = Rlpx::egress_hashers(&nonce, &auth_message, &ack, &ephemeral_shared_secret);
        let (ingress_aes, ingress_mac) = Rlpx::ingress_hashers(&nonce, &ack_message, &ack, &ephemeral_shared_secret);

        Self {
            ingress_mac,
            ingress_aes,
            egress_mac,
            egress_aes
        }
    }
}
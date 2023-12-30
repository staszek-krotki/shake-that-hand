use aes_gcm::aes;
use bytes::BytesMut;
// use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use rand::{Rng, thread_rng};
use secp256k1::{PublicKey, SECP256K1, SecretKey};
use sha2::{Digest, Sha256};
use crate::handshake_protocol::ecdh_x;
use ctr::cipher::{KeyIvInit, StreamCipher};


type Aes128Ctr64BE = ctr::Ctr64BE<aes::Aes128>;
type HmacSha256 = Hmac<Sha256>;

pub struct Ecies;

impl Ecies {
    pub(crate) fn encrypt(bytes: BytesMut, peer_public_key: &PublicKey) -> BytesMut {
        let mut rng = thread_rng();
        let secret_key = SecretKey::new(&mut rng);
        let public_key = PublicKey::from_secret_key(SECP256K1, &secret_key); //R

        let shared_secret = ecdh_x(peer_public_key, &secret_key);

        let (k_e, k_m) = Ecies::calculate_ke_km(&shared_secret);

        let iv: [u8; 16] = rng.gen(); // random vector
        let c = Ecies::calculate_c(bytes, &k_e, &iv);
        let r = Ecies::calculate_r(&public_key);

        let output_len: u16 = (r.len() + iv.len() + c.len() + 32) as u16;
        let d = Ecies::calculate_d(&k_m, &iv, &c, &output_len);

        //send R || iv || c || d
        let mut output = BytesMut::new();
        output.extend_from_slice(&r);
        output.extend_from_slice(&iv);
        output.extend_from_slice(&c);
        output.extend_from_slice(&d);

        output
    }

    fn calculate_ke_km(shared_secret: &[u8; 32]) -> ([u8; 16], [u8; 32]) {
        let mut key = [0u8; 32];
        concat_kdf::derive_key_into::<sha2::Sha256>(shared_secret, &[], &mut key).expect("concat should succeed");

        // key material for encryption and authentication
        let k_e: [u8; 16] = key[..16].try_into().expect("should fit");
        let k_m: [u8; 32] = Sha256::digest(&key[16..32]).as_slice().try_into().expect("should fit");
        (k_e, k_m)
    }

    fn calculate_c(mut buf: BytesMut, k_e: &[u8; 16], iv: &[u8; 16]) -> BytesMut {
        let mut cipher = Aes128Ctr64BE::new(k_e.into(), iv.into());
        cipher.apply_keystream(&mut buf);
        buf
    }

    // r = elliptic curve public key
    fn calculate_r(public_key: &PublicKey) -> [u8; 65] {
        public_key.serialize_uncompressed()
    }

    // d = MAC(sha256(kM), iv || c)
    fn calculate_d(k_m: &[u8; 32], iv: &[u8], buf: &[u8], out_len: &u16) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(k_m)
            .expect("should take key of any size");
        mac.update(iv);
        mac.update(buf);
        mac.update(&out_len.to_be_bytes());
        let d: [u8; 32] = mac.finalize().into_bytes().try_into().expect("should fit into 32 bytes");
        d
    }
}
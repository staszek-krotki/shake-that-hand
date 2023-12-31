use aes_gcm::aes;
use bytes::BytesMut;
use hmac::{Hmac, Mac};
use rand::{Rng, thread_rng};
use secp256k1::{PublicKey, SECP256K1, SecretKey};
use sha2::{Digest, Sha256};
use crate::handshake_protocol::ecdh_x;
use ctr::cipher::{KeyIvInit, StreamCipher};
use crate::rlpx::RlpxError;


pub type Aes128Ctr64BE = ctr::Ctr64BE<aes::Aes128>;
pub type Aes256Ctr64BE = ctr::Ctr64BE<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

pub struct Ecies;

impl Ecies {
    pub fn encrypt(bytes: BytesMut, peer_public_key: &PublicKey) -> BytesMut {
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

    // c = AES(kE, iv , m)
    fn calculate_c(m: BytesMut, k_e: &[u8; 16], iv: &[u8; 16]) -> BytesMut {
        Self::aes128(m, k_e, iv)
    }

    fn aes128(mut m: BytesMut, k_e: &[u8; 16], iv: &[u8; 16]) -> BytesMut {
        let mut cipher = Aes128Ctr64BE::new(k_e.into(), iv.into());
        cipher.apply_keystream(&mut m);
        m
    }

    // r = elliptic curve public key
    fn calculate_r(public_key: &PublicKey) -> [u8; 65] {
        public_key.serialize_uncompressed()
    }

    // d = MAC(sha256(kM), iv || c)
    fn calculate_d(k_m: &[u8; 32], iv: &[u8], buf: &[u8], out_len: &u16) -> [u8; 32] {
        Self::hmac_sha256(k_m, iv, buf, out_len)
    }

    fn hmac_sha256(k_m: &[u8; 32], iv: &[u8], buf: &[u8], len: &u16) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(k_m)
            .expect("should take key of any size");
        mac.update(iv);
        mac.update(buf);
        mac.update(&len.to_be_bytes());
        let result: [u8; 32] = mac.finalize().into_bytes().try_into().expect("should fit into 32 bytes");
        result
    }

    pub fn decrypt(mut bytes: BytesMut, secret_key: &SecretKey) -> Result<BytesMut, RlpxError> {
        let (len_bytes, rest) = bytes.split_at_mut(2);
        let len= u16::from_be_bytes(len_bytes[0..2].try_into().unwrap());

        println!("len={}, res.len={}", len, rest.len());

        let (r, rest) = rest.split_at_mut(65);
        let (iv, rest) = rest.split_at_mut(16);
        let (c, rest) = rest.split_at_mut((len - 65 - 16 - 32) as usize);
        let (d, _) = rest.split_at_mut(32);

        let public_key = PublicKey::from_slice(r).map_err(|_| RlpxError("Invalid public key".to_string()))?;

        let shared_secret = ecdh_x(&public_key, secret_key);
        let (k_e, k_m) = Self::calculate_ke_km(&shared_secret);
        let d_ver = Self::hmac_sha256(&k_m, iv, c, &len);

        if d != d_ver {
            return Err(RlpxError("d verification failed".to_string()))
        }

        let mut buf = BytesMut::new();
        buf.extend_from_slice(c);
        let iv:&[u8; 16] = iv.as_ref().try_into().unwrap();
        let data = Self::aes128(buf, &k_e, iv);

        Ok(data)
    }

}
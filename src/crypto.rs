use std::str::FromStr;
use aes_gcm::aes::Aes256Enc;
use ctr::cipher::{KeyInit};
use cipher::BlockEncrypt;
use secp256k1::{SecretKey, SECP256K1};
use tiny_keccak::{Hasher, Keccak};
use block_padding::NoPadding;

pub struct Crypto;

impl Crypto {
    pub(crate) fn init() -> (SecretKey, [u8; 64]) {
        // let secret_key = SecretKey::new(&mut rand::thread_rng());
        let secret_key = SecretKey::from_str("351bd6c4ca72b468c1a11707505911a766271466aab7cb1d3a9e0d114430bd25").unwrap();
        let public_key = secp256k1::PublicKey::from_secret_key(SECP256K1, &secret_key);
        let id: [u8; 64] = public_key.serialize_uncompressed()[1..]
            .try_into()
            .expect("64 bit array");
        (secret_key, id)
    }
}

pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];

    let mut hasher = tiny_keccak::Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut output);

    output
}

pub fn keccak256_vec(bytes_vec: Vec<&[u8]>) -> [u8; 32] {
    let mut output = [0u8; 32];

    let mut hasher = tiny_keccak::Keccak::v256();
    for bytes in bytes_vec {
        hasher.update(bytes);
    }
    hasher.finalize(&mut output);

    output
}

pub struct KeccakStream {
    hasher: Keccak,
    secret: [u8; 32]
}

impl KeccakStream {
    pub fn new(secret: [u8; 32]) -> Self {
        let hasher = Keccak::v256();
        Self {
            hasher,
            secret
        }
    }
    pub fn update (&mut self, input: &[u8]) {
        self.hasher.update(input);
    }

    pub fn accumulate_with_xor(&mut self, bytes: &[u8]) {
        let aes_enc = Aes256Enc::new_from_slice(self.secret.as_ref()).unwrap();
        let mut encrypted = self.digest();

        aes_enc.encrypt_padded::<NoPadding>(&mut encrypted, 16).unwrap();
        for i in 0..bytes.len() {
            encrypted[i] ^= bytes[i];
        }

        self.update(encrypted.as_ref());
    }

    pub fn update_accumulate_with_xor(&mut self, bytes: &[u8]) {
        self.update(bytes);
        let digest = self.digest();

        let aes_enc = Aes256Enc::new_from_slice(self.secret.as_ref()).unwrap();
        let mut encrypted = digest.clone();

        aes_enc.encrypt_padded::<NoPadding>(&mut encrypted, 16).unwrap();
        for i in 0..digest.len() {
            encrypted[i] ^= digest[i];
        }

        self.update(encrypted.as_ref());
    }

    pub fn digest(&self) -> [u8;16] {
        let mut bytes = [0u8;16];
        self.hasher.clone().finalize(&mut bytes);
        bytes
    }
}

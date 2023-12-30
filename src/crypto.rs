use secp256k1::{SecretKey, SECP256K1};
use tiny_keccak::Hasher;

pub struct Crypto;

impl Crypto {
    pub(crate) fn init() -> (SecretKey, [u8; 64]) {
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let public_key = secp256k1::PublicKey::from_secret_key(SECP256K1, &secret_key);
        let id: [u8; 64] = public_key.serialize_uncompressed()[1..]
            .try_into()
            .expect("64 bit array");
        (secret_key, id)
    }
}

pub(crate) fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];

    let mut hasher = tiny_keccak::Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut output);

    output
}

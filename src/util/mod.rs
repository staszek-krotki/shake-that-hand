use bytes::{BufMut, BytesMut};
use secp256k1::{Error, PublicKey, SecretKey};

pub fn ecdh_x(public_key: &PublicKey, secret_key: &SecretKey) -> [u8;32] {
    let xy = &secp256k1::ecdh::shared_secret_point(public_key, secret_key);
    let x:[u8;32] = xy[0..32].try_into().unwrap();
    x
}

pub fn public_key_from_node_id(node_id: &[u8;64]) -> Result<PublicKey, Error> {
    let mut buf = BytesMut::with_capacity(65);
    buf.put_u8(4); // magic for uncompressed
    buf.put_slice(node_id);
    PublicKey::from_slice(&buf)
}


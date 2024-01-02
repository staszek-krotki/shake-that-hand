use bytes::{BufMut, Bytes, BytesMut};

pub struct Packet {
    bytes: BytesMut,
}

impl Packet {
    pub(crate) fn new(hash: &[u8; 32], signature: &[u8; 65], data_bytes: &Bytes) -> Self {
        let mut packet_bytes = BytesMut::with_capacity(32 + 65 + data_bytes.len());
        packet_bytes.put_slice(hash);
        packet_bytes.put_slice(signature);
        packet_bytes.put_slice(data_bytes);

        Packet {
            bytes: packet_bytes,
        }
    }

    pub(crate) fn bytes(&self) -> Bytes {
        self.bytes.clone().freeze()
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Packet {
        Packet {
            bytes: BytesMut::from(bytes),
        }
    }
}

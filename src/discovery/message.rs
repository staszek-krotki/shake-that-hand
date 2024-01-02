use crate::crypto::keccak256;
use crate::node_record::NodeRecord;
use alloy_rlp::{Decodable, Encodable, Header, RlpDecodable, RlpEncodable};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use secp256k1::{SecretKey, SECP256K1};
use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use super::net::NodeEndpoint;

#[derive(Clone)]
pub enum Message {
    Ping(Ping),
    Pong(Pong),
    FindNode(FindNode),
    Neighbours(Neighbours),
}

#[derive(Debug, Clone, Eq, PartialEq, RlpDecodable, RlpEncodable)]
pub struct Ping {
    pub version: u32,
    pub from: NodeEndpoint,
    pub to: NodeEndpoint,
    pub expire: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, RlpEncodable, RlpDecodable)]
pub struct Pong {
    pub to: NodeEndpoint,
    pub hash: [u8; 32],
    pub expire: u64,
    // pub enr_sq: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, RlpEncodable, RlpDecodable)]
pub struct FindNode {
    pub id: [u8; 64],
    pub expire: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, RlpEncodable, RlpDecodable)]
pub struct Neighbours {
    pub nodes: Vec<NodeRecord>,
    pub expire: u64,
}

pub struct MessageError(String);

impl Message {
    pub(crate) fn rlp_encode(&self) -> Bytes {
        let mut out = BytesMut::new();
        out.put_u8(self.packet_type());

        match self {
            Message::Ping(ping) => ping.encode(&mut out),
            Message::Pong(pong) => pong.encode(&mut out),
            Message::FindNode(find_node) => find_node.encode(&mut out),
            Message::Neighbours(neighbours) => neighbours.encode(&mut out),
        }

        out.freeze()
    }

    fn packet_type(&self) -> u8 {
        match self {
            Message::Ping(_) => 1,
            Message::Pong(_) => 2,
            Message::FindNode(_) => 3,
            Message::Neighbours(_) => 4,
        }
    }

    pub(crate) fn signature(&self, secret_key: &SecretKey) -> [u8; 65] {
        let msg_rlp_encoded = self.rlp_encode();
        let digest = keccak256(&msg_rlp_encoded);

        let signature = SECP256K1.sign_ecdsa_recoverable(
            &secp256k1::Message::from_digest_slice(&digest).unwrap(),
            secret_key,
        );
        let (recovery_id, signature_bytes) = signature.serialize_compact();
        let mut bytes = BytesMut::new();
        bytes.put_slice(&signature_bytes);
        bytes.put_u8(recovery_id.to_i32() as u8);
        bytes.freeze().to_vec().try_into().unwrap()
    }

    // hash = keccak256(signature || msg_rlp_encoded)
    // msg_rlp_encoded = packet-type || packet-data
    pub(crate) fn hash(&self, signature_bytes: [u8; 65]) -> [u8; 32] {
        let msg_rlp_encoded = self.rlp_encode();

        let mut bytes = BytesMut::new();
        bytes.put_slice(&signature_bytes);
        bytes.put_slice(&msg_rlp_encoded);

        keccak256(&bytes)
    }

    pub(crate) fn new_ping(from: NodeRecord, to: NodeRecord) -> Self {
        Message::Ping(Ping {
            version: 4,
            from: NodeEndpoint::from(from),
            to: NodeEndpoint::from(to),
            expire: SystemTime::now()
                .add(Duration::from_secs(60 * 60))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    pub(crate) fn decode_ping(data: &mut &[u8]) -> Result<Self, MessageError> {
        let header = Header::decode(data).map_err(|_| {
            MessageError("Invalid header".to_string())
        })?;
        let skip_bytes = header.payload_length - data.len();

        let err = |s: &str| { MessageError(s.to_string())};

        let ping = Ping {
            version: u32::decode(data).map_err(|_| err("failed to decode version"))?,
            from: Decodable::decode(data).map_err(|_| err("failed to decode from"))?,
            to: Decodable::decode(data).map_err(|_| err("failed to decode to"))?,
            expire: Decodable::decode(data).map_err(|_| err("failed to decode expire"))?
        };

        let skip_bytes = skip_bytes + data.len();
        if skip_bytes>0 {
            data.advance(skip_bytes);
        }

        Ok(Message::Ping(ping))
    }

    pub(crate) fn new_pong(to: NodeRecord, hash: [u8; 32]) -> Self {
        Message::Pong(Pong {
            to: NodeEndpoint::from(to),
            hash,
            expire: SystemTime::now()
                .add(Duration::from_secs(60 * 60))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    pub(crate) fn decode_pong(data: &mut &[u8]) -> Result<Self, MessageError> {
        let header = Header::decode(data).map_err(|_| {
            MessageError("Invalid header".to_string())
        })?;
        let skip_bytes = header.payload_length - data.len();

        let err = |s: &str| { MessageError(s.to_string())};

        let pong = Pong {
            to: Decodable::decode(data).map_err(|_| err("failed to decode to"))?,
            hash: Decodable::decode(data).map_err(|_| err("failed to decode hash"))?,
            expire: Decodable::decode(data).map_err(|_| err("failed to decode expire"))?
        };

        let skip_bytes = skip_bytes + data.len();
        if skip_bytes>0 {
            data.advance(skip_bytes);
        }

        Ok(Message::Pong(pong))
    }

    pub(crate) fn new_find_node(node_id: [u8; 64]) -> Self {
        Message::FindNode(FindNode {
            id: node_id,
            expire: SystemTime::now()
                .add(Duration::from_secs(60 * 60))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    pub(crate) fn decode_find_node(data: &mut &[u8]) -> Result<Self, MessageError> {
        let header = Header::decode(data).map_err(|_| {
            MessageError("Invalid header".to_string())
        })?;
        let skip_bytes = header.payload_length - data.len();

        let err = |s: &str| { MessageError(s.to_string())};

        let find_node = FindNode {
            id: Decodable::decode(data).map_err(|_| err("failed to decode id"))?,
            expire: Decodable::decode(data).map_err(|_| err("failed to decode expire"))?
        };

        let skip_bytes = skip_bytes + data.len();
        if skip_bytes>0 {
            data.advance(skip_bytes);
        }

        Ok(Message::FindNode(find_node))
    }

    #[allow(dead_code)]
    pub(crate) fn new_neighbours(nodes: Vec<NodeRecord>) -> Self {
        Message::Neighbours(Neighbours {
            nodes,
            expire: SystemTime::now()
                .add(Duration::from_secs(60 * 60))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    pub(crate) fn decode_neighbours(data: &mut &[u8]) -> Result<Self, MessageError> {
        let header = Header::decode(data).map_err(|_| {
            MessageError("Invalid header".to_string())
        })?;
        let skip_bytes = header.payload_length - data.len();

        let err = |s: &str| { MessageError(s.to_string())};

        let neighbours = Neighbours {
            nodes: Decodable::decode(data).map_err(|_| err("failed to decode nodes"))?,
            expire: Decodable::decode(data).map_err(|_| err("failed to decode expire"))?
        };

        let skip_bytes = skip_bytes + data.len();
        if skip_bytes>0 {
            data.advance(skip_bytes);
        }

        Ok(Message::Neighbours(neighbours))
    }
}

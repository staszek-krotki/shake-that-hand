use crate::crypto::keccak256;
use super::message::Message;
use crate::node_record::NodeRecord;
use crate::discovery::packet::Packet;
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{SECP256K1, SecretKey};
use std::time::Duration;
use tokio::time::sleep;
use super::net::DiscoveryNet;

pub struct DiscoveryProtocol {
    secret_key: SecretKey,
}

#[derive(Debug)]
pub struct DiscoveryProtocolError(String);

impl DiscoveryProtocol {
    pub(crate) fn new(sk: SecretKey) -> Self {
        DiscoveryProtocol { secret_key: sk }
    }

    pub(crate) async fn find_neighbours(&self, id: [u8; 64], net: &DiscoveryNet) -> Vec<NodeRecord> {
        let mut neighbours: Vec<NodeRecord> = vec![];

        // we're using udp, so just to give it a little resiliency - try up to 3 times to send FindNode
        // for each FindNode try 3 times to get the Neighbours response
        for _i in 0..3 {
            let msg = Message::new_find_node(id);
            let (packet, _find_node_hash) = self.encode_packet(msg);
            net.send(packet).await;

            for _j in 0..3 {
                let receive = tokio::time::timeout(Duration::from_millis(1000), net.receive()).await;
                if let Ok(packet) = receive {
                    let (message, _hash) = self.decode_packet(packet).expect("decode should not fail");
                    if let Message::Neighbours(n) = message {
                        println!("received {} neighbours", n.nodes.len());
                        neighbours.extend_from_slice(&n.nodes);
                    }
                }
            }
            if neighbours.len() > 0 {
                break;
            }
        }

        neighbours
    }

    pub(crate) async fn init(&self, net: &DiscoveryNet) {
        let msg = Message::new_ping(net.local_nr.clone(), net.peer_nr.clone());
        let (packet, ping_hash) = self.encode_packet(msg);
        net.send(packet).await;

        let pong_receive = tokio::time::timeout(Duration::from_millis(3000), net.receive()).await;
        if let Ok(packet) = pong_receive {
            // let packet = net.receive().await;
            let (message, _hash) = self.decode_packet(packet).expect("decode should not fail");

            if let Message::Pong(pong) = message {
                if pong.hash != ping_hash {
                    panic!("PING/PONG hash mismatch");
                }
            }
            else {
                panic!("Invalid packet received after PING, PONG was expected");
            }
        }
        else {
            panic!("Timeout waiting for PONG");
        }

        // bootnode might want to ping us for verification
        let ping_receive = tokio::time::timeout(Duration::from_millis(500), net.receive()).await;
        if let Ok(packet) = ping_receive {
            let (message, hash) = self.decode_packet(packet).expect("decode should not fail");
            if let Message::Ping(_ping) = message {
                let msg = Message::new_pong(net.peer_nr.clone(), hash);
                let (packet, _pong_hash) = self.encode_packet(msg);
                net.send(packet).await;
                //we need to give a little time to register our PONG or otherwise our next requests might be ignored
                sleep(Duration::from_millis(500)).await;
            }
        }
    }

    pub(crate) fn encode_packet(&self, msg: Message) -> (Packet, [u8; 32]) {
        let data_bytes = msg.rlp_encode();

        let signature = msg.signature(&self.secret_key);
        let hash = msg.hash(signature);

        (Packet::new(&hash, &signature, &data_bytes), hash)
    }

    pub(crate) fn decode_packet(&self, packet: Packet) -> Result<(Message, [u8;32]), DiscoveryProtocolError> {
        let bytes = packet.bytes();
        if bytes.len() < 32 + 64 + 1 {
            return Err(DiscoveryProtocolError(format!("packet to short {}", bytes.len())));
        }

        let hash: [u8; 32] = bytes[..32]
            .try_into()
            .map_err(|_| DiscoveryProtocolError("hash should have 32 bits".to_string()))?;

        let calculated_hash = keccak256(&bytes[32..]);

        if calculated_hash != hash {
            return Err(DiscoveryProtocolError("hash mismatch".to_string()));
        }

        let signature: [u8; 64] = bytes[32..96]
            .try_into()
            .map_err(|_| DiscoveryProtocolError("signature should have 64 bits".to_string()))?;

        let recovery_id = bytes[96] as i32;
        let recovery_id = RecoveryId::from_i32(recovery_id)
            .map_err(|_| DiscoveryProtocolError("Invalid recovery id".to_string()))?;

        let recoverable_sig = RecoverableSignature::from_compact(signature.as_slice(), recovery_id)
            .map_err(|_| DiscoveryProtocolError("Invalid recoverable signature".to_string()))?;

        let secp256k1_msg = secp256k1::Message::from_digest_slice(keccak256(&bytes[97..]).as_slice())
            .map_err(|_| DiscoveryProtocolError("Invalid secp256k1 message".to_string()))?;

        let pk = SECP256K1.recover_ecdsa(&secp256k1_msg, &recoverable_sig)
            .map_err(|_| DiscoveryProtocolError("Failed to recover public key".to_string()))?;

        let _id: [u8; 64] = pk.serialize_uncompressed()[1..].try_into().map_err(|_| {
            DiscoveryProtocolError("Invalid node id".to_string())
        })?;

        let packet_type = bytes[97];
        let mut data = &bytes[98..];

        let msg = match packet_type {
            1 => Message::decode_ping(&mut data).map_err(|_| DiscoveryProtocolError("Invalid ping packet".to_string()))?,
            2 => Message::decode_pong(&mut data).map_err(|_| DiscoveryProtocolError("Invalid pong packet".to_string()))?,
            3 => Message::decode_find_node(&mut data).map_err(|_| DiscoveryProtocolError("Invalid find-node packet".to_string()))?,
            4 => Message::decode_neighbours(&mut data).map_err(|_| DiscoveryProtocolError("Invalid neighbours packet".to_string()))?,
            _ => return Err(DiscoveryProtocolError(format!("Unsupported packet type {}", packet_type)))
        };

        Ok((msg, hash))
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use std::net::{IpAddr, Ipv4Addr};
    use rand::thread_rng;
    use super::*;

    #[test]
    fn encode_decode_ping() {
        let from_nr = NodeRecord {
            node_id: [7u8; 64],
            ip: IpAddr::V4(Ipv4Addr::new(10, 11, 12, 13)),
            tcp_port: 12,
            udp_port: 13,
        };

        let to_nr = NodeRecord {
            node_id: [9u8; 64],
            ip: IpAddr::V4(Ipv4Addr::new(121, 122, 123, 124)),
            tcp_port: 1212,
            udp_port: 1313,
        };

        let msg = Message::new_ping(from_nr, to_nr);
        let protocol = DiscoveryProtocol::new(SecretKey::new(&mut thread_rng()));
        let (packet, _hash) = protocol.encode_packet(msg.clone());
        if let Ok((result, _hash)) = protocol.decode_packet(packet) {
            if let Message::Ping(ping) = result {
                match msg {
                    Message::Ping(msg_ping) => {
                        assert_eq!(ping, msg_ping);
                    },
                    _ => panic!("message malformed")
                }
            }
            else {
                panic!("Invalid packet");
            }
        }
        else {
            panic!("Cannot decode packet");
        }
    }

    #[test]
    fn encode_decode_pong() {
        let to_nr = NodeRecord {
            node_id: [9u8; 64],
            ip: IpAddr::V4(Ipv4Addr::new(121, 122, 123, 124)),
            tcp_port: 1212,
            udp_port: 1313,
        };

        let msg = Message::new_pong(to_nr, [5u8; 32]);
        let protocol = DiscoveryProtocol::new(SecretKey::new(&mut thread_rng()));
        let (packet, _hash) = protocol.encode_packet(msg.clone());
        if let Ok((result, _hash)) = protocol.decode_packet(packet) {
            if let Message::Pong(pong) = result {
                match msg {
                    Message::Pong(msg_pong) => {
                        assert_eq!(pong, msg_pong);
                    },
                    _ => panic!("message malformed")
                }
            }
            else {
                panic!("Invalid packet");
            }
        }
        else {
            panic!("Cannot decode packet");
        }
    }

    #[test]
    fn encode_decode_find_node() {
        let msg = Message::new_find_node([5u8; 64]);
        let protocol = DiscoveryProtocol::new(SecretKey::new(&mut thread_rng()));
        let (packet, _hash) = protocol.encode_packet(msg.clone());
        if let Ok((result, _hash)) = protocol.decode_packet(packet) {
            if let Message::FindNode(find_node) = result {
                match msg {
                    Message::FindNode(msg_find_node) => {
                        assert_eq!(find_node, msg_find_node);
                    },
                    _ => panic!("message malformed")
                }
            }
            else {
                panic!("Invalid packet");
            }
        }
        else {
            panic!("Cannot decode packet");
        }
    }

    #[test]
    fn encode_decode_neighbours() {
        let nr1 = NodeRecord {
            node_id: [3u8; 64],
            ip: IpAddr::V4(Ipv4Addr::new(121, 122, 123, 124)),
            tcp_port: 1212,
            udp_port: 1313,
        };
        let nr2 = NodeRecord {
            node_id: [9u8; 64],
            ip: IpAddr::V4(Ipv4Addr::new(221, 222, 223, 224)),
            tcp_port: 2323,
            udp_port: 2424,
        };
        let msg = Message::new_neighbours(vec![nr1, nr2]);
        let protocol = DiscoveryProtocol::new(SecretKey::new(&mut thread_rng()));
        let (packet, _hash) = protocol.encode_packet(msg.clone());
        if let Ok((result, _hash)) = protocol.decode_packet(packet) {
            if let Message::Neighbours(neighbours) = result {
                match msg {
                    Message::Neighbours(msg_neighbours) => {
                        assert_eq!(neighbours, msg_neighbours);
                    },
                    _ => panic!("message malformed")
                }
            }
            else {
                panic!("Invalid packet");
            }
        }
        else {
            panic!("Cannot decode packet");
        }
    }
}

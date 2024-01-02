use crate::discovery::packet::Packet;
use std::net::{IpAddr, SocketAddr};
use alloy_rlp::{RlpDecodable, RlpEncodable};
use tokio::net::UdpSocket;
use crate::node_record::NodeRecord;


#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, RlpDecodable, RlpEncodable)]
pub struct NodeEndpoint {
    pub ip: IpAddr,
    pub udp_port: u16,
    pub tcp_port: u16,
}

impl From<NodeRecord> for NodeEndpoint {
    fn from(nr: NodeRecord) -> Self {
        NodeEndpoint {
            ip: nr.ip,
            udp_port: nr.udp_port,
            tcp_port: nr.tcp_port,
        }
    }
}

pub struct DiscoveryNet {
    udp_socket: UdpSocket,
    pub local_nr: NodeRecord,
    pub peer_nr: NodeRecord,
}

impl DiscoveryNet {
    pub(crate) async fn init(local_nr: NodeRecord, peer_nr: &NodeRecord) -> Self {
        let udp_socket = UdpSocket::bind(SocketAddr::from(&local_nr)).await.unwrap();
        udp_socket
            .connect(SocketAddr::from(peer_nr))
            .await
            .expect("should connect");

        DiscoveryNet {
            udp_socket,
            local_nr,
            peer_nr: *peer_nr
        }
    }

    pub(crate) async fn send(&self, packet: Packet) -> usize {
        self.udp_socket
            .send(&*packet.bytes())
            .await
            .expect("should send")
    }

    pub(crate) async fn receive(&self) -> Packet {
        let mut buf = [0; 1280];
        let bytes_read = self
            .udp_socket
            .recv(&mut buf)
            .await
            .expect("should receive");

        let packet_bytes = &buf[..bytes_read];
        Packet::from_bytes(packet_bytes)
    }
}

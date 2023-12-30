use crate::packet::Packet;
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

pub struct Net {
    udp_socket: UdpSocket,
}

impl Net {
    pub(crate) async fn init(local_addresss: SocketAddr, remote_addr: SocketAddr) -> Self {
        let udp_socket = UdpSocket::bind(local_addresss).await.unwrap();
        udp_socket
            .connect(remote_addr)
            .await
            .expect("should connect");

        Net { udp_socket }
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

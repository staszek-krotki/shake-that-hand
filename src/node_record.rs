use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;
use alloy_rlp::{RlpDecodable, RlpEncodable};
use url::Url;

#[derive(Copy, Clone, Eq, PartialEq, Debug, RlpEncodable, RlpDecodable)]
pub struct NodeRecord {
    pub ip: IpAddr,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub node_id: [u8; 64]
}

impl NodeRecord {
    pub fn new(addr: SocketAddr, id: [u8; 64]) -> Self {
        Self {
            ip: addr.ip(),
            tcp_port: addr.port(),
            udp_port: addr.port(),
            node_id: id,
        }
    }
}

impl FromStr for NodeRecord {
    type Err = url::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(s)?;
        let mut id = [0u8; 64];
        let _ = hex::decode_to_slice(url.username(), &mut id)
            .map_err(|_| url::ParseError::InvalidIpv4Address);
        let host = url.host().ok_or(url::ParseError::InvalidIpv4Address)?;
        let port = url.port().ok_or(url::ParseError::InvalidPort)?;
        let ipv4_addr = Ipv4Addr::from_str(host.to_string().as_str())
            .map_err(|_| url::ParseError::InvalidIpv4Address)?;
        Ok(NodeRecord {
            node_id: id,
            ip: IpAddr::V4(ipv4_addr),
            tcp_port: port,
            udp_port: port,
        })
    }
}
//
// impl Clone for NodeRecord {
//     fn clone(&self) -> Self {
//         NodeRecord {
//             id: self.id.clone(),
//             address: self.address.clone(),
//             tcp_port: self.tcp_port,
//             udp_port: self.udp_port,
//         }
//     }
// }

impl From<NodeRecord> for SocketAddr {
    fn from(nr: NodeRecord) -> Self {
        let addr_v4 = match nr.ip {
            IpAddr::V4(a) => a,
            IpAddr::V6(_) => panic!("V6 is not supported"),
        };

        let addr = SocketAddr::V4(SocketAddrV4::new(addr_v4, nr.udp_port));
        addr
    }
}

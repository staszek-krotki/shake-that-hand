use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;
use alloy_rlp::{RlpDecodable, RlpEncodable};
use url::{Host, Url};

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

impl From<&NodeRecord> for SocketAddr {
    fn from(nr: &NodeRecord) -> Self {
        let addr_v4 = match nr.ip {
            IpAddr::V4(a) => a,
            IpAddr::V6(_) => panic!("V6 is not supported"),
        };

        let addr = SocketAddr::V4(SocketAddrV4::new(addr_v4, nr.udp_port));
        addr
    }
}

fn decode_hex(s: &str) -> [u8; 64] {
    let r:Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();

    let mut a = [0u8; 64];
    a.copy_from_slice(r.as_slice());
    a
}

impl From<Url> for NodeRecord {
    fn from(enode: Url) -> Self {
        let ip = match enode.host().unwrap() {
            Host::Ipv4(addr) => IpAddr::V4(addr),
            Host::Domain(d) => IpAddr::from_str(d).unwrap(),
            Host::Ipv6(_) => panic!("Ipv6 not supported")
        };
        Self {
            ip,
            tcp_port: enode.port().unwrap(),
            udp_port: enode.port().unwrap(),
            node_id: decode_hex(enode.username()),
        }
    }
}

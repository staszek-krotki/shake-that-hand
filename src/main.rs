mod crypto;
mod message;
mod net;
mod node_record;
mod packet;
mod discovery_protocol;
mod handshake_protocol;
mod ecies_crypto;
mod rlpx;

use crate::crypto::Crypto;
use crate::net::Net;
use crate::discovery_protocol::DiscoveryProtocol;
use node_record::NodeRecord;
use std::net::SocketAddr;
use std::str::FromStr;
use rand::{Rng, thread_rng};
use secp256k1::{SECP256K1, SecretKey, PublicKey};
use crate::handshake_protocol::{public_key_from_node_id};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use crate::rlpx::Rlpx;

pub static MAINNET_BOOTNODES: [&str; 4] = [
    "enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303",   // bootnode-aws-ap-southeast-1-001
    "enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de@3.209.45.79:30303",     // bootnode-aws-us-east-1-001
    "enode://2b252ab6a1d0f971d9722cb839a42cb81db019ba44c08754628ab4a823487071b5695317c8ccd085219c3a03af063495b2f1da8d18218da2d6a82981b45e6ffc@65.108.70.101:30303",   // bootnode-hetzner-hel
    "enode://4aeb4ab6c14b23e2c4cfdce879c04b0748a20d8e9b59e25ded2a08143e265c6c25936e74cbc8e641e3312ca288673d91f2f93f8e277de3cfa444ecdaaf982052@157.90.35.166:30303",   // bootnode-hetzner-fsn
];

pub static GOERLI_BOOTNODES : [&str; 7] = [
    // Upstream bootnodes
    "enode://011f758e6552d105183b1761c5e2dea0111bc20fd5f6422bc7f91e0fabbec9a6595caf6239b37feb773dddd3f87240d99d859431891e4a642cf2a0a9e6cbb98a@51.141.78.53:30303",
    "enode://176b9417f511d05b6b2cf3e34b756cf0a7096b3094572a8f6ef4cdcb9d1f9d00683bf0f83347eebdf3b81c3521c2332086d9592802230bf528eaf606a1d9677b@13.93.54.137:30303",
    "enode://46add44b9f13965f7b9875ac6b85f016f341012d84f975377573800a863526f4da19ae2c620ec73d11591fa9510e992ecc03ad0751f53cc02f7c7ed6d55c7291@94.237.54.114:30313",
    "enode://b5948a2d3e9d486c4d75bf32713221c2bd6cf86463302339299bd227dc2e276cd5a1c7ca4f43a0e9122fe9af884efed563bd2a1fd28661f3b5f5ad7bf1de5949@18.218.250.66:30303",

    // Ethereum Foundation bootnode
    "enode://a61215641fb8714a373c80edbfa0ea8878243193f57c96eeb44d0bc019ef295abd4e044fd619bfc4c59731a73fb79afe84e9ab6da0c743ceb479cbb6d263fa91@3.11.147.67:30303",

    // Goerli Initiative bootnodes
    "enode://d4f764a48ec2a8ecf883735776fdefe0a3949eb0ca476bd7bc8d0954a9defe8fea15ae5da7d40b5d2d59ce9524a99daedadf6da6283fca492cc80b53689fb3b3@46.4.99.122:32109",
    "enode://d2b720352e8216c9efc470091aa91ddafc53e222b32780f505c817ceef69e01d5b0b0797b69db254c586f493872352f5a022b4d8479a00fc92ec55f9ad46a27e@88.99.70.182:30303",
];

#[tokio::main]
async fn main() {
    // let key = Aes256Gcm::generate_key(OsRng);
    let (secret_key, id) = Crypto::init();

    let local_addresss = SocketAddr::from_str("0.0.0.0:30302").expect("local address should be valid");
    let local_nr = NodeRecord::new(local_addresss, id);
    let bootnode_nr = NodeRecord::from_str(MAINNET_BOOTNODES[0]).unwrap();
    let protocol = DiscoveryProtocol::new(secret_key);

    let remote_addr = SocketAddr::from(bootnode_nr.clone());
    let net = Net::init(local_addresss, remote_addr).await;

    protocol.init_discovery(local_nr, bootnode_nr, &net).await;
    let neighbours = protocol.discover_neighbours(id, &net).await;

    println!("discovery done");

    let mut rng = thread_rng();
    let nonce: [u8; 32] = rng.gen();
    let ephemeral_secret_key = SecretKey::new(&mut rng);
    let ephemeral_public_key = PublicKey::from_secret_key(SECP256K1, &ephemeral_secret_key);

    for peer in neighbours {
        if let Ok(peer_public_key) = public_key_from_node_id(&peer.node_id) {
            let remote_address = SocketAddr::new(peer.ip, peer.udp_port);
            println!("Peer: {}", remote_address);

            let socket_address = SocketAddr::new(peer.ip, peer.tcp_port);
            match TcpStream::connect(socket_address).await {
                Ok(mut tcp_stream) => {
                    let auth_body = Rlpx::get_auth_body(&secret_key, id, nonce, &ephemeral_secret_key, &peer_public_key);
                    let encrypted_body = Rlpx::encrypt_auth_body(auth_body, &[0u8; 4], &peer_public_key);
                    let auth = Rlpx::build_auth(encrypted_body);

                    tcp_stream.write_all(&auth).await.expect("should be sent");

                    let mut buf = vec![];
                    if let Ok(r) = tcp_stream.read_to_end(&mut buf).await {
                        println!("read {} bytes into {} bytes of buf", r, buf.len());
                    }

                }
                Err(e) => {
                    println!("Couldn't connect: {}", e);
                }
            }
        }
    }

    ()
}

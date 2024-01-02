use std::time::Duration;
use alloy_rlp::Decodable;
use bytes::BytesMut;
use secp256k1::{PublicKey, SecretKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use crate::handshake::rlpx::{AckBody, Hello, Rlpx, RlpxError};
use crate::handshake::session::Session;

pub async fn send_auth(
    tcp_stream: &mut TcpStream,
    secret_key: &SecretKey,
    id: &[u8;64],
    nonce: &[u8; 32],
    ephemeral_secret_key: &SecretKey,
    peer_public_key: &PublicKey
) -> Result<BytesMut, RlpxError> {
    let auth_body = Rlpx::build_auth_body(&secret_key, id, nonce, &ephemeral_secret_key, &peer_public_key);
    let encrypted_body = Rlpx::encrypt_auth_body(auth_body, &[0u8; 4], &peer_public_key);
    let auth = Rlpx::build_auth(encrypted_body);
    let auth_message = auth.clone();

    match tokio::time::timeout(
        Duration::from_millis(3000),
        tcp_stream.write_all(&auth)
    ).await {
        Ok(_) => Ok(auth_message),
        Err(_) => Err(RlpxError("failed to send auth".to_string()))
    }
}

pub async fn read_ack(tcp_stream: &mut TcpStream, secret_key: &SecretKey) -> Result<(AckBody, BytesMut), RlpxError> {
    let mut buf = BytesMut::with_capacity(4*1024*1024);
    let read = tokio::time::timeout(Duration::from_millis(3000), tcp_stream.read_buf(&mut buf)).await;
    if let Ok(Ok(read)) = read {
        let ack_bytes = {
            if read == 0 {
                BytesMut::new()
            } else {
                let payload_size = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                let mut bytes = buf.clone();
                bytes.split_to(payload_size + 2)
            }
        };
        match Rlpx::decrypt_ack(buf, secret_key).await {
            Ok(ack) => return Ok((ack, ack_bytes)),
            Err(e) => return Err(e)
        }
    }
    Err(RlpxError("Failed to receive Ack".to_string()))
}

pub async fn send_hello(tcp_stream: &mut TcpStream, session: &mut Session, id: &[u8; 64]) -> Result<(), RlpxError> {
    let hello_bytes = Rlpx::build_hello(id.clone());
    let frame = Rlpx::encrypt_frame(hello_bytes, session);

    match tokio::time::timeout(
        Duration::from_millis(3000),
        tcp_stream.write_all(&frame)
    ).await {
        Ok(_) => Ok(()),
        Err(_) => Err(RlpxError("failed to send hello".to_string()))
    }
}

pub async fn read_hello(tcp_stream: &mut TcpStream, mut session: Session) -> Result<Hello, RlpxError> {
    let mut buf = BytesMut::with_capacity(4*1024*1024);
    let read = tcp_stream.read_buf(&mut buf).await;
    match read {
        Ok(read) if read > 0 => {
            println!("Hello response read {}", read);
            if let Ok(hello_bytes) = Rlpx::read_hello_frame(buf, &mut session.ingress_aes, &mut session.ingress_mac) {
                let msg_id: u8 = Decodable::decode(&mut &hello_bytes[..]).unwrap();
                return match msg_id {
                    0 => {
                        let hello: Hello = Decodable::decode(&mut &hello_bytes[1..]).unwrap();
                        return Ok(hello);
                    }
                    1 => Err(RlpxError("Disconnect message received".to_string())),
                    _ => Err(RlpxError(format!("Not a hello message! {}", msg_id))),
                }
            }
            return Err(RlpxError("Failed to read hello frame".to_string()))
        },
        Ok(_) => return Err(RlpxError("Empty hello response - connection closed".to_string())),
        Err(e) => return Err(RlpxError(format!("Hello response failed {:?}", e)))
    }
}




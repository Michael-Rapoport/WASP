use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use serde::{Serialize, Deserialize};
use std::time::Duration;

#[derive(Serialize, Deserialize)]
enum Message {
    Data(Vec<u8>),
    Ack,
}

pub struct NetworkCommunicator {
    connect_timeout: Duration,
    read_timeout: Duration,
    write_timeout: Duration,
}

impl NetworkCommunicator {
    pub fn new(connect_timeout: Duration, read_timeout: Duration, write_timeout: Duration) -> Self {
        Self {
            connect_timeout,
            read_timeout,
            write_timeout,
        }
    }

    pub async fn send_to_peer(&self, peer_addr: SocketAddr, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut stream = tokio::time::timeout(
            self.connect_timeout,
            TcpStream::connect(peer_addr)
        ).await??;

        let message = Message::Data(data.to_vec());
        let serialized = bincode::serialize(&message)?;

        let len = serialized.len() as u32;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&serialized).await?;

        let mut len_bytes = [0u8; 4];
        tokio::time::timeout(
            self.read_timeout,
            stream.read_exact(&mut len_bytes)
        ).await??;

        let len = u32::from_be_bytes(len_bytes) as usize;
        let mut response_bytes = vec![0u8; len];
        tokio::time::timeout(
            self.read_timeout,
            stream.read_exact(&mut response_bytes)
        ).await??;

        let response: Message = bincode::deserialize(&response_bytes)?;
        match response {
            Message::Data(data) => Ok(data),
            Message::Ack => Ok(vec![]),
        }
    }
}
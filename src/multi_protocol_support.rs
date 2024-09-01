use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::error_handling::SwarmProxyError;
use crate::peer_discovery::PeerInfo;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;
use rustls::{ServerConfig, ClientConfig};
use std::collections::HashMap;
use hyper::{Body, Request, Response, Server, Client};
use hyper::service::{make_service_fn, service_fn};
use hyper::client::HttpConnector;
use hyper_tls::HttpsConnector;
use trust_dns_resolver::AsyncResolver;

#[derive(Debug, Clone)]
pub enum Protocol {
    HTTP,
    HTTPS,
    TCP,
    UDP,
    // Add more protocols as needed
}

#[async_trait]
pub trait ProtocolHandler: Send + Sync {
    async fn handle(&self, data: &[u8], peer: &PeerInfo) -> Result<Vec<u8>, SwarmProxyError>;
}

pub struct HttpHandler {
    client: Client<HttpsConnector<HttpConnector>>,
}

impl HttpHandler {
    pub fn new() -> Self {
        let https = HttpsConnector::new();
        let client = Client::builder().build::<_, hyper::Body>(https);
        Self { client }
    }
}

#[async_trait]
impl ProtocolHandler for HttpHandler {
    async fn handle(&self, data: &[u8], peer: &PeerInfo) -> Result<Vec<u8>, SwarmProxyError> {
        let req = Request::from_bytes(data.to_vec())
            .map_err(|e| SwarmProxyError::ProtocolError(format!("Failed to parse HTTP request: {}", e)))?;

        let resp = self.client.request(req).await
            .map_err(|e| SwarmProxyError::ProtocolError(format!("Failed to send HTTP request: {}", e)))?;

        let body_bytes = hyper::body::to_bytes(resp.into_body()).await
            .map_err(|e| SwarmProxyError::ProtocolError(format!("Failed to read HTTP response body: {}", e)))?;

        Ok(body_bytes.to_vec())
    }
}

pub struct TcpHandler;

#[async_trait]
impl ProtocolHandler for TcpHandler {
    async fn handle(&self, data: &[u8], peer: &PeerInfo) -> Result<Vec<u8>, SwarmProxyError> {
        let mut stream = TcpStream::connect(peer.addr).await
            .map_err(|e| SwarmProxyError::NetworkError(format!("Failed to connect to peer: {}", e)))?;

        stream.write_all(data).await
            .map_err(|e| SwarmProxyError::NetworkError(format!("Failed to write to peer: {}", e)))?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await
            .map_err(|e| SwarmProxyError::NetworkError(format!("Failed to read from peer: {}", e)))?;

        Ok(response)
    }
}

pub struct MultiProtocolHandler {
    handlers: HashMap<Protocol, Arc<dyn ProtocolHandler>>,
}

impl MultiProtocolHandler {
    pub fn new() -> Self {
        let mut handlers = HashMap::new();
        handlers.insert(Protocol::HTTP, Arc::new(HttpHandler::new()) as Arc<dyn ProtocolHandler>);
        handlers.insert(Protocol::TCP, Arc::new(TcpHandler) as Arc<dyn ProtocolHandler>);
        // Add more handlers for other protocols

        Self { handlers }
    }

    pub async fn send_data(&self, peer: &PeerInfo, data: &[u8]) -> Result<Vec<u8>, SwarmProxyError> {
        let protocol = self.detect_protocol(data);
        let handler = self.handlers.get(&protocol)
            .ok_or_else(|| SwarmProxyError::ProtocolError(format!("Unsupported protocol: {:?}", protocol)))?;

        handler.handle(data, peer).await
    }

    fn detect_protocol(&self, data: &[u8]) -> Protocol {
        // Implement protocol detection logic
        // For simplicity, we'll assume HTTP if it starts with a common HTTP method
        if data.starts_with(b"GET ") || data.starts_with(b"POST ") || data.starts_with(b"HTTP/") {
            Protocol::HTTP
        } else {
            Protocol::TCP
        }
    }
}

pub struct ProxyServer {
    addr: SocketAddr,
    multi_protocol_handler: Arc<MultiProtocolHandler>,
}

impl ProxyServer {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            multi_protocol_handler: Arc::new(MultiProtocolHandler::new()),
        }
    }

    pub async fn run(&self) -> Result<(), SwarmProxyError> {
        let make_svc = make_service_fn(|_conn| {
            let multi_protocol_handler = self.multi_protocol_handler.clone();
            async {
                Ok::<_, hyper::Error>(service_fn(move |req| {
                    let multi_protocol_handler = multi_protocol_handler.clone();
                    async move {
                        let (parts, body) = req.into_parts();
                        let body_bytes = hyper::body::to_bytes(body).await?;
                        
                        // Create a mock PeerInfo for demonstration
                        let peer_info = PeerInfo {
                            id: "mock_peer".to_string(),
                            addr: ([127, 0, 0, 1], 8080).into(),
                            last_seen: std::time::Instant::now(),
                            capabilities: vec![],
                        };

                        match multi_protocol_handler.send_data(&peer_info, &body_bytes).await {
                            Ok(response_data) => Ok::<_, hyper::Error>(Response::new(Body::from(response_data))),
                            Err(e) => Ok(Response::builder()
                                .status(500)
                                .body(Body::from(format!("Error: {:?}", e)))
                                .unwrap()),
                        }
                    }
                }))
            }
        });

        let server = Server::bind(&self.addr).serve(make_svc);

        server.await.map_err(|e| SwarmProxyError::NetworkError(format!("Server error: {}", e)))
    }
}
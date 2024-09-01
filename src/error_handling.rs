use thiserror::Error;
use std::io;

#[derive(Error, Debug)]
pub enum SwarmProxyError {
    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Invalid configuration: {0}")]
    ConfigError(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Compression error: {0}")]
    CompressionError(String),

    #[error("Decompression error: {0}")]
    DecompressionError(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Request timeout")]
    RequestTimeout,

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),

    #[error("Hyper error: {0}")]
    HyperError(#[from] hyper::Error),

    #[error("TLS error: {0}")]
    TlsError(#[from] rustls::Error),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl From<redis::RedisError> for SwarmProxyError {
    fn from(err: redis::RedisError) -> Self {
        SwarmProxyError::CacheError(err.to_string())
    }
}

impl From<bincode::Error> for SwarmProxyError {
    fn from(err: bincode::Error) -> Self {
        SwarmProxyError::SerializationError(err.to_string())
    }
}

impl From<config::ConfigError> for SwarmProxyError {
    fn from(err: config::ConfigError) -> Self {
        SwarmProxyError::ConfigError(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, SwarmProxyError>;
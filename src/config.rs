use serde::Deserialize;
use std::net::SocketAddr;
use std::time::Duration;
use config::{Config, ConfigError, File};

#[derive(Debug, Deserialize)]
pub struct SwarmProxyConfig {
    pub redis_url: String,
    pub local_cache_size: usize,
    pub max_connections: usize,
    pub peer_timeout: Duration,
    pub bootstrap_nodes: Vec<SocketAddr>,
    pub proxy_addr: SocketAddr,
    pub jwt_secret: String,
    pub worker_threads: usize,
    pub metrics_addr: SocketAddr,
    pub max_request_size: usize,
    pub compression_level: i32,
}

impl SwarmProxyConfig {
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let mut config = Config::default();
        config.merge(File::with_name(path))?;

        config.try_into()
    }
}

impl Default for SwarmProxyConfig {
    fn default() -> Self {
        Self {
            redis_url: "redis://localhost/".to_string(),
            local_cache_size: 10000,
            max_connections: 1000,
            peer_timeout: Duration::from_secs(300),
            bootstrap_nodes: vec![],
            proxy_addr: "127.0.0.1:8000".parse().unwrap(),
            jwt_secret: "your-secret-key".to_string(),
            worker_threads: num_cpus::get(),
            metrics_addr: "127.0.0.1:9100".parse().unwrap(),
            max_request_size: 10 * 1024 * 1024, // 10 MB
            compression_level: 3,
        }
    }
}
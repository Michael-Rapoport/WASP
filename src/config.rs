use serde::Deserialize;
use std::time::Duration;
use std::net::SocketAddr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    #[error("Invalid address: {0}")]
    InvalidAddress(#[from] std::net::AddrParseError),
    #[error("Environment error: {0}")]
    EnvironmentError(#[from] config::ConfigError),
}

#[derive(Deserialize)]
pub struct Config {
    pub listen_addr: String,
    pub node_id: String,
    pub consensus_interval: Duration,
    pub min_delay: Duration,
    pub max_delay: Duration,
    pub min_packet_size: usize,
    pub max_packet_size: usize,
    pub operation_time: Duration,
    pub network_config: NetworkConfig,
}

#[derive(Deserialize)]
pub struct NetworkConfig {
    pub bootstrap_nodes: Vec<String>,
    pub max_connections: usize,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut cfg = config::Config::new();
        cfg.merge(config::Environment::new())?;
        let config: Config = cfg.try_into()?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        // Validate listen_addr
        self.listen_addr.parse::<SocketAddr>()?;

        // Validate node_id
        if self.node_id.is_empty() {
            return Err(ConfigError::ConfigurationError("node_id cannot be empty".to_string()));
        }

        // Validate delays
        if self.min_delay > self.max_delay {
            return Err(ConfigError::ConfigurationError("min_delay cannot be greater than max_delay".to_string()));
        }

        // Validate packet sizes
        if self.min_packet_size > self.max_packet_size {
            return Err(ConfigError::ConfigurationError("min_packet_size cannot be greater than max_packet_size".to_string()));
        }

        // Validate operation_time
        if self.operation_time == Duration::from_secs(0) {
            return Err(ConfigError::ConfigurationError("operation_time must be greater than zero".to_string()));
        }

        // Validate network config
        self.network_config.validate()?;

        Ok(())
    }
}

impl NetworkConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        // Validate bootstrap_nodes
        for node in &self.bootstrap_nodes {
            node.parse::<SocketAddr>()?;
        }

        // Validate max_connections
        if self.max_connections == 0 {
            return Err(ConfigError::ConfigurationError("max_connections must be greater than zero".to_string()));
        }

        Ok(())
    }
}
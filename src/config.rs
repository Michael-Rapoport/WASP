use serde::Deserialize;
use std::time::Duration;
use config::{Config as ConfigLoader, File, Environment};

#[derive(Clone, Deserialize)]
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
    pub jwt_secret: String,
    pub database_url: String,
}

#[derive(Clone, Deserialize)]
pub struct NetworkConfig {
    pub bootstrap_nodes: Vec<String>,
    pub max_connections: usize,
}

impl Config {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let mut config = ConfigLoader::default();

        // Start off by merging in the "default" configuration file
        config.merge(File::with_name("config/default"))?;

        // Add in the current environment file
        // Default to 'development' env
        // Note that this file is _optional_
        let env = std::env::var("RUN_MODE").unwrap_or_else(|_| "development".into());
        config.merge(File::with_name(&format!("config/{}", env)).required(false))?;

        // Add in a local configuration file
        // This file shouldn't be checked in to git
        config.merge(File::with_name("config/local").required(false))?;

        // Add in settings from the environment (with a prefix of WASP)
        // Eg.. `WASP_DEBUG=1 ./target/app` would set the `debug` key
        config.merge(Environment::with_prefix("WASP"))?;

        // Now that we're done, let's access our configuration
        config.try_into()
    }
}
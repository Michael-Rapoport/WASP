use tokio;
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod swarm_proxy;
mod network;
mod routing;
mod cache;
mod security;
mod protocols;
mod metrics;
mod health;
mod consensus;
mod crypto;
mod circuit;
mod traffic_shaping;
mod timing_protection;

use crate::config::Config;
use crate::swarm_proxy::{SwarmProxy, SwarmProxyError};
use crate::network::NetworkDatabase;
use crate::routing::RouteSelector;
use crate::consensus::ConsensusProtocol;
use crate::crypto::key_management::KeyManager;
use crate::circuit::Circuit;
use crate::traffic_shaping::TrafficShaper;
use crate::timing_protection::TimingProtection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env().map_err(|e| {
        error!("Failed to load configuration: {:?}", e);
        e
    })?;

    // Initialize and run SwarmProxy
    let swarm_proxy = SwarmProxy::new(config).await.map_err(|e| {
        error!("Failed to initialize SwarmProxy: {:?}", e);
        e
    })?;
    
    info!("SwarmProxy initialized. Starting services...");
    swarm_proxy.run().await.map_err(|e| {
        error!("SwarmProxy encountered an error while running: {:?}", e);
        e
    })?;

    Ok(())
}
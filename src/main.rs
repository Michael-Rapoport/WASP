use std::sync::Arc;
use tokio::signal::ctrl_c;
use futures::future::join_all;
use clap::{App, Arg};
use config::SwarmProxyConfig;
use swarm_proxy::SwarmProxy;
use log::{error, info};
use error_handling::SwarmProxyError;

mod config;
mod swarm_proxy;
mod network_communication;
mod advanced_routing;
mod peer_discovery;
mod distributed_cache;
mod security_manager;
mod multi_protocol_support;
mod error_handling;
mod cache_monitoring;

#[tokio::main]
async fn main() -> Result<(), SwarmProxyError> {
    let matches = App::new("SwarmProxy")
        .version("1.0")
        .author("Your Name")
        .about("Advanced distributed proxy system")
        .arg(Arg::with_name("config")
            .short("c")
            .long("config")
            .value_name("FILE")
            .help("Sets a custom config file")
            .takes_value(true))
        .get_matches();

    init_logging();

    let config_path = matches.value_of("config").unwrap_or("config/default.toml");
    let config = SwarmProxyConfig::from_file(config_path)?;

    info!("Starting SwarmProxy with configuration from {}", config_path);

    let swarm_proxy = Arc::new(SwarmProxy::new(config).await?);

    // Start multiple worker threads
    let num_workers = num_cpus::get();
    let worker_handles: Vec<_> = (0..num_workers)
        .map(|i| {
            let swarm_proxy_clone = Arc::clone(&swarm_proxy);
            tokio::spawn(async move {
                if let Err(e) = swarm_proxy_clone.run_worker(i).await {
                    error!("Worker {} error: {:?}", i, e);
                }
            })
        })
        .collect();

    // Start the metrics server
    let metrics_handle = tokio::spawn(swarm_proxy.run_metrics_server());

    // Wait for Ctrl+C signal
    ctrl_c().await?;
    info!("Shutting down SwarmProxy...");

    // Graceful shutdown
    swarm_proxy.shutdown().await?;

    // Wait for all worker threads to finish
    join_all(worker_handles).await;

    // Wait for the metrics server to shut down
    metrics_handle.await?;

    info!("SwarmProxy shut down successfully");
    Ok(())
}

fn init_logging() {
    use tracing_subscriber::{fmt, EnvFilter};

    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_timer(fmt::time::ChronoUtc::rfc3339())
        .with_thread_ids(true)
        .with_thread_names(true)
        .init();
}
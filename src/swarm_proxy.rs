use crate::config::Config;
use crate::network::{NetworkDatabase, NetworkError};
use crate::routing::{RouteSelector, RouteSelectionError};
use crate::consensus::ConsensusProtocol;
use crate::crypto::key_management::{KeyManager, KeyManagementError};
use crate::circuit::{Circuit, CircuitError};
use crate::traffic_shaping::TrafficShaper;
use crate::timing_protection::TimingProtection;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use thiserror::Error;
use tracing::{info, error};

#[derive(Error, Debug)]
pub enum SwarmProxyError {
    #[error("Network error: {0}")]
    NetworkError(#[from] NetworkError),
    #[error("Route selection error: {0}")]
    RouteSelectionError(#[from] RouteSelectionError),
    #[error("Key management error: {0}")]
    KeyManagementError(#[from] KeyManagementError),
    #[error("Circuit error: {0}")]
    CircuitError(#[from] CircuitError),
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),
}

pub struct SwarmProxy {
    config: Config,
    network_db: NetworkDatabase,
    consensus_protocol: ConsensusProtocol,
    route_selector: RouteSelector,
    key_manager: KeyManager,
    traffic_shaper: TrafficShaper,
    timing_protection: TimingProtection,
}

impl SwarmProxy {
    pub async fn new(config: Config) -> Result<Self, SwarmProxyError> {
        let network_db = NetworkDatabase::new(&config.network_config)?;
        let key_manager = KeyManager::new()?;
        let consensus_protocol = ConsensusProtocol::new(
            network_db.clone(),
            key_manager.clone(),
            config.node_id.clone(),
            config.consensus_interval,
        );
        let route_selector = RouteSelector::new(network_db.clone());
        let traffic_shaper = TrafficShaper::new(
            config.min_delay,
            config.max_delay,
            config.min_packet_size,
            config.max_packet_size,
        );
        let timing_protection = TimingProtection::new(config.operation_time);

        Ok(Self {
            config,
            network_db,
            consensus_protocol,
            route_selector,
            key_manager,
            traffic_shaper,
            timing_protection,
        })
    }

    pub async fn run(&self) -> Result<(), SwarmProxyError> {
        let consensus_handle = tokio::spawn(self.consensus_protocol.run());
        let listener_handle = tokio::spawn(self.listen_for_connections());
        let traffic_shaping_handle = tokio::spawn(self.run_traffic_shaping());

        tokio::try_join!(consensus_handle, listener_handle, traffic_shaping_handle)?;

        Ok(())
    }

    async fn listen_for_connections(&self) -> Result<(), SwarmProxyError> {
        let listener = TcpListener::bind(&self.config.listen_addr).await?;
        info!("Listening for connections on {}", self.config.listen_addr);

        loop {
            let (socket, addr) = listener.accept().await?;
            info!("New connection from: {}", addr);
            let route_selector = self.route_selector.clone();
            let key_manager = self.key_manager.clone();
            let timing_protection = self.timing_protection.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(socket, route_selector, key_manager, timing_protection).await {
                    error!("Error handling connection from {}: {:?}", addr, e);
                }
            });
        }
    }

    async fn handle_connection(
        mut socket: TcpStream,
        route_selector: RouteSelector,
        key_manager: KeyManager,
        timing_protection: TimingProtection,
    ) -> Result<(), SwarmProxyError> {
        let route = route_selector.select_route(3).await?;
        let mut circuit = Circuit::new();

        for node in route {
            timing_protection.execute(|| {
                circuit.add_hop(node, &key_manager)
            }).await?;
        }

        let (mut reader, mut writer) = socket.split();
        
        loop {
            let mut buf = vec![0u8; 1024];
            let n = reader.read(&mut buf).await?;
            if n == 0 { break; }

            timing_protection.execute(|| {
                circuit.send(&buf[..n])
            }).await?;

            let response = timing_protection.execute(|| {
                circuit.receive()
            }).await?;

            writer.write_all(&response).await?;
        }

        Ok(())
    }

    async fn run_traffic_shaping(&self) -> Result<(), SwarmProxyError> {
        self.traffic_shaper.shape_traffic(|data| {
            Box::pin(async move {
                // TODO: Implement sending dummy data through a random circuit
                Ok(())
            })
        }).await;
        Ok(())
    }
}
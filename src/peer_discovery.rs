use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use rand::seq::SliceRandom;

#[derive(Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: String,
    pub addr: SocketAddr,
    pub last_seen: Instant,
    pub capabilities: Vec<String>,
}

pub struct PeerDiscovery {
    peers: Mutex<HashMap<String, PeerInfo>>,
    bootstrap_nodes: Vec<SocketAddr>,
    max_peers: usize,
    peer_timeout: Duration,
}

impl PeerDiscovery {
    pub fn new(bootstrap_nodes: Vec<SocketAddr>, max_peers: usize, peer_timeout: Duration) -> Self {
        Self {
            peers: Mutex::new(HashMap::new()),
            bootstrap_nodes,
            max_peers,
            peer_timeout,
        }
    }

    pub async fn start_discovery(&self) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            self.discover_peers().await?;
            self.prune_inactive_peers().await;
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }

    async fn discover_peers(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut new_peers = HashSet::new();

        // Ask bootstrap nodes for peers
        for &addr in &self.bootstrap_nodes {
            if let Ok(peers) = self.request_peers_from(addr).await {
                new_peers.extend(peers);
            }
        }

        // Ask known peers for more peers
        let known_peers: Vec<SocketAddr> = {
            let peers = self.peers.lock().await;
            peers.values().map(|p| p.addr).collect()
        };

        for addr in known_peers {
            if let Ok(peers) = self.request_peers_from(addr).await {
                new_peers.extend(peers);
            }
        }

        // Add new peers to our list
        let mut peers = self.peers.lock().await;
        for peer in new_peers {
            if peers.len() >= self.max_peers {
                break;
            }
            if !peers.contains_key(&peer.id) {
                peers.insert(peer.id.clone(), peer);
            }
        }

        Ok(())
    }

    async fn request_peers_from(&self, addr: SocketAddr) -> Result<Vec<PeerInfo>, Box<dyn std::error::Error>> {
        // Implement the actual peer request logic here
        // This could involve sending a UDP message to the address and waiting for a response
        // For now, we'll just return an empty vec
        Ok(vec![])
    }

    async fn prune_inactive_peers(&self) {
        let now = Instant::now();
        let mut peers = self.peers.lock().await;
        peers.retain(|_, peer| now.duration_since(peer.last_seen) < self.peer_timeout);
    }

    pub async fn add_peer(&self, peer: PeerInfo) {
        let mut peers = self.peers.lock().await;
        peers.insert(peer.id.clone(), peer);
        if peers.len() > self.max_peers {
            // Remove the oldest peer if we've exceeded the maximum
            if let Some((oldest_id, _)) = peers.iter()
                .min_by_key(|(_, p)| p.last_seen) {
                let oldest_id = oldest_id.clone();
                peers.remove(&oldest_id);
            }
        }
    }

    pub async fn remove_peer(&self, peer_id: &str) {
        let mut peers = self.peers.lock().await;
        peers.remove(peer_id);
    }

    pub async fn get_peer(&self, peer_id: &str) -> Option<PeerInfo> {
        let peers = self.peers.lock().await;
        peers.get(peer_id).cloned()
    }

    pub async fn get_random_peers(&self, n: usize) -> Vec<PeerInfo> {
        let peers = self.peers.lock().await;
        let mut rng = rand::thread_rng();
        peers.values().cloned().choose_multiple(&mut rng, n)
    }

    pub async fn update_peer_last_seen(&self, peer_id: &str) {
        let mut peers = self.peers.lock().await;
        if let Some(peer) = peers.get_mut(peer_id) {
            peer.last_seen = Instant::now();
        }
    }

    pub async fn get_all_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.lock().await;
        peers.values().cloned().collect()
    }
}
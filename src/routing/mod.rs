use crate::network::{NetworkDatabase, NodeInfo};
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

pub struct RouteSelector {
    network_db: NetworkDatabase,
}

impl RouteSelector {
    pub fn new(network_db: NetworkDatabase) -> Self {
        Self { network_db }
    }

    pub async fn select_route(&self, num_hops: usize) -> Result<Vec<NodeInfo>, RouteSelectionError> {
        let all_nodes = self.network_db.get_all_nodes().await?;
        let mut selected_nodes = Vec::with_capacity(num_hops);
        let mut country_diversity = HashMap::new();

        while selected_nodes.len() < num_hops {
            let candidates: Vec<_> = all_nodes.iter()
                .filter(|node| !selected_nodes.contains(node))
                .collect();

            if candidates.is_empty() {
                return Err(RouteSelectionError::InsufficientNodes);
            }

            let node = self.select_best_node(&candidates, &country_diversity)?;
            country_diversity.entry(node.country.clone())
                .and_modify(|e| *e += 1)
                .or_insert(1);
            selected_nodes.push(node.clone());
        }

        Ok(selected_nodes)
    }

    fn select_best_node(&self, candidates: &[&NodeInfo], country_diversity: &HashMap<String, usize>) -> Result<&NodeInfo, RouteSelectionError> {
        let mut weighted_candidates: Vec<(&NodeInfo, f64)> = candidates.iter()
            .map(|&node| {
                let country_weight = 1.0 / (country_diversity.get(&node.country).unwrap_or(&0) + 1) as f64;
                let bandwidth_weight = node.bandwidth as f64 / candidates.iter().map(|n| n.bandwidth).max().unwrap_or(1) as f64;
                let latency_weight = 1.0 / (node.latency as f64 + 1.0);
                let last_seen_weight = 1.0 / SystemTime::now().duration_since(node.last_seen).unwrap().as_secs() as f64;
                
                let total_weight = country_weight * bandwidth_weight * latency_weight * last_seen_weight;
                (node, total_weight)
            })
            .collect();

        weighted_candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        weighted_candidates.choose(&mut rand::thread_rng())
            .map(|(node, _)| *node)
            .ok_or(RouteSelectionError::NoSuitableNode)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum RouteSelectionError {
    #[error("Insufficient nodes available")]
    InsufficientNodes,
    #[error("No suitable node found")]
    NoSuitableNode,
    #[error("Network database error: {0}")]
    NetworkDatabaseError(#[from] crate::network::NetworkError),
}
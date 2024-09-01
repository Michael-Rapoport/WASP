use std::collections::{HashMap, BinaryHeap, HashSet};
use std::cmp::Ordering;
use geo::Point;
use geo::algorithm::haversine_distance::HaversineDistance;
use rand::Rng;
use crate::error_handling::SwarmProxyError;

#[derive(Clone, Debug)]
pub struct NodeMetrics {
    pub id: String,
    pub latency: f64,
    pub bandwidth: f64,
    pub reliability: f64,
    pub location: Point<f64>,
    pub load: f64,
    pub uptime: f64,
}

#[derive(Eq, PartialEq)]
struct RouteNode {
    id: String,
    cost: f64,
}

impl Ord for RouteNode {
    fn cmp(&self, other: &Self) -> Ordering {
        other.cost.partial_cmp(&self.cost).unwrap_or(Ordering::Equal)
    }
}

impl PartialOrd for RouteNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub struct AdvancedRouter {
    nodes: HashMap<String, NodeMetrics>,
    routing_table: HashMap<(String, String), Vec<String>>,
}

impl AdvancedRouter {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            routing_table: HashMap::new(),
        }
    }

    pub fn update_node_metrics(&mut self, node_id: &str, metrics: NodeMetrics) {
        self.nodes.insert(node_id.to_string(), metrics);
        self.update_routing_table();
    }

    pub fn find_best_route(&self, source: &str, destination: &str, data_size: f64) -> Result<Vec<String>, SwarmProxyError> {
        if let Some(route) = self.routing_table.get(&(source.to_string(), destination.to_string())) {
            return Ok(route.clone());
        }

        let mut heap = BinaryHeap::new();
        let mut distances: HashMap<String, f64> = HashMap::new();
        let mut previous: HashMap<String, Option<String>> = HashMap::new();

        for (id, _) in &self.nodes {
            distances.insert(id.clone(), f64::INFINITY);
            previous.insert(id.clone(), None);
        }

        distances.insert(source.to_string(), 0.0);
        heap.push(RouteNode {
            id: source.to_string(),
            cost: 0.0,
        });

        while let Some(RouteNode { id, cost }) = heap.pop() {
            if id == destination {
                return Ok(self.reconstruct_path(&previous, destination));
            }

            if cost > distances[&id] {
                continue;
            }

            for (neighbor_id, neighbor_node) in &self.nodes {
                if neighbor_node.bandwidth < data_size {
                    continue;
                }

                let new_cost = cost + self.calculate_edge_cost(&self.nodes[&id], neighbor_node);
                if new_cost < distances[neighbor_id] {
                    distances.insert(neighbor_id.clone(), new_cost);
                    previous.insert(neighbor_id.clone(), Some(id.clone()));
                    heap.push(RouteNode {
                        id: neighbor_id.clone(),
                        cost: new_cost,
                    });
                }
            }
        }

        Err(SwarmProxyError::RoutingError("No valid route found".to_string()))
    }

    fn calculate_edge_cost(&self, from: &NodeMetrics, to: &NodeMetrics) -> f64 {
        let distance = from.location.haversine_distance(&to.location);
        let latency_factor = to.latency / 1000.0; // Convert to seconds
        let bandwidth_factor = 1.0 / to.bandwidth;
        let reliability_factor = 1.0 / to.reliability;
        let load_factor = to.load;
        let uptime_factor = 1.0 / to.uptime;

        // Weighted sum of factors
        0.3 * distance +
        0.2 * latency_factor +
        0.2 * bandwidth_factor +
        0.1 * reliability_factor +
        0.1 * load_factor +
        0.1 * uptime_factor
    }

    fn reconstruct_path(&self, previous: &HashMap<String, Option<String>>, end: &str) -> Vec<String> {
        let mut path = vec![end.to_string()];
        let mut current = end;

        while let Some(Some(prev)) = previous.get(current) {
            path.push(prev.clone());
            current = prev;
        }

        path.reverse();
        path
    }

    pub fn get_node_metrics(&self, node_id: &str) -> Option<&NodeMetrics> {
        self.nodes.get(node_id)
    }

    fn update_routing_table(&mut self) {
        let mut new_routing_table = HashMap::new();

        for source in self.nodes.keys() {
            for destination in self.nodes.keys() {
                if source != destination {
                    if let Ok(route) = self.find_best_route(source, destination, 0.0) {
                        new_routing_table.insert((source.clone(), destination.clone()), route);
                    }
                }
            }
        }

        self.routing_table = new_routing_table;
    }

    pub fn find_alternative_routes(&self, source: &str, destination: &str, count: usize) -> Vec<Vec<String>> {
        let mut alternative_routes = Vec::new();
        let mut rng = rand::thread_rng();

        for _ in 0..count {
            let mut excluded_nodes = HashSet::new();
            if let Ok(route) = self.find_route_with_exclusions(source, destination, &excluded_nodes) {
                alternative_routes.push(route.clone());
                
                // Randomly exclude some nodes from the found route
                for node in route.iter() {
                    if rng.gen_bool(0.5) {
                        excluded_nodes.insert(node.clone());
                    }
                }
            }
        }

        alternative_routes
    }

    fn find_route_with_exclusions(&self, source: &str, destination: &str, excluded_nodes: &HashSet<String>) -> Result<Vec<String>, SwarmProxyError> {
        let mut heap = BinaryHeap::new();
        let mut distances: HashMap<String, f64> = HashMap::new();
        let mut previous: HashMap<String, Option<String>> = HashMap::new();

        for (id, _) in &self.nodes {
            if !excluded_nodes.contains(id) {
                distances.insert(id.clone(), f64::INFINITY);
                previous.insert(id.clone(), None);
            }
        }

        distances.insert(source.to_string(), 0.0);
        heap.push(RouteNode {
            id: source.to_string(),
            cost: 0.0,
        });

        while let Some(RouteNode { id, cost }) = heap.pop() {
            if id == destination {
                return Ok(self.reconstruct_path(&previous, destination));
            }

            if cost > distances[&id] {
                continue;
            }

            for (neighbor_id, neighbor_node) in &self.nodes {
                if excluded_nodes.contains(neighbor_id) {
                    continue;
                }

                let new_cost = cost + self.calculate_edge_cost(&self.nodes[&id], neighbor_node);
                if new_cost < distances[neighbor_id] {
                    distances.insert(neighbor_id.clone(), new_cost);
                    previous.insert(neighbor_id.clone(), Some(id.clone()));
                    heap.push(RouteNode {
                        id: neighbor_id.clone(),
                        cost: new_cost,
                    });
                }
            }
        }

        Err(SwarmProxyError::RoutingError("No valid route found".to_string()))
    }

    pub fn optimize_network(&mut self) {
        // Implement network optimization logic
        // This could involve load balancing, identifying bottlenecks, etc.
    }
}
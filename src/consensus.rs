use crate::network::{NetworkDatabase, NodeInfo, ConsensusMessage};
use crate::crypto::key_management::KeyManager;
use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::Mutex;
use rand::seq::SliceRandom;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConsensusError {
    #[error("Network error: {0}")]
    NetworkError(#[from] crate::network::NetworkError),
    #[error("Consensus timeout")]
    Timeout,
    #[error("Invalid consensus state")]
    InvalidState,
}

pub struct ConsensusProtocol {
    network_db: Arc<dyn NetworkDatabase>,
    key_manager: Arc<KeyManager>,
    node_id: String,
    interval: Duration,
    state: Mutex<ConsensusState>,
}

struct ConsensusState {
    current_round: u64,
    leader: Option<String>,
    votes: Vec<Vote>,
    last_consensus: Instant,
}

struct Vote {
    node_id: String,
    round: u64,
    leader_id: String,
}

impl ConsensusProtocol {
    pub fn new(
        network_db: Arc<dyn NetworkDatabase>,
        key_manager: Arc<KeyManager>,
        node_id: String,
        interval: Duration,
    ) -> Self {
        Self {
            network_db,
            key_manager,
            node_id,
            interval,
            state: Mutex::new(ConsensusState {
                current_round: 0,
                leader: None,
                votes: Vec::new(),
                last_consensus: Instant::now(),
            }),
        }
    }

    pub async fn run(&self) -> Result<(), ConsensusError> {
        loop {
            tokio::time::sleep(self.interval).await;
            self.perform_consensus_round().await?;
        }
    }

    async fn perform_consensus_round(&self) -> Result<(), ConsensusError> {
        let mut state = self.state.lock().await;
        state.current_round += 1;
        state.votes.clear();

        let nodes = self.network_db.get_all_nodes().await?;
        let leader = self.select_leader(&nodes, state.current_round);
        state.leader = Some(leader.clone());

        let vote = Vote {
            node_id: self.node_id.clone(),
            round: state.current_round,
            leader_id: leader,
        };

        self.broadcast_vote(&vote).await?;
        state.votes.push(vote);

        self.collect_votes(&mut state, nodes.len()).await?;

        if self.check_consensus(&state) {
            state.last_consensus = Instant::now();
            // Perform any necessary actions upon reaching consensus
        }

        Ok(())
    }

    fn select_leader(&self, nodes: &[NodeInfo], round: u64) -> String {
        let mut rng = rand::thread_rng();
        let seed = round.to_le_bytes();
        let mut node_ids: Vec<_> = nodes.iter().map(|n| n.id.clone()).collect();
        node_ids.shuffle(&mut rand::rngs::SmallRng::from_seed(seed));
        node_ids[0].clone()
    }

    async fn broadcast_vote(&self, vote: &Vote) -> Result<(), ConsensusError> {
        let message = ConsensusMessage {
            sender_id: self.node_id.clone(),
            timestamp: std::time::SystemTime::now(),
            content: serde_json::to_vec(&vote).map_err(|e| ConsensusError::InvalidState)?,
            signature: self.key_manager.sign(&serde_json::to_vec(&vote).unwrap()),
        };
        self.network_db.broadcast_consensus_message(message).await?;
        Ok(())
    }

    async fn collect_votes(&self, state: &mut ConsensusState, total_nodes: usize) -> Result<(), ConsensusError> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while state.votes.len() < total_nodes / 2 + 1 {
            if Instant::now() > deadline {
                return Err(ConsensusError::Timeout);
            }
            if let Some(message) = self.network_db.get_consensus_message().await? {
                let vote: Vote = serde_json::from_slice(&message.content)
                    .map_err(|_| ConsensusError::InvalidState)?;
                if vote.round == state.current_round && !state.votes.iter().any(|v| v.node_id == vote.node_id) {
                    let public_key = self.network_db.get_node_public_key(&vote.node_id).await?;
                    self.key_manager.verify(&public_key, &message.content, &message.signature)
                        .map_err(|_| ConsensusError::InvalidState)?;
                    state.votes.push(vote);
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok(())
    }

    fn check_consensus(&self, state: &ConsensusState) -> bool {
        let total_votes = state.votes.len();
        let leader_votes = state.votes.iter().filter(|v| v.leader_id == state.leader.as_ref().unwrap()).count();
        leader_votes > total_votes / 2
    }
}
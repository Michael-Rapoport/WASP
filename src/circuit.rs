use crate::crypto::key_management::{KeyManager, KeyManagementError};
use crate::network::NodeInfo;
use ring::aead::{self, Nonce, Aad};
use std::io;
use thiserror::Error;
use rand::Rng;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Error, Debug)]
pub enum CircuitError {
    #[error("Key management error: {0}")]
    KeyManagementError(#[from] KeyManagementError),
    #[error("Cryptographic error: {0}")]
    CryptoError(#[from] ring::error::Unspecified),
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),
    #[error("Invalid hop index: {0}")]
    InvalidHopIndex(usize),
    #[error("Circuit is empty")]
    EmptyCircuit,
    #[error("Nonce overflow")]
    NonceOverflow,
}

pub struct Circuit {
    hops: Vec<Hop>,
}

struct Hop {
    node: NodeInfo,
    forward_key: aead::LessSafeKey,
    backward_key: aead::LessSafeKey,
    forward_nonce: AtomicU64,
    backward_nonce: AtomicU64,
}

impl Circuit {
    pub fn new() -> Self {
        Self { hops: Vec::new() }
    }

    pub fn add_hop(&mut self, node: NodeInfo, key_manager: &KeyManager) -> Result<(), CircuitError> {
        let forward_key = key_manager.generate_aead_key()?;
        let backward_key = key_manager.generate_aead_key()?;

        self.hops.push(Hop {
            node,
            forward_key,
            backward_key,
            forward_nonce: AtomicU64::new(0),
            backward_nonce: AtomicU64::new(0),
        });
        Ok(())
    }

    pub fn send(&self, data: &[u8]) -> Result<Vec<u8>, CircuitError> {
        if self.hops.is_empty() {
            return Err(CircuitError::EmptyCircuit);
        }

        let mut encrypted_data = data.to_vec();
        for hop in self.hops.iter().rev() {
            let nonce = self.get_next_nonce(&hop.forward_nonce)?;
            encrypted_data = hop.forward_key.seal_in_place_append_tag(nonce, Aad::empty(), &mut encrypted_data)
                .map_err(CircuitError::CryptoError)?;
        }
        Ok(encrypted_data)
    }

    pub fn receive(&self, mut encrypted_data: Vec<u8>) -> Result<Vec<u8>, CircuitError> {
        if self.hops.is_empty() {
            return Err(CircuitError::EmptyCircuit);
        }

        for hop in &self.hops {
            let nonce = self.get_next_nonce(&hop.backward_nonce)?;
            encrypted_data = hop.backward_key.open_in_place(nonce, Aad::empty(), &mut encrypted_data)
                .map_err(CircuitError::CryptoError)?
                .to_vec();
        }
        Ok(encrypted_data)
    }

    fn get_next_nonce(&self, nonce_counter: &AtomicU64) -> Result<Nonce, CircuitError> {
        let nonce_value = nonce_counter.fetch_add(1, Ordering::SeqCst);
        if nonce_value == u64::MAX {
            return Err(CircuitError::NonceOverflow);
        }
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce_value.to_be_bytes());
        Ok(Nonce::assume_unique_for_key(nonce_bytes))
    }

    pub fn len(&self) -> usize {
        self.hops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }

    pub fn get_node(&self, index: usize) -> Result<&NodeInfo, CircuitError> {
        self.hops.get(index)
            .map(|hop| &hop.node)
            .ok_or(CircuitError::InvalidHopIndex(index))
    }
}
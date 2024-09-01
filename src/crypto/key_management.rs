use ring::{aead, agreement, rand, signature};
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyManagementError {
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(#[from] ring::error::Unspecified),
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
}

pub struct KeyManager {
    identity_key: Arc<signature::Ed25519KeyPair>,
    rng: rand::SystemRandom,
}

impl KeyManager {
    pub fn new() -> Result<Self, KeyManagementError> {
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(KeyManagementError::KeyGenerationFailed)?;
        let identity_key = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
            .map_err(KeyManagementError::KeyGenerationFailed)?;

        Ok(Self {
            identity_key: Arc::new(identity_key),
            rng,
        })
    }

    pub fn generate_ephemeral_key(&self) -> Result<(agreement::EphemeralPrivateKey, agreement::PublicKey), KeyManagementError> {
        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &self.rng)
            .map_err(KeyManagementError::KeyGenerationFailed)?;
        let public_key = private_key.compute_public_key()
            .map_err(KeyManagementError::KeyGenerationFailed)?;
        Ok((private_key, public_key))
    }

    pub fn sign(&self, message: &[u8]) -> signature::Signature {
        self.identity_key.sign(message)
    }

    pub fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), KeyManagementError> {
        let peer_public_key = signature::UnparsedPublicKey::new(&signature::ED25519, public_key);
        peer_public_key.verify(message, signature)
            .map_err(|_| KeyManagementError::SignatureVerificationFailed)
    }

    pub fn generate_aead_key(&self) -> Result<aead::LessSafeKey, KeyManagementError> {
        let mut key_bytes = [0u8; 32];
        self.rng.fill(&mut key_bytes)
            .map_err(KeyManagementError::KeyGenerationFailed)?;
        
        aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes)
            .map_err(KeyManagementError::KeyGenerationFailed))
    }
}
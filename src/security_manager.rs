use ring::{aead, digest, pbkdf2, rand};
use std::num::NonZeroU32;
use x25519_dalek::{PublicKey, StaticSecret};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac, NewMac};
use jwt::{Token, Header, Validation};
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

pub struct SecurityManager {
    encryption_key: aead::LessSafeKey,
    hmac_key: Hmac<Sha256>,
    jwt_secret: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: u64,
}

impl SecurityManager {
    pub fn new(jwt_secret: &[u8]) -> Self {
        let rng = rand::SystemRandom::new();
        let encryption_key = aead::UnboundKey::new(&aead::AES_256_GCM, &rand::generate(&rng).unwrap().expose()).unwrap();
        let hmac_key = Hmac::new_from_slice(&rand::generate(&rng).unwrap().expose()).unwrap();

        Self {
            encryption_key: aead::LessSafeKey::new(encryption_key),
            hmac_key,
            jwt_secret: jwt_secret.to_vec(),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::fill(&rand::SystemRandom::new(), &mut nonce).unwrap();

        let mut in_out = plaintext.to_vec();
        self.encryption_key.encrypt_in_place_detached(&aead::Nonce::assume_unique_for_key(nonce), &[], &mut in_out).unwrap();

        let mut result = nonce.to_vec();
        result.extend_from_slice(&in_out);
        result
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() < NONCE_LEN {
            return Err("Invalid ciphertext length");
        }

        let (nonce, encrypted) = ciphertext.split_at(NONCE_LEN);
        let mut in_out = encrypted.to_vec();

        self.encryption_key.decrypt_in_place_detached(
            &aead::Nonce::assume_unique_for_key(nonce.try_into().unwrap()),
            &[],
            &mut in_out
        ).map_err(|_| "Decryption failed")?;

        Ok(in_out)
    }

    pub fn generate_hmac(&self, data: &[u8]) -> Vec<u8> {
        let mut mac = self.hmac_key.clone();
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    pub fn verify_hmac(&self, data: &[u8], hmac: &[u8]) -> bool {
        let mut mac = self.hmac_key.clone();
        mac.update(data);
        mac.verify(hmac).is_ok()
    }

    pub fn hash_password(password: &str, salt: &[u8]) -> [u8; CREDENTIAL_LEN] {
        let mut result = [0u8; CREDENTIAL_LEN];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(100_000).unwrap(),
            salt,
            password.as_bytes(),
            &mut result
        );
        result
    }

    pub fn verify_password(password: &str, salt: &[u8], hash: &[u8]) -> bool {
        pbkdf2::verify(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(100_000).unwrap(),
            salt,
            password.as_bytes(),
            hash
        ).is_ok()
    }

    pub fn generate_token(&self, user_id: &str, expiration: u64) -> Result<String, jwt::Error> {
        let claims = Claims {
            sub: user_id.to_string(),
            exp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + expiration,
        };

        let token = Token::new(Header::default(), claims);
        token.sign(&self.jwt_secret)
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims, jwt::Error> {
        let token: Token<Header, Claims, _> = Token::parse_unverified(token)?;
        let validation = Validation::default();
        token.verify(&self.jwt_secret, &validation)?;
        Ok(token.claims().clone())
    }
}

pub struct DiffieHellmanExchange {
    private_key: StaticSecret,
    public_key: PublicKey,
}

impl DiffieHellmanExchange {
    pub fn new() -> Self {
        let private_key = StaticSecret::new(rand::thread_rng());
        let public_key = PublicKey::from(&private_key);
        Self { private_key, public_key }
    }

    pub fn get_public_key(&self) -> PublicKey {
        self.public_key
    }

    pub fn generate_shared_secret(&self, peer_public_key: &PublicKey) -> [u8; 32] {
        let shared_secret = self.private_key.diffie_hellman(peer_public_key);
        *shared_secret.as_bytes()
    }
}
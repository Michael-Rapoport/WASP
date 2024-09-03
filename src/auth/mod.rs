use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Serialize, Deserialize};
use warp::Filter;
use std::time::{SystemTime, UNIX_EPOCH};
use bcrypt::{hash, verify, DEFAULT_COST};
use anyhow::Result;

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    exp: usize,
}

pub struct Auth {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl Auth {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
        }
    }

    pub fn create_token(&self, username: &str) -> Result<String> {
        let expiration = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() + 3600; // Token valid for 1 hour

        let claims = Claims {
            sub: username.to_owned(),
            exp: expiration as usize,
        };

        Ok(encode(&Header::default(), &claims, &self.encoding_key)?)
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims> {
        Ok(decode::<Claims>(token, &self.decoding_key, &Validation::default())?.claims)
    }

    pub fn hash_password(password: &str) -> Result<String> {
        Ok(hash(password, DEFAULT_COST)?)
    }

    pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
        Ok(verify(password, hash)?)
    }
}

pub fn with_auth(auth: Auth) -> impl Filter<Extract = (Claims,), Error = warp::Rejection> + Clone {
    warp::header::<String>("Authorization")
        .and_then(move |token: String| {
            let auth = auth.clone();
            async move {
                auth.verify_token(&token)
                    .map_err(|_| warp::reject::custom(AuthError::InvalidToken))
            }
        })
}

#[derive(Debug)]
pub enum AuthError {
    InvalidToken,
}

impl warp::reject::Reject for AuthError {}
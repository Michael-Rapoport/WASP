use redis::{Client, Commands, RedisResult};
use serde::{Serialize, Deserialize};
use std::time::Duration;
use tokio::sync::Mutex;
use std::sync::Arc;
use lru::LruCache;
use crate::error_handling::SwarmProxyError;

pub struct DistributedCache {
    client: Client,
    local_cache: Arc<Mutex<LruCache<String, Vec<u8>>>>,
}

impl DistributedCache {
    pub fn new(redis_url: &str, local_cache_size: usize) -> Result<Self, redis::RedisError> {
        let client = Client::open(redis_url)?;
        let local_cache = Arc::new(Mutex::new(LruCache::new(local_cache_size)));
        Ok(Self { client, local_cache })
    }

    pub async fn get<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Result<Option<T>, SwarmProxyError> {
        // Check local cache first
        if let Some(cached_value) = self.local_cache.lock().await.get(key) {
            if let Ok(deserialized) = bincode::deserialize(cached_value) {
                return Ok(Some(deserialized));
            }
        }

        // If not in local cache, check Redis
        let mut conn = self.client.get_connection().map_err(|e| SwarmProxyError::CacheError(e.to_string()))?;
        let result: Option<Vec<u8>> = conn.get(key).map_err(|e| SwarmProxyError::CacheError(e.to_string()))?;

        if let Some(value) = result {
            // Update local cache
            self.local_cache.lock().await.put(key.to_string(), value.clone());

            // Deserialize and return
            Ok(bincode::deserialize(&value).map_err(|e| SwarmProxyError::SerializationError(e.to_string()))?)
        } else {
            Ok(None)
        }
    }

    pub async fn set<T: Serialize>(&self, key: &str, value: &T, expiration: Option<Duration>) -> Result<(), SwarmProxyError> {
        let serialized = bincode::serialize(value).map_err(|e| SwarmProxyError::SerializationError(e.to_string()))?;

        // Update local cache
        self.local_cache.lock().await.put(key.to_string(), serialized.clone());

        // Update Redis
        let mut conn = self.client.get_connection().map_err(|e| SwarmProxyError::CacheError(e.to_string()))?;
        match expiration {
            Some(exp) => conn.set_ex(key, serialized, exp.as_secs() as usize),
            None => conn.set(key, serialized),
        }.map_err(|e| SwarmProxyError::CacheError(e.to_string()))?;

        Ok(())
    }

    pub async fn delete(&self, key: &str) -> Result<(), SwarmProxyError> {
        // Remove from local cache
        self.local_cache.lock().await.pop(key);

        // Remove from Redis
        let mut conn = self.client.get_connection().map_err(|e| SwarmProxyError::CacheError(e.to_string()))?;
        conn.del(key).map_err(|e| SwarmProxyError::CacheError(e.to_string()))?;

        Ok(())
    }

    pub async fn batch_get<T: for<'de> Deserialize<'de>>(&self, keys: &[&str]) -> Result<Vec<Option<T>>, SwarmProxyError> {
        let mut results = Vec::with_capacity(keys.len());
        let mut missing_keys = Vec::new();

        // Check local cache first
        {
            let local_cache = self.local_cache.lock().await;
            for &key in keys {
                if let Some(cached_value) = local_cache.get(key) {
                    if let Ok(deserialized) = bincode::deserialize(cached_value) {
                        results.push(Some(deserialized));
                        continue;
                    }
                }
                results.push(None);
                missing_keys.push(key);
            }
        }

        if !missing_keys.is_empty() {
            // Fetch missing keys from Redis
            let mut conn = self.client.get_connection().map_err(|e| SwarmProxyError::CacheError(e.to_string()))?;
            let redis_results: Vec<Option<Vec<u8>>> = conn.get(missing_keys).map_err(|e| SwarmProxyError::CacheError(e.to_string()))?;

            let mut local_cache = self.local_cache.lock().await;
            for (i, result) in redis_results.into_iter().enumerate() {
                if let Some(value) = result {
                    // Update local cache
                    local_cache.put(missing_keys[i].to_string(), value.clone());

                    // Deserialize and update results
                    if let Ok(deserialized) = bincode::deserialize(&value) {
                        results[keys.iter().position(|&k| k == missing_keys[i]).unwrap()] = Some(deserialized);
                    }
                }
            }
        }

        Ok(results)
    }

    pub async fn batch_set<T: Serialize>(&self, items: &[(&str, &T, Option<Duration>)]) -> Result<(), SwarmProxyError> {
        let mut pipe = redis::pipe();
        
        for (key, value, expiration) in items {
            let serialized = bincode::serialize(value)
                .map_err(|e| SwarmProxyError::SerializationError(e.to_string()))?;
            
            match expiration {
                Some(exp) => pipe.set_ex(key, serialized, exp.as_secs() as usize),
                None => pipe.set(key, serialized),
            };
        }

        let mut conn = self.client.get_connection().map_err(|e| SwarmProxyError::CacheError(e.to_string()))?;
        pipe.execute(&mut conn).map_err(|e| SwarmProxyError::CacheError(e.to_string()))?;

        // Update local cache
        let mut local_cache = self.local_cache.lock().await;
        for (key, value, _) in items {
            let serialized = bincode::serialize(value)
                .map_err(|e| SwarmProxyError::SerializationError(e.to_string()))?;
            local_cache.put(key.to_string(), serialized);
        }

        Ok(())
    }
}
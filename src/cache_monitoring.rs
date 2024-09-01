use std::sync::atomic::{AtomicUsize, Ordering};
use prometheus::{IntCounter, Registry};

pub struct CacheMetrics {
    hits: AtomicUsize,
    misses: AtomicUsize,
    registry: Registry,
    hit_counter: IntCounter,
    miss_counter: IntCounter,
}

impl CacheMetrics {
    pub fn new() -> Self {
        let registry = Registry::new();
        let hit_counter = IntCounter::new("cache_hits", "Number of cache hits").expect("Failed to create hit counter");
        let miss_counter = IntCounter::new("cache_misses", "Number of cache misses").expect("Failed to create miss counter");

        registry.register(Box::new(hit_counter.clone())).expect("Failed to register hit counter");
        registry.register(Box::new(miss_counter.clone())).expect("Failed to register miss counter");

        Self {
            hits: AtomicUsize::new(0),
            misses: AtomicUsize::new(0),
            registry,
            hit_counter,
            miss_counter,
        }
    }

    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
        self.hit_counter.inc();
    }

    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
        self.miss_counter.inc();
    }

    pub fn get_hit_count(&self) -> usize {
        self.hits.load(Ordering::Relaxed)
    }

    pub fn get_miss_count(&self) -> usize {
        self.misses.load(Ordering::Relaxed)
    }

    pub fn get_hit_rate(&self) -> f64 {
        let hits = self.get_hit_count() as f64;
        let total = hits + self.get_miss_count() as f64;
        if total > 0.0 {
            hits / total
        } else {
            0.0
        }
    }

    pub fn get_registry(&self) -> &Registry {
        &self.registry
    }
}
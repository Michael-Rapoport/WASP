use tokio::time::{interval, Duration};
use rand::Rng;
use rand::distributions::{Distribution, Uniform};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct TrafficPattern {
    pub name: String,
    pub min_delay: Duration,
    pub max_delay: Duration,
    pub min_packet_size: usize,
    pub max_packet_size: usize,
    pub burst_probability: f64,
    pub burst_size: usize,
}

pub struct TrafficShaper {
    patterns: Vec<TrafficPattern>,
    current_pattern: Arc<Mutex<usize>>,
}

impl TrafficShaper {
    pub fn new(patterns: Vec<TrafficPattern>) -> Self {
        assert!(!patterns.is_empty(), "At least one traffic pattern must be provided");
        Self {
            patterns,
            current_pattern: Arc::new(Mutex::new(0)),
        }
    }

    pub async fn shape_traffic<F>(&self, mut send_func: F)
    where
        F: FnMut(Vec<u8>) -> futures::future::BoxFuture<'static, Result<(), std::io::Error>>,
    {
        let mut rng = rand::thread_rng();
        let pattern_change_interval = Duration::from_secs(300); // Change pattern every 5 minutes
        let mut pattern_change_timer = tokio::time::interval(pattern_change_interval);

        loop {
            tokio::select! {
                _ = pattern_change_timer.tick() => {
                    self.change_pattern().await;
                }
                _ = self.generate_traffic(&mut rng, &mut send_func) => {}
            }
        }
    }

    async fn generate_traffic<F>(&self, rng: &mut impl Rng, send_func: &mut F) -> Result<(), std::io::Error>
    where
        F: FnMut(Vec<u8>) -> futures::future::BoxFuture<'static, Result<(), std::io::Error>>,
    {
        let pattern_index = *self.current_pattern.lock().await;
        let pattern = &self.patterns[pattern_index];

        let delay = self.random_duration(rng, pattern.min_delay, pattern.max_delay);
        tokio::time::sleep(delay).await;

        if rng.gen_bool(pattern.burst_probability) {
            self.send_burst(rng, send_func, pattern).await?;
        } else {
            let packet_size = rng.gen_range(pattern.min_packet_size..=pattern.max_packet_size);
            let dummy_data = self.generate_dummy_data(rng, packet_size);
            send_func(dummy_data).await?;
        }

        Ok(())
    }

    async fn send_burst<F>(&self, rng: &mut impl Rng, send_func: &mut F, pattern: &TrafficPattern) -> Result<(), std::io::Error>
    where
        F: FnMut(Vec<u8>) -> futures::future::BoxFuture<'static, Result<(), std::io::Error>>,
    {
        for _ in 0..pattern.burst_size {
            let packet_size = rng.gen_range(pattern.min_packet_size..=pattern.max_packet_size);
            let dummy_data = self.generate_dummy_data(rng, packet_size);
            send_func(dummy_data).await?;

            let burst_delay = self.random_duration(rng, Duration::from_millis(10), Duration::from_millis(50));
            tokio::time::sleep(burst_delay).await;
        }
        Ok(())
    }

    fn random_duration(&self, rng: &mut impl Rng, min: Duration, max: Duration) -> Duration {
        Duration::from_millis(rng.gen_range(min.as_millis()..=max.as_millis()) as u64)
    }

    fn generate_dummy_data(&self, rng: &mut impl Rng, size: usize) -> Vec<u8> {
        let dist = Uniform::new(0, 256);
        (0..size).map(|_| dist.sample(rng) as u8).collect()
    }

    async fn change_pattern(&self) {
        let mut current_pattern = self.current_pattern.lock().await;
        *current_pattern = (*current_pattern + 1) % self.patterns.len();
        println!("Switched to traffic pattern: {}", self.patterns[*current_pattern].name);
    }
}

// Example usage:
// let patterns = vec![
//     TrafficPattern {
//         name: "Normal".to_string(),
//         min_delay: Duration::from_millis(100),
//         max_delay: Duration::from_millis(500),
//         min_packet_size: 64,
//         max_packet_size: 1024,
//         burst_probability: 0.1,
//         burst_size: 5,
//     },
//     TrafficPattern {
//         name: "High Load".to_string(),
//         min_delay: Duration::from_millis(50),
//         max_delay: Duration::from_millis(200),
//         min_packet_size: 128,
//         max_packet_size: 2048,
//         burst_probability: 0.3,
//         burst_size: 10,
//     },
// ];
// let traffic_shaper = TrafficShaper::new(patterns);
// traffic_shaper.shape_traffic(|data| Box::pin(async move {
//     // Send data through the network
//     Ok(())
// })).await;
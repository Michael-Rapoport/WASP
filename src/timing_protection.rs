use std::time::{Duration, Instant};
use tokio::time::sleep;

#[derive(Clone)]
pub struct TimingProtection {
    operation_time: Duration,
}

impl TimingProtection {
    pub fn new(operation_time: Duration) -> Self {
        Self { operation_time }
    }

    pub async fn execute<F, T>(&self, operation: F) -> T
    where
        F: FnOnce() -> T,
    {
        let start = Instant::now();
        let result = operation();
        let elapsed = start.elapsed();

        if elapsed < self.operation_time {
            sleep(self.operation_time - elapsed).await;
        }

        result
    }
}
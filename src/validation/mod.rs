use validator::{Validate, ValidationError};
use std::net::IpAddr;
use url::Url;

#[derive(Debug, Validate)]
pub struct ScanRequest {
    #[validate(length(min = 1, max = 100))]
    #[validate(custom = "validate_targets")]
    pub targets: Vec<String>,
    pub options: ScanOptions,
}

#[derive(Debug, Validate)]
pub struct ScanOptions {
    #[validate(range(min = 1, max = 65535))]
    pub max_ports: u16,
    #[validate(range(max = 10))]
    pub max_threads: u8,
}

fn validate_targets(targets: &[String]) -> Result<(), ValidationError> {
    for target in targets {
        if !is_valid_ip(target) && !is_valid_hostname(target) {
            return Err(ValidationError::new("Invalid target"));
        }
    }
    Ok(())
}

fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<IpAddr>().is_ok()
}

fn is_valid_hostname(hostname: &str) -> bool {
    match Url::parse(&format!("http://{}", hostname)) {
        Ok(url) => url.host().is_some(),
        Err(_) => false,
    }
}

pub fn sanitize_input(input: &str) -> String {
    input.chars()
        .filter(|&c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_')
        .collect()
}
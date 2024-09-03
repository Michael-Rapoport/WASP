use wasp::config::Config;
use wasp::wasp::WASP;
use wasp::network_tools::{ScanOptions, ScanResult};
use wasp::auth::Auth;
use warp::test::request;
use serde_json::json;

#[tokio::test]
async fn test_health_endpoint() {
    let config = Config::from_env().expect("Failed to load config");
    let wasp = WASP::new(config.clone()).await.expect("Failed to create WASP instance");
    let auth = Auth::new(config.jwt_secret.as_bytes());

    let api = wasp::setup_routes(wasp, auth);

    let resp = request()
        .method("GET")
        .path("/health")
        .reply(&api)
        .await;

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.body(), r#"{"status":"OK"}"#);
}

#[tokio::test]
async fn test_scan_endpoint() {
    let config = Config::from_env().expect("Failed to load config");
    let wasp = WASP::new(config.clone()).await.expect("Failed to create WASP instance");
    let auth = Auth::new(config.jwt_secret.as_bytes());

    let api = wasp::setup_routes(wasp, auth.clone());

    let token = auth.create_token("test_user").expect("Failed to create token");

    let resp = request()
        .method("POST")
        .path("/api/integrated-scan")
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({
            "targets": ["example.com"],
            "options": {
                "port_scan": true,
                "service_detection": true,
                "os_detection": false,
                "vulnerability_scan": false
            }
        }))
        .reply(&api)
        .await;

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = serde_json::from_slice(resp.body()).expect("Failed to parse response");
    assert!(body["report_id"].is_string());
}

// Add more integration tests as needed
use tokio;
use tracing::{info, error, warn, debug};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use warp::{Filter, Rejection, Reply};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;

mod config;
mod wasp;
mod network;
mod routing;
mod cache;
mod security;
mod protocols;
mod metrics;
mod health;
mod consensus;
mod crypto;
mod circuit;
mod traffic_shaping;
mod timing_protection;
mod lsassy;
mod network_tools;
mod reports;
mod auth;
mod validation;
mod error;
mod node_discovery;
mod exploitation;

use crate::config::Config;
use crate::wasp::WASP;
use crate::network_tools::{ScanOptions, ScanResult};
use crate::reports::ReportsManager;
use crate::auth::{Auth, with_auth};
use crate::validation::ScanRequest;
use crate::error::handle_rejection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env()?;

    // Initialize and run WASP
    let wasp = Arc::new(WASP::new(config.clone()).await?);
    
    info!("WASP initialized. Starting services...");

    // Initialize Auth
    let auth = Auth::new(config.jwt_secret.as_bytes());

    // Set up API routes
    let wasp_clone = wasp.clone();
    let scan_route = warp::post()
        .and(warp::path("api"))
        .and(warp::path("integrated-scan"))
        .and(warp::body::json())
        .and(with_auth(auth.clone()))
        .and_then(move |scan_request: ScanRequest, claims| {
            let wasp = wasp_clone.clone();
            async move {
                debug!("User {} initiated a scan", claims.sub);
                handle_scan_request(wasp, scan_request).await
            }
        });

    let reports_route = warp::get()
        .and(warp::path("api"))
        .and(warp::path("reports"))
        .and(with_auth(auth.clone()))
        .and_then(|claims| async move {
            debug!("User {} requested reports", claims.sub);
            handle_get_reports().await
        });

    let wasp_clone = wasp.clone();
    let exploit_route = warp::post()
        .and(warp::path("api"))
        .and(warp::path("exploit"))
        .and(warp::body::json())
        .and(with_auth(auth.clone()))
        .and_then(move |exploit_request: ExploitRequest, claims| {
            let wasp = wasp_clone.clone();
            async move {
                debug!("User {} initiated an exploit", claims.sub);
                handle_exploit_request(wasp, exploit_request).await
            }
        });

    let health_route = warp::get()
        .and(warp::path("health"))
        .and_then(|| async {
            Ok::<_, Rejection>(warp::reply::json(&json!({"status": "OK"})))
        });

    let routes = scan_route
        .or(reports_route)
        .or(exploit_route)
        .or(health_route)
        .with(warp::trace::request())
        .with(warp::cors().allow_any_origin())
        .with(warp::compression::gzip())
        .with(warp::reply::with::header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload"))
        .with(warp::reply::with::header("X-Frame-Options", "DENY"))
        .with(warp::reply::with::header("X-Content-Type-Options", "nosniff"))
        .with(warp::reply::with::header("X-XSS-Protection", "1; mode=block"))
        .with(warp::reply::with::header("Referrer-Policy", "strict-origin-when-cross-origin"))
        .recover(handle_rejection);

    // Start the web server
    let addr = ([127, 0, 0, 1], 3030);
    info!("Starting server on {:?}", addr);
    warp::serve(routes)
        .tls()
        .cert_path("path/to/cert.pem")
        .key_path("path/to/key.pem")
        .run(addr).await;

    Ok(())
}

async fn handle_scan_request(wasp: Arc<WASP>, scan_request: ScanRequest) -> Result<impl Reply, Rejection> {
    scan_request.validate().map_err(|e| warp::reject::custom(e))?;

    match wasp.integrated_scan(scan_request.targets, scan_request.options).await {
        Ok(results) => {
            let report_id = ReportsManager::save_report(results)?;
            info!("Scan completed successfully, report ID: {}", report_id);
            Ok(warp::reply::json(&json!({
                "message": "Scan completed successfully",
                "report_id": report_id
            })))
        }
        Err(e) => {
            error!("Scan error: {:?}", e);
            Err(warp::reject::custom(e))
        }
    }
}

async fn handle_get_reports() -> Result<impl Reply, Rejection> {
    match ReportsManager::get_all_reports() {
        Ok(reports) => {
            info!("Retrieved {} reports", reports.len());
            Ok(warp::reply::json(&reports))
        }
        Err(e) => {
            error!("Error retrieving reports: {:?}", e);
            Err(warp::reject::custom(e))
        }
    }
}

#[derive(serde::Deserialize)]
struct ExploitRequest {
    target: String,
}

async fn handle_exploit_request(wasp: Arc<WASP>, exploit_request: ExploitRequest) -> Result<impl Reply, Rejection> {
    match wasp.run_exploitation_chain(&exploit_request.target).await {
        Ok(()) => {
            info!("Exploitation chain completed successfully for target: {}", exploit_request.target);
            Ok(warp::reply::json(&json!({
                "message": "Exploitation chain completed successfully"
            })))
        }
        Err(e) => {
            error!("Exploitation error: {:?}", e);
            Err(warp::reject::custom(e))
        }
    }
}
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, debug};
use crate::advanced_routing::AdvancedRouter;
use crate::peer_discovery::PeerDiscovery;
use crate::distributed_cache::DistributedCache;
use crate::security_manager::SecurityManager;
use crate::multi_protocol_support::{MultiProtocolHandler, ProxyServer, Protocol};
use crate::error_handling::{SwarmProxyError, Result};
use crate::cache_monitoring::CacheMetrics;
use crate::config::SwarmProxyConfig;
use hyper::{Body, Request, Response, Server};
use std::net::SocketAddr;
use futures::StreamExt;
use tokio::sync::mpsc;
use tokio_util::codec::{FramedRead, LengthDelimitedCodec};
use bytes::BytesMut;

pub struct SwarmProxy {
    router: Arc<RwLock<AdvancedRouter>>,
    peer_discovery: Arc<PeerDiscovery>,
    distributed_cache: Arc<DistributedCache>,
    security_manager: Arc<SecurityManager>,
    multi_protocol_handler: Arc<MultiProtocolHandler>,
    proxy_server: Arc<ProxyServer>,
    cache_metrics: Arc<CacheMetrics>,
    config: SwarmProxyConfig,
}

impl SwarmProxy {
    pub async fn new(config: SwarmProxyConfig) -> Result<Arc<Self>> {
        let distributed_cache = DistributedCache::new(&config.redis_url, config.local_cache_size).await?;

        let router = Arc::new(RwLock::new(AdvancedRouter::new()));
        let peer_discovery = Arc::new(PeerDiscovery::new(
            config.bootstrap_nodes.clone(),
            config.max_connections,
            config.peer_timeout,
        ));
        let security_manager = Arc::new(SecurityManager::new(&config.jwt_secret));
        let multi_protocol_handler = Arc::new(MultiProtocolHandler::new());
        let proxy_server = Arc::new(ProxyServer::new(config.proxy_addr));
        let cache_metrics = Arc::new(CacheMetrics::new());

        let swarm_proxy = Arc::new(Self {
            router,
            peer_discovery,
            distributed_cache,
            security_manager,
            multi_protocol_handler,
            proxy_server,
            cache_metrics,
            config,
        });

        // Start cache preloading
        let swarm_proxy_clone = swarm_proxy.clone();
        tokio::spawn(async move {
            swarm_proxy_clone.start_cache_preloading().await;
        });

        Ok(swarm_proxy)
    }

    pub async fn run_worker(&self, worker_id: usize) -> Result<()> {
        info!("Starting worker {}", worker_id);

        let (tx, mut rx) = mpsc::channel(1000);

        // Start the request handler
        let self_clone = self.clone();
        tokio::spawn(async move {
            while let Some((req, respond_to)) = rx.recv().await {
                let response = self_clone.handle_request(req).await;
                if let Err(e) = respond_to.send(response) {
                    error!("Failed to send response: {:?}", e);
                }
            }
        });

        // Start the HTTP server
        let addr = SocketAddr::from(([127, 0, 0, 1], 8080 + worker_id as u16));
        let server = Server::bind(&addr).serve(hyper::service::make_service_fn(move |_| {
            let tx = tx.clone();
            async move {
                Ok::<_, hyper::Error>(hyper::service::service_fn(move |req| {
                    let tx = tx.clone();
                    async move {
                        let (respond_to_tx, respond_to_rx) = tokio::sync::oneshot::channel();
                        if let Err(e) = tx.send((req, respond_to_tx)).await {
                            error!("Failed to send request to handler: {:?}", e);
                            return Ok::<_, hyper::Error>(Response::builder()
                                .status(500)
                                .body(Body::from("Internal server error"))
                                .unwrap());
                        }
                        match respond_to_rx.await {
                            Ok(response) => Ok(response),
                            Err(e) => {
                                error!("Failed to receive response from handler: {:?}", e);
                                Ok(Response::builder()
                                    .status(500)
                                    .body(Body::from("Internal server error"))
                                    .unwrap())
                            }
                        }
                    }
                }))
            }
        }));

        info!("Worker {} listening on http://{}", worker_id, addr);

        server.await.map_err(|e| SwarmProxyError::NetworkError(format!("Server error: {}", e)))
    }

    async fn handle_request(&self, req: Request<Body>) -> Response<Body> {
        let (parts, body) = req.into_parts();
        let body = hyper::body::to_bytes(body).await.unwrap();

        match self.process_request(parts.uri.path(), &body).await {
            Ok(response_data) => Response::new(Body::from(response_data)),
            Err(e) => {
                error!("Error processing request: {:?}", e);
                Response::builder()
                    .status(500)
                    .body(Body::from(format!("Error: {:?}", e)))
                    .unwrap()
            }
        }
    }

    async fn process_request(&self, path: &str, data: &[u8]) -> Result<Vec<u8>> {
        // TODO: Implement proper routing based on path
        let token = "dummy_token"; // TODO: Extract token from request
        let protocol = Protocol::HTTP; // TODO: Determine protocol based on request

        self.send_through_swarm(token, data, protocol).await
    }

    pub async fn run_metrics_server(&self) -> Result<()> {
        let metrics_addr = self.config.metrics_addr;
        let metrics = self.cache_metrics.clone();

        tokio::spawn(async move {
            if let Err(e) = prometheus_exporter::start(metrics_addr, metrics.get_registry()) {
                error!("Failed to start metrics server: {:?}", e);
            }
        });

        Ok(())
    }

    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down SwarmProxy");
        // Implement graceful shutdown logic here
        Ok(())
    }

    async fn update_routing_info(&self) {
        let peers = self.peer_discovery.get_all_peers().await;
        let mut router = self.router.write().await;
        for peer in peers {
            router.update_node_metrics(&peer.id, peer.into());
        }
    }

    pub async fn send_through_swarm(&self, token: &str, data: &[u8], protocol: Protocol) -> Result<Vec<u8>> {
        self.security_manager.verify_token(token)?;

        let compressed_data = Self::compress_data(data, self.config.compression_level)?;
        let encrypted_data = self.security_manager.encrypt(&compressed_data)?;

        let route = self.find_best_route(&encrypted_data).await?;

        let mut current_data = encrypted_data;
        for node_id in route {
            let peer = self.peer_discovery.get_peer(&node_id).await
                .ok_or_else(|| SwarmProxyError::PeerNotFound(node_id.clone()))?;
            current_data = self.multi_protocol_handler.send_data(&peer, &current_data).await?;
        }

        let decrypted_data = self.security_manager.decrypt(&current_data)?;
        let decompressed_data = Self::decompress_data(&decrypted_data)?;

        Ok(decompressed_data)
    }

    fn compress_data(data: &[u8], level: i32) -> Result<Vec<u8>> {
        zstd::stream::encode_all(data, level).map_err(|e| SwarmProxyError::CompressionError(e.to_string()))
    }

    fn decompress_data(data: &[u8]) -> Result<Vec<u8>> {
        zstd::stream::decode_all(data).map_err(|e| SwarmProxyError::DecompressionError(e.to_string()))
    }

    async fn find_best_route(&self, data: &[u8]) -> Result<Vec<String>> {
        let cache_key = format!("route:{:x}", sha2::Sha256::digest(data));

        // Try to get the route from cache
        if let Some(cached_route) = self.distributed_cache.get::<Vec<String>>(&cache_key).await? {
            self.cache_metrics.record_hit();
            return Ok(cached_route);
        }

        self.cache_metrics.record_miss();

        // If not in cache, calculate the route
        let router = self.router.read().await;
        let source = "start_node"; // TODO: Implement proper source node selection
        let destination = "end_node"; // TODO: Implement proper destination node selection
        let route = router.find_best_route(source, destination, data.len() as f64)?;

        // Cache the new route
        let expiration = self.get_adaptive_expiration(&cache_key).await;
        self.distributed_cache.set(&cache_key, &route, Some(expiration)).await?;

        Ok(route)
    }

    async fn start_cache_preloading(&self) {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));

        loop {
            interval.tick().await;
            self.preload_cache().await;
        }
    }

    async fn preload_cache(&self) {
        let popular_routes = self.get_popular_routes().await;
        let preload_futures = popular_routes.into_iter().map(|(source, destination)| {
            self.find_best_route(&format!("{}:{}", source, destination).into_bytes())
        });

        futures::future::join_all(preload_futures).await;

        let active_nodes = self.get_active_nodes().await;
        let metrics_futures = active_nodes.into_iter().map(|node_id| {
            self.get_node_metrics(&node_id)
        });

        futures::future::join_all(metrics_futures).await;
    }

    async fn get_popular_routes(&self) -> Vec<(String, String)> {
        self.distributed_cache.get_popular_routes().await.unwrap_or_default()
    }

    async fn get_active_nodes(&self) -> Vec<String> {
        self.peer_discovery.get_active_nodes().await
    }

    async fn get_adaptive_expiration(&self, key: &str) -> std::time::Duration {
        let access_count = self.distributed_cache.get_access_count(key).await.unwrap_or(0);
        let base_expiration = std::time::Duration::from_secs(300); // 5 minutes
        let max_expiration = std::time::Duration::from_secs(3600); // 1 hour

        std::cmp::min(
            base_expiration * (access_count as u32 + 1),
            max_expiration
        )
    }

    async fn get_node_metrics(&self, node_id: &str) -> Option<NodeMetrics> {
        let cache_key = format!("node_metrics:{}", node_id);

        // Try to get the metrics from cache
        if let Some(cached_metrics) = self.distributed_cache.get::<NodeMetrics>(&cache_key).await.ok().flatten() {
            self.cache_metrics.record_hit();
            return Some(cached_metrics);
        }

        self.cache_metrics.record_miss();

        // If not in cache, get from the router
        let router = self.router.read().await;
        let metrics = router.get_node_metrics(node_id).cloned();

        // If found, cache the metrics
        if let Some(ref m) = metrics {
            let expiration = self.get_adaptive_expiration(&cache_key).await;
            if let Err(e) = self.distributed_cache.set(&cache_key, m, Some(expiration)).await {
                error!("Failed to cache node metrics: {}", e);
            }
        }

        metrics
    }
}
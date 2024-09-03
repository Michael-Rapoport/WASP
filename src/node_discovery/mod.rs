use crate::network::NodeInfo;
use crate::error::WASPError;
use reqwest;
use ssh2::Session;
use std::net::{TcpStream, SocketAddr, IpAddr};
use std::time::Duration;
use tokio::time::timeout;
use serde::Deserialize;
use rand::seq::SliceRandom;
use tracing::{info, warn, error};
use futures::stream::{self, StreamExt};
use tokio::net::TcpSocket;
use std::str::FromStr;

const PROXY_LIST_URL: &str = "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all";
const SSH_SCAN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONCURRENT_SCANS: usize = 100;

#[derive(Debug, Deserialize)]
struct ProxyListEntry {
    ip: String,
    port: u16,
}

pub struct NodeDiscovery;

impl NodeDiscovery {
    pub async fn discover_nodes() -> Result<Vec<NodeInfo>, WASPError> {
        let mut nodes = Vec::new();
        
        // Discover public proxies
        let proxy_nodes = Self::discover_public_proxies().await?;
        nodes.extend(proxy_nodes);
        
        // Discover open SSH servers
        let ssh_nodes = Self::discover_open_ssh_servers().await?;
        nodes.extend(ssh_nodes);
        
        Ok(nodes)
    }

    async fn discover_public_proxies() -> Result<Vec<NodeInfo>, WASPError> {
        let client = reqwest::Client::new();
        let response = client.get(PROXY_LIST_URL).send().await?;
        let proxy_list: Vec<ProxyListEntry> = response.json().await?;
        
        let mut nodes = Vec::new();
        for entry in proxy_list {
            let node = NodeInfo {
                id: format!("proxy_{}:{}", entry.ip, entry.port),
                ip: entry.ip.parse()?,
                port: entry.port,
                public_key: Vec::new(), // Public proxies don't have a public key
                last_seen: std::time::SystemTime::now(),
                bandwidth: 0, // Unknown bandwidth
                latency: 0, // Unknown latency
                country: String::new(), // Unknown country
                supported_protocols: vec!["http".to_string()],
            };
            nodes.push(node);
        }
        
        info!("Discovered {} public proxies", nodes.len());
        Ok(nodes)
    }

    async fn discover_open_ssh_servers() -> Result<Vec<NodeInfo>, WASPError> {
        let ip_ranges = vec![
            "192.168.0.0/16",
            "10.0.0.0/8",
            "172.16.0.0/12",
        ];

        let mut tasks = Vec::new();

        for range in ip_ranges {
            let ips: Vec<IpAddr> = ipnetwork::IpNetwork::from_str(range)?.into_iter().collect();
            let chunks = ips.chunks(MAX_CONCURRENT_SCANS);

            for chunk in chunks {
                let chunk_tasks = stream::iter(chunk)
                    .map(|&ip| {
                        let addr = SocketAddr::new(ip, 22);
                        Self::check_ssh_port(addr)
                    })
                    .buffer_unordered(MAX_CONCURRENT_SCANS);

                tasks.push(chunk_tasks.collect::<Vec<_>>());
            }
        }

        let results: Vec<Result<Option<NodeInfo>, WASPError>> = stream::iter(tasks)
            .buffer_unordered(1)
            .flatten()
            .collect()
            .await;

        let nodes: Vec<NodeInfo> = results.into_iter()
            .filter_map(|r| r.ok().flatten())
            .collect();

        info!("Discovered {} open SSH servers", nodes.len());
        Ok(nodes)
    }

    async fn check_ssh_port(addr: SocketAddr) -> Result<Option<NodeInfo>, WASPError> {
        let socket = TcpSocket::new_v4()?;
        socket.set_reuseaddr(true)?;

        match timeout(SSH_SCAN_TIMEOUT, socket.connect(addr)).await {
            Ok(Ok(_)) => {
                let mut sess = Session::new()?;
                sess.set_tcp_stream(TcpStream::connect(addr)?);
                if sess.handshake().is_ok() {
                    let node = NodeInfo {
                        id: format!("ssh_{}:{}", addr.ip(), addr.port()),
                        ip: addr.ip(),
                        port: addr.port(),
                        public_key: sess.host_key().unwrap_or_default().to_vec(),
                        last_seen: std::time::SystemTime::now(),
                        bandwidth: 0, // Unknown bandwidth
                        latency: 0, // Unknown latency
                        country: String::new(), // Unknown country
                        supported_protocols: vec!["ssh".to_string()],
                    };
                    Ok(Some(node))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    pub async fn configure_node(node: &mut NodeInfo) -> Result<(), WASPError> {
        match node.supported_protocols[0].as_str() {
            "http" => Self::configure_http_proxy(node).await,
            "ssh" => Self::configure_ssh_server(node).await,
            _ => Err(WASPError::ConfigurationError("Unsupported protocol".to_string())),
        }
    }

    async fn configure_http_proxy(node: &mut NodeInfo) -> Result<(), WASPError> {
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::http(&format!("http://{}:{}", node.ip, node.port))?)
            .build()?;

        let response = client.get("http://httpbin.org/ip").send().await?;

        if response.status().is_success() {
            info!("Configured HTTP proxy: {}:{}", node.ip, node.port);
            Ok(())
        } else {
            Err(WASPError::ConfigurationError("Failed to configure HTTP proxy".to_string()))
        }
    }

    async fn configure_ssh_server(node: &mut NodeInfo) -> Result<(), WASPError> {
        let tcp = TcpStream::connect((node.ip, node.port))?;
        let mut sess = Session::new()?;
        sess.set_tcp_stream(tcp);
        sess.handshake()?;

        // Get the server's public key
        node.public_key = sess.host_key().unwrap_or_default().to_vec();

        // Test SSH connection
        let mut channel = sess.channel_session()?;
        channel.exec("echo 'SSH connection successful'")?;
        let mut output = String::new();
        channel.read_to_string(&mut output)?;

        if output.contains("SSH connection successful") {
            info!("Configured SSH server: {}:{}", node.ip, node.port);
            Ok(())
        } else {
            Err(WASPError::ConfigurationError("Failed to configure SSH server".to_string()))
        }
    }
}
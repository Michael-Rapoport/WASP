#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    let swarm_proxy = SwarmProxy::new(config).await?;
    swarm_proxy.run().await?;
    Ok(())
}
//! TCP reachability + DNS resolution.

use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

pub async fn resolve_and_connect(target: &str, deadline: Duration) -> anyhow::Result<String> {
    let stream = timeout(deadline, TcpStream::connect(target)).await??;
    let peer = stream.peer_addr()?;
    Ok(peer.ip().to_string())
}

//! TLS 1.3 0-RTT (early-data) acceptance probe.
//!
//! Per RFC 8446 §4.2.10, a server signals 0-RTT eligibility by including
//! `max_early_data_size > 0` in the encrypted NewSessionTicket extensions.
//! A server that ACCEPTS replayed early-data exposes any state-changing
//! requests sent in 0-RTT to a textbook replay attack.
//!
//! Strategy (using tokio-rustls's high-level 0-RTT API):
//!   1. First handshake completes TLS 1.3, sends a minimal HEAD so the
//!      server delivers a NewSessionTicket post-handshake.
//!   2. Brief sleep so the client cache commits.
//!   3. Second handshake — `TlsConnector::early_data(true)`. After
//!      awaiting connect(), inspect `is_early_data_accepted()` on the
//!      established connection.
//!
//! Returns `true` only when rustls confirms the server signaled the
//! early-data extension in EncryptedExtensions — the canonical signal
//! Qualys SSL Labs reports as "0-RTT support".

use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

pub async fn probe(target: &str, sni: &str, deadline: Duration) -> bool {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.enable_early_data = true;
    let config = Arc::new(config);

    let host_name = match ServerName::try_from(sni.to_string()) {
        Ok(n) => n,
        Err(_) => return false,
    };

    // First handshake — warm the resumption cache + receive ticket.
    let connector_warm = TlsConnector::from(config.clone());
    if first_handshake_for_ticket(target, host_name.clone(), sni, &connector_warm, deadline)
        .await
        .is_none()
    {
        return false;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Second handshake — enable early_data on the connector via the
    // gated tokio-rustls API. rustls will offer the early_data
    // extension if the cached session permits it.
    let connector_0rtt = TlsConnector::from(config).early_data(true);
    second_handshake_try_0rtt(target, host_name, &connector_0rtt, deadline)
        .await
        .unwrap_or(false)
}

async fn first_handshake_for_ticket(
    target: &str,
    sni: ServerName<'static>,
    host_only: &str,
    connector: &TlsConnector,
    deadline: Duration,
) -> Option<()> {
    let tcp = timeout(deadline, TcpStream::connect(target))
        .await
        .ok()?
        .ok()?;
    let mut tls = timeout(deadline, connector.connect(sni, tcp))
        .await
        .ok()?
        .ok()?;
    let req = format!("HEAD / HTTP/1.0\r\nHost: {host_only}\r\nConnection: close\r\n\r\n");
    let _ = tls.write_all(req.as_bytes()).await;
    let _ = tls.flush().await;
    let mut buf = [0u8; 1024];
    let _ = timeout(Duration::from_secs(2), tls.read(&mut buf)).await;
    Some(())
}

async fn second_handshake_try_0rtt(
    target: &str,
    sni: ServerName<'static>,
    connector: &TlsConnector,
    deadline: Duration,
) -> Option<bool> {
    let tcp = timeout(deadline, TcpStream::connect(target))
        .await
        .ok()?
        .ok()?;
    let tls = timeout(deadline, connector.connect(sni, tcp))
        .await
        .ok()?
        .ok()?;
    let (_, conn) = tls.get_ref();
    Some(conn.is_early_data_accepted())
}

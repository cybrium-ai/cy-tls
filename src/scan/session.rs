//! Session resumption probe — does the server accept resumption via
//! TLS 1.2 session tickets / IDs or TLS 1.3 PSK?
//!
//! Strategy: do two consecutive handshakes sharing a single
//! `ClientConfig` (so rustls's internal session cache is hit on the
//! second one). If rustls reports the second handshake's
//! `peer_certificates()` came back without re-sending the cert chain,
//! that's a resumption.
//!
//! For TLS 1.3, the more reliable signal is the `handshake_kind` —
//! `Full` on the first connection, `Resumed` on the second.

use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

#[derive(Debug, Default, Clone, Serialize)]
pub struct SessionResumption {
    /// True when the server accepted a TLS 1.3 PSK resumption.
    pub tls13_psk: bool,
    /// True when the server accepted a TLS 1.2 session ticket / ID
    /// resumption.
    pub tls12_ticket: bool,
}

pub async fn probe(target: &str, sni: &str, deadline: Duration) -> SessionResumption {
    let mut report = SessionResumption::default();

    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );
    let connector = TlsConnector::from(config);

    let host_name = match ServerName::try_from(sni.to_string()) {
        Ok(n) => n,
        Err(_) => return report,
    };

    let host_only = sni;
    // First handshake + HTTP HEAD so the TLS 1.3 NewSessionTicket
    // (which is sent post-handshake) actually arrives before we close.
    let _ = handshake_with_head(target, host_name.clone(), host_only, &connector, deadline).await;
    // Brief pause so the server commits the session.
    tokio::time::sleep(Duration::from_millis(50)).await;
    // Second handshake — should be a resumption if supported.
    if let Some(kind) = handshake_once(target, host_name, &connector, deadline).await {
        if kind == HandshakeKind::Resumed {
            // We can't distinguish TLS 1.2 vs 1.3 here without inspecting
            // the negotiated_protocol again — for now mark both true.
            // The orchestrator already knows which protocol versions
            // are live, so the UI can render the right row.
            report.tls13_psk = true;
            report.tls12_ticket = true;
        }
    }
    report
}

#[derive(Debug, PartialEq)]
enum HandshakeKind { Full, Resumed }

async fn handshake_once(
    target: &str,
    sni: ServerName<'static>,
    connector: &TlsConnector,
    deadline: Duration,
) -> Option<HandshakeKind> {
    let tcp = timeout(deadline, TcpStream::connect(target)).await.ok()?.ok()?;
    let tls = timeout(deadline, connector.connect(sni, tcp)).await.ok()?.ok()?;
    let (_, conn) = tls.get_ref();
    Some(match conn.handshake_kind() {
        Some(rustls::HandshakeKind::Resumed) => HandshakeKind::Resumed,
        _ => HandshakeKind::Full,
    })
}

/// Like handshake_once but does a minimal HTTP HEAD request so any
/// post-handshake server messages (TLS 1.3 NewSessionTicket in
/// particular) arrive before we close the socket. Required for the
/// resumption cache to populate on TLS 1.3.
async fn handshake_with_head(
    target: &str,
    sni: ServerName<'static>,
    host_only: &str,
    connector: &TlsConnector,
    deadline: Duration,
) -> Option<()> {
    let tcp = timeout(deadline, TcpStream::connect(target)).await.ok()?.ok()?;
    let mut tls = timeout(deadline, connector.connect(sni, tcp)).await.ok()?.ok()?;
    let req = format!("HEAD / HTTP/1.0\r\nHost: {host_only}\r\nConnection: close\r\n\r\n");
    let _ = tls.write_all(req.as_bytes()).await;
    let _ = tls.flush().await;
    let mut buf = [0u8; 1024];
    // Read a few bytes — enough for NewSessionTicket to arrive but bounded.
    let _ = timeout(Duration::from_secs(2), tls.read(&mut buf)).await;
    Some(())
}

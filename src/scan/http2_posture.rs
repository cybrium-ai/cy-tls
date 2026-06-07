//! HTTP/2 ALPN posture — h2c upgrade probe.
//!
//! Over TLS, HTTP/2 is supposed to be selected via ALPN (`h2`). The
//! HTTP/1.1 `Upgrade: h2c` mechanism (RFC 7540 §3.4) is for cleartext
//! TCP — it should NEVER work over a TLS-fronted endpoint because the
//! protocol is already pinned to HTTP/1.1 (or HTTP/2 via ALPN) after
//! the TLS handshake. A server that responds `101 Switching Protocols`
//! to an `Upgrade: h2c` header sent INSIDE the TLS tunnel is
//! misconfigured — typically a reverse proxy that transparently
//! forwards the Upgrade header to an h2c-capable backend, exposing a
//! protocol-smuggling surface between the TLS terminator and the
//! backend.
//!
//! v0.5.5 — single-handshake passive probe wrapped around a real
//! HTTP/1.1 request that carries:
//!
//!     GET / HTTP/1.1
//!     Host: <sni>
//!     Connection: Upgrade, HTTP2-Settings
//!     Upgrade: h2c
//!     HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
//!     <CRLF><CRLF>
//!
//! Patched / sane servers respond with 200/302/etc — anything except
//! 101. A vulnerable misconfiguration responds with 101 (and possibly
//! follows it with the HTTP/2 connection preface).
//!
//! Runs ALWAYS (not gated behind --no-cipher-enum) since it's a
//! single handshake + single request, but is skipped when the rustls
//! handshake itself can't complete (the underlying error makes the
//! probe inapplicable, not the absence of a finding).

use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2cVerdict {
    /// Server responded with 101 Switching Protocols → upgrade
    /// accepted → smuggling surface present.
    Accepted,
    /// Server responded but did NOT switch protocols.
    NotAccepted,
    /// Probe couldn't run (connect / handshake / IO failure).
    Indeterminate,
}

pub async fn probe(target: &str, sni: &str, deadline: Duration) -> H2cVerdict {
    timeout(deadline.min(Duration::from_secs(8)), async {
        run_probe(target, sni).await
    })
    .await
    .ok()
    .flatten()
    .unwrap_or(H2cVerdict::Indeterminate)
}

async fn run_probe(target: &str, sni: &str) -> Option<H2cVerdict> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // Pin HTTP/1.1 in ALPN — we WANT the server to negotiate
    // HTTP/1.1 (not h2 via ALPN) so the Upgrade: h2c header has
    // semantic meaning. If the server picks h2 via ALPN, the probe
    // is N/A and we report NotAccepted.
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));

    let server_name = ServerName::try_from(sni.to_string()).ok()?;
    let tcp = TcpStream::connect(target).await.ok()?;
    let mut tls = connector.connect(server_name, tcp).await.ok()?;

    // HTTP2-Settings is a base64url-encoded HTTP/2 SETTINGS payload.
    // The exact value below is the canonical RFC 7540 §3.2.1 example
    // (SETTINGS_MAX_CONCURRENT_STREAMS=100, SETTINGS_INITIAL_WINDOW_SIZE=0)
    // — any decodable value is fine since the probe is about whether
    // the server processes the upgrade verb, not whether it likes our
    // settings.
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: {sni}\r\n\
         Connection: Upgrade, HTTP2-Settings\r\n\
         Upgrade: h2c\r\n\
         HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\
         User-Agent: cy-tls h2c-probe\r\n\
         Accept: */*\r\n\
         \r\n",
    );
    tls.write_all(request.as_bytes()).await.ok()?;
    tls.flush().await.ok()?;

    // Read enough of the status line to classify. 1 KiB is plenty —
    // even servers that send a verbose response start with the
    // status line in the first 32 bytes.
    let mut buf = [0u8; 1024];
    let n = timeout(Duration::from_secs(3), tls.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    let response = String::from_utf8_lossy(&buf[..n]);

    // First line: "HTTP/1.1 <status> <reason>\r\n". A 101 in the
    // first line means the server accepted the upgrade. Anything
    // else (200, 302, 400, 426, 502, etc.) is fine.
    let first_line = response.lines().next().unwrap_or("");
    if first_line.starts_with("HTTP/1.1 101") {
        Some(H2cVerdict::Accepted)
    } else {
        Some(H2cVerdict::NotAccepted)
    }
}

//! HTTP/2 Rapid Reset (CVE-2023-44487) eligibility probe.
//!
//! The Rapid Reset attack opens many HTTP/2 streams via HEADERS frames
//! and immediately cancels each via RST_STREAM. Per RFC 7540, a
//! cancelled stream is the client's prerogative — the server still
//! processed the headers, may have routed the request, allocated
//! request-context resources, and only THEN learned to abort. Doing
//! this in rapid succession exhausts server CPU / memory while leaving
//! the connection itself open (the flow-control window doesn't get
//! consumed by data the server never gets to send). Disclosed Oct 2023
//! after multi-Tbps DDoS attacks against Google / Cloudflare / AWS.
//!
//! Mitigation: server enforces `SETTINGS_MAX_CONCURRENT_STREAMS` AND
//! rate-limits the RST_STREAM frame intake. RFC 7540 sets no default
//! for MAX_CONCURRENT_STREAMS; absence ≈ unlimited (RFC 7540 §6.5.2
//! says implementations SHOULD pick "≥100" but "no smaller than 100").
//!
//! Detection in cy-tls is PASSIVE — we never send a flood. We just
//! open one connection, read the server's SETTINGS frame, look for
//! MAX_CONCURRENT_STREAMS. Absent (≈ unlimited) or set to a high
//! value (≥1024) indicates Rapid Reset eligibility. Active confirm
//! would require sending real DoS-style traffic, which is unethical
//! for a scanner.
//!
//! Frame layout (RFC 7540 §4):
//!   length(24-bit be) type(8) flags(8) reserved(1)+stream_id(31)
//!   payload
//!
//! SETTINGS frame body is N * 6 bytes:
//!   identifier(16-bit be) value(32-bit be)
//!
//! Setting identifiers we care about:
//!   0x03 SETTINGS_MAX_CONCURRENT_STREAMS

use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RapidResetVerdict {
    /// MAX_CONCURRENT_STREAMS present and bounded (<1024) — server
    /// has the headline mitigation deployed.
    Mitigated,
    /// MAX_CONCURRENT_STREAMS absent OR >=1024 — server is eligible
    /// for Rapid Reset DoS amplification.
    Eligible { observed_limit: Option<u32> },
    /// Probe couldn't run end-to-end.
    Indeterminate,
}

pub async fn probe(target: &str, sni: &str, deadline: Duration) -> RapidResetVerdict {
    timeout(deadline.min(Duration::from_secs(8)), async {
        run_probe(target, sni).await
    })
    .await
    .ok()
    .flatten()
    .unwrap_or(RapidResetVerdict::Indeterminate)
}

async fn run_probe(target: &str, sni: &str) -> Option<RapidResetVerdict> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    // ALPN h2 only — if the server doesn't speak HTTP/2 the handshake
    // fails (no_application_protocol alert) and we return Indeterminate.
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));

    let server_name = ServerName::try_from(sni.to_string()).ok()?;
    let tcp = TcpStream::connect(target).await.ok()?;
    let mut tls = connector.connect(server_name, tcp).await.ok()?;

    // HTTP/2 connection preface (RFC 7540 §3.5) — 24 fixed bytes.
    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    tls.write_all(PREFACE).await.ok()?;

    // Send our own empty SETTINGS frame (required first frame).
    //   length=0, type=0x04, flags=0, stream_id=0, payload empty
    let empty_settings: [u8; 9] = [0, 0, 0, 0x04, 0, 0, 0, 0, 0];
    tls.write_all(&empty_settings).await.ok()?;
    tls.flush().await.ok()?;

    // Read frames until we either see the server's SETTINGS or hit a
    // budget. Most servers send SETTINGS as their first frame.
    let mut max_concurrent: Option<u32> = None;
    for _ in 0..8 {
        let mut header = [0u8; 9];
        if timeout(Duration::from_secs(3), tls.read_exact(&mut header))
            .await
            .ok()?
            .is_err()
        {
            break;
        }
        let length =
            (u32::from(header[0]) << 16) | (u32::from(header[1]) << 8) | u32::from(header[2]);
        let frame_type = header[3];
        let flags = header[4];
        let length = length as usize;

        // Read the payload — bounded so a malicious server can't OOM us.
        let mut payload = vec![0u8; length.min(64 * 1024)];
        if length > 0 && tls.read_exact(&mut payload).await.is_err() {
            break;
        }

        // SETTINGS frame (type 0x04) with ACK flag (0x01) cleared is
        // the one that carries actual values. ACKs are empty (length=0).
        if frame_type == 0x04 && (flags & 0x01) == 0 && length >= 6 && length % 6 == 0 {
            let mut i = 0;
            while i + 6 <= length {
                let id = (u16::from(payload[i]) << 8) | u16::from(payload[i + 1]);
                let val = (u32::from(payload[i + 2]) << 24)
                    | (u32::from(payload[i + 3]) << 16)
                    | (u32::from(payload[i + 4]) << 8)
                    | u32::from(payload[i + 5]);
                if id == 0x03 {
                    max_concurrent = Some(val);
                }
                i += 6;
            }
            break;
        }
    }

    // Be polite — send GOAWAY to close cleanly.
    let goaway: [u8; 17] = [
        0, 0, 8, 0x07, 0, 0, 0, 0, 0, // header: length=8 type=GOAWAY stream=0
        0, 0, 0, 0, // last_stream_id = 0
        0, 0, 0, 0, // error_code = NO_ERROR
    ];
    let _ = tls.write_all(&goaway).await;
    let _ = tls.flush().await;

    Some(match max_concurrent {
        None => RapidResetVerdict::Eligible {
            observed_limit: None,
        },
        Some(n) if n >= 1024 => RapidResetVerdict::Eligible {
            observed_limit: Some(n),
        },
        Some(n) => {
            let _ = n;
            RapidResetVerdict::Mitigated
        }
    })
}

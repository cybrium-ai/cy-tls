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

/// Aggregated SETTINGS posture observed from the server's first
/// SETTINGS frame. All fields are `Option<u32>` so the orchestrator
/// can distinguish "not advertised" (None) from "advertised with
/// value N" — different semantics per RFC 7540 §6.5.
#[derive(Debug, Clone, Copy, Default)]
pub struct SettingsObserved {
    pub max_concurrent_streams: Option<u32>, // id 0x03
    pub max_frame_size: Option<u32>,         // id 0x05
    pub max_header_list_size: Option<u32>,   // id 0x06
}

/// Single probe that captures the server's SETTINGS frame. The
/// orchestrator derives multiple findings from the same observation
/// (Rapid Reset eligibility v0.5.9 + Header-list DoS v0.5.12 + more
/// as the catalog grows).
pub async fn probe_settings(
    target: &str,
    sni: &str,
    deadline: Duration,
) -> Option<SettingsObserved> {
    timeout(deadline.min(Duration::from_secs(8)), async {
        capture_server_settings(target, sni).await
    })
    .await
    .ok()
    .flatten()
}

/// Shared probe: open ALPN h2 TLS, send preface + empty SETTINGS,
/// read the server's SETTINGS frame, parse out every recognised
/// setting ID. Returns None when any of the connect / preface /
/// SETTINGS-receive steps fail.
async fn capture_server_settings(target: &str, sni: &str) -> Option<SettingsObserved> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    // ALPN h2 only — if the server doesn't speak HTTP/2 the handshake
    // fails (no_application_protocol alert) and we return None.
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));

    let server_name = ServerName::try_from(sni.to_string()).ok()?;
    let tcp = TcpStream::connect(target).await.ok()?;
    let mut tls = connector.connect(server_name, tcp).await.ok()?;

    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    tls.write_all(PREFACE).await.ok()?;
    let empty_settings: [u8; 9] = [0, 0, 0, 0x04, 0, 0, 0, 0, 0];
    tls.write_all(&empty_settings).await.ok()?;
    tls.flush().await.ok()?;

    let mut observed = SettingsObserved::default();
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

        let mut payload = vec![0u8; length.min(64 * 1024)];
        if length > 0 && tls.read_exact(&mut payload).await.is_err() {
            break;
        }

        if frame_type == 0x04 && (flags & 0x01) == 0 && length >= 6 && length % 6 == 0 {
            let mut i = 0;
            while i + 6 <= length {
                let id = (u16::from(payload[i]) << 8) | u16::from(payload[i + 1]);
                let val = (u32::from(payload[i + 2]) << 24)
                    | (u32::from(payload[i + 3]) << 16)
                    | (u32::from(payload[i + 4]) << 8)
                    | u32::from(payload[i + 5]);
                match id {
                    0x03 => observed.max_concurrent_streams = Some(val),
                    0x05 => observed.max_frame_size = Some(val),
                    0x06 => observed.max_header_list_size = Some(val),
                    _ => {}
                }
                i += 6;
            }
            break;
        }
    }

    let goaway: [u8; 17] = [
        0, 0, 8, 0x07, 0, 0, 0, 0, 0, // header: length=8 type=GOAWAY stream=0
        0, 0, 0, 0, // last_stream_id = 0
        0, 0, 0, 0, // error_code = NO_ERROR
    ];
    let _ = tls.write_all(&goaway).await;
    let _ = tls.flush().await;

    Some(observed)
}

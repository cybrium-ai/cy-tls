//! Cipher preference order detection.
//!
//! Qualys SSL Labs reports "Server-preferred cipher order: Yes / No / No
//! (with server-required priorities)" in its grade. The semantics:
//!
//!   Server-preferred — the server enforces its OWN cipher preference
//!     order regardless of how the client orders its `cipher_suites`
//!     list. Considered good practice — keeps the strongest negotiated
//!     ciphers across heterogeneous clients.
//!
//!   Client-preferred (a.k.a. "No") — the server picks the FIRST
//!     mutually-acceptable cipher in the client's list. Considered
//!     weaker because legacy clients can negotiate weaker ciphers even
//!     when the server supports better ones.
//!
//! Detection: send the same TLS 1.2 ClientHello twice, once with the
//! cipher list in ORDER A and once REVERSED. Inspect the negotiated
//! cipher in ServerHello.
//!
//!   - Both ServerHellos return the SAME suite → server enforces order.
//!   - Different suites → server follows the client's order.
//!   - Either handshake fails → indeterminate.
//!
//! Two extra handshakes per host. Skipped when --no-cipher-enum is set.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::cipher_enum::{build_client_hello, parse_server_hello_cipher, TLS12_SUITES};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreferenceVerdict {
    ServerPreferred,
    ClientPreferred,
    Indeterminate,
}

pub async fn probe(target: &str, sni: &str, deadline: Duration) -> PreferenceVerdict {
    let order_a: Vec<u16> = TLS12_SUITES.to_vec();
    let order_b: Vec<u16> = TLS12_SUITES.iter().rev().copied().collect();

    let pick_a = negotiated_with(target, sni, &order_a, deadline).await;
    let pick_b = negotiated_with(target, sni, &order_b, deadline).await;

    match (pick_a, pick_b) {
        (Some(a), Some(b)) if a == b => PreferenceVerdict::ServerPreferred,
        (Some(_), Some(_)) => PreferenceVerdict::ClientPreferred,
        _ => PreferenceVerdict::Indeterminate,
    }
}

async fn negotiated_with(
    target: &str,
    sni: &str,
    suites: &[u16],
    deadline: Duration,
) -> Option<u16> {
    timeout(deadline.min(Duration::from_secs(5)), async {
        let mut sock = TcpStream::connect(target).await.ok()?;
        let hello = build_client_hello(sni, 0x03, 0x03, suites);
        sock.write_all(&hello).await.ok()?;

        let mut hdr = [0u8; 5];
        sock.read_exact(&mut hdr).await.ok()?;
        if hdr[0] != 0x16 {
            return None;
        }
        let body_len = ((hdr[3] as usize) << 8) | (hdr[4] as usize);
        let mut body = vec![0u8; body_len.min(2048)];
        sock.read_exact(&mut body).await.ok()?;
        parse_server_hello_cipher(&body)
    })
    .await
    .ok()
    .flatten()
}

//! TLS_FALLBACK_SCSV (RFC 7507) downgrade-protection probe.
//!
//! Qualys SSL Labs reports "Downgrade attack prevention: Yes/No". The
//! mechanism: when a TLS client decides to retry with a lower protocol
//! version (e.g. after a fatal alert), it adds cipher suite 0x5600
//! (TLS_FALLBACK_SCSV) to its ClientHello. A server that supports a
//! HIGHER protocol than the client offered MUST respond with
//! inappropriate_fallback (alert 86). Servers that ignore SCSV are
//! vulnerable to POODLE-style downgrade attacks where an MITM strips
//! TLS 1.2 to force TLS 1.0 / SSLv3.
//!
//! Probe: send a ClientHello with protocol version capped at TLS 1.1
//! AND TLS_FALLBACK_SCSV in the cipher list.
//!
//!   inappropriate_fallback (alert level 2, desc 86) → SCSV honored.
//!   ServerHello / any other alert / connection close                   → SCSV NOT honored
//!     (only flag when the server actually supports TLS 1.2 or higher —
//!     otherwise SCSV is irrelevant on that endpoint).
//!
//! One handshake per host. Skipped when --no-cipher-enum is set.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::cipher_enum::build_client_hello;

/// TLS_FALLBACK_SCSV signaling cipher suite value per RFC 7507 §4.
const TLS_FALLBACK_SCSV: u16 = 0x5600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScsvVerdict {
    /// Server returned inappropriate_fallback (alert 86). SCSV honored.
    Honored,
    /// Server accepted the lower-version ClientHello despite SCSV.
    NotHonored,
    /// Probe couldn't run (connect / IO failure).
    Indeterminate,
}

pub async fn probe(target: &str, sni: &str, deadline: Duration) -> ScsvVerdict {
    timeout(deadline.min(Duration::from_secs(5)), async {
        // Cap the offered version at TLS 1.1 (0x0302) — the server
        // should reject if it supports TLS 1.2+.
        // Include a few common modern ciphers PLUS the SCSV pseudo-suite.
        let suites: [u16; 5] = [
            0xc02f, // ECDHE-RSA-AES128-GCM-SHA256
            0xc030, // ECDHE-RSA-AES256-GCM-SHA384
            0x009c, // RSA-AES128-GCM-SHA256
            0x002f, // RSA-AES128-CBC-SHA
            TLS_FALLBACK_SCSV,
        ];

        let mut sock = TcpStream::connect(target).await.ok()?;
        let hello = build_client_hello(sni, 0x03, 0x02, &suites);
        sock.write_all(&hello).await.ok()?;

        let mut hdr = [0u8; 5];
        sock.read_exact(&mut hdr).await.ok()?;
        match hdr[0] {
            0x15 => {
                // Alert record. Body: level(1) + description(1).
                let len = ((hdr[3] as usize) << 8) | (hdr[4] as usize);
                let mut body = vec![0u8; len.min(8)];
                let _ = sock.read_exact(&mut body).await;
                let desc = body.get(1).copied().unwrap_or(0);
                if desc == 86 {
                    Some(ScsvVerdict::Honored)
                } else {
                    // Server rejected for a different reason (e.g.
                    // protocol_version, handshake_failure). That's a
                    // different policy — we can't distinguish "no SCSV
                    // support" from "doesn't support this version at all"
                    // here, so be conservative and call it Indeterminate.
                    Some(ScsvVerdict::Indeterminate)
                }
            }
            0x16 => {
                // Got a ServerHello back — server accepted the
                // downgraded handshake despite SCSV.
                Some(ScsvVerdict::NotHonored)
            }
            _ => Some(ScsvVerdict::Indeterminate),
        }
    })
    .await
    .ok()
    .flatten()
    .unwrap_or(ScsvVerdict::Indeterminate)
}

//! RFC 8701 GREASE (Generate Random Extensions And Sustain
//! Extensibility) compatibility probe.
//!
//! GREASE assigns 16 reserved cipher_suite + extension_type code
//! points that aren't and won't be valid. Modern clients (Chrome
//! since 2017, Firefox since 2018) sprinkle these into every
//! ClientHello to make sure servers IGNORE unknown values per the
//! TLS spec, rather than failing the handshake. A server that
//! errors or picks a GREASE cipher has a brittle TLS stack that will
//! break when real new cipher suites / extensions roll out.
//!
//! cy-tls probe: send a ClientHello with two GREASE cipher_suite
//! values interspersed among real suites. Expected outcome: server
//! ignores them and negotiates a REAL cipher. Failure modes:
//!   - Server returns handshake_failure / decode_error / illegal_parameter
//!     alert → brittle (treats GREASE as a real value)
//!   - Server picks a GREASE cipher in ServerHello → blatantly broken
//!     (would echo back our garbage)
//!
//! Returns true when GREASE was tolerated (good), false when the
//! server rejected the hello or echoed a GREASE value (bad).

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::cipher_enum::{build_client_hello, parse_server_hello_cipher};

/// Two GREASE cipher_suite values from the RFC 8701 reserved set.
/// All RFC 8701 GREASE values follow the pattern 0xNANA where N is
/// any hex nibble — i.e. high + low bytes are equal and high nibble
/// == low nibble.
const GREASE_VALUES: [u16; 2] = [0x0a0a, 0xdada];

/// True when the server tolerates GREASE cipher_suite values in the
/// ClientHello (modern, expected). False when the server breaks the
/// handshake or picks a GREASE value back.
pub async fn probe(target: &str, sni: &str, deadline: Duration) -> bool {
    let suites: Vec<u16> = vec![
        GREASE_VALUES[0], // first GREASE
        0xc02f,           // ECDHE-RSA-AES128-GCM-SHA256
        0xc030,           // ECDHE-RSA-AES256-GCM-SHA384
        GREASE_VALUES[1], // second GREASE
        0x009c,           // RSA-AES128-GCM-SHA256 (broad-compat fallback)
        0x002f,           // RSA-AES128-CBC-SHA (last-resort)
    ];

    timeout(deadline.min(Duration::from_secs(5)), async {
        let mut sock = TcpStream::connect(target).await.ok()?;
        let hello = build_client_hello(sni, 0x03, 0x03, &suites);
        sock.write_all(&hello).await.ok()?;
        let mut header = [0u8; 5];
        sock.read_exact(&mut header).await.ok()?;
        if header[0] != 0x16 {
            // Got an Alert or unexpected — server didn't tolerate.
            return Some(false);
        }
        let body_len = ((header[3] as usize) << 8) | (header[4] as usize);
        let mut body = vec![0u8; body_len.min(2048)];
        sock.read_exact(&mut body).await.ok()?;
        let picked = parse_server_hello_cipher(&body)?;
        // Tolerated when the server picked a REAL cipher (not GREASE).
        Some(!GREASE_VALUES.contains(&picked))
    })
    .await
    .ok()
    .flatten()
    .unwrap_or(false)
}

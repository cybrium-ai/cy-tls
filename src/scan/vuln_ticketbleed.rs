//! Ticketbleed (CVE-2016-9244) probe.
//!
//! F5 BIG-IP devices with virtual servers using non-default TLS session
//! ticket support reuse internal memory for the session ID field in the
//! ServerHello. When a client sends a ClientHello with a 32-byte session
//! ID, a vulnerable BIG-IP echoes back the session ID concatenated with
//! ~31 bytes of uninitialised process memory.
//!
//! Detection: send a TLS 1.2 ClientHello with session_id_length=0x20 +
//! 32 deterministic bytes (we use 0x41 repeated for the entire session
//! ID — i.e. 32 'A' bytes). Parse the ServerHello's session_id field.
//! Compare it to what we sent:
//!   - Identical 32 bytes → NotVulnerable (normal echo behaviour).
//!   - First 1-31 bytes match, then mystery bytes → VULNERABLE
//!     (F5 truncated our session ID and filled the rest with leaked
//!     memory).
//!   - Session ID length != 32 → NotApplicable (server isn't echoing
//!     the session ID at all — it's generating a fresh one, so the
//!     Ticketbleed-specific overflow path isn't reachable).

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Copy)]
pub enum TicketbleedVerdict {
    NotVulnerable,
    Vulnerable,
    /// Server didn't echo our session ID at all (fresh ID, or empty).
    /// The classic Ticketbleed pattern is server echoing-then-overflowing,
    /// so a non-echoing server isn't in the F5-vulnerable population.
    NotApplicable,
    Indeterminate,
}

const PROBE_BYTE: u8 = 0x41; // 'A'

pub async fn probe(target: &str, sni: &str, deadline: Duration) -> TicketbleedVerdict {
    let result = timeout(deadline.min(Duration::from_secs(6)), async {
        let mut sock = TcpStream::connect(target).await.ok()?;
        let hello = build_client_hello(sni);
        sock.write_all(&hello).await.ok()?;

        // Read just the ServerHello record (the first one).
        let mut hdr = [0u8; 5];
        sock.read_exact(&mut hdr).await.ok()?;
        if hdr[0] != 0x16 {
            return Some(TicketbleedVerdict::Indeterminate);
        }
        let len = ((hdr[3] as usize) << 8) | (hdr[4] as usize);
        let mut body = vec![0u8; len.min(2048)];
        sock.read_exact(&mut body).await.ok()?;
        parse_server_hello_session_id(&body)
    })
    .await;
    result.ok().flatten().unwrap_or(TicketbleedVerdict::Indeterminate)
}

/// ServerHello body:
///   handshake_type(1)=0x02  length(3)  server_version(2)  random(32)
///   session_id_length(1)  session_id(N)  cipher_suite(2)  compression_method(1)
/// Look at session_id_length + session_id and compare to our probe bytes.
fn parse_server_hello_session_id(body: &[u8]) -> Option<TicketbleedVerdict> {
    if body.first()? != &0x02 {
        return Some(TicketbleedVerdict::Indeterminate);
    }
    let mut i = 4usize; // skip handshake header
    i += 2;             // server_version
    i += 32;            // random
    let sid_len = *body.get(i)? as usize;
    i += 1;

    if sid_len != 32 {
        // Server didn't echo our 32-byte ID — generated its own or
        // omitted. Not in F5's vulnerable code path.
        return Some(TicketbleedVerdict::NotApplicable);
    }

    let sid = body.get(i..i + 32)?;

    // Count how many leading bytes match PROBE_BYTE.
    let mut matches = 0;
    for b in sid {
        if *b == PROBE_BYTE { matches += 1; } else { break; }
    }

    Some(match matches {
        32 => TicketbleedVerdict::NotVulnerable,           // clean echo
        0  => TicketbleedVerdict::NotApplicable,           // server replaced entirely
        _  => TicketbleedVerdict::Vulnerable,              // F5 partial overflow
    })
}

fn build_client_hello(sni: &str) -> Vec<u8> {
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&[0x00, 0x00]);
    let mut sni_list = Vec::new();
    sni_list.push(0x00);
    let sb = sni.as_bytes();
    sni_list.extend_from_slice(&(sb.len() as u16).to_be_bytes());
    sni_list.extend_from_slice(sb);
    let mut sni_inner = Vec::new();
    sni_inner.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
    sni_inner.extend_from_slice(&sni_list);
    sni_ext.extend_from_slice(&(sni_inner.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(&sni_inner);

    let mut groups_ext = Vec::new();
    groups_ext.extend_from_slice(&[0x00, 0x0a]);
    let groups: [u16; 3] = [0x001d, 0x0017, 0x0018];
    let g_bytes: Vec<u8> = groups.iter().flat_map(|g| g.to_be_bytes()).collect();
    groups_ext.extend_from_slice(&((g_bytes.len() as u16 + 2).to_be_bytes()));
    groups_ext.extend_from_slice(&((g_bytes.len() as u16).to_be_bytes()));
    groups_ext.extend_from_slice(&g_bytes);

    let mut sigalg_ext = Vec::new();
    sigalg_ext.extend_from_slice(&[0x00, 0x0d]);
    let sig_algs: [u16; 6] = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806];
    let sig_bytes: Vec<u8> = sig_algs.iter().flat_map(|s| s.to_be_bytes()).collect();
    sigalg_ext.extend_from_slice(&((sig_bytes.len() as u16 + 2).to_be_bytes()));
    sigalg_ext.extend_from_slice(&((sig_bytes.len() as u16).to_be_bytes()));
    sigalg_ext.extend_from_slice(&sig_bytes);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&sni_ext);
    extensions.extend_from_slice(&groups_ext);
    extensions.extend_from_slice(&sigalg_ext);

    let suites: [u16; 7] = [0xc02f, 0xc030, 0xc02b, 0xc02c, 0xcca8, 0xcca9, 0x009c];
    let cipher_bytes: Vec<u8> = suites.iter().flat_map(|s| s.to_be_bytes()).collect();

    let mut body = Vec::new();
    body.push(0x03); body.push(0x03);
    body.extend_from_slice(&[0u8; 32]);

    // Session ID — 32 bytes of 'A' (0x41).
    body.push(0x20);
    body.extend_from_slice(&[PROBE_BYTE; 32]);

    body.extend_from_slice(&(cipher_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&cipher_bytes);
    body.push(0x01); body.push(0x00);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut hs = Vec::new();
    hs.push(0x01);
    let l = body.len() as u32;
    hs.push(((l >> 16) & 0xff) as u8);
    hs.push(((l >> 8) & 0xff) as u8);
    hs.push((l & 0xff) as u8);
    hs.extend_from_slice(&body);

    let mut rec = Vec::new();
    rec.push(0x16);
    rec.push(0x03); rec.push(0x03);
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

//! TLS 1.3 cipher-suite enumeration via raw ClientHello bisection.
//!
//! Analog of `cipher_enum` (which targets TLS 1.2). TLS 1.3 has only
//! five registered suites in the IANA registry — small menu, fast
//! enumeration. The "rejection method" we use for TLS 1.2 works the
//! same way: send a ClientHello offering all candidates, observe the
//! suite picked in ServerHello, remove it, repeat. When the server
//! returns an Alert (or no longer has a mutually-acceptable suite),
//! enumeration stops.
//!
//! TLS 1.3 ClientHello differs from TLS 1.2 in three required
//! extensions:
//!   - supported_versions (0x002b) — must list 0x0304 (TLS 1.3)
//!   - key_share (0x0033) — must include at least one supported group's
//!     public key
//!   - supported_groups (0x000a) — names the groups whose key_shares
//!     are present
//!
//! We send a fixed 32-byte X25519 public key for the key_share. The
//! server picks a cipher in ServerHello BEFORE validating our key
//! share, so an unclamped/cryptographically-invalid pubkey is fine —
//! the bytes after ServerHello are encrypted (we don't read them) and
//! cy-tls drops the connection after parsing the cleartext ServerHello.
//!
//! ServerHello parsing:
//!   1. Read TLS record header (5 bytes). Type must be 0x16 (handshake).
//!   2. Read body. First byte must be 0x02 (ServerHello).
//!   3. Skip msg_len(3) + legacy_version(2) + random(32) + session_id
//!      length(1) + session_id bytes.
//!   4. Read cipher_suite(2). That's our pick.
//!   5. Skip compression_method(1), then extensions block. The
//!      `supported_versions` extension (0x002b) MUST be present in a
//!      TLS 1.3 ServerHello carrying 0x0304 — if missing or wrong, the
//!      server downgraded to TLS 1.2 even though we asked for 1.3, so
//!      the pick isn't a TLS 1.3 suite (drop it).

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// All IANA-registered TLS 1.3 cipher suites we enumerate.
pub const TLS13_SUITES: &[u16] = &[
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0x1304, // TLS_AES_128_CCM_SHA256
    0x1305, // TLS_AES_128_CCM_8_SHA256
];

/// Friendly name for a TLS 1.3 cipher suite ID.
pub fn name(id: u16) -> &'static str {
    match id {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0x1304 => "TLS_AES_128_CCM_SHA256",
        0x1305 => "TLS_AES_128_CCM_8_SHA256",
        _ => "UNKNOWN",
    }
}

/// Enumerate the TLS 1.3 cipher suites a server accepts.
pub async fn enumerate(target: &str, sni: &str, deadline: Duration) -> Vec<u16> {
    let mut accepted = Vec::new();
    let mut remaining: Vec<u16> = TLS13_SUITES.to_vec();
    let mut budget = 16usize;

    while !remaining.is_empty() && budget > 0 {
        budget -= 1;
        match try_one(target, sni, &remaining, deadline).await {
            Some(picked) => {
                accepted.push(picked);
                remaining.retain(|s| *s != picked);
            }
            None => break,
        }
    }
    accepted
}

async fn try_one(target: &str, sni: &str, suites: &[u16], deadline: Duration) -> Option<u16> {
    timeout(deadline.min(Duration::from_secs(5)), async {
        let mut sock = TcpStream::connect(target).await.ok()?;
        let hello = build_client_hello(sni, suites);
        sock.write_all(&hello).await.ok()?;

        let mut header = [0u8; 5];
        sock.read_exact(&mut header).await.ok()?;
        if header[0] != 0x16 {
            return None;
        }
        let body_len = ((header[3] as usize) << 8) | (header[4] as usize);
        let mut body = vec![0u8; body_len.min(4096)];
        sock.read_exact(&mut body).await.ok()?;
        parse_server_hello_tls13(&body)
    })
    .await
    .ok()
    .flatten()
}

/// ServerHello parser. Returns the negotiated cipher iff the server
/// confirmed TLS 1.3 via the supported_versions extension. Returns
/// None when downgraded to TLS 1.2 (we don't want to claim those as
/// TLS 1.3 suites).
fn parse_server_hello_tls13(body: &[u8]) -> Option<u16> {
    // handshake header
    if *body.first()? != 0x02 {
        return None;
    }
    // skip handshake_type(1) + msg_len(3)
    let mut i = 4usize;
    // legacy_version(2)
    if body.len() < i + 2 + 32 + 1 {
        return None;
    }
    i += 2;
    // random(32)
    i += 32;
    // session_id length + bytes
    let sid_len = *body.get(i)? as usize;
    i += 1 + sid_len;
    // cipher_suite(2)
    if body.len() < i + 2 + 1 {
        return None;
    }
    let suite = ((*body.get(i)? as u16) << 8) | (*body.get(i + 1)? as u16);
    i += 2;
    // legacy_compression_method(1)
    i += 1;
    // extensions length + extensions
    if body.len() < i + 2 {
        return None;
    }
    let ext_total = ((body[i] as usize) << 8) | (body[i + 1] as usize);
    i += 2;
    let ext_end = (i + ext_total).min(body.len());
    let mut tls13_confirmed = false;
    while i + 4 <= ext_end {
        let ext_type = ((body[i] as u16) << 8) | (body[i + 1] as u16);
        let ext_len = ((body[i + 2] as usize) << 8) | (body[i + 3] as usize);
        i += 4;
        if i + ext_len > ext_end {
            break;
        }
        if ext_type == 0x002b && ext_len >= 2 {
            let v = ((body[i] as u16) << 8) | (body[i + 1] as u16);
            if v == 0x0304 {
                tls13_confirmed = true;
            }
        }
        i += ext_len;
    }
    if tls13_confirmed {
        Some(suite)
    } else {
        None
    }
}

/// Build a TLS 1.3 ClientHello offering the given suite list. Includes
/// the required-for-TLS-1.3 extensions (supported_versions, key_share,
/// supported_groups, signature_algorithms) plus SNI.
fn build_client_hello(sni: &str, suites: &[u16]) -> Vec<u8> {
    // SNI
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

    // supported_versions — list of 2-byte versions. TLS 1.3 only.
    // Wire format: ext_type(2) ext_len(2) list_len(1) versions(2*N)
    let mut sup_ver = Vec::new();
    sup_ver.extend_from_slice(&[0x00, 0x2b]); // ext type
    sup_ver.extend_from_slice(&[0x00, 0x03]); // ext data length
    sup_ver.push(0x02); // list of 2 bytes (one version)
    sup_ver.extend_from_slice(&[0x03, 0x04]); // TLS 1.3

    // supported_groups — name the groups whose key_shares we're going
    // to present. X25519 (0x001d) is enough.
    let mut groups_ext = Vec::new();
    groups_ext.extend_from_slice(&[0x00, 0x0a]); // ext type
    groups_ext.extend_from_slice(&[0x00, 0x04]); // ext data length
    groups_ext.extend_from_slice(&[0x00, 0x02]); // list length
    groups_ext.extend_from_slice(&[0x00, 0x1d]); // X25519

    // signature_algorithms — broad menu so most servers respond.
    let mut sigalg = Vec::new();
    sigalg.extend_from_slice(&[0x00, 0x0d]);
    let sig_algs: [u16; 6] = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806];
    let sig_bytes: Vec<u8> = sig_algs.iter().flat_map(|s| s.to_be_bytes()).collect();
    sigalg.extend_from_slice(&((sig_bytes.len() as u16 + 2).to_be_bytes()));
    sigalg.extend_from_slice(&((sig_bytes.len() as u16).to_be_bytes()));
    sigalg.extend_from_slice(&sig_bytes);

    // key_share — one X25519 entry. Public key is 32 bytes of fixed
    // value; the server picks a cipher in ServerHello BEFORE validating
    // the key share so an arbitrary value works for enumeration. The
    // record body after ServerHello (the encrypted EncryptedExtensions
    // + Certificate) we never read.
    //   ext_type(2) ext_len(2) list_len(2)
    //   entry: group(2) key_exchange_len(2) key_exchange(32)
    let pubkey: [u8; 32] = [0x42; 32];
    let mut ks_entry = Vec::new();
    ks_entry.extend_from_slice(&[0x00, 0x1d]); // X25519
    ks_entry.extend_from_slice(&(pubkey.len() as u16).to_be_bytes());
    ks_entry.extend_from_slice(&pubkey);
    let mut ks_inner = Vec::new();
    ks_inner.extend_from_slice(&(ks_entry.len() as u16).to_be_bytes());
    ks_inner.extend_from_slice(&ks_entry);
    let mut key_share = Vec::new();
    key_share.extend_from_slice(&[0x00, 0x33]);
    key_share.extend_from_slice(&(ks_inner.len() as u16).to_be_bytes());
    key_share.extend_from_slice(&ks_inner);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&sni_ext);
    extensions.extend_from_slice(&sup_ver);
    extensions.extend_from_slice(&groups_ext);
    extensions.extend_from_slice(&sigalg);
    extensions.extend_from_slice(&key_share);

    let mut body = Vec::new();
    // legacy_version = TLS 1.2 per RFC 8446 §4.1.2 (real version goes in supported_versions).
    body.push(0x03);
    body.push(0x03);
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session_id length

    let cipher_bytes: Vec<u8> = suites.iter().flat_map(|s| s.to_be_bytes()).collect();
    body.extend_from_slice(&(cipher_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&cipher_bytes);
    body.push(0x01);
    body.push(0x00); // legacy_compression_methods = [null]
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
    rec.push(0x03);
    rec.push(0x01); // legacy_record_version = TLS 1.0
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

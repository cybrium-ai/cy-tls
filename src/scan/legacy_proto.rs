//! Raw protocol-version probes for SSLv2 / SSLv3 / TLS 1.0 / TLS 1.1.
//!
//! TLS 1.0 (0x0301), TLS 1.1 (0x0302), and SSLv3 (0x0300) share the
//! same TLS record layer — a 5-byte header followed by the ClientHello.
//!
//! SSLv2 uses a different record format entirely: a 2-byte length
//! header (top bit set), no SNI, no extensions. We send a v2-format
//! CLIENT-HELLO and watch for a v2 SERVER-HELLO (message type 0x04)
//! in the response.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Returns true if the server accepted a ClientHello for the given
/// (major, minor) protocol version pair. Supports SSLv3, TLS 1.0,
/// TLS 1.1.
pub async fn probe_version(
    target: &str,
    sni: &str,
    major: u8,
    minor: u8,
    deadline: Duration,
) -> bool {
    let result = timeout(deadline, attempt(target, sni, major, minor)).await;
    matches!(result, Ok(Ok(true)))
}

/// SSLv2 probe — separate record-layer format from TLS.
/// Returns true if the server responds with a v2 SERVER-HELLO.
pub async fn probe_sslv2(target: &str, deadline: Duration) -> bool {
    let result = timeout(deadline, attempt_sslv2(target)).await;
    matches!(result, Ok(Ok(true)))
}

async fn attempt_sslv2(target: &str) -> std::io::Result<bool> {
    let mut sock = TcpStream::connect(target).await?;
    let hello = build_sslv2_client_hello();
    sock.write_all(&hello).await?;

    // SSLv2 record header: 2 bytes. Top bit of first byte is set
    // (no padding); remaining 15 bits are the length.
    let mut header = [0u8; 2];
    if sock.read_exact(&mut header).await.is_err() {
        return Ok(false);
    }
    // Reject TLS-style alert (0x15) or handshake (0x16) — those mean
    // the server interpreted our bytes as TLS, not SSLv2.
    if matches!(header[0], 0x15 | 0x16) {
        return Ok(false);
    }
    // V2 records have top bit set on the length-byte-high.
    if header[0] & 0x80 == 0 {
        return Ok(false);
    }
    let len = (((header[0] & 0x7f) as usize) << 8) | (header[1] as usize);
    let mut body = vec![0u8; len.min(2048)];
    if sock.read_exact(&mut body).await.is_err() {
        return Ok(false);
    }
    // SERVER-HELLO message type is 0x04.
    Ok(body.first() == Some(&0x04))
}

/// Build a minimal SSLv2 CLIENT-HELLO message.
/// Format (RFC 6101 appendix E.2):
///   record_header(2): length with top bit set
///   msg_type(1): 0x01 (CLIENT-HELLO)
///   version(2): 0x00 0x02 (SSLv2)
///   cipher_specs_length(2)
///   session_id_length(2): 0
///   challenge_length(2): 16 (or 32)
///   cipher_specs: list of 3-byte cipher IDs
///   challenge: 16 bytes of random
fn build_sslv2_client_hello() -> Vec<u8> {
    // 9 SSLv2 cipher specs — all the ones DROWN-vulnerable servers
    // typically support. Each is 3 bytes.
    let ciphers: [[u8; 3]; 9] = [
        [0x01, 0x00, 0x80], // RC4_128_WITH_MD5
        [0x02, 0x00, 0x80], // RC4_128_EXPORT40_WITH_MD5
        [0x03, 0x00, 0x80], // RC2_128_CBC_WITH_MD5
        [0x04, 0x00, 0x80], // RC2_128_CBC_EXPORT40_WITH_MD5
        [0x05, 0x00, 0x80], // IDEA_128_CBC_WITH_MD5
        [0x06, 0x00, 0x40], // DES_64_CBC_WITH_MD5
        [0x07, 0x00, 0xc0], // DES_192_EDE3_CBC_WITH_MD5
        [0x00, 0x00, 0x00], // NULL
        [0x00, 0x00, 0x01], // NULL_WITH_MD5
    ];
    let cipher_spec_bytes: Vec<u8> = ciphers.iter().flat_map(|c| c.iter().copied()).collect();
    let challenge = [0x42u8; 16];

    let mut msg = Vec::new();
    msg.push(0x01); // CLIENT-HELLO
    msg.extend_from_slice(&[0x00, 0x02]); // SSL 2.0
    msg.extend_from_slice(&(cipher_spec_bytes.len() as u16).to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes()); // session_id_length
    msg.extend_from_slice(&(challenge.len() as u16).to_be_bytes());
    msg.extend_from_slice(&cipher_spec_bytes);
    msg.extend_from_slice(&challenge);

    // Record header: 2 bytes, top bit set, 15-bit length.
    let mut rec = Vec::new();
    let len = msg.len() as u16;
    rec.push(0x80 | ((len >> 8) as u8 & 0x7f));
    rec.push(len as u8);
    rec.extend_from_slice(&msg);
    rec
}

async fn attempt(target: &str, sni: &str, major: u8, minor: u8) -> std::io::Result<bool> {
    let mut sock = TcpStream::connect(target).await?;
    let hello = build_client_hello(sni, major, minor);
    sock.write_all(&hello).await?;

    let mut header = [0u8; 5];
    if sock.read_exact(&mut header).await.is_err() {
        return Ok(false);
    }
    // Record layer:  [content_type(1)] [version(2)] [length(2)]
    let content_type = header[0];
    let resp_major = header[1];
    let resp_minor = header[2];

    if content_type != 0x16 {
        // Alert (0x15) or anything else → not accepted.
        return Ok(false);
    }
    if (resp_major, resp_minor) != (major, minor) {
        return Ok(false);
    }

    // Confirm the body starts with a ServerHello handshake message (type 0x02).
    let body_len = ((header[3] as usize) << 8) | (header[4] as usize);
    let mut body = vec![0u8; body_len.min(64)];
    if sock.read_exact(&mut body).await.is_err() {
        return Ok(false);
    }
    Ok(body.first() == Some(&0x02))
}

fn build_client_hello(sni: &str, major: u8, minor: u8) -> Vec<u8> {
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&[0x00, 0x00]); // extension type 0 (server_name)

    let mut sni_list = Vec::new();
    sni_list.push(0x00); // name_type = host_name
    let sni_bytes = sni.as_bytes();
    sni_list.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_list.extend_from_slice(sni_bytes);

    let mut sni_list_with_len = Vec::new();
    sni_list_with_len.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
    sni_list_with_len.extend_from_slice(&sni_list);

    sni_ext.extend_from_slice(&(sni_list_with_len.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(&sni_list_with_len);

    let extensions_len = sni_ext.len() as u16;

    let mut hello_body = Vec::new();
    hello_body.push(major);
    hello_body.push(minor); // client_version
    hello_body.extend_from_slice(&[0u8; 32]); // random (zeros — fine for probe)
    hello_body.push(0); // session_id length
                        // Cipher suites — a small but representative set:
    let suites: [u16; 9] = [
        0xC02F, // ECDHE-RSA-AES128-GCM-SHA256
        0xC030, // ECDHE-RSA-AES256-GCM-SHA384
        0xC02B, // ECDHE-ECDSA-AES128-GCM-SHA256
        0xC02C, // ECDHE-ECDSA-AES256-GCM-SHA384
        0x009C, // RSA-AES128-GCM-SHA256
        0x009D, // RSA-AES256-GCM-SHA384
        0x002F, // RSA-AES128-SHA
        0x0035, // RSA-AES256-SHA
        0x000A, // RSA-3DES-EDE-SHA
    ];
    let cipher_bytes: Vec<u8> = suites.iter().flat_map(|s| s.to_be_bytes()).collect();
    hello_body.extend_from_slice(&(cipher_bytes.len() as u16).to_be_bytes());
    hello_body.extend_from_slice(&cipher_bytes);

    hello_body.push(0x01); // compression methods length
    hello_body.push(0x00); // null compression

    hello_body.extend_from_slice(&extensions_len.to_be_bytes());
    hello_body.extend_from_slice(&sni_ext);

    let mut handshake = Vec::new();
    handshake.push(0x01); // handshake type = ClientHello
    let body_len = hello_body.len() as u32;
    handshake.push(((body_len >> 16) & 0xff) as u8);
    handshake.push(((body_len >> 8) & 0xff) as u8);
    handshake.push((body_len & 0xff) as u8);
    handshake.extend_from_slice(&hello_body);

    let mut record = Vec::new();
    record.push(0x16); // content type = Handshake
    record.push(major);
    record.push(minor); // record version
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

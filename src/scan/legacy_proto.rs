//! Raw TLS version probes for protocols rustls won't negotiate.
//!
//! Sends a minimal ClientHello byte sequence over a plain TcpStream and
//! inspects the server's response to detect whether TLS 1.0 (0x0301)
//! and TLS 1.1 (0x0302) are accepted. SSLv2 / SSLv3 probes are honestly
//! deferred — see TODO.md (the v0.2.1 list).
//!
//! Reasoning over correctness: a server that does NOT support the
//! requested version will either send an Alert record (content type
//! 0x15), close the socket immediately, or downgrade. We treat a
//! Handshake record (0x16) with a ServerHello (handshake type 0x02)
//! whose version field matches the requested version as confirmation.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Returns true if the server accepted a ClientHello for the given
/// (major, minor) protocol version pair.
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
    hello_body.push(major); hello_body.push(minor);          // client_version
    hello_body.extend_from_slice(&[0u8; 32]);                // random (zeros — fine for probe)
    hello_body.push(0);                                       // session_id length
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
    handshake.push(0x01);                                              // handshake type = ClientHello
    let body_len = hello_body.len() as u32;
    handshake.push(((body_len >> 16) & 0xff) as u8);
    handshake.push(((body_len >> 8) & 0xff) as u8);
    handshake.push((body_len & 0xff) as u8);
    handshake.extend_from_slice(&hello_body);

    let mut record = Vec::new();
    record.push(0x16);                                                  // content type = Handshake
    record.push(major); record.push(minor);                            // record version
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

//! OpenSSL CCS Injection (CVE-2014-0224) active probe.
//!
//! Vulnerable OpenSSL <1.0.1h / <1.0.0m / <0.9.8za accepts a
//! ChangeCipherSpec record before the handshake completes and
//! transitions to an encrypted state with empty keying material —
//! letting a network attacker decrypt the subsequent session.
//!
//! Detection: send a TLS 1.2 ClientHello, drain the server's
//! ServerHello / Certificate / ServerHelloDone, then send an EARLY
//! ChangeCipherSpec record (type 0x14) before the client has sent
//! ClientKeyExchange or its own ChangeCipherSpec. A non-vulnerable
//! server responds with an `unexpected_message` Alert (type 0x15,
//! alert level fatal). A vulnerable server accepts silently and
//! continues. If we get a Handshake or Application Data record
//! (type 0x16 / 0x17) instead of an Alert, the server accepted the
//! CCS injection.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Copy)]
pub enum CcsVerdict {
    NotVulnerable,
    Vulnerable,
    Indeterminate,
}

pub async fn probe(target: &str, sni: &str, deadline: Duration) -> CcsVerdict {
    let result = timeout(deadline.min(Duration::from_secs(6)), async {
        let mut sock = TcpStream::connect(target).await.ok()?;
        let hello = build_client_hello(sni);
        sock.write_all(&hello).await.ok()?;

        // Drain handshake records until ServerHelloDone (type 0x0e).
        let mut got_done = false;
        for _ in 0..16 {
            let mut hdr = [0u8; 5];
            if sock.read_exact(&mut hdr).await.is_err() {
                break;
            }
            if hdr[0] == 0x15 {
                return Some(CcsVerdict::Indeterminate);
            }
            if hdr[0] != 0x16 {
                break;
            }
            let len = ((hdr[3] as usize) << 8) | (hdr[4] as usize);
            let mut body = vec![0u8; len.min(16 * 1024)];
            if sock.read_exact(&mut body).await.is_err() {
                break;
            }
            if has_handshake_type(&body, 0x0e) {
                got_done = true;
                break;
            }
        }
        if !got_done {
            return Some(CcsVerdict::Indeterminate);
        }

        // Inject ChangeCipherSpec before we've sent ClientKeyExchange.
        //   record_header: type=0x14 (CCS), version=0x0303, length=0x0001
        //   payload: 0x01
        let ccs: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        sock.write_all(&ccs).await.ok()?;

        // What does the server send back?
        let mut hdr = [0u8; 5];
        match timeout(Duration::from_secs(3), sock.read_exact(&mut hdr)).await {
            Ok(Ok(_)) => {
                match hdr[0] {
                    // Alert (0x15) — server rejected the early CCS. Good.
                    0x15 => Some(CcsVerdict::NotVulnerable),
                    // Handshake (0x16) or Application Data (0x17) — server
                    // accepted the CCS and is continuing the conversation.
                    // Vulnerable.
                    0x16 | 0x17 => Some(CcsVerdict::Vulnerable),
                    _ => Some(CcsVerdict::Indeterminate),
                }
            }
            // Connection closed silently — usually means server rejected.
            _ => Some(CcsVerdict::NotVulnerable),
        }
    })
    .await;
    result.ok().flatten().unwrap_or(CcsVerdict::Indeterminate)
}

fn has_handshake_type(body: &[u8], typ: u8) -> bool {
    let mut i = 0;
    while i + 4 <= body.len() {
        let msg_len =
            ((body[i + 1] as usize) << 16) | ((body[i + 2] as usize) << 8) | (body[i + 3] as usize);
        if body[i] == typ {
            return true;
        }
        if i + 4 + msg_len > body.len() {
            return false;
        }
        i += 4 + msg_len;
    }
    false
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
    body.push(0x03);
    body.push(0x03);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&(cipher_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&cipher_bytes);
    body.push(0x01);
    body.push(0x00);
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
    rec.push(0x03);
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

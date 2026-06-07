//! GOLDENDOODLE / Zombie POODLE active record-injection probe.
//!
//! Hanno Böck's 2019 CBC-oracle disclosures identified families of
//! TLS implementations that, on the TLS 1.2 + CBC decrypt path, return
//! DIFFERENT alert types for "MAC failed" vs "padding failed" even when
//! the underlying record was equally malformed from the receiver's
//! perspective. That distinguishability is a Vaudenay-style padding
//! oracle that lets attackers recover plaintext byte-by-byte.
//!
//! v0.5.0: full record-layer active probe that drives a real TLS 1.2
//! handshake with cipher 0x002f (TLS_RSA_WITH_AES_128_CBC_SHA), derives
//! keys via `tls12_crypto`, then sends two deliberately-corrupt
//! application_data records carrying ORTHOGONAL corruptions:
//!
//!   V_a: invalid MAC + valid PKCS#7 padding
//!     Patched server : bad_record_mac (alert 20) — unified error path
//!     Vulnerable     : bad_record_mac (alert 20)
//!   V_c: valid MAC over a frame whose padding bytes have been swapped
//!        out so the padding pattern is wrong
//!     Patched server : bad_record_mac (alert 20) — same unified path
//!     Vulnerable     : decrypt_error (alert 51) — server SAW the bad
//!                       padding distinct from the MAC failure
//!
//! Verdict: alert(V_a) != alert(V_c) ⇒ Vulnerable.
//!
//! Distinction from `vuln_padding_oracle_active` (CVE-2016-2107):
//!   - CVE-2016-2107 tests V1=(bad_mac, good_pad) vs V2=(bad_mac, bad_pad)
//!     — both records have bad MAC; the AES-NI bug distinguishes WITHIN
//!     the bad-MAC code path based on whether decrypt ALSO produced bad
//!     padding.
//!   - GOLDENDOODLE tests (bad_mac) vs (bad_pad) — flips ONE error at a
//!     time and asks whether the server's response distinguishes which
//!     check fired first. Different oracle root cause, different fix
//!     populations, separate finding ID.
//!
//! Reuses ClientHello + RSA-encrypt + handshake walkers from
//! `vuln_padding_oracle_active` via the pub(super) interface — no
//! duplication.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::tls12_crypto::{derive_key_block, derive_master_secret, encrypt_record_with_corruption};
use super::vuln_padding_oracle_active::{
    build_cke_record, build_client_hello, generate_random_32, has_handshake_type,
    parse_rsa_pubkey_from_cert_message, parse_server_hello_random, rsa_pkcs1_v15_encrypt,
    AlertClass,
};

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // NotApplicable reserved for future RSA-kx-absent branch.
pub enum GoldendoodleVerdict {
    NotVulnerable,
    Vulnerable,
    NotApplicable,
    Indeterminate,
}

pub async fn probe(target: &str, sni: &str, deadline: Duration) -> GoldendoodleVerdict {
    timeout(deadline.min(Duration::from_secs(20)), async move {
        run_probe(target, sni).await
    })
    .await
    .unwrap_or(GoldendoodleVerdict::Indeterminate)
}

async fn run_probe(target: &str, sni: &str) -> GoldendoodleVerdict {
    // V_a = (corrupt_mac=true,  corrupt_padding=false)
    // V_c = (corrupt_mac=false, corrupt_padding=true)
    let va = match drive_oracle(target, sni, true, false).await {
        Some(a) => a,
        None => return GoldendoodleVerdict::Indeterminate,
    };
    let vc = match drive_oracle(target, sni, false, true).await {
        Some(a) => a,
        None => return GoldendoodleVerdict::Indeterminate,
    };

    if matches!(va, AlertClass::Timeout) && matches!(vc, AlertClass::Timeout) {
        return GoldendoodleVerdict::Indeterminate;
    }
    if va == vc {
        // Server reacted identically to "bad MAC, good pad" and
        // "good MAC, bad pad" — no distinguisher. Patched.
        GoldendoodleVerdict::NotVulnerable
    } else if matches!(va, AlertClass::BadRecordMac) && matches!(vc, AlertClass::DecryptError) {
        // Textbook GOLDENDOODLE oracle: padding error gets its own
        // alert distinct from the MAC-failure path.
        GoldendoodleVerdict::Vulnerable
    } else {
        // Different alerts but not the bad_record_mac vs decrypt_error
        // split — could be a non-OpenSSL stack with its own peculiar
        // error mapping. Conservative: not flagged.
        GoldendoodleVerdict::NotVulnerable
    }
}

async fn drive_oracle(
    target: &str,
    sni: &str,
    corrupt_mac: bool,
    corrupt_padding: bool,
) -> Option<AlertClass> {
    let mut sock = TcpStream::connect(target).await.ok()?;

    let client_random = generate_random_32();
    let hello = build_client_hello(sni, &client_random);
    sock.write_all(&hello).await.ok()?;

    // Drain server handshake until ServerHelloDone (0x0e).
    let mut accumulated = Vec::with_capacity(8 * 1024);
    for _ in 0..32 {
        let mut hdr = [0u8; 5];
        if sock.read_exact(&mut hdr).await.is_err() {
            return None;
        }
        if hdr[0] == 0x15 {
            return Some(AlertClass::Other(0x15));
        }
        if hdr[0] != 0x16 {
            return None;
        }
        let len = ((hdr[3] as usize) << 8) | (hdr[4] as usize);
        let mut body = vec![0u8; len.min(16 * 1024)];
        if sock.read_exact(&mut body).await.is_err() {
            return None;
        }
        accumulated.extend_from_slice(&body);
        if has_handshake_type(&accumulated, 0x0e) {
            break;
        }
    }

    let server_random = parse_server_hello_random(&accumulated)?;
    let cert_body = find_cert_message(&accumulated)?;
    let (n, e) = parse_rsa_pubkey_from_cert_message(&cert_body)?;

    // Premaster: 0x03 0x03 || 46 deterministic bytes.
    let mut premaster = [0u8; 48];
    premaster[0] = 0x03;
    premaster[1] = 0x03;
    for (i, byte) in premaster.iter_mut().enumerate().skip(2) {
        *byte = (i as u8).wrapping_mul(41);
    }

    let cke_ct = rsa_pkcs1_v15_encrypt(&n, &e, &premaster)?;
    let cke_record = build_cke_record(&cke_ct);
    sock.write_all(&cke_record).await.ok()?;

    let ccs: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
    sock.write_all(&ccs).await.ok()?;

    let master = derive_master_secret(&premaster, &client_random, &server_random);
    let keys = derive_key_block(&master, &client_random, &server_random);

    // Finished-shaped plaintext: handshake_type=0x14 + length(3) + 12
    // garbage bytes. Contents don't matter — vulnerable stacks fail at
    // the MAC-vs-padding distinguishability layer before message
    // structure or verify_data validation.
    let mut finished_plain = vec![0x14, 0x00, 0x00, 0x0c];
    finished_plain.extend_from_slice(&[0u8; 12]);

    let encrypted =
        encrypt_record_with_corruption(&finished_plain, 0u64, &keys, corrupt_mac, corrupt_padding);
    sock.write_all(&encrypted).await.ok()?;

    let mut hdr = [0u8; 5];
    match timeout(Duration::from_secs(3), sock.read_exact(&mut hdr)).await {
        Ok(Ok(_)) => match hdr[0] {
            0x15 => {
                let len = ((hdr[3] as usize) << 8) | (hdr[4] as usize);
                let mut body = vec![0u8; len.min(8)];
                let _ = sock.read_exact(&mut body).await;
                let desc = body.get(1).copied().unwrap_or(0);
                Some(match desc {
                    20 => AlertClass::BadRecordMac,
                    51 => AlertClass::DecryptError,
                    other => AlertClass::Other(other),
                })
            }
            _ => Some(AlertClass::Other(hdr[0])),
        },
        Ok(Err(_)) => Some(AlertClass::ConnectionClosed),
        Err(_) => Some(AlertClass::Timeout),
    }
}

/// Find the Certificate handshake message body in the accumulated
/// handshake stream. The reused `parse_rsa_pubkey_from_cert_message`
/// expects the body bytes, so we use the same find_handshake_body
/// pattern but inline it here to keep cross-module ABI small.
fn find_cert_message(accumulated: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0;
    while i + 4 <= accumulated.len() {
        let msg_type = accumulated[i];
        let msg_len = ((accumulated[i + 1] as usize) << 16)
            | ((accumulated[i + 2] as usize) << 8)
            | (accumulated[i + 3] as usize);
        let start = i + 4;
        let end = start + msg_len;
        if end > accumulated.len() {
            return None;
        }
        if msg_type == 0x0b {
            return Some(accumulated[start..end].to_vec());
        }
        i = end;
    }
    None
}

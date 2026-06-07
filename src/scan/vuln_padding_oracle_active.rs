//! Active CVE-2016-2107 — OpenSSL AES-NI padding oracle.
//!
//! v0.4.0: full record-layer active probe. Walks a real TLS 1.2
//! handshake using cipher suite 0x002f (TLS_RSA_WITH_AES_128_CBC_SHA),
//! derives the symmetric keys via `tls12_crypto`, then sends two
//! deliberately-corrupt application_data records and compares the
//! alert types the server returns:
//!
//!   V1: valid PKCS#7 padding + invalid MAC
//!     Patched OpenSSL: bad_record_mac (alert 20)
//!     Vulnerable     : bad_record_mac (alert 20) — control case.
//!   V2: invalid PKCS#7 padding + invalid MAC
//!     Patched OpenSSL: bad_record_mac (alert 20) — unified error path
//!     Vulnerable     : decrypt_error (alert 51) — AES-NI fast path
//!                       leaks padding-failure-distinct-from-MAC.
//!
//! Verdict: alert(V1) != alert(V2) ⇒ Vulnerable.
//!
//! Note on Finished verify_data: we deliberately do NOT compute a real
//! verify_data. Vulnerable OpenSSL fails at the PADDING check, which
//! happens BEFORE the MAC verification and BEFORE the message-structure
//! check, so verify_data correctness is irrelevant — the oracle lives
//! strictly in the AES-NI decrypt path's padding-vs-MAC error
//! distinguishability.

use std::time::Duration;

use num_bigint::BigUint;
use num_traits::Zero;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use x509_parser::prelude::*;

use super::tls12_crypto::{derive_key_block, derive_master_secret, encrypt_record_with_corruption};

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // NotApplicable reserved for future RSA-kx-absent branch.
pub enum OracleVerdict {
    NotVulnerable,
    Vulnerable,
    NotApplicable,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AlertClass {
    BadRecordMac,
    DecryptError,
    Other(u8),
    ConnectionClosed,
    Timeout,
}

pub async fn probe(target: &str, sni: &str, deadline: Duration) -> OracleVerdict {
    timeout(deadline.min(Duration::from_secs(20)), async move {
        run_probe(target, sni).await
    })
    .await
    .unwrap_or(OracleVerdict::Indeterminate)
}

async fn run_probe(target: &str, sni: &str) -> OracleVerdict {
    let v1 = match drive_oracle(target, sni, false).await {
        Some(a) => a,
        None => return OracleVerdict::Indeterminate,
    };
    let v2 = match drive_oracle(target, sni, true).await {
        Some(a) => a,
        None => return OracleVerdict::Indeterminate,
    };

    if matches!(v1, AlertClass::Timeout) && matches!(v2, AlertClass::Timeout) {
        return OracleVerdict::Indeterminate;
    }
    if v1 == v2 {
        OracleVerdict::NotVulnerable
    } else if matches!(v1, AlertClass::BadRecordMac) && matches!(v2, AlertClass::DecryptError) {
        OracleVerdict::Vulnerable
    } else {
        OracleVerdict::NotVulnerable
    }
}

async fn drive_oracle(target: &str, sni: &str, corrupt_padding: bool) -> Option<AlertClass> {
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
    let cert_body = find_handshake_body(&accumulated, 0x0b)?;
    let (n, e) = parse_rsa_pubkey_from_cert_message(&cert_body)?;

    // Premaster: 0x03 0x03 || 46 deterministic bytes.
    let mut premaster = [0u8; 48];
    premaster[0] = 0x03;
    premaster[1] = 0x03;
    for (i, byte) in premaster.iter_mut().enumerate().skip(2) {
        *byte = (i as u8).wrapping_mul(37);
    }

    let cke_ct = rsa_pkcs1_v15_encrypt(&n, &e, &premaster)?;
    let cke_record = build_cke_record(&cke_ct);
    sock.write_all(&cke_record).await.ok()?;

    let ccs: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
    sock.write_all(&ccs).await.ok()?;

    let master = derive_master_secret(&premaster, &client_random, &server_random);
    let keys = derive_key_block(&master, &client_random, &server_random);

    // Build a Finished-shaped plaintext: handshake_type=0x14 + length(3) + 12 garbage bytes.
    // The contents don't matter — vulnerable OpenSSL fails before MAC/structure validation.
    let mut finished_plain = vec![0x14, 0x00, 0x00, 0x0c];
    finished_plain.extend_from_slice(&[0u8; 12]);

    let encrypted = encrypt_record_with_corruption(
        &finished_plain,
        0u64, // seq_num — first encrypted record after CCS
        &keys,
        true,            // corrupt_mac
        corrupt_padding, // V1 vs V2
    );
    // encrypt_record_with_corruption marks the record as application_data
    // (type 0x17). Patched OpenSSL still treats the bad MAC the same way.
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

// ── ClientHello + record builders (cipher 0x002f only) ──────────────

fn generate_random_32() -> [u8; 32] {
    // Deterministic across runs is fine — we're not relying on
    // unpredictability for any security property here.
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(31).wrapping_add(7);
    }
    out
}

fn build_client_hello(sni: &str, client_random: &[u8; 32]) -> Vec<u8> {
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

    let mut sigalg_ext = Vec::new();
    sigalg_ext.extend_from_slice(&[0x00, 0x0d]);
    let sig_algs: [u16; 4] = [0x0401, 0x0501, 0x0601, 0x0201];
    let sig_bytes: Vec<u8> = sig_algs.iter().flat_map(|s| s.to_be_bytes()).collect();
    sigalg_ext.extend_from_slice(&((sig_bytes.len() as u16 + 2).to_be_bytes()));
    sigalg_ext.extend_from_slice(&((sig_bytes.len() as u16).to_be_bytes()));
    sigalg_ext.extend_from_slice(&sig_bytes);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&sni_ext);
    extensions.extend_from_slice(&sigalg_ext);

    // Cipher 0x002f only: TLS_RSA_WITH_AES_128_CBC_SHA — exactly what
    // tls12_crypto.rs targets.
    let suites: [u16; 1] = [0x002f];
    let cipher_bytes: Vec<u8> = suites.iter().flat_map(|s| s.to_be_bytes()).collect();

    let mut body = Vec::new();
    body.push(0x03);
    body.push(0x03);
    body.extend_from_slice(client_random);
    body.push(0); // session_id length
    body.extend_from_slice(&(cipher_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&cipher_bytes);
    body.push(0x01);
    body.push(0x00); // compression: null
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

fn build_cke_record(rsa_ct: &[u8]) -> Vec<u8> {
    let mut hs_body = Vec::new();
    hs_body.extend_from_slice(&(rsa_ct.len() as u16).to_be_bytes());
    hs_body.extend_from_slice(rsa_ct);

    let mut hs = Vec::new();
    hs.push(0x10);
    let l = hs_body.len() as u32;
    hs.push(((l >> 16) & 0xff) as u8);
    hs.push(((l >> 8) & 0xff) as u8);
    hs.push((l & 0xff) as u8);
    hs.extend_from_slice(&hs_body);

    let mut rec = Vec::new();
    rec.push(0x16);
    rec.push(0x03);
    rec.push(0x03);
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

// ── RSA PKCS#1 v1.5 encrypt (valid padding) ─────────────────────────

fn rsa_pkcs1_v15_encrypt(n: &BigUint, e: &BigUint, m: &[u8]) -> Option<Vec<u8>> {
    let n_byte_len = (n.bits() as usize).div_ceil(8);
    if m.len() > n_byte_len.saturating_sub(11) {
        return None;
    }

    // EM = 0x00 || 0x02 || PS || 0x00 || M
    // PS = at least 8 non-zero bytes
    let ps_len = n_byte_len - m.len() - 3;
    let mut em = vec![0u8; n_byte_len];
    em[0] = 0x00;
    em[1] = 0x02;
    for i in 0..ps_len {
        // Non-zero pad — value doesn't matter for correctness, only that
        // it stays nonzero. Use a simple non-zero pattern.
        em[2 + i] = (i as u8).wrapping_mul(7).wrapping_add(1) | 0x01;
    }
    em[2 + ps_len] = 0x00;
    em[2 + ps_len + 1..].copy_from_slice(m);

    let p = BigUint::from_bytes_be(&em);
    if p.is_zero() || p >= *n {
        return None;
    }
    let c = p.modpow(e, n);
    let mut ct = c.to_bytes_be();
    while ct.len() < n_byte_len {
        ct.insert(0, 0x00);
    }
    Some(ct)
}

// ── Server handshake walkers ────────────────────────────────────────

fn parse_server_hello_random(accumulated: &[u8]) -> Option<[u8; 32]> {
    let body = find_handshake_body(accumulated, 0x02)?;
    // ServerHello body: server_version(2) || random(32) || ...
    if body.len() < 34 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&body[2..34]);
    Some(out)
}

fn find_handshake_body(buf: &[u8], typ: u8) -> Option<Vec<u8>> {
    let mut i = 0;
    while i + 4 <= buf.len() {
        let msg_type = buf[i];
        let msg_len =
            ((buf[i + 1] as usize) << 16) | ((buf[i + 2] as usize) << 8) | (buf[i + 3] as usize);
        let start = i + 4;
        let end = start + msg_len;
        if end > buf.len() {
            return None;
        }
        if msg_type == typ {
            return Some(buf[start..end].to_vec());
        }
        i = end;
    }
    None
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

fn parse_rsa_pubkey_from_cert_message(body: &[u8]) -> Option<(BigUint, BigUint)> {
    if body.len() < 6 {
        return None;
    }
    let mut i = 3; // skip outer 3-byte total length
    let cert_len =
        ((body[i] as usize) << 16) | ((body[i + 1] as usize) << 8) | (body[i + 2] as usize);
    i += 3;
    let cert_der = body.get(i..i + cert_len)?;
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    let spki = &cert.tbs_certificate.subject_pki;
    let der = spki.subject_public_key.data.as_ref();
    rsa_pubkey_from_der(der)
}

fn rsa_pubkey_from_der(der: &[u8]) -> Option<(BigUint, BigUint)> {
    let mut i = 0;
    if *der.get(i)? != 0x30 {
        return None;
    }
    i += 1;
    let _ = read_der_length(der, &mut i)?;
    if *der.get(i)? != 0x02 {
        return None;
    }
    i += 1;
    let mod_len = read_der_length(der, &mut i)?;
    let mod_bytes = der.get(i..i + mod_len)?;
    i += mod_len;
    if *der.get(i)? != 0x02 {
        return None;
    }
    i += 1;
    let exp_len = read_der_length(der, &mut i)?;
    let exp_bytes = der.get(i..i + exp_len)?;

    fn strip(b: &[u8]) -> &[u8] {
        if b.first() == Some(&0x00) {
            &b[1..]
        } else {
            b
        }
    }
    let n = BigUint::from_bytes_be(strip(mod_bytes));
    let e = BigUint::from_bytes_be(strip(exp_bytes));
    Some((n, e))
}

fn read_der_length(buf: &[u8], i: &mut usize) -> Option<usize> {
    let first = *buf.get(*i)?;
    *i += 1;
    if first < 0x80 {
        return Some(first as usize);
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 {
        return None;
    }
    let mut len = 0usize;
    for _ in 0..n {
        len = (len << 8) | (*buf.get(*i)? as usize);
        *i += 1;
    }
    Some(len)
}

//! ROBOT — Return Of Bleichenbacher's Oracle Threat (CVE-2017-13099 et al).
//!
//! The original 1998 Bleichenbacher RSA padding-oracle attack returns
//! when TLS servers distinguish — by alert type, by connection-close
//! pattern, or by timing — between RSA-encrypted ClientKeyExchange
//! messages with valid vs invalid PKCS#1 v1.5 padding.
//!
//! Active probe (Hanno Böck / Juraj Somorovsky 2017 methodology):
//!
//! 1. Complete a TLS 1.2 ClientHello → ServerHello → Certificate →
//!    ServerHelloDone exchange offering only RSA key-exchange ciphers.
//! 2. Extract the server's RSA public key (modulus + exponent) from
//!    the Certificate message.
//! 3. For each of 5 padding variants, craft a 2048-bit plaintext,
//!    raw-RSA-encrypt with the server's public key, send as a
//!    ClientKeyExchange record. Then send ChangeCipherSpec + a dummy
//!    encrypted Finished (random bytes — the server will reject but
//!    HOW it rejects is what we measure).
//! 4. Read the server's response — alert type / connection close.
//! 5. Compare responses across the 5 variants. If at least 2 distinct
//!    response classes appear AND the "correct" vector elicits a
//!    different response from at least one "incorrect" vector, the
//!    server is leaking the oracle and ROBOT-vulnerable.
//!
//! The 5 vectors test the well-known distinguishable PKCS#1 v1.5
//! padding mistakes from Section 3 of Bleichenbacher 1998:
//!
//!     V1 (control):  0x00 0x02 [PS] 0x00 [TLS-version] [random 46]
//!     V2:            0x42 0x02 ...   (wrong first byte)
//!     V3:            0x00 0x17 ...   (wrong second byte — not 0x02)
//!     V4:            0x00 0x02 0x00 [PS too short]  (early 0x00)
//!     V5:            0x00 0x02 [PS][PS]   (no 0x00 separator at all)
//!
//! A correctly-patched server returns the SAME generic "bad_record_mac"
//! or "decrypt_error" alert for ALL five variants. A vulnerable server
//! distinguishes by returning different alerts, by closing the
//! connection at different points, or by visible timing differences.

use std::time::Duration;

use num_bigint::BigUint;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use x509_parser::prelude::*;

#[derive(Debug, Clone, Copy)]
pub enum RobotVerdict {
    /// Server is not vulnerable — all 5 padding variants produced the
    /// same response class (oracle is closed).
    NotVulnerable,
    /// Server's responses differ across variants — oracle leaks.
    Vulnerable,
    /// Server doesn't support RSA key exchange (the attack surface is
    /// structurally absent) — no probe possible.
    NotApplicable,
    /// Probe couldn't run (connect / handshake / cert-parse / IO failure).
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ResponseClass {
    AlertBadRecordMac,
    AlertDecryptError,
    AlertOther(u8),
    ConnectionClosed,
    Timeout,
}

pub async fn probe(target: &str, sni: &str, deadline: Duration) -> RobotVerdict {
    let outcome = timeout(deadline.min(Duration::from_secs(30)), async {
        // 1. Connect + handshake to get the cert + ServerHelloDone
        let (rsa_n, rsa_e) = match obtain_rsa_pubkey(target, sni).await {
            Some(k) => k,
            None => return Some(RobotVerdict::NotApplicable),
        };

        // 2. Probe each of the 5 padding variants on a FRESH connection.
        //    Each variant gets its own handshake-up-to-CKE + malformed
        //    CKE so server state isn't polluted across attempts.
        let mut classes: Vec<ResponseClass> = Vec::with_capacity(5);
        for vector in 0u8..5 {
            let ct = build_malformed_cke_ciphertext(vector, &rsa_n, &rsa_e);
            let class = send_malformed_cke_and_observe(target, sni, &ct)
                .await
                .unwrap_or(ResponseClass::Timeout);
            classes.push(class);
        }

        // 3. Compare. If every variant produced the same class, server
        //    is safe. If the control (V1, the "correct" padding) elicited
        //    a different class from any non-control vector, the oracle
        //    is leaking.
        let unique_count: usize = classes
            .iter()
            .fold(Vec::<&ResponseClass>::new(), |mut acc, c| {
                if !acc.contains(&c) {
                    acc.push(c);
                }
                acc
            })
            .len();

        Some(if unique_count <= 1 {
            RobotVerdict::NotVulnerable
        } else {
            // Multiple classes — only flag Vulnerable if the control
            // distinguishes from at least one other. (A server that
            // distinguishes between two equally-invalid variants but
            // not against the control is rare and likely a transient
            // network anomaly rather than a real oracle.)
            let control = &classes[0];
            if classes[1..].iter().any(|c| c != control) {
                RobotVerdict::Vulnerable
            } else {
                RobotVerdict::NotVulnerable
            }
        })
    })
    .await;
    outcome
        .ok()
        .flatten()
        .unwrap_or(RobotVerdict::Indeterminate)
}

// ── Handshake helpers ─────────────────────────────────────────────────

/// Complete a partial TLS 1.2 handshake offering ONLY RSA key-exchange
/// ciphers. Read the server's Certificate message + ServerHelloDone.
/// Return the RSA (modulus, exponent) of the leaf cert if one is sent.
async fn obtain_rsa_pubkey(target: &str, sni: &str) -> Option<(BigUint, BigUint)> {
    let mut sock = TcpStream::connect(target).await.ok()?;
    let hello = build_rsa_only_client_hello(sni);
    sock.write_all(&hello).await.ok()?;

    let mut buf = Vec::with_capacity(8 * 1024);
    let mut got_done = false;
    for _ in 0..32 {
        let mut hdr = [0u8; 5];
        if sock.read_exact(&mut hdr).await.is_err() {
            break;
        }
        if hdr[0] != 0x16 {
            return None;
        }
        let len = ((hdr[3] as usize) << 8) | (hdr[4] as usize);
        let mut body = vec![0u8; len.min(16 * 1024)];
        if sock.read_exact(&mut body).await.is_err() {
            return None;
        }
        buf.extend_from_slice(&body);
        if has_handshake_type(&buf, 0x0e) {
            got_done = true;
            break;
        }
    }
    if !got_done {
        return None;
    }

    // Find the Certificate message (handshake type 0x0b) in the
    // accumulated stream and parse the first cert.
    let cert_body = find_handshake_body(&buf, 0x0b)?;
    parse_rsa_pubkey_from_cert_message(&cert_body)
}

/// Open a new connection, complete handshake-up-to-ServerHelloDone,
/// send our crafted ClientKeyExchange, then send ChangeCipherSpec and a
/// dummy Finished. Read whatever the server returns and classify it.
async fn send_malformed_cke_and_observe(
    target: &str,
    sni: &str,
    rsa_ct: &[u8],
) -> Option<ResponseClass> {
    let mut sock = TcpStream::connect(target).await.ok()?;
    let hello = build_rsa_only_client_hello(sni);
    sock.write_all(&hello).await.ok()?;

    // Drain server handshake.
    let mut tmp = Vec::new();
    for _ in 0..32 {
        let mut hdr = [0u8; 5];
        if sock.read_exact(&mut hdr).await.is_err() {
            return Some(ResponseClass::ConnectionClosed);
        }
        if hdr[0] != 0x16 {
            return Some(ResponseClass::AlertOther(0));
        }
        let len = ((hdr[3] as usize) << 8) | (hdr[4] as usize);
        let mut body = vec![0u8; len.min(16 * 1024)];
        if sock.read_exact(&mut body).await.is_err() {
            return Some(ResponseClass::ConnectionClosed);
        }
        tmp.extend_from_slice(&body);
        if has_handshake_type(&tmp, 0x0e) {
            break;
        }
    }

    // Send CKE with the crafted RSA ciphertext.
    let cke = build_cke_record(rsa_ct);
    sock.write_all(&cke).await.ok()?;
    // ChangeCipherSpec record (always required after CKE).
    let ccs: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
    sock.write_all(&ccs).await.ok()?;
    // Dummy Finished — 16 bytes of random "encrypted handshake message"
    // wrapped in a record. The server can't actually decrypt it because
    // we used a bogus premaster, but it will react SOMEHOW — and the
    // reaction is what we measure.
    let finished_payload: [u8; 40] = [0x42u8; 40];
    let mut fin_record = vec![0x16, 0x03, 0x03];
    fin_record.extend_from_slice(&(finished_payload.len() as u16).to_be_bytes());
    fin_record.extend_from_slice(&finished_payload);
    sock.write_all(&fin_record).await.ok()?;

    // Read what comes back.
    let mut hdr = [0u8; 5];
    match timeout(Duration::from_secs(2), sock.read_exact(&mut hdr)).await {
        Ok(Ok(_)) => match hdr[0] {
            0x15 => {
                // Alert record.
                let len = ((hdr[3] as usize) << 8) | (hdr[4] as usize);
                let mut body = vec![0u8; len.min(8)];
                let _ = sock.read_exact(&mut body).await;
                // Alert body: 1 byte level + 1 byte description.
                let desc = body.get(1).copied().unwrap_or(0);
                Some(match desc {
                    20 => ResponseClass::AlertBadRecordMac, // bad_record_mac
                    51 => ResponseClass::AlertDecryptError, // decrypt_error
                    other => ResponseClass::AlertOther(other),
                })
            }
            _ => Some(ResponseClass::AlertOther(hdr[0])),
        },
        Ok(Err(_)) => Some(ResponseClass::ConnectionClosed),
        Err(_) => Some(ResponseClass::Timeout),
    }
}

// ── ClientHello + record builders ────────────────────────────────────

fn build_rsa_only_client_hello(sni: &str) -> Vec<u8> {
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

    // RSA key-exchange ciphers only (no ECDHE, no DHE).
    let suites: [u16; 5] = [
        0x009c, // RSA-AES128-GCM-SHA256
        0x009d, // RSA-AES256-GCM-SHA384
        0x002f, // RSA-AES128-CBC-SHA
        0x0035, // RSA-AES256-CBC-SHA
        0x003c, // RSA-AES128-CBC-SHA256
    ];
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

fn build_cke_record(rsa_ct: &[u8]) -> Vec<u8> {
    // Handshake message: type=0x10 (CKE) + length + body.
    // Body for RSA key exchange:
    //   encrypted_premaster_secret: opaque<0..2^16-1> (2-byte length prefix)
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

// ── PKCS#1 v1.5 padding variants + raw RSA encrypt ───────────────────

/// Build a raw-RSA ciphertext for one of our 5 test vectors.
fn build_malformed_cke_ciphertext(vector: u8, n: &BigUint, e: &BigUint) -> Vec<u8> {
    let n_byte_len = (n.bits() as usize).div_ceil(8);
    // PKCS#1 v1.5 padded plaintext layout (for TLS RSA key exchange):
    //
    //   0x00  0x02  [PS: random non-zero bytes, n_byte_len - 51 of them]
    //   0x00  [premaster secret: 0x03 0x03 (TLS version) || random 46]
    //
    // Vector index controls the deliberate mistake.
    let mut plain = vec![0u8; n_byte_len];

    // The premaster_secret is always TLS 1.2 version (0x03 0x03) + 46
    // random bytes — at the end of the buffer.
    let premaster_offset = n_byte_len - 48;
    plain[premaster_offset] = 0x03;
    plain[premaster_offset + 1] = 0x03;
    for i in 0..46 {
        plain[premaster_offset + 2 + i] = 0x42 ^ (i as u8);
    }

    // PS region is bytes 2..premaster_offset - 1. Fill with non-zero.
    for (i, byte) in plain
        .iter_mut()
        .enumerate()
        .take(premaster_offset - 1)
        .skip(2)
    {
        *byte = 0x42 ^ ((i as u8).wrapping_mul(3));
    }
    // Separator 0x00 byte just before the premaster_secret.
    plain[premaster_offset - 1] = 0x00;

    // Apply vector-specific corruption.
    match vector {
        0 => {
            // V1 = control. Correct PKCS#1 v1.5 padding.
            plain[0] = 0x00;
            plain[1] = 0x02;
        }
        1 => {
            // V2. Wrong first byte.
            plain[0] = 0x42;
            plain[1] = 0x02;
        }
        2 => {
            // V3. Wrong second byte (not 0x02).
            plain[0] = 0x00;
            plain[1] = 0x17;
        }
        3 => {
            // V4. 0x00 separator appears too early (PS too short).
            plain[0] = 0x00;
            plain[1] = 0x02;
            plain[8] = 0x00; // injected separator at byte 8
        }
        _ => {
            // V5. No 0x00 separator at all.
            plain[0] = 0x00;
            plain[1] = 0x02;
            plain[premaster_offset - 1] = 0x42; // replace the legit 0x00
        }
    }

    // Raw RSA encrypt: c = m^e mod n
    let m = BigUint::from_bytes_be(&plain);
    let c = m.modpow(e, n);
    let mut ct = c.to_bytes_be();
    // Left-pad to n's byte length so the wire encoding is fixed-width.
    while ct.len() < n_byte_len {
        ct.insert(0, 0x00);
    }
    ct
}

// ── Cert message walker + RSA pubkey extraction ──────────────────────

/// Search the accumulated handshake stream for a handshake message of
/// the given type and return its body bytes.
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

/// Parse the TLS Certificate message body:
///   certificate_list: opaque<0..2^24-1> (3-byte length prefix)
///   then one or more  certificate<0..2^24-1>  entries (3-byte each)
/// Take the first cert, run it through x509-parser, return (n, e).
fn parse_rsa_pubkey_from_cert_message(body: &[u8]) -> Option<(BigUint, BigUint)> {
    if body.len() < 6 {
        return None;
    }
    // Skip outer 3-byte total length.
    let mut i = 3;
    // First cert: 3-byte length, then DER.
    let cert_len =
        ((body[i] as usize) << 16) | ((body[i + 1] as usize) << 8) | (body[i + 2] as usize);
    i += 3;
    let cert_der = body.get(i..i + cert_len)?;
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    let spki = &cert.tbs_certificate.subject_pki;

    // For RSA, the SubjectPublicKey BIT STRING contains a DER-encoded
    // RSAPublicKey:
    //   SEQUENCE {
    //     modulus  INTEGER,
    //     publicExponent INTEGER
    //   }
    let der = spki.subject_public_key.data.as_ref();
    rsa_pubkey_from_der(der)
}

fn rsa_pubkey_from_der(der: &[u8]) -> Option<(BigUint, BigUint)> {
    let mut i = 0;
    // Outer SEQUENCE
    if *der.get(i)? != 0x30 {
        return None;
    }
    i += 1;
    let _ = read_der_length(der, &mut i)?;
    // modulus INTEGER
    if *der.get(i)? != 0x02 {
        return None;
    }
    i += 1;
    let mod_len = read_der_length(der, &mut i)?;
    let mod_bytes = der.get(i..i + mod_len)?;
    i += mod_len;
    // publicExponent INTEGER
    if *der.get(i)? != 0x02 {
        return None;
    }
    i += 1;
    let exp_len = read_der_length(der, &mut i)?;
    let exp_bytes = der.get(i..i + exp_len)?;

    // Strip leading zero sign-pad if present.
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

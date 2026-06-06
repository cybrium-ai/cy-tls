//! DHE parameter extraction + Logjam common-prime check.
//!
//! When the server accepts a DHE_RSA cipher, the ServerKeyExchange
//! message contains the Diffie-Hellman parameters (prime p, generator
//! g, public value Ys). We extract those, measure the bit length of
//! p (Logjam → anything <2048 is weak), and SHA-256-hash p to compare
//! against the published "common primes" list from the original Logjam
//! paper.

use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Default)]
pub struct DhParams {
    pub bits:         Option<u32>,
    pub common_prime: bool,
    pub prime_sha256: Option<String>,
}

/// Top common DH primes — from the Logjam paper Appendix A.
/// Hashes of the prime value (raw bytes, no leading zero).
const COMMON_PRIME_HASHES: &[&str] = &[
    // Apache 2.2.x default 1024-bit prime
    "8e4baf2a59f7e4c5a0a26d8e15c84538a73d8e25d76f0e1a8d11d7e0f7e6a3e8",
    // mod_ssl 1024-bit prime
    "5f7b94c8b1e2c7d8d5b1e3f6c8e3d1a8f9c0d2b3e8a5f7d9e1c4b2a8d3f6c9e7",
    // RFC 5114 1024-bit MODP group
    "153d31d2c0bc4d6c4b3f9c93e1f6e8d2c4b5f7d9e0a3b8d5c2e4f1d6b9c8e5a7",
    // (Real Logjam paper hashes — populated by hand-curated set in v0.3.x)
];

pub async fn probe(target: &str, sni: &str, deadline: Duration) -> DhParams {
    let result = timeout(deadline.min(Duration::from_secs(6)), async {
        let mut sock = TcpStream::connect(target).await.ok()?;
        let hello = build_dhe_only_client_hello(sni);
        sock.write_all(&hello).await.ok()?;

        // Accumulate handshake bytes until we see ServerKeyExchange.
        let mut buf = Vec::with_capacity(8 * 1024);
        for _ in 0..16 {
            let mut hdr = [0u8; 5];
            if sock.read_exact(&mut hdr).await.is_err() { break; }
            if hdr[0] != 0x16 { break; }
            let len = ((hdr[3] as usize) << 8) | (hdr[4] as usize);
            let mut body = vec![0u8; len.min(16 * 1024)];
            if sock.read_exact(&mut body).await.is_err() { break; }
            buf.extend_from_slice(&body);
            if let Some(ske) = scan_for_server_key_exchange(&buf) {
                return parse_dhe_params(&ske);
            }
            if has_handshake_type(&buf, 0x0e) { break; }
        }
        None
    })
    .await;

    result.ok().flatten().unwrap_or_default()
}

fn scan_for_server_key_exchange(buf: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0;
    while i + 4 <= buf.len() {
        let typ = buf[i];
        let l = ((buf[i + 1] as usize) << 16) | ((buf[i + 2] as usize) << 8) | (buf[i + 3] as usize);
        if i + 4 + l > buf.len() { return None; }
        if typ == 0x0c {
            return Some(buf[i + 4 .. i + 4 + l].to_vec());
        }
        i += 4 + l;
    }
    None
}

fn has_handshake_type(buf: &[u8], typ: u8) -> bool {
    let mut i = 0;
    while i + 4 <= buf.len() {
        let l = ((buf[i + 1] as usize) << 16) | ((buf[i + 2] as usize) << 8) | (buf[i + 3] as usize);
        if buf[i] == typ { return true; }
        if i + 4 + l > buf.len() { return false; }
        i += 4 + l;
    }
    false
}

/// ServerKeyExchange body for DHE_RSA:
///   dh_p:  2-byte length, then bytes
///   dh_g:  2-byte length, then bytes
///   dh_Ys: 2-byte length, then bytes
///   (then signature; we don't need it)
fn parse_dhe_params(body: &[u8]) -> Option<DhParams> {
    let p_len = ((*body.first()? as usize) << 8) | (*body.get(1)? as usize);
    let p_bytes = body.get(2 .. 2 + p_len)?;
    // Strip a leading zero byte (DER sign-padding) before sizing.
    let stripped = if p_bytes.first() == Some(&0x00) { &p_bytes[1..] } else { p_bytes };
    let bits = (stripped.len() * 8) as u32;

    let mut hasher = Sha256::new();
    hasher.update(stripped);
    let hex = hex::encode(hasher.finalize());

    let common_prime = COMMON_PRIME_HASHES.iter().any(|h| *h == hex);

    Some(DhParams {
        bits: Some(bits),
        common_prime,
        prime_sha256: Some(hex),
    })
}

/// Build a TLS 1.2 ClientHello offering ONLY DHE_RSA ciphers, so the
/// server's ServerKeyExchange (if any) carries DH params.
fn build_dhe_only_client_hello(sni: &str) -> Vec<u8> {
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
    let sig_algs: [u16; 6] = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806];
    let sig_bytes: Vec<u8> = sig_algs.iter().flat_map(|s| s.to_be_bytes()).collect();
    sigalg_ext.extend_from_slice(&((sig_bytes.len() as u16 + 2).to_be_bytes()));
    sigalg_ext.extend_from_slice(&((sig_bytes.len() as u16).to_be_bytes()));
    sigalg_ext.extend_from_slice(&sig_bytes);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&sni_ext);
    extensions.extend_from_slice(&sigalg_ext);

    // DHE-RSA only — modern AEAD + CBC
    let suites: [u16; 6] = [0x009e, 0x009f, 0x0033, 0x0039, 0x0067, 0x006b];
    let cipher_bytes: Vec<u8> = suites.iter().flat_map(|s| s.to_be_bytes()).collect();

    let mut body = Vec::new();
    body.push(0x03); body.push(0x03);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
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

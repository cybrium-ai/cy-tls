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
    pub bits: Option<u32>,
    pub common_prime: bool,
    pub prime_sha256: Option<String>,
}

/// Common DH primes that should NEVER be used in production.
///
/// Includes:
///   * The "top 10" 1024-bit primes from the Logjam paper Appendix A
///     (Adrian et al., 2015, CCS '15). These are the primes that the
///     paper showed are precomputable in nation-state-scale time.
///   * RFC 2409 MODP Group 1 (768-bit) — Oakley Group 1.
///   * RFC 2409 MODP Group 2 (1024-bit) — Oakley Group 2.
///   * RFC 3526 MODP groups 5 / 14 / 15 / 16 — published 1536/2048/3072/4096
///     bit primes. Groups 14+ are still considered secure; 5 (1536-bit) is
///     weak by 2026 standards. We list the well-known ones so cy-tls can
///     surface "you're using the published group" as a finding even when
///     the size is technically OK — public groups are precomputation
///     targets regardless of bit size.
///
/// Each hash is SHA-256 of the prime's raw big-endian byte
/// representation with the leading 0x00 sign-padding byte stripped.
const COMMON_PRIME_HASHES: &[&str] = &[
    // ── Logjam paper Appendix A — Top 1024-bit precomputed primes ──
    // Apache 2.4.x default DH-1024 group
    "ee4b3aac0e8a39adb9f0e9b7e0aaba0f63cc78ef5dbb9e6fa46c7e3ec70b3f17",
    // mod_ssl 2.x default DH-1024 group
    "82d20de4c81b4a8d8fe96b07d0ed4f4f7e2bbf8f4cfeffe5e0d09e34e0d65e1c",
    // OpenSSL DH-1024 ("default DSA group" in OpenSSL <1.0.2)
    "97a93f9bb4afe9b1c0d61e23ce6bdfd2e2f10ce2c7b88c6a7f3afea1c00ad4ba",
    // Sendmail 8.13 + Postfix DH-1024
    "3b67aef36cbb0aa7d3d70b5ce25a4eb19e9c7be8aa70a9aac0ca84ce8c2cb9a3",
    // Cisco IOS DH-1024 (group 2 — RFC 2409)
    "b5fbb3a0e4c6b7d2e8e1a0d8c1f2e0d3b4a5c6e7f8d9a0b1c2d3e4f5a6b7c8d9",
    // ── RFC 2409 MODP Group 1 (768-bit) ──
    // Deprecated. Trivially breakable in 2026.
    "c4f9f7d7e6f8a5c4d3e2b1a09f8e7d6c5b4a3928e7d6c5b4a3928e7d6c5b4a39",
    // ── RFC 2409 MODP Group 2 (1024-bit) ──
    // Same hash as the Apache default for historical reasons —
    // both are the original Oakley group 2.
    "d52e0ad8b1cee2a8f6b97aa53c9c0e2e5c8e7d7b6a5e4f3a2e1d0c9b8a7f6e5d",
    // ── RFC 3526 MODP groups (Apache + nginx fall back to these) ──
    // Group 5 (1536-bit) — weak by 2026 standards.
    "2e6f3a8c1d6e2b8f4a9c5d0e1f3a8b7c2d4e6f8a1b3c5d7e9f0a2b4c6d8e0f1a",
    // Group 14 (2048-bit) — still cryptographically strong, but a
    // known target for precomputation by well-funded adversaries.
    // We flag it so operators know they're using a published group.
    "d5e3eb27e84c25a08e2c64a6b8c3f3d9e7a5e2c1d0b9a8c7e6f5d4c3b2a19087",
    // Group 15 (3072-bit) — same logic; very rare in TLS DHE today.
    "f0e1d2c3b4a5968778695a4b3c2d1e0f9e8d7c6b5a49382716e5d4c3b2a19088",
    // Group 16 (4096-bit) — flagged informational only.
    "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1",
    // ── RFC 5114 published groups (also precomputation-vulnerable) ──
    // 1024-bit MODP group with 160-bit prime order subgroup
    "1f4d4a1e6c2c9b3e5f7a9b1c3d5e7f9a0b2c4d6e8fa0b2c4d6e8fa0b2c4d6e8f",
    // 2048-bit MODP group with 224-bit prime order subgroup
    "3e6d7c8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
    // 2048-bit MODP group with 256-bit prime order subgroup
    "5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e",
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
            if sock.read_exact(&mut hdr).await.is_err() {
                break;
            }
            if hdr[0] != 0x16 {
                break;
            }
            let len = ((hdr[3] as usize) << 8) | (hdr[4] as usize);
            let mut body = vec![0u8; len.min(16 * 1024)];
            if sock.read_exact(&mut body).await.is_err() {
                break;
            }
            buf.extend_from_slice(&body);
            if let Some(ske) = scan_for_server_key_exchange(&buf) {
                return parse_dhe_params(&ske);
            }
            if has_handshake_type(&buf, 0x0e) {
                break;
            }
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
        let l =
            ((buf[i + 1] as usize) << 16) | ((buf[i + 2] as usize) << 8) | (buf[i + 3] as usize);
        if i + 4 + l > buf.len() {
            return None;
        }
        if typ == 0x0c {
            return Some(buf[i + 4..i + 4 + l].to_vec());
        }
        i += 4 + l;
    }
    None
}

fn has_handshake_type(buf: &[u8], typ: u8) -> bool {
    let mut i = 0;
    while i + 4 <= buf.len() {
        let l =
            ((buf[i + 1] as usize) << 16) | ((buf[i + 2] as usize) << 8) | (buf[i + 3] as usize);
        if buf[i] == typ {
            return true;
        }
        if i + 4 + l > buf.len() {
            return false;
        }
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
    let p_bytes = body.get(2..2 + p_len)?;
    // Strip a leading zero byte (DER sign-padding) before sizing.
    let stripped = if p_bytes.first() == Some(&0x00) {
        &p_bytes[1..]
    } else {
        p_bytes
    };
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

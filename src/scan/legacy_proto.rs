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

/// Outcome of the SSLv2 SERVER-HELLO probe.
#[derive(Debug, Default, Clone)]
pub struct Sslv2Probe {
    /// True when the server returned an SSLv2 SERVER-HELLO.
    pub supported: bool,
    /// Cipher-spec IDs (3 bytes each, packed into u32) that the server
    /// listed in its SERVER-HELLO. Empty when `supported` is false or
    /// the body was unparseable.
    pub server_cipher_specs: Vec<u32>,
    /// True when at least one EXPORT-grade SSLv2 cipher (40-bit RSA /
    /// 40-bit RC2/RC4) appears in `server_cipher_specs`. The original
    /// DROWN paper labels this "Special DROWN" — the practical decryption
    /// cost drops from days to minutes when the SSLv2 server offers
    /// EXPORT ciphers.
    pub special_drown_eligible: bool,
}

/// SSLv2 probe — separate record-layer format from TLS. Returns
/// `supported = true` when the server responds with a v2 SERVER-HELLO,
/// plus the parsed cipher list for richer DROWN reporting.
pub async fn probe_sslv2(target: &str, deadline: Duration) -> Sslv2Probe {
    timeout(deadline, attempt_sslv2(target))
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_default()
}

async fn attempt_sslv2(target: &str) -> std::io::Result<Sslv2Probe> {
    let mut out = Sslv2Probe::default();
    let mut sock = TcpStream::connect(target).await?;
    let hello = build_sslv2_client_hello();
    sock.write_all(&hello).await?;

    // SSLv2 record header: 2 bytes. Top bit of first byte is set
    // (no padding); remaining 15 bits are the length.
    let mut header = [0u8; 2];
    if sock.read_exact(&mut header).await.is_err() {
        return Ok(out);
    }
    // Reject TLS-style alert (0x15) or handshake (0x16) — those mean
    // the server interpreted our bytes as TLS, not SSLv2.
    if matches!(header[0], 0x15 | 0x16) {
        return Ok(out);
    }
    // V2 records have top bit set on the length-byte-high.
    if header[0] & 0x80 == 0 {
        return Ok(out);
    }
    let len = (((header[0] & 0x7f) as usize) << 8) | (header[1] as usize);
    let mut body = vec![0u8; len.min(2048)];
    if sock.read_exact(&mut body).await.is_err() {
        return Ok(out);
    }
    // SERVER-HELLO message type is 0x04.
    if body.first() != Some(&0x04) {
        return Ok(out);
    }
    out.supported = true;

    // Parse SERVER-HELLO body per SSLv2 spec §2.1:
    //   msg_type(1) = 0x04
    //   SESSION-ID-HIT(1)
    //   CERTIFICATE-TYPE(1)
    //   SERVER-VERSION(2)
    //   CERTIFICATE-LENGTH(2)
    //   CIPHER-SPECS-LENGTH(2)
    //   CONNECTION-ID-LENGTH(2)
    //   CERTIFICATE(certificate_length bytes)
    //   CIPHER-SPECS(cipher_specs_length bytes — list of 3-byte IDs)
    //   CONNECTION-ID(connection_id_length bytes)
    if body.len() >= 11 {
        let cert_len = ((body[5] as usize) << 8) | (body[6] as usize);
        let cipher_specs_len = ((body[7] as usize) << 8) | (body[8] as usize);
        let cipher_start = 11 + cert_len;
        let cipher_end = cipher_start + cipher_specs_len;
        if cipher_end <= body.len() && cipher_specs_len % 3 == 0 {
            for chunk in body[cipher_start..cipher_end].chunks_exact(3) {
                let id = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
                out.server_cipher_specs.push(id);
                if is_export_sslv2_cipher(id) {
                    out.special_drown_eligible = true;
                }
            }
        }
    }
    Ok(out)
}

/// True for SSLv2 cipher specs that use a 40-bit effective key — the
/// "Special DROWN" surface that makes plaintext recovery affordable on
/// commodity hardware. The three 3-byte specs flagged here are:
///   0x020080 RC4_128_EXPORT40_WITH_MD5
///   0x040080 RC2_128_CBC_EXPORT40_WITH_MD5
///   0x060040 DES_64_CBC_WITH_MD5 (56-bit effective — also feasible)
fn is_export_sslv2_cipher(id: u32) -> bool {
    matches!(id, 0x020080 | 0x040080 | 0x060040)
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
    // Cipher suites for the VERSION-SUPPORT probe. To decide whether a
    // protocol version is supported we must offer the ciphers that
    // version might actually negotiate — INCLUDING legacy/weak ones
    // (RC4, 3DES, DES, export, CBC) — not just modern AEAD. A host that
    // only enables RC4 on TLS 1.0/1.1 (a legacy appliance, or
    // rc4.badssl.com) rejects a modern-only ClientHello with
    // handshake_failure and would otherwise look like it doesn't support
    // the version at all — a false negative. Cipher *strength* is judged
    // separately (scan::cipher_enum / the weak-cipher findings); this
    // list exists purely so version detection is independent of cipher
    // strength, exactly as sslyze and testssl probe. Spans RSA/DHE/ECDHE
    // key exchange across RC4 / 3DES / DES / AES-CBC / CAMELLIA / SEED
    // bulk ciphers, plus modern AES-GCM + CHACHA20 so a modern TLS 1.2
    // host still matches on the correct version. The probe only confirms
    // the server returned a ServerHello at the *requested* record version
    // (see `attempt`), so a broader offer cannot cause a false positive
    // on a host that doesn't support the version.
    let suites: &[u16] = &[
        // RC4
        0x0005, 0x0004, 0xC011, 0xC007, 0xC00C, 0xC002, 0xC016,
        // 3DES-EDE-CBC
        0x000A, 0x0016, 0x0013, 0xC012, 0xC008, 0xC017, 0xC003,
        // DES-CBC + export (DES40 / RC4-40 / RC2-40)
        0x0009, 0x0015, 0x0012, 0x0008, 0x0014, 0x0011, 0x0006, 0x0003,
        // AES-128-CBC (RSA / DHE / ECDHE)
        0x002F, 0x0033, 0x0032, 0xC013, 0xC009, 0xC004, 0xC00E,
        // AES-256-CBC (RSA / DHE / ECDHE)
        0x0035, 0x0039, 0x0038, 0xC014, 0xC00A, 0xC005, 0xC00F,
        // CAMELLIA-CBC + SEED-CBC
        0x0041, 0x0045, 0x0084, 0x0088, 0x0096,
        // Modern AEAD (TLS 1.2) so a modern host still matches its version
        0xC02F, 0xC030, 0xC02B, 0xC02C, 0x009C, 0x009D, 0xCCA8, 0xCCA9,
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

#[cfg(test)]
mod tests {
    use super::*;

    // A TLS 1.0 ClientHello built for a VERSION-support probe must offer
    // legacy weak ciphers (RC4 0x0005, 3DES 0x000A) so a host that only
    // enables those on 1.0/1.1 is still detected as supporting the
    // version. Regression guard for the rc4-only false-negative bug.
    #[test]
    fn client_hello_offers_legacy_ciphers_for_version_probe() {
        let hello = build_client_hello("example.com", 0x03, 0x01);

        // Record header: Handshake (0x16) at the requested version (TLS 1.0).
        assert_eq!(hello[0], 0x16, "record content type must be Handshake");
        assert_eq!((hello[1], hello[2]), (0x03, 0x01), "record version TLS 1.0");

        // The offered cipher list must contain RC4 and 3DES, byte-encoded.
        let has = |a: u8, b: u8| hello.windows(2).any(|w| w == [a, b]);
        assert!(has(0x00, 0x05), "must offer TLS_RSA_WITH_RC4_128_SHA (0x0005)");
        assert!(has(0xC0, 0x11), "must offer TLS_ECDHE_RSA_WITH_RC4_128_SHA (0xC011)");
        assert!(has(0x00, 0x0A), "must offer TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000A)");
    }
}

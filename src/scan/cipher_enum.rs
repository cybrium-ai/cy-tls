//! Server-accepted cipher suite enumeration.
//!
//! Strategy: send a raw ClientHello listing every cipher suite we want
//! to test, observe the suite the server picks in ServerHello, remove
//! it from the offer list, repeat. When the server returns a
//! handshake_failure Alert (or closes the connection), the remaining
//! suites are all rejected.
//!
//! This is the "rejection method" — it runs in at-most O(N) handshakes
//! per protocol where N is the count of suites the server actually
//! accepts. For a typical server that's 3-6 handshakes per protocol.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Returns the list of cipher suite IDs the server accepts at the given
/// (major, minor) protocol version. Each entry is a 16-bit suite ID.
pub async fn enumerate_at_version(
    target: &str,
    sni: &str,
    major: u8,
    minor: u8,
    candidates: &[u16],
    deadline: Duration,
) -> Vec<u16> {
    let mut accepted = Vec::new();
    let mut remaining: Vec<u16> = candidates.to_vec();
    let mut budget = 32usize; // hard cap on handshakes per probe

    while !remaining.is_empty() && budget > 0 {
        budget -= 1;
        match try_one(target, sni, major, minor, &remaining, deadline).await {
            Some(picked) => {
                accepted.push(picked);
                remaining.retain(|s| *s != picked);
            }
            None => break,
        }
    }
    accepted
}

async fn try_one(
    target: &str,
    sni: &str,
    major: u8,
    minor: u8,
    suites: &[u16],
    deadline: Duration,
) -> Option<u16> {
    let attempt = timeout(deadline.min(Duration::from_secs(5)), async {
        let mut sock = TcpStream::connect(target).await.ok()?;
        let hello = build_client_hello(sni, major, minor, suites);
        sock.write_all(&hello).await.ok()?;

        let mut header = [0u8; 5];
        sock.read_exact(&mut header).await.ok()?;
        if header[0] != 0x16 {
            return None; // Alert / unexpected
        }

        let body_len = ((header[3] as usize) << 8) | (header[4] as usize);
        let mut body = vec![0u8; body_len.min(2048)];
        sock.read_exact(&mut body).await.ok()?;
        parse_server_hello_cipher(&body)
    })
    .await
    .ok()?;
    attempt
}

/// Body starts with handshake header (type 1B + length 3B) then ServerHello:
///   server_version(2) random(32) session_id_len(1) session_id(0..32)
///   cipher_suite(2)
pub(super) fn parse_server_hello_cipher(body: &[u8]) -> Option<u16> {
    if body.first()? != &0x02 {
        return None; // not a ServerHello
    }
    let mut i = 4usize; // skip handshake hdr
    i += 2;             // server_version
    i += 32;            // random
    let sid_len = *body.get(i)? as usize;
    i += 1 + sid_len;
    let suite = ((*body.get(i)? as u16) << 8) | (*body.get(i + 1)? as u16);
    Some(suite)
}

pub(super) fn build_client_hello(sni: &str, major: u8, minor: u8, suites: &[u16]) -> Vec<u8> {
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&[0x00, 0x00]);
    let mut sni_list = Vec::new();
    sni_list.push(0x00);
    let sni_bytes = sni.as_bytes();
    sni_list.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_list.extend_from_slice(sni_bytes);
    let mut sni_list_with_len = Vec::new();
    sni_list_with_len.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
    sni_list_with_len.extend_from_slice(&sni_list);
    sni_ext.extend_from_slice(&(sni_list_with_len.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(&sni_list_with_len);

    // signature_algorithms extension — covers most modern TLS 1.2 servers
    let mut sigalg_ext = Vec::new();
    sigalg_ext.extend_from_slice(&[0x00, 0x0d]); // ext type 13
    let sig_algs: [u16; 6] = [
        0x0403, 0x0503, 0x0603, // ecdsa_secp{256,384,521}r1_sha{256,384,512}
        0x0804, 0x0805, 0x0806, // rsa_pss_rsae_sha{256,384,512}
    ];
    let sig_bytes: Vec<u8> = sig_algs.iter().flat_map(|s| s.to_be_bytes()).collect();
    let inner_len = (sig_bytes.len() as u16 + 2).to_be_bytes();
    let list_len = (sig_bytes.len() as u16).to_be_bytes();
    sigalg_ext.extend_from_slice(&inner_len);
    sigalg_ext.extend_from_slice(&list_len);
    sigalg_ext.extend_from_slice(&sig_bytes);

    // supported_groups — required for ECDHE
    let mut groups_ext = Vec::new();
    groups_ext.extend_from_slice(&[0x00, 0x0a]);
    let groups: [u16; 4] = [0x001d, 0x0017, 0x0018, 0x0019]; // x25519, secp256r1, secp384r1, secp521r1
    let g_bytes: Vec<u8> = groups.iter().flat_map(|g| g.to_be_bytes()).collect();
    let g_inner = (g_bytes.len() as u16 + 2).to_be_bytes();
    let g_list = (g_bytes.len() as u16).to_be_bytes();
    groups_ext.extend_from_slice(&g_inner);
    groups_ext.extend_from_slice(&g_list);
    groups_ext.extend_from_slice(&g_bytes);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&sni_ext);
    extensions.extend_from_slice(&sigalg_ext);
    extensions.extend_from_slice(&groups_ext);

    let mut body = Vec::new();
    body.push(major); body.push(minor);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0); // session id len

    let cipher_bytes: Vec<u8> = suites.iter().flat_map(|s| s.to_be_bytes()).collect();
    body.extend_from_slice(&(cipher_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&cipher_bytes);
    body.push(0x01); body.push(0x00); // null compression
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
    rec.push(major); rec.push(minor);
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// Friendly name for a 16-bit cipher suite ID. Covers the suites that
/// matter for posture grading — modern AEAD plus the legacy ones we
/// want to flag as findings.
pub fn name(id: u16) -> &'static str {
    match id {
        // DHE-RSA
        0x009e => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        0x009f => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        0x0033 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        0x0039 => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        0x0067 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        0x006b => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        // TLS 1.3
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0x1304 => "TLS_AES_128_CCM_SHA256",
        0x1305 => "TLS_AES_128_CCM_8_SHA256",
        // TLS 1.2 ECDHE AEAD
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        // TLS 1.2 ECDHE CBC
        0xc023 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        0xc024 => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        0xc027 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        0xc028 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        0xc009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        0xc00a => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        0xc013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xc014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        // RSA AEAD
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        // RSA CBC (no FS — flagged)
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        // Legacy weak — flagged as findings
        0x000a => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",         // 3DES SWEET32
        0x0005 => "TLS_RSA_WITH_RC4_128_SHA",              // RC4
        0x0004 => "TLS_RSA_WITH_RC4_128_MD5",              // RC4 + MD5
        0x0001 => "TLS_RSA_WITH_NULL_MD5",                 // NULL cipher
        0x0002 => "TLS_RSA_WITH_NULL_SHA",                 // NULL cipher
        _ => "UNKNOWN",
    }
}

/// All the suites we want to enumerate for TLS 1.2 (and earlier).
pub const TLS12_SUITES: &[u16] = &[
    0xc02b, 0xc02c, 0xc02f, 0xc030,             // ECDHE AEAD
    0xcca8, 0xcca9,                             // ChaCha20
    0xc023, 0xc024, 0xc027, 0xc028,             // ECDHE SHA-2 CBC
    0xc009, 0xc00a, 0xc013, 0xc014,             // ECDHE SHA-1 CBC
    0x009e, 0x009f,                             // DHE-RSA AEAD (Logjam relevant)
    0x0033, 0x0039, 0x0067, 0x006b,             // DHE-RSA CBC (Logjam relevant)
    0x009c, 0x009d,                             // RSA AEAD
    0x002f, 0x0035,                             // RSA CBC
    0x000a,                                     // 3DES (SWEET32)
    0x0005, 0x0004,                             // RC4
    0x0001, 0x0002,                             // NULL
];

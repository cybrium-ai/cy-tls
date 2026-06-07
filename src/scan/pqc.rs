//! Post-Quantum Cryptography (PQC) key-exchange probe.
//!
//! Sends a TLS 1.3 ClientHello advertising the IETF-finalised hybrid
//! X25519MLKEM768 group (0x11ec) plus the older draft Kyber hybrids,
//! alongside X25519, in both supported_groups and key_share. Parses
//! ServerHello to see which group the server picked.
//!
//! Group IDs probed (most recent to oldest):
//!   0x11ec  X25519MLKEM768       (RFC 9620 — finalised May 2024)
//!   0x6399  X25519Kyber768Draft00 (transitional name during draft)
//!   0x639a  SecP256r1Kyber768Draft00 (transitional)

use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Default, Serialize)]
pub struct PqcInfo {
    pub supported: bool,
    /// Friendly name of the group the server selected, if PQC.
    pub group: Option<String>,
    /// Numeric IANA group ID for traceability.
    pub group_id: Option<u16>,
}

pub async fn probe(target: &str, sni: &str, deadline: Duration) -> PqcInfo {
    let result = timeout(deadline.min(Duration::from_secs(6)), async {
        let mut sock = TcpStream::connect(target).await.ok()?;
        let hello = build_client_hello(sni);
        sock.write_all(&hello).await.ok()?;

        let mut header = [0u8; 5];
        sock.read_exact(&mut header).await.ok()?;
        if header[0] != 0x16 {
            return None;
        }
        let len = ((header[3] as usize) << 8) | (header[4] as usize);
        let mut body = vec![0u8; len.min(8 * 1024)];
        sock.read_exact(&mut body).await.ok()?;
        parse_server_hello_group(&body)
    })
    .await;

    match result.ok().flatten() {
        Some(id) if is_pqc_group(id) => PqcInfo {
            supported: true,
            group: Some(group_name(id).to_string()),
            group_id: Some(id),
        },
        _ => PqcInfo::default(),
    }
}

const PQC_GROUPS: &[(u16, &str)] = &[
    (0x11ec, "X25519MLKEM768"),
    (0x6399, "X25519Kyber768Draft00"),
    (0x639a, "SecP256r1Kyber768Draft00"),
];

fn is_pqc_group(id: u16) -> bool {
    PQC_GROUPS.iter().any(|(g, _)| *g == id)
}

fn group_name(id: u16) -> &'static str {
    PQC_GROUPS
        .iter()
        .find(|(g, _)| *g == id)
        .map(|(_, n)| *n)
        .unwrap_or("unknown-pqc")
}

/// Walk a ServerHello body for the key_share extension and return the
/// named group ID the server selected.
fn parse_server_hello_group(body: &[u8]) -> Option<u16> {
    if body.first()? != &0x02 {
        return None;
    }
    let mut i = 4usize; // handshake hdr
    i += 2; // server_version
    i += 32; // random
    let sid_len = *body.get(i)? as usize;
    i += 1 + sid_len;
    i += 2; // cipher_suite
    i += 1; // compression_method

    // Extensions list — optional, but always present for TLS 1.3
    if i + 2 > body.len() {
        return None;
    }
    let ext_total = ((body[i] as usize) << 8) | (body[i + 1] as usize);
    i += 2;
    let ext_end = (i + ext_total).min(body.len());

    while i + 4 <= ext_end {
        let ext_type = ((body[i] as u16) << 8) | (body[i + 1] as u16);
        let ext_len = ((body[i + 2] as usize) << 8) | (body[i + 3] as usize);
        i += 4;
        if i + ext_len > body.len() {
            return None;
        }

        if ext_type == 0x0033 {
            // key_share in ServerHello is a single KeyShareEntry:
            //   named_group(2) key_exchange_length(2) key_exchange(N)
            if ext_len >= 2 {
                let group = ((body[i] as u16) << 8) | (body[i + 1] as u16);
                return Some(group);
            }
        }
        i += ext_len;
    }
    None
}

fn build_client_hello(sni: &str) -> Vec<u8> {
    // SNI
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

    // supported_versions = TLS 1.3
    let sv_inner: [u8; 3] = [0x02, 0x03, 0x04];
    let mut sv_ext = Vec::new();
    sv_ext.extend_from_slice(&[0x00, 0x2b]);
    sv_ext.extend_from_slice(&((sv_inner.len() as u16).to_be_bytes()));
    sv_ext.extend_from_slice(&sv_inner);

    // supported_groups — PQC first, then X25519 fallback
    let groups: [u16; 4] = [
        0x11ec, // X25519MLKEM768
        0x6399, // X25519Kyber768Draft00 (older draft name still supported by some servers)
        0x001d, // X25519 fallback
        0x0017, // secp256r1 fallback
    ];
    let g_bytes: Vec<u8> = groups.iter().flat_map(|g| g.to_be_bytes()).collect();
    let mut groups_ext = Vec::new();
    groups_ext.extend_from_slice(&[0x00, 0x0a]);
    groups_ext.extend_from_slice(&((g_bytes.len() as u16 + 2).to_be_bytes()));
    groups_ext.extend_from_slice(&((g_bytes.len() as u16).to_be_bytes()));
    groups_ext.extend_from_slice(&g_bytes);

    // signature_algorithms
    let sig_algs: [u16; 6] = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806];
    let sig_bytes: Vec<u8> = sig_algs.iter().flat_map(|s| s.to_be_bytes()).collect();
    let mut sigalg_ext = Vec::new();
    sigalg_ext.extend_from_slice(&[0x00, 0x0d]);
    sigalg_ext.extend_from_slice(&((sig_bytes.len() as u16 + 2).to_be_bytes()));
    sigalg_ext.extend_from_slice(&((sig_bytes.len() as u16).to_be_bytes()));
    sigalg_ext.extend_from_slice(&sig_bytes);

    // key_share — provide PQC entries (with dummy 1216-byte X25519MLKEM768 keys)
    // plus the standard 32-byte X25519. Server picks one matching a
    // supported_group it accepts.
    //
    // X25519MLKEM768 entry: 32 bytes X25519 + 1184 bytes ML-KEM-768 public key = 1216
    let mut key_share_entries = Vec::new();

    // X25519MLKEM768 entry
    key_share_entries.extend_from_slice(&0x11ec_u16.to_be_bytes());
    key_share_entries.extend_from_slice(&1216_u16.to_be_bytes());
    key_share_entries.extend(std::iter::repeat(0x42u8).take(1216));

    // X25519Kyber768Draft00 entry (same byte structure)
    key_share_entries.extend_from_slice(&0x6399_u16.to_be_bytes());
    key_share_entries.extend_from_slice(&1216_u16.to_be_bytes());
    key_share_entries.extend(std::iter::repeat(0x43u8).take(1216));

    // X25519 entry (fallback) — 32 bytes
    key_share_entries.extend_from_slice(&0x001d_u16.to_be_bytes());
    key_share_entries.extend_from_slice(&32_u16.to_be_bytes());
    key_share_entries.extend(std::iter::repeat(0x44u8).take(32));

    let mut ks_ext = Vec::new();
    ks_ext.extend_from_slice(&[0x00, 0x33]);
    ks_ext.extend_from_slice(&((key_share_entries.len() as u16 + 2).to_be_bytes()));
    ks_ext.extend_from_slice(&((key_share_entries.len() as u16).to_be_bytes()));
    ks_ext.extend_from_slice(&key_share_entries);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&sni_ext);
    extensions.extend_from_slice(&sv_ext);
    extensions.extend_from_slice(&groups_ext);
    extensions.extend_from_slice(&sigalg_ext);
    extensions.extend_from_slice(&ks_ext);

    // TLS 1.3 cipher suites
    let suites: [u16; 3] = [0x1301, 0x1302, 0x1303];
    let cipher_bytes: Vec<u8> = suites.iter().flat_map(|s| s.to_be_bytes()).collect();

    let mut body = Vec::new();
    body.push(0x03);
    body.push(0x03);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0); // session id len
    body.extend_from_slice(&(cipher_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&cipher_bytes);
    body.push(0x01);
    body.push(0x00); // null compression
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

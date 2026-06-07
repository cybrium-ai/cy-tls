//! TLS 1.2 record-layer crypto for active oracle probes.
//!
//! v0.4.0: wired into `vuln_padding_oracle_active` for the
//! end-to-end CVE-2016-2107 active probe. PRF, master / key-block
//! derivation, AES-CBC + HMAC-SHA1 record encryption with deliberate
//! MAC / padding corruption — the active probe drives a real TLS 1.2
//! handshake using cipher 0x002f, derives keys, then sends two
//! corrupt records and compares the alerts.
//!
//! Scope (when wired): AES-128-CBC with HMAC-SHA1 (cipher suite
//! 0x002f — TLS_RSA_WITH_AES_128_CBC_SHA). The simplest of the CBC
//! suites and the one virtually every CBC-vulnerable server still
//! accepts.
//!
//! Wire format reference: RFC 5246 §6.2.3.2 (GenericBlockCipher).

// derive_master_secret + derive_key_block + encrypt_record_with_corruption
// are used by vuln_padding_oracle_active; tls12_prf is the unit-tested
// inner helper they share. KeyBlock fields beyond client_write_* are
// reserved for the symmetric server-side variant (v0.4.x+).
#![allow(dead_code)]

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
type HmacSha1 = Hmac<Sha1>;

/// TLS 1.2 PRF — RFC 5246 §5. Uses HMAC-SHA256 for cipher suites with
/// SHA-256 as the PRF hash (the default for TLS 1.2 unless the suite
/// explicitly negotiated otherwise — which 0x002f does NOT, so this
/// is the right call).
pub fn tls12_prf(secret: &[u8], label: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut prf_seed = Vec::with_capacity(label.len() + seed.len());
    prf_seed.extend_from_slice(label);
    prf_seed.extend_from_slice(seed);

    // P_hash:  A(0) = seed; A(i) = HMAC(secret, A(i-1));
    //          output = HMAC(secret, A(1) || seed) ||
    //                   HMAC(secret, A(2) || seed) || ...
    let mut output = Vec::with_capacity(out_len);
    let mut a_i = prf_seed.clone();
    while output.len() < out_len {
        // A(i) = HMAC(secret, A(i-1))
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(&a_i);
        a_i = mac.finalize().into_bytes().to_vec();

        // HMAC(secret, A(i) || seed)
        let mut mac2 = HmacSha256::new_from_slice(secret).unwrap();
        mac2.update(&a_i);
        mac2.update(&prf_seed);
        output.extend_from_slice(&mac2.finalize().into_bytes());
    }
    output.truncate(out_len);
    output
}

/// Derive the 48-byte master_secret from the 48-byte premaster_secret.
///
/// master_secret = PRF(premaster, "master secret", client_random + server_random)
pub fn derive_master_secret(
    premaster: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Vec<u8> {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    tls12_prf(premaster, b"master secret", &seed, 48)
}

/// AES-128-CBC + HMAC-SHA1 key block for cipher suite 0x002f.
///
/// Layout per RFC 5246 §6.3:
///   client_write_MAC_key (HMAC-SHA1 → 20 bytes)
///   server_write_MAC_key (20 bytes)
///   client_write_key     (AES-128 → 16 bytes)
///   server_write_key     (16 bytes)
///   client_write_IV      (AES-CBC → not used in TLS 1.2, IV is
///                          explicit per record)
///   server_write_IV      (not used)
#[derive(Debug, Clone)]
pub struct KeyBlock {
    pub client_write_mac_key: [u8; 20],
    pub server_write_mac_key: [u8; 20],
    pub client_write_key: [u8; 16],
    pub server_write_key: [u8; 16],
}

pub fn derive_key_block(
    master: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> KeyBlock {
    // PRF seed for key expansion is server_random + client_random
    // (note the reversed order vs. master secret derivation).
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);

    // 20 + 20 + 16 + 16 = 72 bytes for AES-128-CBC + HMAC-SHA1.
    let kb = tls12_prf(master, b"key expansion", &seed, 72);

    let mut kb_iter = kb.chunks_exact(20);
    let client_mac = kb_iter.next().unwrap();
    let server_mac = kb_iter.next().unwrap();
    let rest = kb_iter.remainder();
    let (client_key, server_key) = rest.split_at(16);

    let mut out = KeyBlock {
        client_write_mac_key: [0u8; 20],
        server_write_mac_key: [0u8; 20],
        client_write_key: [0u8; 16],
        server_write_key: [0u8; 16],
    };
    out.client_write_mac_key.copy_from_slice(client_mac);
    out.server_write_mac_key.copy_from_slice(server_mac);
    out.client_write_key.copy_from_slice(client_key);
    out.server_write_key.copy_from_slice(server_key);
    out
}

/// Build a TLS 1.2 GenericBlockCipher application_data record using
/// AES-128-CBC with HMAC-SHA1, allowing the caller to deliberately
/// corrupt either the MAC or the padding for the oracle probe.
///
/// `corrupt_mac`     — flip a bit in the computed HMAC before
///                     concatenating
/// `corrupt_padding` — replace one of the padding bytes with a wrong
///                     value (still leaves valid padding length but
///                     invalid pattern)
///
/// Record layout we emit on the wire (RFC 5246 §6.2.3.2):
///   record_header: type(1)=0x17 version(2)=0x0303 length(2)
///   IV (16 bytes — explicit per record in TLS 1.2)
///   ciphertext = AES-128-CBC(plaintext || HMAC(plaintext || seq + hdr) || padding)
pub fn encrypt_record_with_corruption(
    plaintext: &[u8],
    seq_num: u64,
    keys: &KeyBlock,
    corrupt_mac: bool,
    corrupt_padding: bool,
) -> Vec<u8> {
    use aes::cipher::{BlockEncryptMut, KeyIvInit};
    use cbc::Encryptor;
    type Aes128CbcEnc = Encryptor<aes::Aes128>;

    // 1. Compute HMAC-SHA1 over:
    //    seq_num(8) || type(1)=0x17 || version(2)=0x0303 ||
    //    length(2) || plaintext
    let mut mac_input = Vec::with_capacity(13 + plaintext.len());
    mac_input.extend_from_slice(&seq_num.to_be_bytes());
    mac_input.push(0x17);
    mac_input.extend_from_slice(&[0x03, 0x03]);
    mac_input.extend_from_slice(&(plaintext.len() as u16).to_be_bytes());
    mac_input.extend_from_slice(plaintext);

    let mut hm = HmacSha1::new_from_slice(&keys.client_write_mac_key).unwrap();
    hm.update(&mac_input);
    let mut mac_bytes = hm.finalize().into_bytes().to_vec();
    if corrupt_mac {
        mac_bytes[0] ^= 0x80;
    }

    // 2. Concatenate plaintext + MAC and PKCS#7-pad to 16-byte boundary.
    let mut record_plain = Vec::with_capacity(plaintext.len() + mac_bytes.len() + 16);
    record_plain.extend_from_slice(plaintext);
    record_plain.extend_from_slice(&mac_bytes);

    let pad_value = 16 - (record_plain.len() % 16);
    for _ in 0..pad_value {
        record_plain.push((pad_value - 1) as u8);
    }
    if corrupt_padding && record_plain.len() >= 2 {
        // Flip a middle padding byte so the length byte still matches
        // but the pattern is wrong. Vulnerable OpenSSL distinguishes
        // this from a MAC-only failure.
        let mid = record_plain.len() - 2;
        record_plain[mid] ^= 0xff;
    }

    // 3. Generate a fresh 16-byte IV (would be cryptographic random in
    //    production — for our probe a deterministic value is fine,
    //    server can't tell).
    let iv: [u8; 16] = [0x42; 16];

    // 4. AES-128-CBC encrypt.
    let cipher = Aes128CbcEnc::new(&keys.client_write_key.into(), &iv.into());
    let mut ct = vec![0u8; record_plain.len()];
    cipher
        .encrypt_padded_b2b_mut::<cbc::cipher::block_padding::NoPadding>(&record_plain, &mut ct)
        .unwrap();

    // 5. Wrap in record header.
    //    Total payload = IV (16) + ciphertext.
    let payload_len = 16 + ct.len();
    let mut record = Vec::with_capacity(5 + payload_len);
    record.push(0x17); // application_data
    record.push(0x03); // TLS 1.2 major.minor
    record.push(0x03);
    record.extend_from_slice(&(payload_len as u16).to_be_bytes());
    record.extend_from_slice(&iv);
    record.extend_from_slice(&ct);
    record
}

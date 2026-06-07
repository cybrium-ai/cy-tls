//! Active OCSP responder query (RFC 6960).
//!
//! When a server doesn't staple OCSP, the client conventionally falls
//! back to querying the OCSP responder URL embedded in the cert's
//! Authority Information Access extension. v0.5.15 already extracts
//! the URL into CertificateInfo.ocsp_responder_url; v0.5.16 makes
//! that URL actually queryable.
//!
//! Flow: build a DER-encoded OCSPRequest (CertID with SHA-1 hashes of
//! issuer DN + issuer public key plus leaf serial number), POST to the
//! responder URL with Content-Type: application/ocsp-request, return
//! the response bytes for the caller to parse via the existing
//! parse_ocsp_status heuristic. The OCSPRequest ASN.1 layout is per
//! RFC 6960 §4.1.1 — SEQUENCE wrapping TBSRequest wrapping a
//! SEQUENCE OF Request, each Request carrying a CertID.
//!
//! Build issues with malformed DER → responder returns
//! malformed_request and the response bytes don't contain a valid
//! certStatus context tag, so parse_ocsp_status correctly returns
//! None. Safe-by-design failure mode.

use sha1::{Digest, Sha1};
use std::time::Duration;

/// Build the OCSPRequest DER for a single cert.
pub fn build_ocsp_request(
    issuer_name_der: &[u8],
    issuer_pubkey_bytes: &[u8],
    leaf_serial_bytes: &[u8],
) -> Vec<u8> {
    let issuer_name_hash = sha1(issuer_name_der);
    let issuer_key_hash = sha1(issuer_pubkey_bytes);

    // AlgorithmIdentifier ::= SEQUENCE { OID 1.3.14.3.2.26, NULL }
    // Encoded:  06 05 2B 0E 03 02 1A 05 00  inside SEQUENCE.
    let alg_id_der = der_seq(&[&der_oid_sha1(), &der_null()]);
    // CertID
    let cert_id_der = der_seq(&[
        &alg_id_der,
        &der_octet_string(&issuer_name_hash),
        &der_octet_string(&issuer_key_hash),
        &der_integer(leaf_serial_bytes),
    ]);
    // Request ::= SEQUENCE { reqCert CertID }
    let request_der = der_seq(&[&cert_id_der]);
    // requestList SEQUENCE OF Request
    let request_list_der = der_seq(&[&request_der]);
    // TBSRequest ::= SEQUENCE { requestList ... }
    let tbs_request_der = der_seq(&[&request_list_der]);
    // OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest }
    der_seq(&[&tbs_request_der])
}

/// POST the OCSPRequest to the responder URL. Returns the response
/// body bytes on 200 OK; None on any other status / connect failure.
/// We use a blocking ureq call wrapped in spawn_blocking because the
/// rest of the orchestrator is async.
pub async fn query_responder(
    url: &str,
    request_der: Vec<u8>,
    deadline: Duration,
) -> Option<Vec<u8>> {
    let url = url.to_string();
    let timeout = deadline.min(Duration::from_secs(5));
    tokio::task::spawn_blocking(move || {
        let agent = ureq::AgentBuilder::new().timeout(timeout).build();
        let resp = agent
            .post(&url)
            .set("Content-Type", "application/ocsp-request")
            .set("Accept", "application/ocsp-response")
            .send_bytes(&request_der)
            .ok()?;
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut resp.into_reader(), &mut bytes).ok()?;
        Some(bytes)
    })
    .await
    .ok()
    .flatten()
}

// ── DER builder helpers ─────────────────────────────────────────────

fn sha1(bytes: &[u8]) -> Vec<u8> {
    let mut h = Sha1::new();
    h.update(bytes);
    h.finalize().to_vec()
}

fn der_seq(parts: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for p in parts {
        content.extend_from_slice(p);
    }
    der_wrap(0x30, &content)
}

fn der_octet_string(bytes: &[u8]) -> Vec<u8> {
    der_wrap(0x04, bytes)
}

fn der_integer(bytes: &[u8]) -> Vec<u8> {
    // Per X.690 §8.3.2 INTEGERs are signed and must NOT have a
    // redundant 0-byte prefix unless the high bit of the first content
    // byte is set (would otherwise be interpreted as negative).
    let stripped: &[u8] =
        if bytes.first() == Some(&0x00) && bytes.get(1).is_some_and(|b| b & 0x80 == 0) {
            &bytes[1..]
        } else {
            bytes
        };
    let mut content = Vec::with_capacity(stripped.len() + 1);
    if stripped.first().is_some_and(|b| b & 0x80 != 0) {
        // Prepend 0x00 to disambiguate signed-int parser.
        content.push(0x00);
    }
    content.extend_from_slice(stripped);
    der_wrap(0x02, &content)
}

fn der_oid_sha1() -> Vec<u8> {
    // OID 1.3.14.3.2.26 = SHA-1.  Pre-encoded.
    vec![0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a]
}

fn der_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

/// Wrap content bytes with a DER tag + length header.
fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 0x10000 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
    out.extend_from_slice(content);
    out
}

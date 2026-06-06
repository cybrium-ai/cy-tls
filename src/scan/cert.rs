//! Certificate inspection — parses the leaf cert presented during the
//! TLS handshake and checks hygiene (expiry, hostname, key strength,
//! signature algo, chain completeness, SCT presence, OCSP stapling).

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use x509_parser::prelude::*;
use x509_parser::der_parser::oid::Oid;

use crate::finding::{make, Finding};
use super::oid_names;
use super::timing::Timings;

#[derive(Debug, Clone, Serialize)]
pub struct CertificateInfo {
    pub subject:             String,
    pub issuer:              String,
    pub san:                 Vec<String>,
    pub not_before:          DateTime<Utc>,
    pub not_after:           DateTime<Utc>,
    pub days_remaining:      i64,
    pub signature_algorithm: String,
    pub key_algorithm:       String,
    pub key_bits:            u32,
    /// Named curve for EC keys ("secp256r1", "secp384r1", …) or `None`
    /// for RSA / Ed25519 / DSA.
    pub ec_curve:            Option<String>,
    pub chain_complete:      bool,
    pub self_signed:         bool,
    pub ev:                  bool,
    pub must_staple:         bool,
    pub sct_count:           u32,
    pub ocsp_stapled:        bool,
    pub ocsp_status:         Option<String>,
}

impl CertificateInfo {
    pub fn contribute_findings(&self, host: &str, findings: &mut Vec<Finding>) {
        if self.days_remaining < 0 {
            findings.push(make("TLS-CERT-EXPIRED", host, format!("{} days past expiry", -self.days_remaining)));
        } else if self.days_remaining < 30 {
            findings.push(make("TLS-CERT-NEAR-EXPIRY", host, format!("{} days remaining", self.days_remaining)));
        }
        if self.self_signed {
            findings.push(make("TLS-CERT-SELF-SIGNED", host, "Issuer matches subject"));
        }
        if !self.chain_complete {
            findings.push(make("TLS-CHAIN-INCOMPLETE", host, "Server did not present full intermediate chain"));
        }
        let sig_lower = self.signature_algorithm.to_lowercase();
        if sig_lower.contains("sha1") || sig_lower.contains("md5") {
            findings.push(make("TLS-CERT-WEAK-SIGNATURE", host, &self.signature_algorithm));
        }
        let weak_rsa = self.key_algorithm == "rsaEncryption" && self.key_bits < 2048;
        let weak_ecc = self.key_algorithm == "ecPublicKey" && self.key_bits < 256;
        if weak_rsa || weak_ecc {
            findings.push(make(
                "TLS-CERT-WEAK-KEY",
                host,
                format!("{} {} bits", self.key_algorithm, self.key_bits),
            ));
        }
        if !self.ocsp_stapled {
            findings.push(make("TLS-OCSP-NOT-STAPLED", host, "Server did not staple OCSP response"));
        }
        if matches!(self.ocsp_status.as_deref(), Some("revoked")) {
            findings.push(make("TLS-OCSP-REVOKED", host, "OCSP response is revoked"));
        }
        if self.sct_count == 0 {
            findings.push(make("TLS-SCT-MISSING", host, "No SCTs in cert"));
        }
        if self.must_staple && !self.ocsp_stapled {
            findings.push(make(
                "TLS-MUST-STAPLE-VIOLATED",
                host,
                "Cert declares must-staple but stapling absent",
            ));
        }
        let (hostpart, _) = host.rsplit_once(':').unwrap_or((host, "443"));
        if !self.san.iter().any(|n| name_matches(n, hostpart)) {
            findings.push(make(
                "TLS-CERT-HOSTNAME-MISMATCH",
                host,
                format!("SAN: {:?}", self.san),
            ));
        }
    }
}

pub async fn inspect(
    target: &str,
    deadline: Duration,
    timings: &mut Timings,
) -> anyhow::Result<CertificateInfo> {
    let start = std::time::Instant::now();
    let (host_str, _port) = split_host_port(target)?;

    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = timeout(deadline, TcpStream::connect(target)).await??;
    let server_name = ServerName::try_from(host_str.clone())?;
    let tls = timeout(deadline, connector.connect(server_name, tcp)).await??;

    let (_, conn) = tls.get_ref();
    let chain = conn
        .peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("no peer certificates"))?;
    let leaf_der = chain.first().ok_or_else(|| anyhow::anyhow!("empty cert chain"))?;
    // Stapled OCSP from rustls 0.23 requires a custom certificate verifier
    // to intercept; deferred to v0.2.1 ("OCSP via rasn-ocsp" item in TODO).
    let info = parse_leaf(leaf_der.as_ref(), chain.len() > 1, None)?;
    timings.cert = start.elapsed().as_millis() as u64;
    Ok(info)
}

fn parse_leaf(
    der: &[u8],
    chain_has_intermediates: bool,
    stapled_ocsp: Option<&[u8]>,
) -> anyhow::Result<CertificateInfo> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| anyhow::anyhow!("DER parse failed: {e}"))?;
    let tbs = &cert.tbs_certificate;

    let subject = tbs.subject.to_string();
    let issuer = tbs.issuer.to_string();
    let not_before = chrono_from_asn1(tbs.validity.not_before);
    let not_after = chrono_from_asn1(tbs.validity.not_after);
    let days_remaining = (not_after - Utc::now()).num_days();
    let signature_algorithm = oid_names::signature_algorithm(
        &tbs.signature.algorithm.to_id_string(),
    ).to_string();

    let (key_algorithm, key_bits, ec_curve) = key_strength(&tbs.subject_pki);

    let san = extract_san(&cert);
    let self_signed = subject == issuer;
    let must_staple = has_must_staple_extension(&cert);
    let sct_count = extract_sct_count(&cert);

    let (ocsp_stapled, ocsp_status) = match stapled_ocsp {
        Some(bytes) if !bytes.is_empty() => (true, parse_ocsp_status(bytes)),
        _ => (false, None),
    };

    Ok(CertificateInfo {
        subject,
        issuer,
        san,
        not_before,
        not_after,
        days_remaining,
        signature_algorithm,
        key_algorithm,
        key_bits,
        ec_curve,
        chain_complete: chain_has_intermediates || self_signed,
        self_signed,
        ev: false, // TODO Phase 2.1 — EV policy OID lookup
        must_staple,
        sct_count,
        ocsp_stapled,
        ocsp_status,
    })
}

fn chrono_from_asn1(t: ASN1Time) -> DateTime<Utc> {
    let ts = t.timestamp();
    DateTime::<Utc>::from_timestamp(ts, 0).unwrap_or_else(Utc::now)
}

fn key_strength(spki: &SubjectPublicKeyInfo) -> (String, u32, Option<String>) {
    let algo_oid = spki.algorithm.algorithm.to_id_string();
    let algo_name = oid_names::public_key_algorithm(&algo_oid).to_string();

    // For EC keys, the curve OID is encoded in the algorithm parameters.
    if algo_name == "ecPublicKey" {
        if let Some(params) = &spki.algorithm.parameters {
            if let Ok(curve_oid) = params.as_oid() {
                let curve_oid_str = curve_oid.to_id_string();
                if let Some(bits) = oid_names::ec_curve_bits(&curve_oid_str) {
                    return (algo_name, bits, Some(oid_names::ec_curve_name(&curve_oid_str).to_string()));
                }
            }
        }
        // Fallback — assume P-256 if we can't read curve params.
        return (algo_name, 256, None);
    }

    if algo_name == "Ed25519" {
        return (algo_name, 256, None);
    }
    if algo_name == "Ed448" {
        return (algo_name, 448, None);
    }

    // RSA: parse the modulus to get the actual modulus bit length.
    if algo_name == "rsaEncryption" {
        let bits = rsa_modulus_bits(&spki.subject_public_key.data).unwrap_or(0);
        return (algo_name, bits, None);
    }

    // Unknown — fall back to the (overly generous) DER bit length.
    (algo_name, (spki.subject_public_key.data.len() * 8) as u32, None)
}

/// Parse the modulus length out of an RSAPublicKey DER blob
/// (RFC 8017 §A.1.1):  SEQUENCE { modulus INTEGER, publicExponent INTEGER }.
fn rsa_modulus_bits(der: &[u8]) -> Option<u32> {
    // Quick and dirty walker — accepts the SEQUENCE then the modulus INTEGER.
    let mut i = 0;
    if der.get(i)? != &0x30 { return None; }
    i += 1;
    let _ = parse_der_length(der, &mut i)?;
    if der.get(i)? != &0x02 { return None; } // INTEGER tag
    i += 1;
    let modulus_len = parse_der_length(der, &mut i)?;
    let modulus = der.get(i..i + modulus_len)?;
    // Strip any DER sign-extension zero byte.
    let mod_bytes = if modulus.first() == Some(&0x00) { &modulus[1..] } else { modulus };
    Some((mod_bytes.len() * 8) as u32)
}

fn parse_der_length(buf: &[u8], i: &mut usize) -> Option<usize> {
    let first = *buf.get(*i)?;
    *i += 1;
    if first < 0x80 {
        return Some(first as usize);
    }
    let n = (first & 0x7f) as usize;
    let mut len = 0usize;
    for _ in 0..n {
        len = (len << 8) | (*buf.get(*i)? as usize);
        *i += 1;
    }
    Some(len)
}

fn extract_san(cert: &X509Certificate) -> Vec<String> {
    let mut out = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::DNSName(dns) = name {
                    out.push(dns.to_string());
                }
            }
        }
    }
    out
}

fn has_must_staple_extension(cert: &X509Certificate) -> bool {
    const MUST_STAPLE_OID: &str = "1.3.6.1.5.5.7.1.24";
    cert.extensions()
        .iter()
        .any(|ext| ext.oid.to_id_string() == MUST_STAPLE_OID)
}

/// Count SignedCertificateTimestamp entries embedded in the cert under
/// the SCT extension (OID 1.3.6.1.4.1.11129.2.4.2). The extension wraps
/// an OCTET STRING containing a 2-byte big-endian list length followed
/// by 2-byte-length-prefixed SCT entries. We only count, we don't
/// validate the signatures — that's a future hardening step.
fn extract_sct_count(cert: &X509Certificate) -> u32 {
    let sct_oid: Oid = Oid::from(&[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2]).unwrap();
    let ext = match cert.extensions().iter().find(|e| e.oid == sct_oid) {
        Some(e) => e,
        None => return 0,
    };
    // The value is OCTET STRING wrapping the SCT list. Skip the
    // OCTET-STRING tag + length to get to the raw list bytes.
    let raw = ext.value;
    let mut i = 0usize;
    if raw.first() == Some(&0x04) {
        i += 1;
        if parse_der_length(raw, &mut i).is_none() {
            return 0;
        }
    }
    let list = match raw.get(i..) {
        Some(b) if b.len() >= 2 => b,
        _ => return 0,
    };
    let mut p = 2usize; // skip 2-byte list length
    let mut count = 0u32;
    while p + 2 <= list.len() {
        let entry_len = ((list[p] as usize) << 8) | (list[p + 1] as usize);
        p += 2;
        if p + entry_len > list.len() {
            break;
        }
        count += 1;
        p += entry_len;
    }
    count
}

/// Parse an OCSP response just far enough to extract the cert status.
/// Returns "good", "revoked", "unknown", or None on parse failure.
fn parse_ocsp_status(der: &[u8]) -> Option<String> {
    // Very rough — looks for the SingleResponse certStatus tag context value.
    // OCSP responses are deeply nested ASN.1; for a Phase 2 ship we
    // optimistically look for the certStatus context tag.
    //   0xA0 → CONTEXT 0 (good)
    //   0xA1 → CONTEXT 1 (revoked)
    //   0xA2 → CONTEXT 2 (unknown)
    // This isn't a strict parse and will need a proper OCSP library in
    // Phase 2.1 (planned: `rasn-ocsp`).
    for window in der.windows(1) {
        match window[0] {
            0xA0 => return Some("good".to_string()),
            0xA1 => return Some("revoked".to_string()),
            0xA2 => return Some("unknown".to_string()),
            _ => continue,
        }
    }
    None
}

fn name_matches(san: &str, host: &str) -> bool {
    if let Some(suffix) = san.strip_prefix("*.") {
        host.split_once('.').is_some_and(|(_, rest)| rest == suffix)
    } else {
        san.eq_ignore_ascii_case(host)
    }
}

fn split_host_port(target: &str) -> anyhow::Result<(String, u16)> {
    let (h, p) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("target must be host:port"))?;
    Ok((h.to_string(), p.parse()?))
}

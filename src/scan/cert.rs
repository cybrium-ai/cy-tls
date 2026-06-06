//! Certificate inspection — parses the leaf cert presented during the
//! TLS handshake and checks hygiene (expiry, hostname, key strength,
//! signature algo, chain completeness).

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

use crate::finding::{make, Finding};
use super::timing::Timings;

#[derive(Debug, Serialize)]
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
        if self.signature_algorithm.to_lowercase().contains("sha1")
            || self.signature_algorithm.to_lowercase().contains("md5")
        {
            findings.push(make("TLS-CERT-WEAK-SIGNATURE", host, &self.signature_algorithm));
        }
        let weak_rsa = self.key_algorithm.to_lowercase().contains("rsa") && self.key_bits < 2048;
        let weak_ecc = self.key_algorithm.to_lowercase().contains("ec") && self.key_bits < 256;
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
            findings.push(make("TLS-SCT-MISSING", host, "No SCTs from cert, OCSP, or TLS extension"));
        }
        if self.must_staple && !self.ocsp_stapled {
            findings.push(make(
                "TLS-MUST-STAPLE-VIOLATED",
                host,
                "Cert declares must-staple but stapling absent",
            ));
        }
        // Hostname mismatch — caller must verify against SAN/CN.
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
    let info = parse_leaf(leaf_der.as_ref(), chain.len() > 1)?;
    timings.cert = start.elapsed().as_millis() as u64;
    Ok(info)
}

fn parse_leaf(der: &[u8], chain_has_intermediates: bool) -> anyhow::Result<CertificateInfo> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| anyhow::anyhow!("DER parse failed: {e}"))?;
    let tbs = &cert.tbs_certificate;

    let subject = tbs.subject.to_string();
    let issuer = tbs.issuer.to_string();
    let not_before = chrono_from_asn1(tbs.validity.not_before);
    let not_after = chrono_from_asn1(tbs.validity.not_after);
    let days_remaining = (not_after - Utc::now()).num_days();
    let signature_algorithm = format!("{:?}", tbs.signature.algorithm);

    let (key_algorithm, key_bits) = key_strength(&tbs.subject_pki);

    let san = extract_san(&cert);
    let self_signed = subject == issuer;
    let must_staple = has_must_staple_extension(&cert);

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
        chain_complete: chain_has_intermediates || self_signed,
        self_signed,
        ev: false,           // TODO Phase 2 — EV OID lookup
        must_staple,
        sct_count: 0,        // TODO Phase 2 — parse SCT extension
        ocsp_stapled: false, // TODO Phase 2 — read CertificateStatus message
        ocsp_status: None,
    })
}

fn chrono_from_asn1(t: ASN1Time) -> DateTime<Utc> {
    let ts = t.timestamp();
    DateTime::<Utc>::from_timestamp(ts, 0).unwrap_or_else(Utc::now)
}

fn key_strength(spki: &SubjectPublicKeyInfo) -> (String, u32) {
    let algo = format!("{:?}", spki.algorithm.algorithm);
    let bits = (spki.subject_public_key.data.len() * 8) as u32;
    (algo, bits)
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
    // TLS-feature extension OID = 1.3.6.1.5.5.7.1.24 carrying status_request (5).
    const MUST_STAPLE_OID: &str = "1.3.6.1.5.5.7.1.24";
    cert.extensions()
        .iter()
        .any(|ext| ext.oid.to_id_string() == MUST_STAPLE_OID)
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

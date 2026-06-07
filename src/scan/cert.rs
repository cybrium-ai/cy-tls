//! Certificate inspection — parses the leaf cert presented during the
//! TLS handshake and checks hygiene (expiry, hostname, key strength,
//! signature algo, chain completeness, SCT presence, OCSP stapling).

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use serde::Serialize;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::der_parser::oid::Oid;
use x509_parser::prelude::*;

use super::oid_names;
use super::timing::Timings;
use crate::finding::{make, Finding};

#[derive(Debug, Clone, Serialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub san: Vec<String>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub days_remaining: i64,
    pub signature_algorithm: String,
    pub key_algorithm: String,
    pub key_bits: u32,
    /// Named curve for EC keys ("secp256r1", "secp384r1", …) or `None`
    /// for RSA / Ed25519 / DSA.
    pub ec_curve: Option<String>,
    pub chain_complete: bool,
    /// v0.5.17 — number of certificates the server presented in its
    /// chain (leaf + intermediates). Empty / 1 → bare leaf; 2-4 →
    /// typical; >5 → deep chain (cross-signed sprawl, redundant
    /// intermediates, or misconfig).
    pub chain_length: u32,
    pub self_signed: bool,
    pub ev: bool,
    pub must_staple: bool,
    pub sct_count: u32,
    /// v0.5.11 — number of DISTINCT CT log operators represented in
    /// the cert's embedded SCTs. Chrome's CT policy (Sep 2022+) needs
    /// ≥2 distinct operators (one Google + one non-Google historically;
    /// post-2024 just ≥2 operators).
    pub sct_distinct_operators: u32,
    pub ocsp_stapled: bool,
    pub ocsp_status: Option<String>,
    /// v0.5.19 — true when the cert's Extended Key Usage extension
    /// (OID 2.5.29.37) includes id-kp-serverAuth (1.3.6.1.5.5.7.3.1).
    /// Required by CA/B Forum BR §7.1.2.7 for publicly-trusted TLS
    /// server certs — browsers reject leaf certs that lack it.
    pub has_server_auth_eku: bool,
    /// v0.5.15 — OCSP responder URL parsed from the cert's
    /// Authority Information Access extension (RFC 5280 §4.2.2.1
    /// accessMethod id-ad-ocsp 1.3.6.1.5.5.7.48.1). Populated when
    /// the leaf cert publishes one. Used in v0.5.16+ to perform an
    /// active OCSP query when the server didn't staple a response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ocsp_responder_url: Option<String>,
    /// v0.5.20 — CRL Distribution Points URLs parsed from the cert's
    /// CRLDistributionPoints extension (RFC 5280 §4.2.1.13, OID
    /// 2.5.29.31). Sibling of the OCSP responder URL — many CAs ship
    /// CRLs as fallback or, post-2024 (e.g. Let's Encrypt's OCSP
    /// deprecation), as the primary revocation channel.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub crl_distribution_points: Vec<String>,
    /// v0.5.21 — entropy bits in the cert's serial number after
    /// stripping the X.690 sign-pad. CA/B Forum BR §7.1 requires
    /// publicly-trusted CA-issued certs to carry ≥64 bits of
    /// CA-generated entropy in the serial.
    pub serial_entropy_bits: u32,
    /// v0.5.22 — leaf cert's Basic Constraints cA bit (RFC 5280
    /// §4.2.1.9, OID 2.5.29.19). FALSE / absent is correct for an
    /// end-entity cert; TRUE is catastrophic (leaf could sign
    /// sub-certs).
    pub basic_constraints_ca: bool,
    /// v0.5.23 — true when the cert carries an AuthorityKeyIdentifier
    /// extension (RFC 5280 §4.2.1.1, OID 2.5.29.35). Mandatory on
    /// non-self-signed certs so chain validators can disambiguate
    /// among multiple roots with the same issuer DN.
    pub has_authority_key_identifier: bool,
}

impl CertificateInfo {
    pub fn contribute_findings(&self, host: &str, findings: &mut Vec<Finding>) {
        if self.days_remaining < 0 {
            findings.push(make(
                "TLS-CERT-EXPIRED",
                host,
                format!("{} days past expiry", -self.days_remaining),
            ));
        } else if self.days_remaining < 30 {
            findings.push(make(
                "TLS-CERT-NEAR-EXPIRY",
                host,
                format!("{} days remaining", self.days_remaining),
            ));
        }
        // v0.5.13 — CA/B Forum Baseline Requirements §6.3.2: server
        // cert validity capped at 397 days (398 days inclusive of
        // start day). Browsers (Apple Sep 2020, then Chrome / Mozilla)
        // hard-enforce this; certs issued > 398 days after 2020-09-01
        // are not accepted by modern browsers.
        let lifetime_days = (self.not_after - self.not_before).num_days();
        if lifetime_days > 398 {
            findings.push(make(
                "TLS-CERT-EXCESSIVE-LIFETIME",
                host,
                format!(
                    "Cert lifetime is {lifetime_days} days (not_before..not_after) — exceeds the CA/B Forum BR §6.3.2 cap of 398 days enforced by browsers since Sep 2020. Certs issued after that date with this lifetime won't validate in Chrome / Firefox / Safari."
                ),
            ));
        }
        if self.self_signed {
            findings.push(make("TLS-CERT-SELF-SIGNED", host, "Issuer matches subject"));
        }
        if !self.chain_complete {
            findings.push(make(
                "TLS-CHAIN-INCOMPLETE",
                host,
                "Server did not present full intermediate chain",
            ));
        }
        // v0.5.17 — deep chain sanity. Typical leaf+1-3 intermediates
        // is normal; >5 usually indicates a cross-signed sprawl, a
        // stale intermediate left in place after a CA migration, or a
        // misconfig. Browsers fold the chain at validation time so
        // the user-visible impact is bandwidth + handshake-latency.
        if self.chain_length > 5 {
            findings.push(make(
                "TLS-CERT-CHAIN-DEEP",
                host,
                format!(
                    "Server presented {} certificates in the chain — typical chains are 2-4. Often indicates cross-signed sprawl or a stale intermediate left in place after a CA migration; prune the chain to reduce handshake bandwidth.",
                    self.chain_length,
                ),
            ));
        }
        let sig_lower = self.signature_algorithm.to_lowercase();
        if sig_lower.contains("sha1") || sig_lower.contains("md5") {
            findings.push(make(
                "TLS-CERT-WEAK-SIGNATURE",
                host,
                &self.signature_algorithm,
            ));
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
        if !self.has_server_auth_eku {
            findings.push(make(
                "TLS-CERT-MISSING-SERVER-AUTH-EKU",
                host,
                "Leaf cert Extended Key Usage does not include id-kp-serverAuth (1.3.6.1.5.5.7.3.1) — CA/B Forum BR §7.1.2.7 requires this for publicly-trusted TLS server certs; modern browsers reject leafs that lack it.",
            ));
        }
        if !self.has_authority_key_identifier && !self.self_signed {
            findings.push(make(
                "TLS-CERT-NO-AKI",
                host,
                "Non-self-signed leaf cert is missing the AuthorityKeyIdentifier extension (RFC 5280 §4.2.1.1) — chain validators have to fall back to issuer-DN matching which is ambiguous when the issuer has rotated keys or operates multiple parallel intermediates.",
            ));
        }
        if self.basic_constraints_ca && !self.self_signed {
            findings.push(make(
                "TLS-CERT-LEAF-IS-CA",
                host,
                "Leaf certificate has BasicConstraints cA: TRUE — this is an end-entity cert that the CA also marked as a CA. The leaf could in theory sign sub-certs that browsers might trust through it. Catastrophic misissuance per RFC 5280 §4.2.1.9.",
            ));
        }
        if self.serial_entropy_bits < 64 {
            findings.push(make(
                "TLS-CERT-WEAK-SERIAL-ENTROPY",
                host,
                format!(
                    "Cert serial has {} bits of entropy (after sign-pad strip) — CA/B Forum BR §7.1 requires ≥64 bits of CA-generated entropy. Short serials are a Symantec-era footgun (CA/B Forum prohibited sequential serials in 2016) and break browser chain-validation heuristics.",
                    self.serial_entropy_bits,
                ),
            ));
        }
        if !self.ocsp_stapled {
            findings.push(make(
                "TLS-OCSP-NOT-STAPLED",
                host,
                "Server did not staple OCSP response",
            ));
        }
        if matches!(self.ocsp_status.as_deref(), Some("revoked")) {
            findings.push(make("TLS-OCSP-REVOKED", host, "OCSP response is revoked"));
        }
        if self.sct_count == 0 {
            findings.push(make("TLS-SCT-MISSING", host, "No SCTs in cert"));
        } else if self.sct_distinct_operators == 1 {
            // 0 = no known operators (table-coverage gap, silent)
            // 1 = one known but ≥1 SCT → real diversity issue
            // 2+ = silent (Chrome policy satisfied)
            findings.push(make(
                "TLS-CT-INSUFFICIENT-DIVERSITY",
                host,
                format!(
                    "Cert embeds {} SCT(s) but only 1 distinct CT log operator is recognised — Chrome's CT policy (Sep 2022 onwards) requires ≥2 INDEPENDENT operators. Likely a cert issued before the log-diversity tightening landed; reissue with a current chain to pick up SCTs from a second operator.",
                    self.sct_count,
                ),
            ));
        }

        // v0.4.3 — Symantec-era distrusted CA heuristic. Chrome 70 +
        // Firefox 63 (Sep–Oct 2018) removed trust from all
        // Symantec-controlled root certs (Symantec, GeoTrust, Thawte,
        // RapidSSL, and certain VeriSign brands) per the 2017 PKI
        // distrust agreement. Certs still chaining through those
        // issuer DNs fail in every modern browser. DigiCert acquired
        // the Symantec PKI business in late 2017 — new DigiCert-
        // branded issuers are fine; only the legacy issuer DNs trip.
        if let Some(matched) = symantec_era_issuer_match(&self.issuer) {
            findings.push(make(
                "TLS-SYMANTEC-DISTRUSTED-CA",
                host,
                format!(
                    "Issuer DN matches the {matched} family — distrusted by Chrome 70 / Firefox 63 since October 2018. Modern browsers will refuse this cert. Issuer: {}",
                    self.issuer,
                ),
            ));
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
        // v0.5.18 — dangerous wildcard policy. CA/B Forum BR §3.2.2.6
        // prohibits wildcard certs on public suffixes (*.com, *.co.uk,
        // etc.). RFC 6125 §6.4.3 also says wildcards may only replace
        // the LEFTMOST label, so *.*.example.com is invalid. Most public
        // CAs reject such requests but private / internal CAs sometimes
        // issue these.
        for san in &self.san {
            if let Some(reason) = dangerous_wildcard_reason(san) {
                findings.push(make(
                    "TLS-CERT-DANGEROUS-WILDCARD",
                    host,
                    format!("SAN {san:?}: {reason}"),
                ));
            }
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
    let leaf_der = chain
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty cert chain"))?;
    // Stapled OCSP from rustls 0.23 requires a custom certificate verifier
    // to intercept; deferred to v0.2.1 ("OCSP via rasn-ocsp" item in TODO).
    let mut info = parse_leaf(leaf_der.as_ref(), chain.len() as u32, None)?;

    // v0.5.16 — active OCSP query when the responder URL is published
    // and we have an issuer cert in the chain. The result populates
    // ocsp_status; the orchestrator's stapling probe runs afterwards
    // and will OVERWRITE only when it sees an actual stapled response
    // (stapling is more authoritative when present).
    if let (Some(url), Some(issuer_der)) = (info.ocsp_responder_url.as_deref(), chain.get(1)) {
        if let Some(status) =
            active_ocsp_query(leaf_der.as_ref(), issuer_der.as_ref(), url, deadline).await
        {
            info.ocsp_status = Some(status);
        }
    }

    timings.cert = start.elapsed().as_millis() as u64;
    Ok(info)
}

/// Run an OCSP request against the cert's AIA responder URL. Returns
/// the parsed status string ("good" / "revoked" / "unknown") or None
/// when the query couldn't be built or the responder didn't return a
/// parseable response.
async fn active_ocsp_query(
    leaf_der: &[u8],
    issuer_der: &[u8],
    responder_url: &str,
    deadline: Duration,
) -> Option<String> {
    let (_, leaf) = X509Certificate::from_der(leaf_der).ok()?;
    let (_, issuer) = X509Certificate::from_der(issuer_der).ok()?;
    // Issuer DN as DER bytes — needed for SHA-1 hashing.
    let issuer_name_der = issuer.tbs_certificate.subject.as_raw();
    // Issuer subject public key BIT STRING content (NOT the SPKI).
    let issuer_pubkey_bytes = issuer
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .as_ref();
    // Leaf serial as big-endian bytes.
    let leaf_serial_bytes = leaf.tbs_certificate.raw_serial();

    let request_der = super::ocsp_query::build_ocsp_request(
        issuer_name_der,
        issuer_pubkey_bytes,
        leaf_serial_bytes,
    );
    let response = super::ocsp_query::query_responder(responder_url, request_der, deadline).await?;
    parse_ocsp_status(&response)
}

fn parse_leaf(
    der: &[u8],
    chain_length: u32,
    stapled_ocsp: Option<&[u8]>,
) -> anyhow::Result<CertificateInfo> {
    let chain_has_intermediates = chain_length > 1;
    let (_, cert) =
        X509Certificate::from_der(der).map_err(|e| anyhow::anyhow!("DER parse failed: {e}"))?;
    let tbs = &cert.tbs_certificate;

    let subject = tbs.subject.to_string();
    let issuer = tbs.issuer.to_string();
    let not_before = chrono_from_asn1(tbs.validity.not_before);
    let not_after = chrono_from_asn1(tbs.validity.not_after);
    let days_remaining = (not_after - Utc::now()).num_days();
    let signature_algorithm =
        oid_names::signature_algorithm(&tbs.signature.algorithm.to_id_string()).to_string();

    let (key_algorithm, key_bits, ec_curve) = key_strength(&tbs.subject_pki);

    let san = extract_san(&cert);
    let self_signed = subject == issuer;
    let must_staple = has_must_staple_extension(&cert);
    let sct_log_ids = extract_sct_log_ids(&cert);
    let sct_count = sct_log_ids.len() as u32;
    let sct_distinct_operators = distinct_ct_operators(&sct_log_ids) as u32;
    let ocsp_responder_url = extract_ocsp_responder_url(&cert);
    let has_server_auth_eku = has_extended_key_usage_server_auth(&cert);
    let crl_distribution_points = extract_crl_distribution_points(&cert);
    let serial_entropy_bits = serial_entropy_bits(tbs.raw_serial());
    let basic_constraints_ca = basic_constraints_ca_bit(&cert);
    let has_authority_key_identifier = has_aki_extension(&cert);

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
        chain_length,
        self_signed,
        ev: has_ev_policy_oid(&cert),
        must_staple,
        sct_count,
        sct_distinct_operators,
        ocsp_responder_url,
        has_server_auth_eku,
        crl_distribution_points,
        serial_entropy_bits,
        basic_constraints_ca,
        has_authority_key_identifier,
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
                    return (
                        algo_name,
                        bits,
                        Some(oid_names::ec_curve_name(&curve_oid_str).to_string()),
                    );
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
    (
        algo_name,
        (spki.subject_public_key.data.len() * 8) as u32,
        None,
    )
}

/// Parse the modulus length out of an RSAPublicKey DER blob
/// (RFC 8017 §A.1.1):  SEQUENCE { modulus INTEGER, publicExponent INTEGER }.
fn rsa_modulus_bits(der: &[u8]) -> Option<u32> {
    // Quick and dirty walker — accepts the SEQUENCE then the modulus INTEGER.
    let mut i = 0;
    if der.get(i)? != &0x30 {
        return None;
    }
    i += 1;
    let _ = parse_der_length(der, &mut i)?;
    if der.get(i)? != &0x02 {
        return None;
    } // INTEGER tag
    i += 1;
    let modulus_len = parse_der_length(der, &mut i)?;
    let modulus = der.get(i..i + modulus_len)?;
    // Strip any DER sign-extension zero byte.
    let mod_bytes = if modulus.first() == Some(&0x00) {
        &modulus[1..]
    } else {
        modulus
    };
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

/// Extract the OCSP responder URL from the cert's Authority
/// Information Access extension (RFC 5280 §4.2.2.1, OID
/// 1.3.6.1.5.5.7.1.1). AIA is a SEQUENCE OF AccessDescription;
/// each AccessDescription has an accessMethod OID and an accessLocation
/// GeneralName (typically URI). The accessMethod for OCSP is
/// id-ad-ocsp = 1.3.6.1.5.5.7.48.1. Returns the first OCSP URI found,
/// or None when AIA is absent / contains no OCSP entry.
fn extract_ocsp_responder_url(cert: &X509Certificate) -> Option<String> {
    use x509_parser::extensions::{AccessDescription, ParsedExtension};
    use x509_parser::prelude::GeneralName;
    let ocsp_oid: Oid = Oid::from(&[1, 3, 6, 1, 5, 5, 7, 48, 1]).unwrap();
    for ext in cert.extensions() {
        if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
            for AccessDescription {
                access_method,
                access_location,
            } in aia.accessdescs.iter()
            {
                if *access_method == ocsp_oid {
                    if let GeneralName::URI(uri) = access_location {
                        return Some(uri.to_string());
                    }
                }
            }
        }
    }
    None
}

/// True when the cert's Extended Key Usage extension (OID 2.5.29.37)
/// includes id-kp-serverAuth (1.3.6.1.5.5.7.3.1). x509-parser parses
/// EKU into a ParsedExtension::ExtendedKeyUsage variant with a
/// `server_auth: bool` shortcut.
fn has_extended_key_usage_server_auth(cert: &X509Certificate) -> bool {
    use x509_parser::extensions::ParsedExtension;
    for ext in cert.extensions() {
        if let ParsedExtension::ExtendedKeyUsage(eku) = ext.parsed_extension() {
            return eku.server_auth;
        }
    }
    // Pre-EKU certs (RFC 3280 era) often omit the extension entirely —
    // those legitimately work for TLS server auth via the cert's basic
    // constraints + key usage. We treat absence as "OK" rather than
    // emit a false positive on legacy chains.
    true
}

/// True when the cert carries an AuthorityKeyIdentifier extension
/// (RFC 5280 §4.2.1.1, OID 2.5.29.35). Mandatory on non-self-signed
/// certs to disambiguate among parallel intermediates with the same
/// issuer DN.
fn has_aki_extension(cert: &X509Certificate) -> bool {
    use x509_parser::extensions::ParsedExtension;
    for ext in cert.extensions() {
        if matches!(
            ext.parsed_extension(),
            ParsedExtension::AuthorityKeyIdentifier(_)
        ) {
            return true;
        }
    }
    false
}

/// True when the cert's BasicConstraints extension (RFC 5280 §4.2.1.9,
/// OID 2.5.29.19) has cA: TRUE. End-entity certs (leafs) MUST NOT
/// have this flag set; intermediates / roots MUST set it.
fn basic_constraints_ca_bit(cert: &X509Certificate) -> bool {
    use x509_parser::extensions::ParsedExtension;
    for ext in cert.extensions() {
        if let ParsedExtension::BasicConstraints(bc) = ext.parsed_extension() {
            return bc.ca;
        }
    }
    // Absent extension = treat as cA: FALSE per RFC 5280 §4.2.1.9
    // ("if the basic constraints extension is not present in a
    // certificate ... then the certified public key MUST NOT be used
    // to verify certificate signatures").
    false
}

/// Calculate the entropy bits in a cert serial number. The raw_serial
/// from x509-parser includes the X.690 INTEGER encoding's sign-pad
/// (a leading 0x00 when the high bit of the next byte is set) which
/// doesn't carry entropy. After stripping that, multiply by 8.
fn serial_entropy_bits(raw: &[u8]) -> u32 {
    // Strip leading 0x00 sign-pad if present AND the next byte has
    // high bit set (only then is the 0x00 a pad, not actual entropy).
    let stripped: &[u8] = if raw.first() == Some(&0x00) && raw.get(1).is_some_and(|b| b & 0x80 != 0)
    {
        &raw[1..]
    } else {
        raw
    };
    (stripped.len() as u32) * 8
}

/// Extract CRL Distribution Points URIs from the cert's
/// CRLDistributionPoints extension (RFC 5280 §4.2.1.13, OID
/// 2.5.29.31). Walks the SEQUENCE OF DistributionPoint structure
/// pulling URI-form GeneralNames out of the distributionPoint
/// fullName field. Returns an empty Vec when CRLDP is absent or
/// contains no URI-form names.
fn extract_crl_distribution_points(cert: &X509Certificate) -> Vec<String> {
    use x509_parser::extensions::{DistributionPointName, ParsedExtension};
    use x509_parser::prelude::GeneralName;
    let mut out = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::CRLDistributionPoints(crldp) = ext.parsed_extension() {
            for point in crldp.points.iter() {
                if let Some(DistributionPointName::FullName(names)) =
                    point.distribution_point.as_ref()
                {
                    for name in names.iter() {
                        if let GeneralName::URI(uri) = name {
                            out.push(uri.to_string());
                        }
                    }
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

/// Walk the SCT extension (OID 1.3.6.1.4.1.11129.2.4.2) and return
/// the 32-byte log_id of each SCT. log_id is SHA-256 of the log's
/// public key (RFC 6962 §3.2 SignedCertificateTimestamp). Used both
/// for the existing SCT count and the v0.5.11 CT-log-diversity check.
fn extract_sct_log_ids(cert: &X509Certificate) -> Vec<[u8; 32]> {
    let sct_oid: Oid = Oid::from(&[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2]).unwrap();
    let Some(ext) = cert.extensions().iter().find(|e| e.oid == sct_oid) else {
        return Vec::new();
    };
    // OCTET STRING wraps the SCT list. Skip the OCTET-STRING tag +
    // length to get to the raw list bytes.
    let raw = ext.value;
    let mut i = 0usize;
    if raw.first() == Some(&0x04) {
        i += 1;
        if parse_der_length(raw, &mut i).is_none() {
            return Vec::new();
        }
    }
    let list = match raw.get(i..) {
        Some(b) if b.len() >= 2 => b,
        _ => return Vec::new(),
    };
    let mut p = 2usize; // skip 2-byte list length
    let mut out = Vec::new();
    while p + 2 <= list.len() {
        let entry_len = ((list[p] as usize) << 8) | (list[p + 1] as usize);
        p += 2;
        let entry_end = p + entry_len;
        if entry_end > list.len() {
            break;
        }
        // SerializedSCT layout (RFC 6962 §3.2):
        //   sct_version(1) log_id(32) timestamp(8) extensions(>=2) signature(>=4)
        if entry_len > 32 {
            let log_id_start = p + 1;
            let log_id_end = log_id_start + 32;
            if log_id_end <= entry_end {
                let mut log_id = [0u8; 32];
                log_id.copy_from_slice(&list[log_id_start..log_id_end]);
                out.push(log_id);
            }
        }
        p = entry_end;
    }
    out
}

/// Map a CT log's 32-byte log_id (SHA-256 of its public key) to the
/// log operator family. Chrome's CT policy (Sep 2022 onwards) requires
/// SCTs from ≥2 INDEPENDENT operators — so chasing the "log count" up
/// to 2 by getting two Google logs (e.g. one Argon shard + one Xenon
/// shard) doesn't satisfy the policy. cy-tls calls this from the
/// diversity check.
///
/// We key on the 4-byte log_id prefix — the public-key hash space is
/// large enough that 4 bytes uniquely identifies known logs, AND
/// active logs are rotated yearly so storing full hashes would mean
/// constant maintenance. Source: Chrome's log_list.json (sept 2024
/// snapshot).
fn ct_log_operator(log_id: &[u8; 32]) -> &'static str {
    // Tracked operators (sorted alphabetically). Each row is a known
    // log_id prefix bound to its operator family. Updates land when
    // Chrome adds new logs.
    const KNOWN: &[(&[u8], &str)] = &[
        // ── Google ──────────────────────────────────────────────────
        (&[0xee, 0x4b, 0xbd, 0xb7], "google"), // Argon 2024
        (&[0x4c, 0x68, 0xc4, 0x35], "google"), // Argon 2025h1
        (&[0xe6, 0xd2, 0x31, 0x63], "google"), // Argon 2025h2
        (&[0x7d, 0x59, 0x1e, 0x12], "google"), // Xenon 2024
        (&[0x4e, 0x75, 0xa3, 0x27], "google"), // Xenon 2025h1
        (&[0xcf, 0x11, 0x56, 0xee], "google"), // Xenon 2025h2
        // ── Cloudflare ──────────────────────────────────────────────
        (&[0xda, 0xb6, 0xbf, 0x6b], "cloudflare"), // Nimbus 2024
        (&[0xcc, 0xfb, 0x0f, 0x6a], "cloudflare"), // Nimbus 2025
        (&[0xde, 0x85, 0x81, 0xd7], "cloudflare"), // Nimbus 2026
        // ── DigiCert ────────────────────────────────────────────────
        (&[0x35, 0xcf, 0x19, 0x1b], "digicert"), // Yeti2024
        (&[0xe3, 0x80, 0xa4, 0x9e], "digicert"), // Yeti2025
        (&[0x66, 0x37, 0x05, 0x8e], "digicert"), // Nessie2024
        (&[0x37, 0xfa, 0xb6, 0xae], "digicert"), // Nessie2025
        // ── Sectigo ─────────────────────────────────────────────────
        (&[0x55, 0x81, 0xd4, 0xc2], "sectigo"), // Sabre / Mammoth
        (&[0x29, 0xd0, 0x3a, 0x1b], "sectigo"), // Sabre2024h1
        (&[0xa2, 0xe2, 0xbf, 0xd6], "sectigo"), // Sabre2024h2
        // ── Let's Encrypt ───────────────────────────────────────────
        (&[0xda, 0xb6, 0xbf, 0xd1], "lets-encrypt"), // Oak (older)
        (&[0xa4, 0x39, 0x4b, 0xd4], "lets-encrypt"), // Oak 2024
        (&[0xe0, 0x12, 0x76, 0x29], "lets-encrypt"), // Oak 2025
        // ── TrustAsia ───────────────────────────────────────────────
        (&[0x84, 0x9f, 0x5f, 0x7f], "trustasia"), // TrustAsia 2024-1/2
    ];
    for (prefix, op) in KNOWN {
        if log_id.starts_with(prefix) {
            return op;
        }
    }
    "unknown"
}

/// Count distinct KNOWN (non-"unknown") CT log operators across a
/// list of SCT log_ids. We exclude the catch-all "unknown" bucket so
/// gaps in cy-tls's curated log_id table never cause false-positive
/// TLS-CT-INSUFFICIENT-DIVERSITY findings — a row from a log we
/// haven't tracked yet contributes 0 to the diversity count instead
/// of 1 against an "unknown" bucket. Conservative on purpose; new
/// real CT logs land in `ct_log_operator()` as they're observed in
/// real-world certs.
fn distinct_ct_operators(log_ids: &[[u8; 32]]) -> usize {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    for id in log_ids {
        let op = ct_log_operator(id);
        if op != "unknown" {
            seen.insert(op);
        }
    }
    seen.len()
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

/// Heuristic match against the 2018-distrusted CA families. Returns the
/// family name when the issuer DN string contains one of the known
/// brand names. Case-insensitive — Issuer DNs in the wild use varied
/// casing ("thawte" vs "Thawte" vs "THAWTE").
///
/// Important: this matches by ISSUER name, so DigiCert-branded certs
/// that replaced the old Symantec issuer entries are unaffected — only
/// the original Symantec-PKI issuer DNs trip the finding. False
/// positives are theoretically possible if some other CA uses a
/// similar brand string in their DN, but no current public CA does.
pub fn symantec_era_issuer_match(issuer: &str) -> Option<&'static str> {
    let lower = issuer.to_ascii_lowercase();
    // Order: most-specific tokens first so we report the right family.
    if lower.contains("rapidssl") {
        return Some("RapidSSL");
    }
    if lower.contains("geotrust") {
        return Some("GeoTrust");
    }
    if lower.contains("thawte") {
        return Some("Thawte");
    }
    if lower.contains("verisign") {
        return Some("VeriSign");
    }
    if lower.contains("symantec") {
        return Some("Symantec");
    }
    None
}

#[cfg(test)]
mod symantec_distrust_tests {
    use super::symantec_era_issuer_match;

    #[test]
    fn matches_symantec() {
        assert_eq!(
            symantec_era_issuer_match(
                "CN=Symantec Class 3 Secure Server CA - G4, O=Symantec Corporation, C=US"
            ),
            Some("Symantec"),
        );
    }

    #[test]
    fn matches_geotrust_case_insensitive() {
        assert_eq!(
            symantec_era_issuer_match("CN=GEOTRUST Primary Certification Authority - G3"),
            Some("GeoTrust"),
        );
    }

    #[test]
    fn matches_thawte() {
        assert_eq!(
            symantec_era_issuer_match("CN=thawte Primary Root CA - G3, OU=\"(c) 2008 thawte, Inc. - For authorized use only\""),
            Some("Thawte"),
        );
    }

    #[test]
    fn matches_verisign() {
        assert_eq!(
            symantec_era_issuer_match(
                "CN=VeriSign Class 3 Public Primary Certification Authority - G5"
            ),
            Some("VeriSign"),
        );
    }

    #[test]
    fn matches_rapidssl() {
        assert_eq!(
            symantec_era_issuer_match("CN=RapidSSL SHA256 CA"),
            Some("RapidSSL"),
        );
    }

    #[test]
    fn does_not_match_digicert() {
        assert_eq!(
            symantec_era_issuer_match("CN=DigiCert SHA2 Secure Server CA, O=DigiCert Inc, C=US"),
            None,
        );
    }

    #[test]
    fn does_not_match_lets_encrypt() {
        assert_eq!(
            symantec_era_issuer_match("CN=R3, O=Let's Encrypt, C=US"),
            None,
        );
    }
}

/// Detect whether the leaf cert carries an Extended Validation policy
/// OID. EV certs include one of a curated list of CA-specific policy
/// OIDs in their certificatePolicies extension (RFC 5280 §4.2.1.4,
/// OID 2.5.29.32). The list below tracks the public CA/B Forum + ETSI
/// EN 319 411-1 disclosures; it covers every public CA that ships EV
/// certs as of 2024-2025.
///
/// We DON'T validate that the EV policy is honored end-to-end (which
/// would require chain-walking against a CA's EV-issuing intermediate
/// AND Mozilla policy enforcement). Presence of the OID on the leaf
/// is the canonical "this CA intends EV" signal; browsers that
/// display EV badges use the same shape of check.
fn has_ev_policy_oid(cert: &X509Certificate) -> bool {
    use x509_parser::extensions::ParsedExtension;
    for ext in cert.extensions() {
        if let ParsedExtension::CertificatePolicies(policies) = ext.parsed_extension() {
            for info in policies.iter() {
                let oid = info.policy_id.to_id_string();
                if EV_POLICY_OIDS.contains(&oid.as_str()) {
                    return true;
                }
            }
        }
    }
    false
}

/// Curated list of policy OIDs the public CAs use to mark Extended
/// Validation certificates. Sources: CA/B Forum EV Guidelines §A,
/// Mozilla Root CA Program (EVPolicyOIDs.inc), ETSI EN 319 411-1.
/// Add new OIDs here when a new EV CA enters the public root program.
const EV_POLICY_OIDS: &[&str] = &[
    // ── DigiCert / Symantec acquired family ─────────────────────────
    "2.16.840.1.114412.2.1",      // DigiCert High Assurance EV CA-1 / -2 / -3
    "2.16.840.1.114412.1.3.0.2",  // DigiCert
    "1.3.6.1.4.1.6334.1.100.1",   // Symantec (cybertrust legacy)
    "2.16.840.1.113733.1.7.23.6", // VeriSign Class 3 EV (legacy, still on chains)
    "2.16.840.1.113733.1.7.48.1", // Thawte EV
    "2.16.840.1.113733.1.7.54",   // GeoTrust EV
    // ── Sectigo / Comodo ─────────────────────────────────────────────
    "1.3.6.1.4.1.6449.1.2.1.5.1", // Sectigo (formerly Comodo) EV SSL
    "1.3.6.1.4.1.782.1.2.1.8.1",  // Network Solutions EV
    "1.3.6.1.4.1.5237.1.1.3",     // CertiSign Certificadora Digital EV
    "1.3.6.1.4.1.7879.13.24.1",   // T-Systems EV
    // ── Entrust ──────────────────────────────────────────────────────
    "2.16.840.1.114028.10.1.2",    // Entrust EV
    "1.3.6.1.4.1.13177.10.1.3.10", // Izenpe EV (also used by Entrust EV per some chains)
    // ── GlobalSign ───────────────────────────────────────────────────
    "1.3.6.1.4.1.4146.1.1", // GlobalSign EV CA - SHA256 G2 / G3 / G4
    // ── GoDaddy / Starfield ──────────────────────────────────────────
    "2.16.840.1.114413.1.7.23.3", // GoDaddy EV
    "2.16.840.1.114414.1.7.23.3", // Starfield EV
    // ── QuoVadis / DigiCert acquired ─────────────────────────────────
    "1.3.6.1.4.1.8024.0.2.100.1.2", // QuoVadis EV
    // ── E-Tugra ──────────────────────────────────────────────────────
    "2.16.792.3.0.4.1.1.4", // E-Tugra EV
    // ── SwissSign ────────────────────────────────────────────────────
    "2.16.756.1.89.1.2.1.1", // SwissSign Gold EV
    // ── TWCA ─────────────────────────────────────────────────────────
    "1.3.6.1.4.1.40869.1.1.22.3", // TWCA EV (Taiwan)
    // ── Buypass ──────────────────────────────────────────────────────
    "2.16.578.1.26.1.3.3", // Buypass Class 3 EV
    // ── WoSign / StartCom (deprecated but historical chains exist) ───
    "1.3.6.1.4.1.36305.2",     // WoSign EV
    "1.3.6.1.4.1.23223.1.1.1", // StartCom EV
    // ── HARICA, Greek academic ───────────────────────────────────────
    "1.3.6.1.4.1.26513.1.1.5", // HARICA EV
    // ── Microsec / e-Szigno ──────────────────────────────────────────
    "1.3.6.1.4.1.21528.2.1.1.7", // Microsec e-Szigno EV
    // ── NetLock ──────────────────────────────────────────────────────
    "1.3.6.1.4.1.3731.7.2.1", // NetLock EV
    // ── Apple Inc. ──────────────────────────────────────────────────
    "1.2.840.113635.100.1.6.1", // Apple Identification (used for some EV)
];

#[cfg(test)]
mod ev_oid_tests {
    use super::EV_POLICY_OIDS;
    use std::collections::HashSet;

    #[test]
    fn ev_policy_oid_table_has_no_duplicates() {
        let mut seen = HashSet::new();
        for oid in EV_POLICY_OIDS {
            assert!(seen.insert(*oid), "duplicate EV OID in table: {oid}");
        }
    }

    #[test]
    fn ev_policy_oid_table_covers_canonical_cas() {
        // Sanity — the table should mention at least these widely-used
        // EV-issuing CA families.
        let blob = EV_POLICY_OIDS.join(" ");
        for must_contain in &[
            "2.16.840.1.114412", // DigiCert family root prefix
            "1.3.6.1.4.1.6449",  // Sectigo / Comodo
            "1.3.6.1.4.1.4146",  // GlobalSign
            "2.16.840.1.114413", // GoDaddy
        ] {
            assert!(
                blob.contains(must_contain),
                "EV OID table missing {must_contain}",
            );
        }
    }
}

/// Detect dangerous wildcard SAN patterns. Returns a human-readable
/// reason when the wildcard is policy-violating, or None when the SAN
/// is safe.
///
/// Checks:
///   - Multi-label wildcard (e.g. *.*.example.com) violates RFC 6125
///     §6.4.3 — wildcards may only replace the LEFTMOST label.
///   - Wildcard at a public-suffix level (*.com, *.co.uk, *.io, etc.)
///     violates CA/B Forum BR §3.2.2.6. We use a curated list of
///     common TLDs + eTLDs; not exhaustive but covers the cases that
///     show up in practice.
fn dangerous_wildcard_reason(san: &str) -> Option<&'static str> {
    if !san.starts_with("*.") {
        return None;
    }
    let rest = &san[2..];
    // Multi-label wildcard.
    if rest.contains('*') {
        return Some(
            "multi-label wildcard (RFC 6125 §6.4.3 — wildcards may only replace the leftmost label)",
        );
    }
    // Public-suffix wildcard. The list below covers IANA-root TLDs
    // most-commonly seen plus the eTLD-style multi-label suffixes
    // browsers also treat as "public" via the Public Suffix List
    // project.
    let lower = rest.to_ascii_lowercase();
    if PUBLIC_SUFFIX_BLOCKLIST.iter().any(|s| lower == *s) {
        return Some(
            "wildcard at a public-suffix level (CA/B Forum BR §3.2.2.6 prohibits this — would cover every subdomain on the TLD)",
        );
    }
    None
}

/// Curated subset of the Public Suffix List — the suffixes a wildcard
/// must NOT directly attach to. Browsers / CAs source from the full
/// PSL (publicsuffix.org). cy-tls keeps a curated cut focused on the
/// suffixes that appear in real-world cert issuance attempts.
const PUBLIC_SUFFIX_BLOCKLIST: &[&str] = &[
    // ── Generic TLDs ────────────────────────────────────────────────
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name", "pro", "museum", "aero",
    "coop", "jobs", "mobi", "tel", "travel", "asia", "cat", "xxx",
    // ── Common new gTLDs that often appear in misissuance attempts ──
    "io", "ai", "app", "dev", "cloud", "tech", "online", "site", "shop", "store", "blog", "news",
    "tv", "fm", "me", "co",
    // ── Country-code TLDs (most populous) ───────────────────────────
    "uk", "us", "de", "fr", "it", "es", "nl", "se", "ch", "be", "at", "dk", "no", "fi", "ie", "pl",
    "ru", "ua", "cz", "gr", "hu", "ro", "tr", "il", "br", "ar", "mx", "cl", "co", "pe", "ca", "au",
    "nz", "jp", "kr", "cn", "tw", "hk", "sg", "my", "th", "id", "ph", "vn", "in", "pk", "bd", "lk",
    "za", "eg", "ng", "ke", "ma",
    // ── Common eTLD-style multi-label public suffixes ───────────────
    "co.uk", "ac.uk", "gov.uk", "org.uk", "ltd.uk", "plc.uk", "net.uk", "com.au", "net.au",
    "org.au", "edu.au", "gov.au", "co.nz", "net.nz", "org.nz", "ac.nz", "govt.nz", "co.in",
    "net.in", "org.in", "ac.in", "gov.in", "edu.in", "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.kr", "ne.kr", "or.kr", "go.kr", "co.za", "org.za", "net.za", "gov.za", "com.br", "net.br",
    "org.br", "gov.br", "edu.br", "com.mx", "net.mx", "org.mx", "gob.mx", "com.sg", "net.sg",
    "org.sg", "gov.sg", "com.hk", "net.hk", "org.hk", "com.tw", "net.tw", "org.tw", "gov.tw",
];

#[cfg(test)]
mod dangerous_wildcard_tests {
    use super::dangerous_wildcard_reason;

    #[test]
    fn safe_wildcards() {
        assert!(dangerous_wildcard_reason("*.example.com").is_none());
        assert!(dangerous_wildcard_reason("*.foo.example.com").is_none());
        assert!(dangerous_wildcard_reason("example.com").is_none()); // no wildcard
    }

    #[test]
    fn rejects_public_suffix_wildcards() {
        assert!(dangerous_wildcard_reason("*.com").is_some());
        assert!(dangerous_wildcard_reason("*.io").is_some());
        assert!(dangerous_wildcard_reason("*.co.uk").is_some());
        assert!(dangerous_wildcard_reason("*.gov").is_some());
    }

    #[test]
    fn rejects_multi_label_wildcards() {
        assert!(dangerous_wildcard_reason("*.*.example.com").is_some());
        assert!(dangerous_wildcard_reason("*.foo.*.example.com").is_some());
    }

    #[test]
    fn case_insensitive_match() {
        assert!(dangerous_wildcard_reason("*.COM").is_some());
        assert!(dangerous_wildcard_reason("*.Co.UK").is_some());
    }
}

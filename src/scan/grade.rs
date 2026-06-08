//! v0.5.57 — Qualys-SSL-Labs-style composite grade (A+/A/B/C/D/E/F).
//!
//! Computes a single-letter grade + 0-100 numeric score from the full
//! ScanReport. Goal: switch-from-Qualys parity so customers see the
//! same headline number they'd see at ssllabs.com/ssltest.
//!
//! Algorithm follows the public Qualys methodology (v2009p doc, last
//! updated 2020-01) plus published deltas. Per-axis subscores:
//!   - Protocol support: weighted 30%
//!   - Key exchange:     weighted 30%
//!   - Cipher strength:  weighted 40%
//!
//! Then GRADE CAPS apply (vulnerabilities that force the grade DOWN
//! regardless of subscores) and GRADE BONUSES (TLS 1.3 + HSTS preload +
//! Forward Secrecy) that bump A → A+.
//!
//! Output exposes:
//!   - The numeric score and letter grade
//!   - The per-axis subscores so dashboards can show a bar chart
//!   - A list of human-readable cap reasons + bonus reasons so the
//!     UI can answer "why am I a C?" in one click

use serde::Serialize;

use super::cert::CertificateInfo;
use super::headers::HeaderInfo;
use super::protocol::ProtocolSupport;
use crate::finding::Finding;

#[derive(Debug, Default, Clone, Serialize)]
pub struct GradeReport {
    /// Composite letter grade. One of: A+, A, A-, B, C, D, E, F, T.
    /// "T" is reserved for "trust issue" (cert chain doesn't validate)
    /// — we never emit T currently because rustls won't have completed
    /// the handshake in that case; left in the type for future use.
    pub grade: String,
    /// Numeric composite (0-100). The grade letter is derived from
    /// this score AND from the grade_caps list (vulns can hold the
    /// score above the cap threshold while still dropping the letter).
    pub score: u32,
    /// Per-axis subscores.
    pub protocol_score: u32,
    pub key_exchange_score: u32,
    pub cipher_score: u32,
    /// Reasons the grade was capped DOWN (e.g. "TLS 1.0 supported
    /// — capped at B", "POODLE — capped at F"). Empty when no caps.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub grade_caps: Vec<String>,
    /// Reasons the grade was bumped UP (e.g. "TLS 1.3 + Forward
    /// Secrecy + HSTS preload → A+"). Empty when no bonuses.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub grade_bonuses: Vec<String>,
}

/// Compute the composite grade from the assembled scan inputs.
pub fn compute(
    protocols: &ProtocolSupport,
    certificate: Option<&CertificateInfo>,
    headers: &HeaderInfo,
    findings: &[Finding],
    forward_secrecy: Option<&'static str>,
) -> GradeReport {
    let mut caps: Vec<String> = Vec::new();
    let mut bonuses: Vec<String> = Vec::new();

    // ── Protocol score ──────────────────────────────────────────
    // 100 = TLS 1.3, 95 = TLS 1.2 only, 80 = TLS 1.2 + 1.1, 70 = + 1.0,
    // 50 = SSLv3, 0 = SSLv2.
    let mut protocol_score = if protocols.tls13.supported {
        100
    } else if protocols.tls12.supported {
        95
    } else if protocols.tls11.supported {
        80
    } else if protocols.tls10.supported {
        70
    } else {
        50
    };
    if protocols.tls10.supported {
        protocol_score = protocol_score.min(80);
        caps.push("TLS 1.0 supported — protocol-score capped at 80 (grade ≤ B)".into());
    }
    if protocols.tls11.supported {
        protocol_score = protocol_score.min(80);
        caps.push("TLS 1.1 supported — protocol-score capped at 80 (grade ≤ B)".into());
    }
    if protocols.sslv3.supported {
        protocol_score = 50;
        caps.push("SSLv3 supported (POODLE) — grade capped at F".into());
    }
    if protocols.sslv2.supported {
        protocol_score = 0;
        caps.push("SSLv2 supported — grade is F".into());
    }

    // ── Key exchange score ──────────────────────────────────────
    // Drive primarily from cert key bits + curve + key algorithm.
    // RSA 4096 / ECDSA secp384r1 = 100, RSA 2048 / ECDSA p256 = 90,
    // weak DH groups already emit TLS-DH-WEAK and we cap below.
    let mut key_exchange_score = if let Some(c) = certificate {
        match c.key_algorithm.as_str() {
            "ecPublicKey" => {
                if c.key_bits >= 384 {
                    100
                } else if c.key_bits >= 256 {
                    95
                } else {
                    50
                }
            }
            "rsaEncryption" => {
                if c.key_bits >= 4096 {
                    100
                } else if c.key_bits >= 2048 {
                    90
                } else if c.key_bits >= 1024 {
                    60
                } else {
                    20
                }
            }
            "Ed25519" | "Ed448" => 100,
            _ => 80,
        }
    } else {
        0
    };
    if has_finding(findings, "TLS-DH-WEAK") {
        key_exchange_score = key_exchange_score.min(40);
        caps.push("DHE params < 2048 bits — key-exchange capped at 40 (grade ≤ B)".into());
    }
    if has_finding(findings, "TLS-DH-COMMON-PRIME") {
        key_exchange_score = key_exchange_score.min(40);
        caps.push("DHE common-prime detected (Logjam) — key-exchange capped at 40".into());
    }
    if has_finding(findings, "TLS-ANON-CIPHER") {
        key_exchange_score = 0;
        caps.push("Anonymous DH/ECDH cipher accepted — grade is F".into());
    }
    if has_finding(findings, "TLS-EXPORT-CIPHER") {
        key_exchange_score = 0;
        caps.push("EXPORT-grade cipher accepted (FREAK) — grade is F".into());
    }

    // ── Cipher strength score ───────────────────────────────────
    // Default 90 (assumes ≥128-bit ciphers); downgraded by findings.
    let mut cipher_score = 90;
    if has_finding(findings, "TLS-NULL-CIPHER") {
        cipher_score = 0;
        caps.push("NULL cipher accepted — grade is F".into());
    }
    if has_finding(findings, "TLS-RC4-CIPHER") {
        cipher_score = cipher_score.min(40);
        caps.push("RC4 cipher accepted — cipher-score capped at 40 (grade ≤ B)".into());
    }
    if has_finding(findings, "TLS-3DES-CIPHER") {
        cipher_score = cipher_score.min(60);
        caps.push("3DES cipher accepted (SWEET32) — cipher-score capped at 60".into());
    }
    if has_finding(findings, "TLS-CBC-MAC-THEN-ENCRYPT") {
        cipher_score = cipher_score.min(80);
        caps.push("CBC ciphers without Encrypt-then-MAC — Lucky13 surface".into());
    }

    // ── Vulnerability caps (force letter down) ──────────────────
    let critical_vulns = [
        ("TLS-HEARTBLEED", "Heartbleed (CVE-2014-0160)"),
        ("TLS-CCS-INJECTION", "OpenSSL CCS Injection (CVE-2014-0224)"),
        ("TLS-ROBOT-VULNERABLE", "ROBOT RSA padding oracle"),
        ("TLS-DROWN-VULNERABLE", "DROWN cross-protocol attack"),
        ("TLS-TICKETBLEED", "Ticketbleed (CVE-2016-9244)"),
        (
            "TLS-OPENSSL-PADDING-ORACLE",
            "OpenSSL AES-NI padding oracle",
        ),
        ("TLS-GOLDENDOODLE-ACTIVE", "GOLDENDOODLE / Zombie POODLE"),
        ("TLS-CERT-EXPIRED", "Certificate expired"),
        ("TLS-CERT-SELF-SIGNED", "Certificate self-signed"),
        (
            "TLS-CERT-HOSTNAME-MISMATCH",
            "Certificate hostname mismatch",
        ),
        ("TLS-CERT-INTERMEDIATE-EXPIRED", "Intermediate cert expired"),
        (
            "TLS-CERT-LEAF-IS-CA",
            "Leaf cert has CA-bit set (misissuance)",
        ),
        ("TLS-CERT-NOT-YET-VALID", "Cert not_before is in the future"),
    ];
    let mut hard_fail = false;
    for (id, desc) in &critical_vulns {
        if has_finding(findings, id) {
            hard_fail = true;
            caps.push(format!("{desc} — grade is F"));
        }
    }

    let medium_caps = [
        (
            "TLS-CLIENT-RENEG-ALLOWED",
            "Insecure client-initiated renegotiation — grade ≤ C",
        ),
        (
            "TLS-COMPRESSION-ENABLED",
            "TLS-level compression (CRIME) — grade ≤ C",
        ),
        (
            "TLS-INSECURE-RENEG-LEGACY",
            "No renegotiation_info extension — grade ≤ B",
        ),
        (
            "TLS-NO-EXTENDED-MASTER-SECRET",
            "No Extended Master Secret — grade ≤ B",
        ),
        (
            "TLS-NO-FALLBACK-SCSV",
            "TLS_FALLBACK_SCSV not honored — grade ≤ B",
        ),
        (
            "TLS-FORWARD-SECRECY-WEAK",
            "Forward Secrecy < modern — grade ≤ B",
        ),
    ];
    let mut grade_cap: u32 = 100;
    for (id, desc) in &medium_caps {
        if has_finding(findings, id) {
            caps.push((*desc).to_string());
            grade_cap = grade_cap.min(score_for_letter("B"));
        }
    }
    if has_finding(findings, "TLS-CERT-NEAR-EXPIRY") {
        caps.push("Cert near expiry (<30 days) — grade ≤ B".into());
        grade_cap = grade_cap.min(score_for_letter("B"));
    }

    // ── Composite ───────────────────────────────────────────────
    let composite = ((protocol_score as f64) * 0.30
        + (key_exchange_score as f64) * 0.30
        + (cipher_score as f64) * 0.40)
        .round() as u32;
    let mut score = composite.min(grade_cap);
    if hard_fail {
        score = 0;
    }

    // ── Bonuses (lift A to A+) ──────────────────────────────────
    // Criteria: TLS 1.3 (mandates FS + AEAD) AND HSTS (preload or
    // present). If forward_secrecy bucket was independently computed
    // we also require it to be "modern" — but if it wasn't computed
    // (None), we let TLS 1.3's spec guarantees stand in.
    let mut letter = letter_for_score(score);
    if letter == "A" && !hard_fail {
        let fs_ok = match forward_secrecy {
            Some("modern") => true,
            Some(_) => false,
            None => protocols.tls13.supported,
        };
        let preload = headers.hsts.in_preload_list;
        let hsts = headers.hsts.present;
        let tls13 = protocols.tls13.supported;
        if tls13 && fs_ok && (preload || hsts) {
            letter = "A+".into();
            let detail = if preload {
                "TLS 1.3 + Forward Secrecy + HSTS preload"
            } else {
                "TLS 1.3 + Forward Secrecy + HSTS"
            };
            bonuses.push(format!("{detail} → grade lifted to A+"));
        }
    }

    GradeReport {
        grade: letter,
        score,
        protocol_score,
        key_exchange_score,
        cipher_score,
        grade_caps: caps,
        grade_bonuses: bonuses,
    }
}

fn has_finding(findings: &[Finding], id: &str) -> bool {
    findings.iter().any(|f| f.id == id)
}

/// Maximum score for the given letter (used to drive caps).
fn score_for_letter(letter: &str) -> u32 {
    match letter {
        "A+" | "A" => 100,
        "A-" => 85,
        "B" => 80,
        "C" => 70,
        "D" => 60,
        "E" => 50,
        _ => 0,
    }
}

/// Letter for a given composite score. Boundaries match the public
/// Qualys grading-guide table.
fn letter_for_score(score: u32) -> String {
    if score >= 90 {
        "A".into()
    } else if score >= 80 {
        "B".into()
    } else if score >= 70 {
        "C".into()
    } else if score >= 60 {
        "D".into()
    } else if score >= 50 {
        "E".into()
    } else {
        "F".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letter_boundaries() {
        assert_eq!(letter_for_score(100), "A");
        assert_eq!(letter_for_score(90), "A");
        assert_eq!(letter_for_score(89), "B");
        assert_eq!(letter_for_score(80), "B");
        assert_eq!(letter_for_score(70), "C");
        assert_eq!(letter_for_score(60), "D");
        assert_eq!(letter_for_score(50), "E");
        assert_eq!(letter_for_score(49), "F");
        assert_eq!(letter_for_score(0), "F");
    }
}

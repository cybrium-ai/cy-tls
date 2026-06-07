//! Stable finding ID catalog. These IDs MUST NOT be renamed across
//! cy-tls releases — the platform's `cytls_runner.py` enrichment table
//! keys off them for control mapping.
//!
//! See `docs/finding-ids.md` for the human-facing catalog.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: &'static str,
    pub host: String,
    pub severity: Severity,
    pub title: &'static str,
    pub evidence: String,
    pub controls: Vec<&'static str>,
}

/// Catalog of every stable finding ID cy-tls will ever emit. Adding a
/// new ID is a deliberate act — bump the cy-tls minor version, update
/// `docs/finding-ids.md`, and add the enrichment row to
/// `backend/tools_runtime/cytls_runner.py`.
pub const FINDING_CATALOG: &[(&str, Severity, &str)] = &[
    // ── Reachability ────────────────────────────────────────────────
    ("TLS-UNREACHABLE", Severity::High, "Target did not accept TCP connection"),

    // ── Protocol versions ───────────────────────────────────────────
    ("TLS-SSLV2",            Severity::Critical, "SSLv2 accepted"),
    ("TLS-SSLV3",            Severity::Critical, "SSLv3 accepted (POODLE)"),
    ("TLS-WEAK-VERSION-1.0", Severity::High,     "TLS 1.0 accepted"),
    ("TLS-WEAK-VERSION-1.1", Severity::High,     "TLS 1.1 accepted"),
    ("TLS-NO-TLS13",         Severity::Info,     "TLS 1.3 unavailable"),

    // ── Cipher suites ───────────────────────────────────────────────
    ("TLS-RC4-CIPHER",          Severity::Critical, "RC4 cipher suite accepted"),
    ("TLS-3DES-CIPHER",         Severity::High,     "3DES (SWEET32) accepted"),
    ("TLS-NULL-CIPHER",         Severity::Critical, "NULL cipher accepted"),
    ("TLS-EXPORT-CIPHER",       Severity::Critical, "EXPORT-grade cipher accepted (FREAK)"),
    ("TLS-ANON-CIPHER",         Severity::Critical, "Anonymous DH/ECDH cipher accepted"),
    ("TLS-CBC-MAC-THEN-ENCRYPT", Severity::Medium,  "CBC ciphers without EtM extension (Lucky13)"),

    // ── Key exchange ────────────────────────────────────────────────
    ("TLS-DH-WEAK",         Severity::High,   "DHE params <2048 bits (Logjam)"),
    ("TLS-DH-COMMON-PRIME", Severity::High,   "DHE using known common prime"),
    ("TLS-CURVE-WEAK",      Severity::Medium, "ECDHE curve <256 bits"),

    // ── Certificate ─────────────────────────────────────────────────
    ("TLS-CERT-EXPIRED",            Severity::Critical, "Certificate expired"),
    ("TLS-CERT-NEAR-EXPIRY",        Severity::Medium,   "Certificate expires within 30 days"),
    ("TLS-CERT-HOSTNAME-MISMATCH",  Severity::High,     "Subject/SAN does not include target hostname"),
    ("TLS-CERT-SELF-SIGNED",        Severity::Critical, "Certificate self-signed"),
    ("TLS-CERT-WEAK-SIGNATURE",     Severity::High,     "Signature algorithm SHA-1 or MD5"),
    ("TLS-CERT-WEAK-KEY",           Severity::High,     "RSA key <2048 or ECC <256 bits"),
    ("TLS-CHAIN-INCOMPLETE",        Severity::High,     "Intermediate certificate missing from chain"),

    // ── OCSP / SCT ──────────────────────────────────────────────────
    ("TLS-OCSP-NOT-STAPLED",     Severity::Low,      "OCSP stapling not offered"),
    ("TLS-OCSP-REVOKED",         Severity::Critical, "OCSP response says certificate revoked"),
    ("TLS-SCT-MISSING",          Severity::Medium,   "No SCT in cert, OCSP, or TLS extension"),
    ("TLS-MUST-STAPLE-VIOLATED", Severity::High,     "Cert has must-staple but stapling not offered"),

    // ── TLS 1.3 surface ─────────────────────────────────────────────
    ("TLS-ZERO-RTT-ACCEPTED", Severity::Medium, "TLS 1.3 0-RTT early-data accepted on state-changing endpoint"),

    // ── Renegotiation / compression / heartbeat ─────────────────────
    ("TLS-CLIENT-RENEG-ALLOWED", Severity::High,   "Insecure client-initiated renegotiation accepted"),
    ("TLS-COMPRESSION-ENABLED",  Severity::High,   "TLS-level compression enabled (CRIME)"),
    ("TLS-HEARTBEAT-ENABLED",    Severity::Medium, "Heartbeat extension offered (Heartbleed surface)"),

    // ── Padding oracle / cross-protocol ─────────────────────────────
    ("TLS-ROBOT-VULNERABLE",  Severity::Critical, "RSA padding oracle (ROBOT) detected"),
    ("TLS-DROWN-VULNERABLE",  Severity::Critical, "Server shares cert with SSLv2 server (DROWN)"),
    ("TLS-HEARTBLEED",        Severity::Critical, "Heartbleed (CVE-2014-0160) — server leaks memory via heartbeat over-read"),
    ("TLS-CCS-INJECTION",     Severity::Critical, "OpenSSL CCS Injection (CVE-2014-0224) — server accepts ChangeCipherSpec before handshake completion"),
    ("TLS-TICKETBLEED",       Severity::High,     "Ticketbleed (CVE-2016-9244) — F5 BIG-IP leaks process memory via session ID echo overflow"),
    ("TLS-OPENSSL-PADDING-ORACLE", Severity::High, "OpenSSL AES-NI padding oracle (CVE-2016-2107) — alert leakage on invalid CBC padding"),
    ("TLS-CBC-ORACLE-FAMILY-FP",   Severity::High, "CBC padding-oracle family eligibility + product fingerprint matches a known-vulnerable vendor"),

    // ── HSTS ────────────────────────────────────────────────────────
    ("HSTS-MISSING",         Severity::Medium, "Strict-Transport-Security header not sent"),
    ("HSTS-SHORT-MAX-AGE",   Severity::Low,    "HSTS max-age <6 months"),
    ("HSTS-NO-SUBDOMAINS",   Severity::Low,    "HSTS missing includeSubDomains"),
    ("HSTS-NOT-PRELOADED",   Severity::Info,   "HSTS-preload-eligible site not on Chromium preload list"),

    // ── Deprecated trust hardening (informational) ──────────────────
    ("EXPECT-CT-MISSING", Severity::Info, "Expect-CT header absent (deprecated)"),

    // ── Cipher policy + downgrade protection (v0.4.1) ───────────────
    ("TLS-CIPHER-CLIENT-PREFERENCE-ONLY", Severity::Low,    "Server follows client's cipher preference order — weak ciphers may negotiate when legacy clients prefer them"),
    ("TLS-FORWARD-SECRECY-WEAK",          Severity::Medium, "Forward Secrecy bucket below 'modern' — legacy non-FS key-exchange ciphers accepted"),
    ("TLS-NO-FALLBACK-SCSV",              Severity::Medium, "Server accepts TLS_FALLBACK_SCSV in a downgraded ClientHello — no protection against POODLE-style version-downgrade attacks"),

    // ── Renegotiation + deprecated trust hardening (v0.4.2) ─────────
    ("TLS-INSECURE-RENEG-LEGACY", Severity::High, "Server does not advertise renegotiation_info extension — legacy CVE-2009-3555 plaintext-injection surface"),
    ("TLS-HPKP-PRESENT",          Severity::Info, "Public-Key-Pins header present (HPKP is deprecated and ignored by modern browsers — informational only)"),

    // ── Distrusted CA chains (v0.4.3) ───────────────────────────────
    ("TLS-SYMANTEC-DISTRUSTED-CA", Severity::High, "Leaf certificate is issued by a Symantec-era CA family distrusted by Chrome / Firefox since 2018 — connections from modern browsers will fail"),

    // ── Lucky13 timing-side-channel (v0.4.5) ────────────────────────
    ("TLS-LUCKY13-LIKELY", Severity::Medium, "Server fingerprint matches an OpenSSL release predating the constant-time CBC decrypt fix (1.0.1g, April 2014) and accepts TLS 1.2 + CBC ciphers — Lucky13 (CVE-2013-0169) timing-side-channel plaintext recovery is likely feasible"),
];

/// Look up the canonical title + default severity for a finding ID. Panics
/// if the ID isn't in the catalog — every emitter MUST use a registered ID.
pub fn lookup(id: &'static str) -> (Severity, &'static str) {
    for (cat_id, sev, title) in FINDING_CATALOG {
        if *cat_id == id {
            return (*sev, *title);
        }
    }
    panic!("finding ID not registered in FINDING_CATALOG: {id}");
}

/// Convenience constructor — pulls the canonical severity + title from the
/// catalog so emitters don't accidentally drift.
pub fn make(id: &'static str, host: impl Into<String>, evidence: impl Into<String>) -> Finding {
    let (severity, title) = lookup(id);
    Finding {
        id,
        host: host.into(),
        severity,
        title,
        evidence: evidence.into(),
        controls: crate::controls::for_id(id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_catalog_id_has_unique_name() {
        let mut seen = std::collections::HashSet::new();
        for (id, _, _) in FINDING_CATALOG {
            assert!(seen.insert(*id), "duplicate finding ID: {id}");
        }
    }

    #[test]
    fn catalog_count_matches_design_doc() {
        // 37 in v0.1.0; v0.2.13 added TLS-HEARTBLEED; v0.3.0 added TLS-CCS-INJECTION;
        // v0.3.1 added TLS-TICKETBLEED; v0.3.2 added TLS-OPENSSL-PADDING-ORACLE;
        // v0.3.6 added TLS-CBC-ORACLE-FAMILY-FP. v0.4.1 added TLS-CIPHER-CLIENT-PREFERENCE-ONLY,
        // TLS-FORWARD-SECRECY-WEAK, TLS-NO-FALLBACK-SCSV. v0.4.2 added
        // TLS-INSECURE-RENEG-LEGACY, TLS-HPKP-PRESENT. v0.4.3 added
        // TLS-SYMANTEC-DISTRUSTED-CA. v0.4.5 added TLS-LUCKY13-LIKELY.
        assert_eq!(
            FINDING_CATALOG.len(),
            49,
            "FINDING_CATALOG size drifted from spec"
        );
    }
}

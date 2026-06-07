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
    ("TLS-ZERO-RTT-ACCEPTED", Severity::Medium, "TLS 1.3 0-RTT early-data accepted — any state-changing request sent in the early-data flight is exposed to replay-attack capture-and-resubmit unless mitigated app-side"),

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

    // ── GOLDENDOODLE / Zombie POODLE active probe (v0.5.0) ──────────
    ("TLS-GOLDENDOODLE-ACTIVE", Severity::High, "Active record-layer probe confirmed a CBC oracle in the GOLDENDOODLE / Zombie POODLE family: server returned distinct alert types for invalid-MAC vs invalid-padding records over an established TLS 1.2 CBC session — Vaudenay-style plaintext recovery is feasible"),

    // ── HTTP-level compression eligibility (v0.5.1) ─────────────────
    ("TLS-BREACH-ELIGIBLE", Severity::Low, "Server returns compressed HTTP responses (Content-Encoding: gzip/br/deflate/zstd) — BREACH (CVE-2013-3587) attack surface eligibility. Whether the attack is exploitable depends on whether the application also reflects attacker-controlled input alongside a secret"),

    // ── Triple Handshake / Extended Master Secret (v0.5.2) ──────────
    ("TLS-NO-EXTENDED-MASTER-SECRET", Severity::Medium, "Server does not support the Extended Master Secret extension (RFC 7627, ext 0x0017) — Triple Handshake (CVE-2014-1295) cross-session key reuse is possible"),

    // ── HTTP/2 ALPN posture (v0.5.5) ────────────────────────────────
    ("TLS-H2C-UPGRADE-ACCEPTED", Severity::Medium, "Server inside the TLS tunnel accepted an HTTP/1.1 Upgrade: h2c request with 101 Switching Protocols — typically indicates a reverse-proxy / TLS-terminator misconfig that allows protocol smuggling between the front-end and an h2c-capable backend"),

    // ── HTTP/2 Rapid Reset eligibility (v0.5.9) ─────────────────────
    ("TLS-HTTP2-RAPID-RESET-ELIGIBLE", Severity::Low, "Server HTTP/2 SETTINGS lacks MAX_CONCURRENT_STREAMS or sets it ≥ 1024 — eligible surface for CVE-2023-44487 Rapid Reset CPU-exhaustion DoS. Passive eligibility check only (no flood traffic sent); confirmation requires rate-limit testing on RST_STREAM frames"),

    // ── CT log diversity (v0.5.11) ──────────────────────────────────
    ("TLS-CT-INSUFFICIENT-DIVERSITY", Severity::Low, "Embedded SCTs in the leaf cert come from fewer than 2 distinct CT log operators — Chrome's CT policy (Sep 2022 onwards) requires ≥2 INDEPENDENT operators to defeat a single-operator collusion attack on the log"),

    // ── HTTP/2 header-list DoS surface (v0.5.12) ────────────────────
    ("TLS-HTTP2-NO-HEADER-LIST-LIMIT", Severity::Low, "Server HTTP/2 SETTINGS lacks MAX_HEADER_LIST_SIZE or sets it > 1 MiB — exposes the HPACK-bomb / large-header-flood DoS family (CVE-2019-9516 et al)"),

    // ── Cert lifetime BR cap (v0.5.13) ──────────────────────────────
    ("TLS-CERT-EXCESSIVE-LIFETIME", Severity::Medium, "Leaf certificate lifetime exceeds CA/B Forum BR §6.3.2 cap of 398 days (Apple / Chrome / Mozilla enforce this in browsers since Sep 2020) — connections from modern browsers will be rejected if the cert was issued after the cap took effect"),

    // ── Cert chain depth (v0.5.17) ──────────────────────────────────
    ("TLS-CERT-CHAIN-DEEP", Severity::Low, "Server presented more than 5 certificates in the TLS chain — typical is 2-4 (leaf + 1-3 intermediates). Deep chains indicate cross-signed sprawl, stale intermediates, or misconfig; prune to reduce handshake bandwidth and validation cost"),

    // ── SAN wildcard policy (v0.5.18) ───────────────────────────────
    ("TLS-CERT-DANGEROUS-WILDCARD", Severity::High, "Leaf cert SAN includes a dangerous wildcard: multi-label (e.g. *.*.example.com — violates RFC 6125 §6.4.3) OR attached to a public suffix (e.g. *.com — violates CA/B Forum BR §3.2.2.6 — would cover every subdomain on that TLD)"),

    // ── Extended Key Usage validation (v0.5.19) ─────────────────────
    ("TLS-CERT-MISSING-SERVER-AUTH-EKU", Severity::High, "Leaf cert Extended Key Usage extension does not include id-kp-serverAuth (1.3.6.1.5.5.7.3.1) — CA/B Forum BR §7.1.2.7 requires this for publicly-trusted TLS server certs; modern browsers reject leafs that lack it"),

    // ── Cert serial entropy (v0.5.21) ───────────────────────────────
    ("TLS-CERT-WEAK-SERIAL-ENTROPY", Severity::Medium, "Cert serial has < 64 bits of entropy — CA/B Forum BR §7.1 requires ≥64 bits of CA-generated entropy. Short / sequential serials are a Symantec-era footgun (prohibited industry-wide in 2016) and break browser chain-validation heuristics"),

    // ── Basic Constraints CA-bit (v0.5.22) ──────────────────────────
    ("TLS-CERT-LEAF-IS-CA", Severity::Critical, "Leaf certificate has BasicConstraints cA: TRUE — end-entity certs MUST NOT have this flag set per RFC 5280 §4.2.1.9; allowing it means the leaf could sign sub-certs that chain to the same root. Catastrophic misissuance pattern (Comodo 2008, ANSSI 2013)"),

    // ── Authority Key Identifier (v0.5.23) ──────────────────────────
    ("TLS-CERT-NO-AKI", Severity::Low, "Non-self-signed cert lacks the AuthorityKeyIdentifier extension (RFC 5280 §4.2.1.1) — chain validators must fall back to issuer-DN matching, which is ambiguous when the issuer rotates keys or runs parallel intermediates"),
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
        // v0.5.0 added TLS-GOLDENDOODLE-ACTIVE. v0.5.1 added
        // TLS-BREACH-ELIGIBLE. v0.5.2 added TLS-NO-EXTENDED-MASTER-SECRET.
        // v0.5.5 added TLS-H2C-UPGRADE-ACCEPTED. v0.5.9 added
        // TLS-HTTP2-RAPID-RESET-ELIGIBLE. v0.5.11 added
        // TLS-CT-INSUFFICIENT-DIVERSITY. v0.5.12 added
        // TLS-HTTP2-NO-HEADER-LIST-LIMIT. v0.5.13 added
        // TLS-CERT-EXCESSIVE-LIFETIME. v0.5.17 added
        // TLS-CERT-CHAIN-DEEP. v0.5.18 added
        // TLS-CERT-DANGEROUS-WILDCARD. v0.5.19 added
        // TLS-CERT-MISSING-SERVER-AUTH-EKU. v0.5.21 added
        // TLS-CERT-WEAK-SERIAL-ENTROPY. v0.5.22 added
        // TLS-CERT-LEAF-IS-CA. v0.5.23 added TLS-CERT-NO-AKI.
        assert_eq!(
            FINDING_CATALOG.len(),
            63,
            "FINDING_CATALOG size drifted from spec"
        );
    }
}

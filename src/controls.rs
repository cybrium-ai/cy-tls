//! Control mapping table. Per-finding-ID list of compliance / framework
//! controls the finding maps to. Kept in cy-tls (not the platform) so
//! that SARIF / standalone JSON output is self-describing.

pub fn for_id(id: &str) -> Vec<&'static str> {
    match id {
        // ── TLS version surface ─────────────────────────────────────
        "TLS-SSLV2" | "TLS-SSLV3" | "TLS-WEAK-VERSION-1.0" | "TLS-WEAK-VERSION-1.1" => vec![
            "NIST 800-53 SC-8",
            "NIST 800-53 SC-13",
            "NIST 800-53 SC-23",
            "PCI DSS 4.2.1",
            "ISO 27001 A.8.24",
            "CIS Benchmark §3.1",
        ],

        // ── Cipher / key exchange ───────────────────────────────────
        "TLS-RC4-CIPHER"
        | "TLS-3DES-CIPHER"
        | "TLS-NULL-CIPHER"
        | "TLS-EXPORT-CIPHER"
        | "TLS-ANON-CIPHER"
        | "TLS-CBC-MAC-THEN-ENCRYPT"
        | "TLS-DH-WEAK"
        | "TLS-DH-COMMON-PRIME"
        | "TLS-CURVE-WEAK" => vec!["NIST 800-53 SC-13", "PCI DSS 4.2.1", "ISO 27001 A.8.24"],

        // ── Certificate hygiene ─────────────────────────────────────
        "TLS-CERT-EXPIRED"
        | "TLS-CERT-NEAR-EXPIRY"
        | "TLS-CERT-HOSTNAME-MISMATCH"
        | "TLS-CERT-SELF-SIGNED"
        | "TLS-CERT-WEAK-SIGNATURE"
        | "TLS-CERT-WEAK-KEY"
        | "TLS-CHAIN-INCOMPLETE" => vec![
            "NIST 800-53 SC-12",
            "NIST 800-53 SC-17",
            "PCI DSS 4.2.1.1",
            "ISO 27001 A.10.1.2",
        ],

        // ── OCSP / SCT ──────────────────────────────────────────────
        "TLS-OCSP-NOT-STAPLED"
        | "TLS-OCSP-REVOKED"
        | "TLS-SCT-MISSING"
        | "TLS-MUST-STAPLE-VIOLATED" => {
            vec!["NIST 800-53 SC-17", "CA/B Forum Baseline Requirements §4.9"]
        }

        // ── TLS 1.3 0-RTT ───────────────────────────────────────────
        "TLS-ZERO-RTT-ACCEPTED" => vec!["NIST SP 800-52 Rev. 2 §3.3.4", "OWASP ASVS 9.2.4"],

        // ── Cross-protocol attacks ──────────────────────────────────
        "TLS-CLIENT-RENEG-ALLOWED"
        | "TLS-COMPRESSION-ENABLED"
        | "TLS-HEARTBEAT-ENABLED"
        | "TLS-ROBOT-VULNERABLE"
        | "TLS-DROWN-VULNERABLE"
        | "TLS-HEARTBLEED"
        | "TLS-CCS-INJECTION"
        | "TLS-TICKETBLEED"
        | "TLS-OPENSSL-PADDING-ORACLE"
        | "TLS-CBC-ORACLE-FAMILY-FP" => vec!["NIST 800-53 SC-13", "PCI DSS 4.2.1"],

        // ── HSTS ────────────────────────────────────────────────────
        "HSTS-MISSING" | "HSTS-SHORT-MAX-AGE" | "HSTS-NO-SUBDOMAINS" | "HSTS-NOT-PRELOADED" => {
            vec!["NIST 800-53 SC-8", "OWASP ASVS 9.1"]
        }

        // ── Reachability + deprecated headers ───────────────────────
        "TLS-UNREACHABLE" | "TLS-NO-TLS13" | "EXPECT-CT-MISSING" => vec![],

        // ── Cipher policy + downgrade protection (v0.4.1) ───────────
        "TLS-CIPHER-CLIENT-PREFERENCE-ONLY" | "TLS-FORWARD-SECRECY-WEAK" => {
            vec!["NIST 800-53 SC-13", "PCI DSS 4.2.1", "ISO 27001 A.8.24"]
        }
        "TLS-NO-FALLBACK-SCSV" => vec!["NIST 800-53 SC-8", "NIST 800-53 SC-13", "RFC 7507"],

        // ── Renegotiation + HPKP (v0.4.2) ───────────────────────────
        "TLS-INSECURE-RENEG-LEGACY" => vec![
            "NIST 800-53 SC-23",
            "PCI DSS 4.2.1",
            "RFC 5746",
            "CVE-2009-3555",
        ],
        "TLS-HPKP-PRESENT" => vec![
            // Deprecated — informational only, no compliance mapping.
        ],

        // ── Distrusted CA chains (v0.4.3) ───────────────────────────
        "TLS-SYMANTEC-DISTRUSTED-CA" => vec![
            "NIST 800-53 SC-17",
            "CA/B Forum Baseline Requirements §1.6",
            "Mozilla Root Store Policy 2.7",
            "Chromium Root Program Policy",
        ],

        // ── Lucky13 timing side-channel (v0.4.5) ────────────────────
        "TLS-LUCKY13-LIKELY" => vec!["NIST 800-53 SC-13", "PCI DSS 4.2.1", "CVE-2013-0169"],

        // ── GOLDENDOODLE / Zombie POODLE active (v0.5.0) ────────────
        "TLS-GOLDENDOODLE-ACTIVE" => vec![
            "NIST 800-53 SC-13",
            "PCI DSS 4.2.1",
            "ISO 27001 A.8.24",
            "Böck 2019 — Goldendoodle / Zombie POODLE disclosure",
        ],

        // ── HTTP-level compression / BREACH (v0.5.1) ────────────────
        "TLS-BREACH-ELIGIBLE" => vec!["NIST 800-53 SC-8", "OWASP ASVS 9.2.3", "CVE-2013-3587"],

        // ── Triple Handshake / EMS (v0.5.2) ─────────────────────────
        "TLS-NO-EXTENDED-MASTER-SECRET" => vec![
            "NIST 800-53 SC-23",
            "PCI DSS 4.2.1",
            "RFC 7627",
            "CVE-2014-1295",
        ],

        // ── HTTP/2 ALPN posture (v0.5.5) ────────────────────────────
        "TLS-H2C-UPGRADE-ACCEPTED" => {
            vec!["NIST 800-53 SC-8", "OWASP ASVS 14.4.1", "RFC 7540 §3.4"]
        }

        // ── HTTP/2 Rapid Reset eligibility (v0.5.9) ─────────────────
        "TLS-HTTP2-RAPID-RESET-ELIGIBLE" => {
            vec!["NIST 800-53 SC-5", "CVE-2023-44487", "RFC 7540 §6.5.2"]
        }

        // ── CT log diversity (v0.5.11) ──────────────────────────────
        "TLS-CT-INSUFFICIENT-DIVERSITY" => vec![
            "RFC 6962",
            "CA/B Forum BR §7.1.2.2",
            "Chromium CT Policy 2022-09",
        ],

        // ── HTTP/2 header-list DoS surface (v0.5.12) ────────────────
        "TLS-HTTP2-NO-HEADER-LIST-LIMIT" => {
            vec!["NIST 800-53 SC-5", "CVE-2019-9516", "RFC 7540 §6.5.2"]
        }

        // ── Cert lifetime BR cap (v0.5.13) ──────────────────────────
        "TLS-CERT-EXCESSIVE-LIFETIME" => vec![
            "NIST 800-53 SC-17",
            "CA/B Forum BR §6.3.2",
            "Apple Root Cert Policy 2020-09",
            "Chromium Root Program Policy",
        ],

        // ── Cert chain depth (v0.5.17) ──────────────────────────────
        "TLS-CERT-CHAIN-DEEP" => vec!["NIST 800-53 SC-17", "RFC 5280 §6"],

        // ── SAN wildcard policy (v0.5.18) ───────────────────────────
        "TLS-CERT-DANGEROUS-WILDCARD" => vec![
            "NIST 800-53 SC-17",
            "CA/B Forum BR §3.2.2.6",
            "RFC 6125 §6.4.3",
        ],

        // ── Extended Key Usage validation (v0.5.19) ─────────────────
        "TLS-CERT-MISSING-SERVER-AUTH-EKU" => vec![
            "NIST 800-53 SC-17",
            "CA/B Forum BR §7.1.2.7",
            "RFC 5280 §4.2.1.12",
        ],

        // ── Cert serial entropy (v0.5.21) ───────────────────────────
        "TLS-CERT-WEAK-SERIAL-ENTROPY" => vec![
            "NIST 800-53 SC-17",
            "CA/B Forum BR §7.1",
            "RFC 5280 §4.1.2.2",
        ],

        // ── Basic Constraints CA-bit (v0.5.22) ──────────────────────
        "TLS-CERT-LEAF-IS-CA" => vec![
            "NIST 800-53 SC-17",
            "CA/B Forum BR §7.1.2.7",
            "RFC 5280 §4.2.1.9",
        ],

        // ── Authority Key Identifier (v0.5.23) ──────────────────────
        "TLS-CERT-NO-AKI" => vec!["NIST 800-53 SC-17", "RFC 5280 §4.2.1.1"],

        // ── Not yet valid (v0.5.24) ─────────────────────────────────
        "TLS-CERT-NOT-YET-VALID" => vec!["NIST 800-53 SC-17", "RFC 5280 §4.1.2.5"],

        _ => vec![],
    }
}

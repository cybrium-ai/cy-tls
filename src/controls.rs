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

        _ => vec![],
    }
}

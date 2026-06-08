//! v0.5.62 — Per-finding canonical reference URL. Auto-attached by
//! `finding::make()` so dashboards / SARIF output can deep-link from
//! each finding to the authoritative advisory / RFC / CVE entry.
//!
//! Empty string returned when no single canonical URL applies (purely
//! informational findings tied to a broad concept).

pub fn for_id(id: &str) -> &'static str {
    match id {
        // ── Protocol versions ───────────────────────────────────────
        "TLS-SSLV2" => "https://datatracker.ietf.org/doc/html/rfc6176",
        "TLS-SSLV3" => "https://datatracker.ietf.org/doc/html/rfc7568",
        "TLS-WEAK-VERSION-1.0" | "TLS-WEAK-VERSION-1.1" => {
            "https://datatracker.ietf.org/doc/html/rfc8996"
        }
        "TLS-NO-TLS13" => "https://datatracker.ietf.org/doc/html/rfc8446",

        // ── Cipher suites ───────────────────────────────────────────
        "TLS-RC4-CIPHER" => "https://datatracker.ietf.org/doc/html/rfc7465",
        "TLS-3DES-CIPHER" => "https://sweet32.info/",
        "TLS-EXPORT-CIPHER" => "https://www.smacktls.com/#freak",
        "TLS-NULL-CIPHER" | "TLS-ANON-CIPHER" | "TLS-CBC-MAC-THEN-ENCRYPT" => {
            "https://wiki.mozilla.org/Security/Server_Side_TLS"
        }

        // ── Key exchange ────────────────────────────────────────────
        "TLS-DH-WEAK" | "TLS-DH-COMMON-PRIME" => "https://weakdh.org/",
        "TLS-CURVE-WEAK" => "https://safecurves.cr.yp.to/",

        // ── Certificate ─────────────────────────────────────────────
        "TLS-CERT-EXPIRED" | "TLS-CERT-NEAR-EXPIRY" => {
            "https://letsencrypt.org/docs/expiration-emails/"
        }
        "TLS-CERT-HOSTNAME-MISMATCH" => "https://datatracker.ietf.org/doc/html/rfc6125#section-6.4",
        "TLS-CERT-SELF-SIGNED" => "https://letsencrypt.org/",
        "TLS-CERT-WEAK-SIGNATURE" => "https://shattered.io/",
        "TLS-CERT-WEAK-KEY" => {
            "https://cabforum.org/working-groups/server/baseline-requirements/documents/"
        }
        "TLS-CHAIN-INCOMPLETE" => "https://www.ssllabs.com/ssltest/",
        "TLS-CERT-CHAIN-DEEP" | "TLS-CERT-CHAIN-MISORDERED" => {
            "https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.2"
        }
        "TLS-CERT-EXCESSIVE-LIFETIME" => {
            "https://cabforum.org/2020/07/16/ballot-sc31-browser-alignment/"
        }
        "TLS-CERT-DANGEROUS-WILDCARD" => {
            "https://datatracker.ietf.org/doc/html/rfc6125#section-6.4.3"
        }
        "TLS-CERT-MISSING-SERVER-AUTH-EKU" => {
            "https://cabforum.org/baseline-requirements-documents/"
        }
        "TLS-CERT-WEAK-SERIAL-ENTROPY" => "https://crt.sh/?q=serial",
        "TLS-CERT-LEAF-IS-CA" => "https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9",
        "TLS-CERT-NO-AKI" => "https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.1",
        "TLS-CERT-NOT-YET-VALID" => "https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5",
        "TLS-CERT-CN-ONLY" => "https://datatracker.ietf.org/doc/html/rfc6125#section-6.4.4",
        "TLS-CERT-INTERMEDIATE-NEAR-EXPIRY" | "TLS-CERT-INTERMEDIATE-EXPIRED" => {
            "https://datatracker.ietf.org/doc/html/rfc5280#section-6"
        }
        "TLS-CERT-AIA-CA-ISSUERS-UNREACHABLE" => {
            "https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1"
        }
        "TLS-CERT-SCT-COUNT-INSUFFICIENT" | "TLS-CT-INSUFFICIENT-DIVERSITY" => {
            "https://googlechrome.github.io/CertificateTransparency/ct_policy.html"
        }
        "TLS-CERT-SHARED-INFRA-CERT" => "https://www.cloudflare.com/learning/ssl/what-is-ssl/",
        "TLS-CHAIN-NOT-TRUSTED-MOZILLA" => "https://wiki.mozilla.org/CA/Included_Certificates",

        // ── OCSP / SCT ──────────────────────────────────────────────
        "TLS-OCSP-NOT-STAPLED" => "https://datatracker.ietf.org/doc/html/rfc6066#section-8",
        "TLS-OCSP-REVOKED" => "https://datatracker.ietf.org/doc/html/rfc6960",
        "TLS-SCT-MISSING" => "https://datatracker.ietf.org/doc/html/rfc6962",
        "TLS-MUST-STAPLE-VIOLATED" => "https://datatracker.ietf.org/doc/html/rfc7633",
        "TLS-OCSP-URL-HTTPS-SCHEME" => "https://datatracker.ietf.org/doc/html/rfc6960#appendix-A.1",

        // ── TLS 1.3 surface ─────────────────────────────────────────
        "TLS-ZERO-RTT-ACCEPTED" => "https://datatracker.ietf.org/doc/html/rfc8446#section-2.3",

        // ── Cross-protocol attacks (CVE-keyed) ──────────────────────
        "TLS-CLIENT-RENEG-ALLOWED" => "https://nvd.nist.gov/vuln/detail/CVE-2009-3555",
        "TLS-COMPRESSION-ENABLED" => "https://nvd.nist.gov/vuln/detail/CVE-2012-4929",
        "TLS-HEARTBLEED" | "TLS-HEARTBEAT-ENABLED" => {
            "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"
        }
        "TLS-ROBOT-VULNERABLE" => "https://robotattack.org/",
        "TLS-DROWN-VULNERABLE" => "https://drownattack.com/",
        "TLS-CCS-INJECTION" => "https://nvd.nist.gov/vuln/detail/CVE-2014-0224",
        "TLS-TICKETBLEED" => "https://nvd.nist.gov/vuln/detail/CVE-2016-9244",
        "TLS-OPENSSL-PADDING-ORACLE" => "https://nvd.nist.gov/vuln/detail/CVE-2016-2107",
        "TLS-CBC-ORACLE-FAMILY-FP" => "https://www.usenix.org/system/files/sec19-merget.pdf",
        "TLS-GOLDENDOODLE-ACTIVE" => {
            "https://www.tripwire.com/state-of-security/goldendoodle-attack-vaudenay"
        }
        "TLS-LUCKY13-LIKELY" => "https://nvd.nist.gov/vuln/detail/CVE-2013-0169",
        "TLS-BREACH-ELIGIBLE" => "https://breachattack.com/",
        "TLS-NO-EXTENDED-MASTER-SECRET" => "https://datatracker.ietf.org/doc/html/rfc7627",

        // ── Renegotiation + downgrade ───────────────────────────────
        "TLS-INSECURE-RENEG-LEGACY" => "https://datatracker.ietf.org/doc/html/rfc5746",
        "TLS-NO-FALLBACK-SCSV" => "https://datatracker.ietf.org/doc/html/rfc7507",
        "TLS-CIPHER-CLIENT-PREFERENCE-ONLY" | "TLS-FORWARD-SECRECY-WEAK" => {
            "https://wiki.mozilla.org/Security/Server_Side_TLS"
        }
        "TLS-SYMANTEC-DISTRUSTED-CA" => {
            "https://security.googleblog.com/2017/09/chromes-plan-to-distrust-symantec.html"
        }

        // ── HPKP + Expect-CT (deprecated) ───────────────────────────
        "TLS-HPKP-PRESENT" => {
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Public-Key-Pins"
        }
        "EXPECT-CT-MISSING" => {
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT"
        }

        // ── HSTS ────────────────────────────────────────────────────
        "HSTS-MISSING" | "HSTS-SHORT-MAX-AGE" | "HSTS-NO-SUBDOMAINS" => {
            "https://datatracker.ietf.org/doc/html/rfc6797"
        }
        "HSTS-NOT-PRELOADED" | "HSTS-PRELOAD-ELIGIBLE-BUT-UNREGISTERED" => {
            "https://hstspreload.org/"
        }

        // ── HTTP/2 ──────────────────────────────────────────────────
        "TLS-H2C-UPGRADE-ACCEPTED" => "https://datatracker.ietf.org/doc/html/rfc7540#section-3.4",
        "TLS-HTTP2-RAPID-RESET-ELIGIBLE" => "https://nvd.nist.gov/vuln/detail/CVE-2023-44487",
        "TLS-HTTP2-NO-HEADER-LIST-LIMIT" => "https://nvd.nist.gov/vuln/detail/CVE-2019-9516",

        // ── GREASE ──────────────────────────────────────────────────
        "TLS-GREASE-INTOLERANT" => "https://datatracker.ietf.org/doc/html/rfc8701",

        // ── DNS posture ─────────────────────────────────────────────
        "DNS-SOA-STALE" => "https://datatracker.ietf.org/doc/html/rfc1912#section-2.2",
        "DNS-CAA-NO-IODEF" => "https://datatracker.ietf.org/doc/html/rfc8657",
        "DNS-CAA-NO-ISSUEWILD" => "https://datatracker.ietf.org/doc/html/rfc8659#section-4.3",

        // ── HTTP hygiene ────────────────────────────────────────────
        "HTTP-SERVER-VERSION-LEAK" | "HTTP-X-POWERED-BY-PRESENT" => {
            "https://owasp.org/www-project-secure-headers/"
        }
        "HTTP-COOKIE-NO-SECURE" | "HTTP-COOKIE-NO-HTTPONLY" | "HTTP-COOKIE-NO-SAMESITE" => {
            "https://datatracker.ietf.org/doc/html/rfc6265"
        }
        "HTTP-CACHE-CONTROL-MISSING" => "https://datatracker.ietf.org/doc/html/rfc7234#section-5.2",
        "HTTP-NO-REDIRECT-TO-HTTPS" => {
            "https://www.pcisecuritystandards.org/document_library?category=pcidss&document=pci_dss"
        }
        "HTTP-TRACE-ENABLED" => "https://nvd.nist.gov/vuln/detail/CVE-2003-0825",
        "HTTP-CONTENT-TYPE-NO-CHARSET" => "https://owasp.org/www-community/attacks/xss/utf7",
        "HTTP-SERVER-TIMING-PRESENT" => "https://w3c.github.io/server-timing/",
        "HTTP-VIA-PRESENT" => "https://datatracker.ietf.org/doc/html/rfc7230#section-5.7.1",
        "HTTP-DEPRECATED-REPORT-TO" => "https://w3c.github.io/reporting/",

        // ── Reachability ────────────────────────────────────────────
        "TLS-UNREACHABLE" => "",

        _ => "",
    }
}

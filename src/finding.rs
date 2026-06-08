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
    /// v0.5.60 — concrete remediation step. Auto-populated by `make()`
    /// from the per-ID lookup table in `remediation.rs`. Empty when the
    /// finding is purely informational or the title already says what
    /// to do. Surfaces as the "how to fix" line in dashboards.
    #[serde(skip_serializing_if = "str::is_empty")]
    pub remediation: &'static str,
    /// v0.5.62 — canonical external reference URL (CVE / RFC / vendor
    /// advisory / Mozilla wiki). Auto-attached from `reference.rs`.
    /// Lets dashboards + SARIF deep-link the finding to the
    /// authoritative source.
    #[serde(skip_serializing_if = "str::is_empty")]
    pub reference_url: &'static str,
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

    // ── not_before future-dated (v0.5.24) ───────────────────────────
    ("TLS-CERT-NOT-YET-VALID", Severity::High, "Cert not_before is in the future — cert is not yet valid; browsers reject as INVALID. Usually CA-side clock skew or a staged-rollout misconfig where the cert deployed before its validity window opened"),

    // ── CN-only cert (v0.5.25) ──────────────────────────────────────
    ("TLS-CERT-CN-ONLY", Severity::High, "Cert has no SubjectAltName entries — modern browsers (Chrome 58+, Firefox 48+) don't consult the legacy Subject CN for hostname matching per RFC 6125 §6.4.4. Cert is unusable for TLS validation"),

    // ── HSTS preload eligibility (v0.5.27) ──────────────────────────
    ("HSTS-PRELOAD-ELIGIBLE-BUT-UNREGISTERED", Severity::Info, "Host meets hstspreload.org submission requirements (max-age ≥ 1yr + includeSubDomains + preload directive) but is not on the Chromium preload list. Submitting locks in HSTS from the first browser visit instead of waiting for the trust-on-first-use header to arrive"),

    // ── GREASE intolerance (v0.5.28) ────────────────────────────────
    ("TLS-GREASE-INTOLERANT", Severity::Low, "Server rejected a ClientHello containing RFC 8701 GREASE cipher_suite values OR picked a GREASE value back — brittle TLS stack that violates the 'ignore unknown values' rule. Will break when new cipher suites or extensions roll out"),

    // ── Chain order (v0.5.29) ───────────────────────────────────────
    ("TLS-CERT-CHAIN-MISORDERED", Severity::Medium, "Server sent the cert chain in an order that violates RFC 5246 §7.4.2 — at some point cert[i+1].subject ≠ cert[i].issuer. Strict clients fail; lenient ones fall back to AIA-fetching at extra round-trip cost"),

    // ── AIA caIssuers reachability (v0.5.31) ────────────────────────
    ("TLS-CERT-AIA-CA-ISSUERS-UNREACHABLE", Severity::Low, "Cert's AIA caIssuers URL is published but unreachable via HTTP HEAD — AIA-walking clients (those without the issuer cert pinned) can't fetch the missing intermediate, breaking chain validation"),

    // ── OCSP URL scheme (v0.5.38) ───────────────────────────────────
    ("TLS-OCSP-URL-HTTPS-SCHEME", Severity::Low, "OCSP responder URL uses https:// — RFC 6960 §A.1 recommends http:// to avoid the OCSP-over-OCSP loop where the OCSP query itself would need an OCSP-validated cert for the responder"),

    // ── DNS SOA serial freshness (v0.5.44) ──────────────────────────
    ("DNS-SOA-STALE", Severity::Info, "SOA serial uses RFC 1912 YYYYMMDDNN convention and the embedded date is > 365 days old — zone hasn't been updated in over a year. Forgotten zones, orphaned subsidiaries, and abandoned dynamic-DNS targets show up here"),

    // ── HTTP product disclosure (v0.5.45) ───────────────────────────
    ("HTTP-SERVER-VERSION-LEAK",   Severity::Low, "Server response header discloses product + version (e.g. nginx/1.18.0, Apache/2.4.7). Feeds vulnerability inventories without effort — production deployments should strip the version (server_tokens off / ServerTokens Prod / equivalent)"),
    ("HTTP-X-POWERED-BY-PRESENT",  Severity::Low, "X-Powered-By response header present. Modern frameworks default to disabling it; presence is a posture signal regardless of value (the header serves no operational purpose and leaks the framework + sometimes version)"),

    // ── Cookie + cache hygiene (v0.5.46) ────────────────────────────
    ("HTTP-COOKIE-NO-SECURE",       Severity::Medium, "Set-Cookie line lacks the Secure attribute — cookie will be transmitted in cleartext if the user is downgraded to HTTP (e.g. via SSL-stripping at a coffee-shop AP)"),
    ("HTTP-COOKIE-NO-HTTPONLY",     Severity::Medium, "Set-Cookie line lacks the HttpOnly attribute — cookie is readable from JavaScript via document.cookie, expanding the impact of any XSS to full session-token theft"),
    ("HTTP-COOKIE-NO-SAMESITE",     Severity::Low,    "Set-Cookie line has no SameSite attribute — cross-site CSRF protection depends on the browser's default (Chrome=Lax since 80, Safari historically=None)"),
    ("HTTP-CACHE-CONTROL-MISSING",  Severity::Low,    "Response sets cookies but has no Cache-Control header — middlebox / reverse-proxy caches may store the response (including the Set-Cookie line) and serve it to other clients"),

    // ── HTTP→HTTPS redirect (v0.5.47) ───────────────────────────────
    ("HTTP-NO-REDIRECT-TO-HTTPS", Severity::High, "Port 80 either serves content directly (2xx response) or redirects somewhere other than https://. PCI DSS 4.0 §4.2.1 requires migration of all clear-text channels — listeners on 80 must return a 301/308 to https:// or refuse the connection entirely"),

    // ── Shared-infra cert (v0.5.48) ─────────────────────────────────
    ("TLS-CERT-SHARED-INFRA-CERT", Severity::Info, "Leaf cert SAN count exceeds 100 — the Cloudflare / Fastly / SaaS-edge multi-tenant cert pattern. Not a vulnerability; informational data point for compliance scoping and third-party-keypair ownership review"),

    // ── HTTP TRACE / XST (v0.5.49) ──────────────────────────────────
    ("HTTP-TRACE-ENABLED", Severity::Medium, "Server's Allow response header (OPTIONS /) lists TRACE — Cross-Site Tracing prerequisite. TRACE echoes the request including any client-sent headers, which combined with an XSS or browser bug becomes a credential-exfil channel"),

    // ── Intermediate cert expiry (v0.5.51) ──────────────────────────
    ("TLS-CERT-INTERMEDIATE-NEAR-EXPIRY", Severity::Medium,   "An intermediate cert in the presented chain expires within 90 days. Browser chain validation breaks once the intermediate goes regardless of leaf freshness — coordinate rotation with the CA before the leaf"),
    ("TLS-CERT-INTERMEDIATE-EXPIRED",     Severity::Critical, "An intermediate cert in the presented chain has already expired — strict-mode clients reject the chain, the leaf's own validity is irrelevant"),

    // ── HTTP disclosure (v0.5.52) ───────────────────────────────────
    ("HTTP-SERVER-TIMING-PRESENT", Severity::Info, "Server-Timing response header present. Spec'd for legitimate front-end debugging but in production it leaks backend timings and cache-status descriptors (e.g. `cdn-cache;desc=HIT, origin;dur=42.3`)"),
    ("HTTP-VIA-PRESENT",           Severity::Info, "Via response header present. RFC 7230 §5.7.1 discloses the proxy chain. Rarely useful externally and leaks intermediate infrastructure to attackers"),

    // ── CAA hygiene (v0.5.53) ───────────────────────────────────────
    ("DNS-CAA-NO-IODEF",     Severity::Info, "CAA records are published but none has an `iodef` property tag (RFC 8657). Without iodef, a CA noticing a disallowed-issuance attempt has no operator endpoint to send a notification to"),
    ("DNS-CAA-NO-ISSUEWILD", Severity::Low,  "CAA records published with `issue` policy but no `issuewild`. Wildcards inherit the issue policy by default, so CAs in the issue list may also issue wildcards. Add an explicit `issuewild` line (or `0 issuewild \";\"` to deny wildcards entirely)"),

    // ── Content-Type hygiene (v0.5.54) ──────────────────────────────
    ("HTTP-CONTENT-TYPE-NO-CHARSET", Severity::Low, "Response Content-Type is text-y (text/* or application/xhtml*) but lacks an explicit `charset=` parameter. Browser falls back to sniffing or OS-locale defaults, enabling UTF-7-based XSS bypass and Latin-1 character-confusion attacks"),

    // ── Deprecated Report-To (v0.5.55) ──────────────────────────────
    ("HTTP-DEPRECATED-REPORT-TO", Severity::Info, "Legacy `Report-To` response header observed. W3C deprecated it in favor of `Reporting-Endpoints`; Chrome's shipping plan removes support through 2025. Replace with `Reporting-Endpoints` group definitions"),

    // ── SCT count policy (v0.5.56) ──────────────────────────────────
    ("TLS-CERT-SCT-COUNT-INSUFFICIENT", Severity::Medium, "Cert has fewer SCTs than Chrome's 2022 CT policy requires — <180-day-lifetime certs need ≥2 SCTs, ≥180-day certs need ≥3. Browsers treat the cert as CT-non-compliant"),

    // ── Trust outcome (v0.5.61) ─────────────────────────────────────
    ("TLS-CHAIN-NOT-TRUSTED-MOZILLA", Severity::High, "Chain fails the Mozilla / webpki trust-store validation (strict-mode handshake rejected). Fires only when none of the more-specific cert findings already explain the failure — usually means an issuer that's not in the public trust store (private CA, decommissioned-but-still-deployed root, etc)"),

    // ── CSP + XFO (v0.5.64) ─────────────────────────────────────────
    ("HTTP-CSP-MISSING",            Severity::Low,    "No Content-Security-Policy or Content-Security-Policy-Report-Only header. CSP is the strongest browser-level XSS / data-exfil mitigation; modern web apps should have it"),
    ("HTTP-CSP-UNSAFE-INLINE",      Severity::Medium, "CSP policy contains 'unsafe-inline' — defeats most of the XSS-mitigation value of CSP. Use nonces or hashes per directive instead"),
    ("HTTP-X-FRAME-OPTIONS-MISSING", Severity::Low,   "Neither X-Frame-Options nor CSP frame-ancestors directive set — site is embeddable in a cross-origin iframe, which is the clickjacking-attack prerequisite"),

    // ── MIME sniffing (v0.5.65) ─────────────────────────────────────
    ("HTTP-NOSNIFF-MISSING", Severity::Low, "X-Content-Type-Options header is absent or not set to 'nosniff' — browsers will MIME-sniff response bodies, enabling CSS-as-script and image-polyglot XSS vectors"),

    // ── Extended CSP danger (v0.5.66) ───────────────────────────────
    ("HTTP-CSP-UNSAFE-EVAL",         Severity::Medium, "CSP policy contains 'unsafe-eval' — allows eval()/new Function()/setTimeout(string)/setInterval(string), re-introducing the dynamic-code-execution surface CSP exists to close"),
    ("HTTP-CSP-DATA-IN-SCRIPT-SRC",  Severity::High,   "CSP script-src (or default-src fallback) allows `data:` — attacker can construct a data: URL containing arbitrary script and the browser will execute it. Classic CSP-bypass primitive"),
    ("HTTP-CSP-WILDCARD-SCRIPT-SRC", Severity::High,   "CSP script-src (or default-src fallback) is `*` — every external origin can load scripts; CSP provides no XSS mitigation under this policy"),

    // ── Multi-trust-store divergence (v0.5.70) ──────────────────────
    ("TLS-CHAIN-NOT-TRUSTED-APPLE",   Severity::High, "Chain fails Apple platform trust-store validation (macOS / iOS / iPadOS / tvOS / watchOS / visionOS). Connections from Apple clients will be rejected"),
    ("TLS-CHAIN-NOT-TRUSTED-ANDROID", Severity::High, "Chain fails Android system trust-store validation. Connections from Android clients will be rejected"),
    ("TLS-CHAIN-NOT-TRUSTED-JAVA",    Severity::High, "Chain fails OpenJDK / Java cacerts validation. Java HTTP clients (Spring, Apache HttpClient, etc) will reject the connection"),
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
        remediation: crate::remediation::for_id(id),
        reference_url: crate::reference::for_id(id),
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
        // v0.5.24 added TLS-CERT-NOT-YET-VALID. v0.5.25 added
        // TLS-CERT-CN-ONLY. v0.5.27 added
        // HSTS-PRELOAD-ELIGIBLE-BUT-UNREGISTERED. v0.5.28 added
        // TLS-GREASE-INTOLERANT. v0.5.29 added
        // TLS-CERT-CHAIN-MISORDERED. v0.5.31 added
        // TLS-CERT-AIA-CA-ISSUERS-UNREACHABLE. v0.5.38 added
        // TLS-OCSP-URL-HTTPS-SCHEME.
        // v0.5.44 added DNS-SOA-STALE. v0.5.45 added
        // HTTP-SERVER-VERSION-LEAK + HTTP-X-POWERED-BY-PRESENT.
        // v0.5.46 added HTTP-COOKIE-NO-SECURE + HTTP-COOKIE-NO-HTTPONLY
        // + HTTP-COOKIE-NO-SAMESITE + HTTP-CACHE-CONTROL-MISSING.
        // v0.5.47 added HTTP-NO-REDIRECT-TO-HTTPS.
        // v0.5.48 added TLS-CERT-SHARED-INFRA-CERT.
        // v0.5.49 added HTTP-TRACE-ENABLED.
        // v0.5.51 added TLS-CERT-INTERMEDIATE-NEAR-EXPIRY +
        // TLS-CERT-INTERMEDIATE-EXPIRED. v0.5.52 added
        // HTTP-SERVER-TIMING-PRESENT + HTTP-VIA-PRESENT.
        // v0.5.53 added DNS-CAA-NO-IODEF + DNS-CAA-NO-ISSUEWILD.
        // v0.5.54 added HTTP-CONTENT-TYPE-NO-CHARSET. v0.5.55 added
        // HTTP-DEPRECATED-REPORT-TO. v0.5.56 added
        // TLS-CERT-SCT-COUNT-INSUFFICIENT. v0.5.61 added
        // TLS-CHAIN-NOT-TRUSTED-MOZILLA. v0.5.64 added HTTP-CSP-MISSING,
        // HTTP-CSP-UNSAFE-INLINE, HTTP-X-FRAME-OPTIONS-MISSING.
        // v0.5.65 added HTTP-NOSNIFF-MISSING. v0.5.66 added
        // HTTP-CSP-UNSAFE-EVAL + HTTP-CSP-DATA-IN-SCRIPT-SRC +
        // HTTP-CSP-WILDCARD-SCRIPT-SRC. v0.5.70 added per-store
        // trust failures (APPLE/ANDROID/JAVA).
        assert_eq!(
            FINDING_CATALOG.len(),
            100,
            "FINDING_CATALOG size drifted from spec"
        );
    }
}

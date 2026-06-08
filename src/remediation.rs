//! v0.5.60 — Per-finding remediation strings. Auto-attached by
//! `finding::make()` so every emitter gets the right "how to fix"
//! text without remembering to pass it.
//!
//! Each entry is a single short paragraph (≤ ~200 chars) describing
//! the concrete action — config knob, package version, RFC reference,
//! whatever the operator needs to flip. Empty string is returned for
//! findings where the title already describes the fix (most
//! informational findings).

/// Returns the remediation string for the given finding ID, or "" when
/// no concrete remediation applies (the finding is purely informational
/// or the title already says what to do).
pub fn for_id(id: &str) -> &'static str {
    match id {
        // ── Protocol versions ───────────────────────────────────────
        "TLS-SSLV2" | "TLS-SSLV3" => "Disable SSLv2/SSLv3 entirely: `ssl_protocols TLSv1.2 TLSv1.3;` (nginx) / `SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1` (Apache). No legitimate browser still needs these.",
        "TLS-WEAK-VERSION-1.0" | "TLS-WEAK-VERSION-1.1" => "Remove TLS 1.0 and TLS 1.1 from the protocol list — only TLS 1.2 and TLS 1.3 should be enabled. All modern browsers + clients support TLS 1.2+; 1.0/1.1 were deprecated by browser vendors in 2020 and are PCI DSS 4.0 §4.2.1 failures.",
        "TLS-NO-TLS13" => "Enable TLS 1.3 (RFC 8446) — every major web server has supported it since 2019. `ssl_protocols TLSv1.2 TLSv1.3;` (nginx) / `SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1` (Apache 2.4.37+).",

        // ── Cipher suites ───────────────────────────────────────────
        "TLS-RC4-CIPHER" => "Remove RC4 from the cipher list. RFC 7465 (Feb 2015) prohibits it; AES-GCM and ChaCha20-Poly1305 are the modern replacements.",
        "TLS-3DES-CIPHER" => "Remove all 3DES cipher suites (SWEET32, CVE-2016-2183). Use AES-128-GCM / AES-256-GCM instead.",
        "TLS-NULL-CIPHER" | "TLS-ANON-CIPHER" | "TLS-EXPORT-CIPHER" => "Remove anonymous / NULL / EXPORT-grade cipher suites entirely — they are NEVER appropriate. Use the Mozilla SSL Configurator's 'modern' or 'intermediate' profile to pick a safe list.",
        "TLS-CBC-MAC-THEN-ENCRYPT" => "Move to AEAD ciphers (AES-GCM / ChaCha20-Poly1305) or enable the Encrypt-then-MAC extension (RFC 7366). CBC-mode without EtM is a Lucky13 timing-attack surface.",

        // ── Key exchange ────────────────────────────────────────────
        "TLS-DH-WEAK" => "Generate fresh DH parameters at ≥ 2048 bits (`openssl dhparam -out dhparam.pem 2048`) and reference them in the server config. Better: switch to ECDHE-only key exchange entirely.",
        "TLS-DH-COMMON-PRIME" => "Stop using the well-known shared DH prime. Generate a unique 2048+ bit DH group, or switch to ECDHE (which uses standardized curves without the shared-prime weakness).",
        "TLS-CURVE-WEAK" => "Restrict ECDHE curves to secp256r1 (P-256), secp384r1 (P-384), and X25519. nginx: `ssl_ecdh_curve X25519:secp256r1:secp384r1;`",

        // ── Certificate ─────────────────────────────────────────────
        "TLS-CERT-EXPIRED" => "Renew the certificate IMMEDIATELY — every browser is currently rejecting connections. Automate renewal via certbot / acme.sh / your CA's API to prevent recurrence.",
        "TLS-CERT-NEAR-EXPIRY" => "Schedule renewal within the next two weeks. If renewal is automated (Let's Encrypt etc), verify the renewal cron / systemd timer is actually running.",
        "TLS-CERT-HOSTNAME-MISMATCH" => "Reissue the certificate with the target hostname in the SubjectAlternativeName. The Subject CN is no longer consulted by browsers (RFC 6125 §6.4.4); SAN is required.",
        "TLS-CERT-SELF-SIGNED" => "Replace the self-signed cert with a publicly-trusted one — Let's Encrypt is free + automated. Self-signed certs train users to bypass browser warnings, eroding the trust model.",
        "TLS-CERT-WEAK-SIGNATURE" => "Reissue the certificate with SHA-256 or stronger. SHA-1 has been distrusted by all major browsers since 2017; MD5 since 2012.",
        "TLS-CERT-WEAK-KEY" => "Reissue with RSA ≥ 2048 bits or ECC ≥ 256 bits. RSA 1024 was rejected by browsers in 2014; CA/B Forum BR §6.1.5 mandates ≥ 2048 today.",
        "TLS-CHAIN-INCOMPLETE" => "Configure the server to send the full certificate chain (leaf + all intermediates). Browsers that don't AIA-walk will fail to validate. Most CAs provide a 'fullchain.pem' for exactly this.",
        "TLS-CERT-CHAIN-DEEP" => "Prune the chain to leaf + 1-3 intermediates. Deep chains usually indicate cross-signed sprawl after a CA migration; remove the deprecated cross-sign.",
        "TLS-CERT-CHAIN-MISORDERED" => "Reorder the cert chain so each cert's issuer matches the next cert's subject (leaf → intermediate → root). Strict TLS stacks reject misordered chains.",
        "TLS-CERT-EXCESSIVE-LIFETIME" => "Reissue with a lifetime ≤ 398 days (CA/B Forum BR §6.3.2 cap, enforced by Apple / Chrome / Mozilla since Sep 2020). Most CAs default to 365 days now.",
        "TLS-CERT-DANGEROUS-WILDCARD" => "Reissue without the policy-violating wildcard. Use specific SANs per hostname, or a single-label wildcard at a non-public-suffix scope (e.g. `*.app.example.com`, not `*.com`).",
        "TLS-CERT-MISSING-SERVER-AUTH-EKU" => "Reissue with id-kp-serverAuth (OID 1.3.6.1.5.5.7.3.1) in the ExtendedKeyUsage extension. CA/B Forum BR §7.1.2.7 requires it for publicly-trusted TLS server certs.",
        "TLS-CERT-WEAK-SERIAL-ENTROPY" => "Reissue from a CA that uses ≥ 64 bits of entropy in the serial (CA/B Forum BR §7.1). Modern CAs do this by default; an old / private CA issuing weak serials should be replaced.",
        "TLS-CERT-LEAF-IS-CA" => "Reissue WITHOUT the BasicConstraints cA=TRUE flag — end-entity certs MUST NOT have this set (RFC 5280 §4.2.1.9). This is a CA misissuance; contact the CA to revoke.",
        "TLS-CERT-NO-AKI" => "Reissue with the AuthorityKeyIdentifier extension (RFC 5280 §4.2.1.1). Modern CAs include this by default; missing AKI usually indicates a private / mis-configured CA.",
        "TLS-CERT-NOT-YET-VALID" => "Verify server + CA clock skew. If it's a staged rollout, redeploy the cert after its not_before window opens. Browsers reject not-yet-valid certs.",
        "TLS-CERT-CN-ONLY" => "Reissue with the target hostname(s) in SubjectAlternativeName. Modern browsers (Chrome 58+, Firefox 48+) ignore the legacy CN field entirely for hostname matching.",
        "TLS-CERT-INTERMEDIATE-NEAR-EXPIRY" => "Coordinate intermediate rotation with your CA before the existing intermediate expires. Let's Encrypt R3→R10 was a recent example; subscribe to your CA's intermediate-rotation announcements.",
        "TLS-CERT-INTERMEDIATE-EXPIRED" => "Reissue the leaf with a current intermediate IMMEDIATELY — strict-mode clients are already rejecting the chain regardless of leaf freshness.",
        "TLS-CERT-AIA-CA-ISSUERS-UNREACHABLE" => "Verify the URL in the AIA caIssuers extension is reachable. If the CA has rotated, reissue with the current chain so the URL points somewhere valid.",
        "TLS-CERT-SCT-COUNT-INSUFFICIENT" => "Reissue from a CA that embeds enough SCTs to meet Chrome's 2022 policy: < 180-day certs need ≥ 2 SCTs, ≥ 180-day need ≥ 3. Most public CAs already do this.",
        "TLS-CERT-SHARED-INFRA-CERT" => "",

        // ── OCSP / SCT ──────────────────────────────────────────────
        "TLS-OCSP-NOT-STAPLED" => "Enable OCSP stapling. nginx: `ssl_stapling on; ssl_stapling_verify on;` Apache: `SSLUseStapling on`. Reduces handshake latency and prevents CA-side OCSP outages from breaking the cert.",
        "TLS-OCSP-REVOKED" => "URGENT — the OCSP responder has marked this cert as revoked. Reissue and replace IMMEDIATELY; existing connections may still trust it depending on response cache.",
        "TLS-SCT-MISSING" => "Reissue from a CA that publishes the cert to CT logs (Let's Encrypt / DigiCert / GlobalSign all do this by default). Chrome rejects publicly-trusted certs without SCTs.",
        "TLS-MUST-STAPLE-VIOLATED" => "Either remove the must-staple cert extension (reissue without it) OR enable OCSP stapling on the server. Browsers will block the connection until one or the other is done.",
        "TLS-OCSP-URL-HTTPS-SCHEME" => "Reissue with an OCSP responder URL using `http://` (RFC 6960 §A.1 explicitly recommends this — HTTPS-on-HTTPS creates a circular validation problem).",

        // ── TLS 1.3 surface ─────────────────────────────────────────
        "TLS-ZERO-RTT-ACCEPTED" => "Disable TLS 1.3 0-RTT early-data for HTTP request handlers that mutate state (POST/PUT/PATCH/DELETE). nginx: `ssl_early_data off;` for sensitive locations.",

        // ── Cross-protocol attacks ──────────────────────────────────
        "TLS-CLIENT-RENEG-ALLOWED" => "Disable client-initiated renegotiation entirely. nginx ≥ 1.0.5 / OpenSSL ≥ 0.9.8m does this by default; older builds need an upgrade.",
        "TLS-COMPRESSION-ENABLED" => "Disable TLS-level compression (`SSL_OP_NO_COMPRESSION`). All modern stacks default to off; this finding means the server has explicitly enabled it.",
        "TLS-HEARTBEAT-ENABLED" => "Upgrade OpenSSL ≥ 1.0.1g to ensure Heartbleed is patched, and disable the heartbeat extension if not in use. Most modern builds don't ship with it enabled.",
        "TLS-ROBOT-VULNERABLE" => "URGENT — disable RSA key exchange ciphers entirely (use ECDHE-only). The fix at the cipher list level: `kRSA:!RSA-PSK` removed. Also patch OpenSSL / your TLS stack to the latest.",
        "TLS-DROWN-VULNERABLE" => "URGENT — disable SSLv2 on ALL servers sharing the cert, not just this one. DROWN works cross-protocol: an SSLv2 server elsewhere with the same key compromises this connection too.",
        "TLS-HEARTBLEED" => "URGENT — upgrade OpenSSL to ≥ 1.0.1g, reissue ALL certs (the private key is compromised), and revoke the old certs.",
        "TLS-CCS-INJECTION" => "URGENT — upgrade OpenSSL past CVE-2014-0224 (1.0.1h / 1.0.0m / 0.9.8za).",
        "TLS-TICKETBLEED" => "URGENT — upgrade F5 BIG-IP past CVE-2016-9244. Until then, disable session tickets if practical.",
        "TLS-OPENSSL-PADDING-ORACLE" => "Upgrade OpenSSL past CVE-2016-2107 (1.0.2h / 1.0.1t). Below that the AES-NI implementation leaks padding-validity via timing-distinguishable alert.",
        "TLS-CBC-ORACLE-FAMILY-FP" => "Upgrade the underlying TLS stack (vendor + version listed in the evidence). Switch to AEAD ciphers (AES-GCM / ChaCha20-Poly1305) to remove CBC from the negotiable list.",
        "TLS-GOLDENDOODLE-ACTIVE" => "Upgrade the vendor TLS stack listed in the evidence; disable CBC ciphers in the meantime as a workaround.",
        "TLS-LUCKY13-LIKELY" => "Upgrade OpenSSL ≥ 1.0.1g (April 2014) which added the constant-time CBC decrypt fix, or move to AEAD ciphers entirely.",
        "TLS-BREACH-ELIGIBLE" => "BREACH exploitation requires both compression AND user-input reflection adjacent to a secret. Either disable HTTP compression on sensitive endpoints OR ensure no reflection happens there. Rotate CSRF tokens per request as an additional mitigation.",
        "TLS-NO-EXTENDED-MASTER-SECRET" => "Upgrade the TLS stack to one that supports RFC 7627 EMS. OpenSSL ≥ 1.1.0, Java 8u161+, Schannel post-2018 all support it.",

        // ── Renegotiation + downgrade ───────────────────────────────
        "TLS-INSECURE-RENEG-LEGACY" => "Upgrade the TLS stack so the server advertises the renegotiation_info extension (RFC 5746). All modern stacks do; if this is firing the server is years out of date.",
        "TLS-NO-FALLBACK-SCSV" => "Upgrade the TLS stack to one supporting RFC 7507 (most modern versions). The server should refuse downgraded ClientHellos that contain TLS_FALLBACK_SCSV.",
        "TLS-CIPHER-CLIENT-PREFERENCE-ONLY" => "Set the server to enforce its own cipher preference order. nginx: `ssl_prefer_server_ciphers on;` Apache: `SSLHonorCipherOrder on`.",
        "TLS-FORWARD-SECRECY-WEAK" => "Remove non-FS cipher suites (RSA key exchange, static-DH). Use only ECDHE / DHE families. Mozilla's 'modern' profile is FS-only by default.",
        "TLS-SYMANTEC-DISTRUSTED-CA" => "Reissue from a non-distrusted CA. The Symantec PKI tree (Symantec, GeoTrust, Thawte, RapidSSL, VeriSign) has been distrusted in browsers since 2018.",

        // ── Distrusted / dangerous (deprecated headers) ─────────────
        "TLS-HPKP-PRESENT" => "Remove the Public-Key-Pins header — HPKP is deprecated and ignored by all modern browsers, and a misconfigured HPKP header has caused real lockout incidents. Use HSTS for transport hardening.",
        "EXPECT-CT-MISSING" => "Expect-CT is deprecated (modern browsers enforce CT by default since Chrome 75 / June 2019). Removing it does nothing useful; leaving it does nothing harmful. Safe to ignore.",

        // ── HSTS ────────────────────────────────────────────────────
        "HSTS-MISSING" => "Add the Strict-Transport-Security response header with max-age ≥ 31536000 (1 year), includeSubDomains, and preload. nginx: `add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;`",
        "HSTS-SHORT-MAX-AGE" => "Bump max-age to ≥ 31536000 (1 year). Anything shorter doesn't survive a typical user's browser cache between visits.",
        "HSTS-NO-SUBDOMAINS" => "Add the `includeSubDomains` directive to the HSTS header. Without it, an attacker can serve an HTTP cookie from a sibling subdomain and the browser will accept it.",
        "HSTS-NOT-PRELOADED" => "Either submit to hstspreload.org (and meet the requirements: max-age ≥ 1yr + includeSubDomains + preload directive) OR remove the `preload` directive from the header.",
        "HSTS-PRELOAD-ELIGIBLE-BUT-UNREGISTERED" => "Submit to hstspreload.org — the site already meets every requirement, just needs to register. Locks in HSTS from the very first browser visit, not the trust-on-first-use moment.",

        // ── HTTP/2 ──────────────────────────────────────────────────
        "TLS-H2C-UPGRADE-ACCEPTED" => "Disable HTTP/1.1 → h2c upgrade on the reverse proxy / TLS terminator. nginx: ensure `proxy_pass` doesn't pass through Upgrade headers. h2c (cleartext HTTP/2) should NEVER traverse the TLS boundary.",
        "TLS-HTTP2-RAPID-RESET-ELIGIBLE" => "Patch to a version mitigating CVE-2023-44487 (nginx ≥ 1.25.3, h2o ≥ 2.2.6, envoy ≥ 1.28.0, etc), or configure SETTINGS_MAX_CONCURRENT_STREAMS to a sensible cap (typically 100-128).",
        "TLS-HTTP2-NO-HEADER-LIST-LIMIT" => "Set SETTINGS_MAX_HEADER_LIST_SIZE to ≤ 64 KiB to bound HPACK-bomb / header-flood DoS exposure (CVE-2019-9516 family).",

        // ── CT diversity ────────────────────────────────────────────
        "TLS-CT-INSUFFICIENT-DIVERSITY" => "Reissue from a CA that ships SCTs from ≥ 2 distinct CT log operators. Most modern CAs do this by default; reissuing usually fixes it without operator action beyond a renewal.",

        // ── GREASE ──────────────────────────────────────────────────
        "TLS-GREASE-INTOLERANT" => "Upgrade the TLS stack — it's failing the RFC 8701 'ignore unknown values' rule and will break when new cipher suites / extensions roll out. Most modern stacks honour GREASE.",

        // ── DNS posture ─────────────────────────────────────────────
        "DNS-SOA-STALE" => "Bump the SOA serial after the next legitimate zone change so the date-prefix reflects current operations. If the zone is genuinely abandoned, delegate it to a holding-page nameserver or remove the delegation.",
        "DNS-CAA-NO-IODEF" => "Add an iodef line to your zone's CAA: `0 iodef \"mailto:security@example.com\"` (or a URL). CAs send disallowed-issuance notifications here.",
        "DNS-CAA-NO-ISSUEWILD" => "Add an explicit issuewild line. To deny wildcards entirely: `0 issuewild \";\"`. To allow only specific CAs: `0 issuewild \"letsencrypt.org\"`.",

        // ── HTTP hygiene ────────────────────────────────────────────
        "HTTP-SERVER-VERSION-LEAK" => "Strip the version from the Server response header. nginx: `server_tokens off;` Apache: `ServerTokens Prod` + `ServerSignature Off`. IIS: `removeServerHeader` in URL Rewrite module.",
        "HTTP-X-POWERED-BY-PRESENT" => "Remove the X-Powered-By header. Express: `app.disable('x-powered-by')`. PHP: `expose_php = Off` in php.ini. ASP.NET: customHeaders entry in web.config.",
        "HTTP-COOKIE-NO-SECURE" => "Set the Secure attribute on every Set-Cookie. In Django/Rails/Express it's typically a single config flag; for hand-written cookies append `; Secure` to the cookie value.",
        "HTTP-COOKIE-NO-HTTPONLY" => "Set the HttpOnly attribute on every Set-Cookie. Same config-flag pattern as Secure. Without HttpOnly, an XSS reads session tokens via document.cookie.",
        "HTTP-COOKIE-NO-SAMESITE" => "Set SameSite=Lax (or Strict for high-value cookies, or None for cross-site cookies — which then ALSO require Secure). Don't rely on browser defaults.",
        "HTTP-CACHE-CONTROL-MISSING" => "Add `Cache-Control: no-store, no-cache, must-revalidate` on responses that set cookies. Stops middlebox caches from echoing the Set-Cookie line back to other clients.",
        "HTTP-NO-REDIRECT-TO-HTTPS" => "Configure port 80 to issue a 301/308 redirect to https://, OR close port 80 entirely (recommended for new deployments). nginx: `return 301 https://$host$request_uri;`",
        "HTTP-TRACE-ENABLED" => "Disable the TRACE method. Apache: `TraceEnable Off`. nginx: doesn't support TRACE by default — if it's firing, a downstream app server does; restrict at the proxy.",
        "HTTP-CONTENT-TYPE-NO-CHARSET" => "Append `; charset=utf-8` to text/html responses. nginx: `charset utf-8;`. Most application frameworks set this automatically; if it's missing the framework or proxy is stripping it.",
        "HTTP-SERVER-TIMING-PRESENT" => "Strip Server-Timing on the production edge. The header is useful in development but leaks backend timing + cache descriptors externally.",
        "HTTP-VIA-PRESENT" => "Strip the Via response header on the production edge. The proxy chain it discloses is rarely useful externally and aids reconnaissance.",
        "HTTP-DEPRECATED-REPORT-TO" => "Replace the legacy Report-To header with the modern Reporting-Endpoints header (Reporting API draft). Chrome's shipping plan removes Report-To support through 2025.",

        // ── Reachability sentinel ────────────────────────────────────
        "TLS-UNREACHABLE" => "Verify TCP port 443 is accessible from the scanning vantage point. Firewall / security-group / WAF block, host-down, or scanner egress IP not in the allow-list are the usual causes.",

        _ => "",
    }
}

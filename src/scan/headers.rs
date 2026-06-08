//! HTTP-layer security header probe — fetches the target with a TLS
//! GET and inspects `Strict-Transport-Security`, `Expect-CT`, and
//! `Public-Key-Pins-Report-Only`.

use std::time::Duration;

use serde::Serialize;

use crate::finding::{make, Finding};

#[derive(Debug, Default, Clone, Serialize)]
pub struct HeaderInfo {
    pub hsts: Hsts,
    pub expect_ct: ExpectCt,
    pub hpkp: Hpkp,
    /// v0.5.32 — modern feature-policy header (replaced
    /// Feature-Policy in Chrome 88). Browsers honour it for camera,
    /// mic, geolocation, payment, etc. gating. Informational —
    /// present-or-absent doesn't drive a finding; the raw value is
    /// surfaced for posture dashboards.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions_policy: Option<String>,
    /// v0.5.33 — Cross-Origin-Opener-Policy. Spectre-class side-
    /// channel mitigation; controls whether a new window's process
    /// is isolated from openers across origins.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_origin_opener_policy: Option<String>,
    /// v0.5.33 — Cross-Origin-Embedder-Policy. Requires explicit
    /// opt-in (require-corp / credentialless) for cross-origin
    /// subresources; needed for the SharedArrayBuffer API.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_origin_embedder_policy: Option<String>,
    /// v0.5.33 — Cross-Origin-Resource-Policy. Server-set declaration
    /// of which origin-classes may include this resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_origin_resource_policy: Option<String>,
    /// v0.5.34 — Content-Security-Policy (RFC-status, browser-honoured).
    /// The single biggest HTTP-layer XSS / data-exfil mitigation;
    /// directs the browser on which sources can be loaded (scripts,
    /// styles, images, frames, etc.). Raw value preserved — directive
    /// parsing is a separate concern.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_security_policy: Option<String>,
    /// v0.5.34 — Content-Security-Policy-Report-Only. Same as
    /// content_security_policy but the browser only reports violations,
    /// doesn't block. Used during staged rollouts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_security_policy_report_only: Option<String>,
    /// v0.5.36 — Referrer-Policy. Controls what the browser sends in
    /// the Referer header on outbound requests (strict-origin, no-
    /// referrer, same-origin, etc.). Defaults vary per browser;
    /// explicit declaration is good posture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referrer_policy: Option<String>,
    /// v0.5.37 — X-Frame-Options. Legacy clickjacking mitigation
    /// (DENY / SAMEORIGIN). Mostly subsumed by CSP frame-ancestors
    /// but still honoured by browsers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_frame_options: Option<String>,
    /// v0.5.37 — X-Content-Type-Options. The canonical "nosniff"
    /// directive blocks MIME-sniffing-based content-type attacks
    /// (CSS-as-script, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_content_type_options: Option<String>,
    /// v0.5.1 — HTTP response compression detection. Populated by
    /// observing `Content-Encoding` on a regular GET. Used to emit
    /// TLS-BREACH-ELIGIBLE — BREACH (CVE-2013-3587) requires the
    /// server to compress responses AND the application to reflect
    /// user-controlled input alongside a secret. cy-tls only sees the
    /// transport surface; the reflection axis stays out-of-scope.
    pub http_compression: HttpCompression,
    /// v0.5.45 — value of the Server response header. Surfaced raw
    /// so dashboards can group by product family ("nginx", "Apache",
    /// "envoy", "cloudflare"). Findings fire only when this string
    /// contains a version-number pattern (slash + digits).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_header: Option<String>,
    /// v0.5.45 — value of the X-Powered-By response header. Modern
    /// frameworks default to disabling this; presence is itself a
    /// posture signal regardless of value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_powered_by: Option<String>,
    /// v0.5.46 — per-cookie hygiene audit. One entry per Set-Cookie
    /// header observed on the root GET (capped at 16 to bound output).
    /// Empty when the server set no cookies on `/`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub set_cookies: Vec<CookieAudit>,
    /// v0.5.46 — Cache-Control header value. Surfaced raw; HTTP-CACHE-
    /// CONTROL-MISSING fires only when the response sets cookies (a
    /// strong signal of sensitive content) AND has no Cache-Control
    /// header at all — middlebox-cacheable response leaking session
    /// state to the next requester.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<String>,
    /// v0.5.49 — value of the `Allow` response header from an OPTIONS
    /// probe against `/`. Captures which HTTP methods the server
    /// advertises as supported. Used to detect HTTP-TRACE-ENABLED
    /// (Cross-Site Tracing / XST prerequisite).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_methods: Option<String>,
    /// v0.5.50 — normalized product family extracted from the Server
    /// header (or None when Server is missing / unrecognized). One of:
    /// nginx / apache / cloudflare / envoy / caddy / iis / gunicorn /
    /// litespeed / openresty / haproxy / traefik / akamai-ghost / akamai /
    /// fastly. Lowercase, no version. Pure informational — feeds
    /// inventory + fleet-wide product-version dashboards.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_product: Option<String>,
    /// v0.5.52 — value of the Server-Timing response header. Spec'd
    /// for legitimate front-end debugging but in production it leaks
    /// backend timings + cache-status descriptors (e.g.
    /// `cdn-cache;desc=HIT, origin;dur=42.3`). Surfaced raw so
    /// operators can decide whether to strip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_timing: Option<String>,
    /// v0.5.52 — value of the Via response header. RFC 7230 §5.7.1.
    /// Discloses the proxy chain ("1.1 vegur, 1.1 cloudfront"). Rarely
    /// useful externally; leaks intermediate infra to attackers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    /// v0.5.54 — Content-Type response header from the root GET.
    /// Surfaced raw so dashboards can inventory + classify response
    /// content types. Used to emit HTTP-CONTENT-TYPE-NO-CHARSET when
    /// the type is text-y but no charset is declared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CookieAudit {
    /// Cookie name. We don't capture the value — it may be a session
    /// token or other secret.
    pub name: String,
    pub secure: bool,
    pub http_only: bool,
    /// Lowercased SameSite attribute value when present
    /// ("strict"/"lax"/"none"), otherwise None.
    pub same_site: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct HttpCompression {
    /// True when the server returned a Content-Encoding header
    /// indicating compression of the response body.
    pub offered: bool,
    /// Normalised algorithm — "gzip" / "br" / "deflate" / "zstd" /
    /// "identity" / or whatever the server literally sent. Empty
    /// when `offered` is false.
    pub algorithm: String,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Hsts {
    pub present: bool,
    pub max_age: u64,
    pub include_subdomains: bool,
    pub preload: bool,
    pub in_preload_list: bool,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct ExpectCt {
    pub present: bool,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Hpkp {
    pub present: bool,
}

impl HeaderInfo {
    pub fn contribute_findings(&self, host: &str, findings: &mut Vec<Finding>) {
        // v0.5.45 — Server / X-Powered-By disclosure. Checked BEFORE
        // the HSTS-MISSING short-circuit because header leaks are
        // independent of HSTS posture (and historically the most
        // version-leaky sites are also the ones with no HSTS).
        if let Some(v) = self.server_header.as_deref() {
            if server_header_leaks_version(v) {
                findings.push(make(
                    "HTTP-SERVER-VERSION-LEAK",
                    host,
                    format!("Server header discloses product+version: {v}"),
                ));
            }
        }
        if let Some(v) = self.x_powered_by.as_deref() {
            findings.push(make(
                "HTTP-X-POWERED-BY-PRESENT",
                host,
                format!("X-Powered-By header present: {v}"),
            ));
        }
        // v0.5.46 — per-cookie hygiene. Each missing attribute fires
        // its own finding so dashboards can ladder severity (a cookie
        // missing all three is three distinct issues, each with its
        // own remediation control mapping).
        for c in &self.set_cookies {
            if !c.secure {
                findings.push(make(
                    "HTTP-COOKIE-NO-SECURE",
                    host,
                    format!("Set-Cookie {} lacks the Secure attribute — cookie will be transmitted over plain HTTP if the user is ever downgraded", c.name),
                ));
            }
            if !c.http_only {
                findings.push(make(
                    "HTTP-COOKIE-NO-HTTPONLY",
                    host,
                    format!("Set-Cookie {} lacks the HttpOnly attribute — cookie is readable from JavaScript, expanding the impact of any XSS", c.name),
                ));
            }
            if c.same_site.is_none() {
                findings.push(make(
                    "HTTP-COOKIE-NO-SAMESITE",
                    host,
                    format!("Set-Cookie {} has no SameSite attribute — cross-site CSRF protection relies on browser default (Lax in Chrome, None in old Safari)", c.name),
                ));
            }
        }
        // v0.5.46 — Cache-Control gap when cookies are present.
        // A response that sets cookies AND has no Cache-Control header
        // can be cached by middleboxes; the cached body (containing the
        // Set-Cookie line) gets served to the next requester.
        if !self.set_cookies.is_empty() && self.cache_control.is_none() {
            findings.push(make(
                "HTTP-CACHE-CONTROL-MISSING",
                host,
                "Response sets cookies but has no Cache-Control header — intermediate caches may store the response (including the Set-Cookie line) and serve it to other clients",
            ));
        }
        // v0.5.52 — Server-Timing + Via disclosure. Both are info-level
        // (the values may be benign, but they're rarely useful outside
        // a development environment and they cost nothing to strip).
        if let Some(v) = self.server_timing.as_deref() {
            findings.push(make(
                "HTTP-SERVER-TIMING-PRESENT",
                host,
                format!("Server-Timing header present: {v}"),
            ));
        }
        if let Some(v) = self.via.as_deref() {
            findings.push(make(
                "HTTP-VIA-PRESENT",
                host,
                format!("Via header present: {v}"),
            ));
        }
        // v0.5.54 — Content-Type charset hygiene. An HTML response
        // without an explicit charset lets the browser sniff (or
        // default to the OS locale), enabling UTF-7-based XSS bypasses
        // and Latin-1 character-set surprises. Fires only for text/*
        // / application/xhtml+xml types.
        if let Some(ct) = self.content_type.as_deref() {
            let lower = ct.to_ascii_lowercase();
            let is_text = lower.starts_with("text/") || lower.starts_with("application/xhtml");
            if is_text && !lower.contains("charset=") {
                findings.push(make(
                    "HTTP-CONTENT-TYPE-NO-CHARSET",
                    host,
                    format!("Content-Type \"{ct}\" lacks an explicit charset — browser will sniff (UTF-7 / Latin-1 XSS-bypass surface). Add `; charset=utf-8` to the response"),
                ));
            }
        }
        // v0.5.49 — TRACE method (XST surface). Parse comma-separated
        // Allow header, case-insensitive match on TRACE.
        if let Some(allow) = self.allow_methods.as_deref() {
            let has_trace = allow
                .split(',')
                .any(|m| m.trim().eq_ignore_ascii_case("TRACE"));
            if has_trace {
                findings.push(make(
                    "HTTP-TRACE-ENABLED",
                    host,
                    format!("OPTIONS response Allow header lists TRACE: {allow} — Cross-Site Tracing (XST) prerequisite. TraceMethod off (Apache) / proxy_method_filter (nginx) / similar should be set"),
                ));
            }
        }
        if !self.hsts.present {
            findings.push(make(
                "HSTS-MISSING",
                host,
                "No Strict-Transport-Security header",
            ));
            return;
        }
        if self.hsts.max_age < 15_768_000 {
            findings.push(make(
                "HSTS-SHORT-MAX-AGE",
                host,
                format!("max-age={}", self.hsts.max_age),
            ));
        }
        if !self.hsts.include_subdomains {
            findings.push(make(
                "HSTS-NO-SUBDOMAINS",
                host,
                "HSTS missing includeSubDomains",
            ));
        }
        if self.hsts.preload && !self.hsts.in_preload_list {
            findings.push(make(
                "HSTS-NOT-PRELOADED",
                host,
                "Header declares preload but host not on Chromium preload list",
            ));
        }
        // v0.5.27 — HSTS preload eligibility. Host meets the formal
        // hstspreload.org submission requirements (max-age ≥ 1yr,
        // includeSubDomains, preload directive, present) but is NOT
        // yet on the Chromium preload list. Operator can submit at
        // hstspreload.org to lock in HSTS even on first browser visit.
        if self.hsts.present
            && self.hsts.max_age >= 31_536_000
            && self.hsts.include_subdomains
            && self.hsts.preload
            && !self.hsts.in_preload_list
        {
            findings.push(make(
                "HSTS-PRELOAD-ELIGIBLE-BUT-UNREGISTERED",
                host,
                "Host meets the hstspreload.org submission requirements (max-age ≥ 1yr, includeSubDomains, preload directive present) but is NOT yet on the Chromium preload list. Submit at hstspreload.org to lock in HSTS protection from the very first browser visit.",
            ));
        }
        if !self.expect_ct.present {
            findings.push(make("EXPECT-CT-MISSING", host, "Expect-CT absent"));
        }
        if self.hpkp.present {
            findings.push(make(
                "TLS-HPKP-PRESENT",
                host,
                "Public-Key-Pins (or -Report-Only) header observed — HPKP is deprecated and ignored by browsers, but Qualys SSL Labs still surfaces it.",
            ));
        }
        if self.http_compression.offered {
            findings.push(make(
                "TLS-BREACH-ELIGIBLE",
                host,
                format!(
                    "Server returned Content-Encoding: {} — BREACH (CVE-2013-3587) attack surface present whenever the application also reflects attacker-controlled input alongside a secret (CSRF token, session ID, etc.) in compressed responses. Transport-layer signal only; reflection axis is application-specific.",
                    self.http_compression.algorithm,
                ),
            ));
        }
    }
}

pub fn fetch(target: &str, deadline: Duration) -> anyhow::Result<HeaderInfo> {
    let (host, _) = target.rsplit_once(':').unwrap_or((target, "443"));
    let url = format!("https://{host}/");
    let agent = ureq::AgentBuilder::new().timeout(deadline).build();
    // v0.5.1 — explicitly request compression so the server has a
    // reason to respond with Content-Encoding (BREACH eligibility
    // detection). Without this header most servers default to identity.
    let resp = agent
        .get(&url)
        .set("Accept-Encoding", "gzip, br, deflate, zstd")
        .call();

    let mut info = HeaderInfo::default();
    let response = match resp {
        Ok(r) => r,
        Err(_) => return Ok(info),
    };

    if let Some(hsts) = response.header("strict-transport-security") {
        info.hsts.present = true;
        for part in hsts.split(';') {
            let part = part.trim().to_ascii_lowercase();
            if let Some(rest) = part.strip_prefix("max-age=") {
                if let Ok(n) = rest.parse() {
                    info.hsts.max_age = n;
                }
            } else if part == "includesubdomains" {
                info.hsts.include_subdomains = true;
            } else if part == "preload" {
                info.hsts.preload = true;
            }
        }
        // Chromium HSTS preload status — uses the embedded curated
        // set in `src/preload.rs` (v0.2.0). Full trie ships in v0.2.1.
        info.hsts.in_preload_list = crate::preload::is_preloaded(host).is_some();
    }

    if response.header("expect-ct").is_some() {
        info.expect_ct.present = true;
    }
    if response
        .header("public-key-pins-report-only")
        .or_else(|| response.header("public-key-pins"))
        .is_some()
    {
        info.hpkp.present = true;
    }
    // v0.5.32 — Permissions-Policy (or its legacy alias Feature-Policy).
    if let Some(v) = response
        .header("permissions-policy")
        .or_else(|| response.header("feature-policy"))
    {
        info.permissions_policy = Some(v.to_string());
    }
    // v0.5.33 — Cross-Origin isolation headers.
    if let Some(v) = response.header("cross-origin-opener-policy") {
        info.cross_origin_opener_policy = Some(v.to_string());
    }
    if let Some(v) = response.header("cross-origin-embedder-policy") {
        info.cross_origin_embedder_policy = Some(v.to_string());
    }
    if let Some(v) = response.header("cross-origin-resource-policy") {
        info.cross_origin_resource_policy = Some(v.to_string());
    }
    // v0.5.34 — Content-Security-Policy + report-only variant.
    if let Some(v) = response.header("content-security-policy") {
        info.content_security_policy = Some(v.to_string());
    }
    if let Some(v) = response.header("content-security-policy-report-only") {
        info.content_security_policy_report_only = Some(v.to_string());
    }
    // v0.5.36 — Referrer-Policy.
    if let Some(v) = response.header("referrer-policy") {
        info.referrer_policy = Some(v.to_string());
    }
    // v0.5.37 — X-Frame-Options + X-Content-Type-Options (legacy
    // but still honoured by all major browsers).
    if let Some(v) = response.header("x-frame-options") {
        info.x_frame_options = Some(v.to_string());
    }
    if let Some(v) = response.header("x-content-type-options") {
        info.x_content_type_options = Some(v.to_string());
    }

    // v0.5.1 — BREACH eligibility. Observe Content-Encoding directly.
    // ureq transparently decompresses gzip but still exposes the
    // original header on the response object. "identity" or no header
    // mean no compression — not eligible.
    if let Some(enc) = response.header("content-encoding") {
        let normalised = enc.trim().to_ascii_lowercase();
        if !normalised.is_empty() && normalised != "identity" {
            info.http_compression.offered = true;
            info.http_compression.algorithm = normalised;
        }
    }

    // v0.5.45 — Server + X-Powered-By disclosure capture. Findings
    // are emitted in contribute_findings(); here we just record.
    if let Some(v) = response.header("server") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            info.server_header = Some(trimmed.to_string());
            // v0.5.50 — normalize into a product family.
            info.server_product = classify_server_product(trimmed);
        }
    }
    if let Some(v) = response.header("x-powered-by") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            info.x_powered_by = Some(trimmed.to_string());
        }
    }

    // v0.5.46 — Cookie hygiene audit + Cache-Control capture.
    // ureq's response.all() returns every Set-Cookie line separately
    // (HTTP servers MAY fold or split — ureq surfaces both shapes).
    for raw in response.all("set-cookie").into_iter().take(16) {
        if let Some(audit) = parse_cookie_audit(raw) {
            info.set_cookies.push(audit);
        }
    }
    if let Some(v) = response.header("cache-control") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            info.cache_control = Some(trimmed.to_string());
        }
    }

    // v0.5.52 — Server-Timing + Via disclosure.
    if let Some(v) = response.header("server-timing") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            info.server_timing = Some(trimmed.to_string());
        }
    }
    if let Some(v) = response.header("via") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            info.via = Some(trimmed.to_string());
        }
    }
    if let Some(v) = response.header("content-type") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            info.content_type = Some(trimmed.to_string());
        }
    }

    // v0.5.49 — OPTIONS probe to detect TRACE method (XST surface).
    // Second request, same agent. We accept any 2xx / 4xx response —
    // 4xx is normal when the server returns "OPTIONS not allowed" but
    // includes an Allow: header anyway. Network failure → silent skip.
    if let Ok(opts_resp) = agent.request("OPTIONS", &url).call() {
        if let Some(allow) = opts_resp.header("allow") {
            let trimmed = allow.trim();
            if !trimmed.is_empty() {
                info.allow_methods = Some(trimmed.to_string());
            }
        }
    } else if let Err(ureq::Error::Status(_, opts_resp)) = agent.request("OPTIONS", &url).call() {
        if let Some(allow) = opts_resp.header("allow") {
            let trimmed = allow.trim();
            if !trimmed.is_empty() {
                info.allow_methods = Some(trimmed.to_string());
            }
        }
    }

    Ok(info)
}

/// v0.5.46 — parse a single Set-Cookie header line into a CookieAudit.
/// Returns None when the line has no name=value pair (malformed).
pub(crate) fn parse_cookie_audit(raw: &str) -> Option<CookieAudit> {
    let mut parts = raw.split(';').map(str::trim);
    let first = parts.next()?;
    let (name_raw, _) = first.split_once('=')?;
    let name = name_raw.trim().to_string();
    if name.is_empty() {
        return None;
    }
    let mut secure = false;
    let mut http_only = false;
    let mut same_site = None;
    for attr in parts {
        let lower = attr.to_ascii_lowercase();
        if lower == "secure" {
            secure = true;
        } else if lower == "httponly" {
            http_only = true;
        } else if let Some(rest) = lower.strip_prefix("samesite=") {
            let v = rest.trim().to_string();
            if !v.is_empty() {
                same_site = Some(v);
            }
        }
    }
    Some(CookieAudit {
        name,
        secure,
        http_only,
        same_site,
    })
}

/// v0.5.45 — does the Server header value contain a version number?
/// Pattern: `<product>/<digits>[.digits…]`. Matches `nginx/1.18.0`,
/// `Apache/2.4.7`, `Microsoft-IIS/10.0` — but NOT `nginx`,
/// `cloudflare`, `envoy`, where the operator has stripped the version.
pub(crate) fn server_header_leaks_version(value: &str) -> bool {
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '/' {
            // The next non-space char after the slash must be a digit.
            while let Some(&nx) = chars.peek() {
                if nx == ' ' {
                    chars.next();
                    continue;
                }
                return nx.is_ascii_digit();
            }
            return false;
        }
    }
    false
}

/// v0.5.50 — match the Server header against a known-product table.
/// Returns the lowercase product family name when matched; None
/// otherwise. Matching is case-insensitive and substring-based — both
/// "nginx" and "nginx/1.18.0" return "nginx". Order matters: more
/// specific patterns (akamai-ghost) are checked before less-specific
/// ones (akamai).
pub(crate) fn classify_server_product(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    // Specific → general. AkamaiGHost / openresty / litespeed / cloudfront
    // need to win over their parent matches.
    const PATTERNS: &[(&str, &str)] = &[
        ("akamaighost", "akamai-ghost"),
        ("akamainetstorage", "akamai-netstorage"),
        ("openresty", "openresty"),
        ("litespeed", "litespeed"),
        ("microsoft-iis", "iis"),
        ("microsoft-httpapi", "httpapi"),
        ("cloudflare", "cloudflare"),
        ("cloudfront", "cloudfront"),
        ("amazons3", "s3"),
        ("amazon", "amazon"),
        ("fastly", "fastly"),
        ("varnish", "varnish"),
        ("envoy", "envoy"),
        ("traefik", "traefik"),
        ("caddy", "caddy"),
        ("haproxy", "haproxy"),
        ("gunicorn", "gunicorn"),
        ("uvicorn", "uvicorn"),
        ("waitress", "waitress"),
        ("puma", "puma"),
        ("apache", "apache"),
        ("nginx", "nginx"),
        ("jetty", "jetty"),
        ("tomcat", "tomcat"),
        ("kestrel", "kestrel"),
        ("werkzeug", "werkzeug"),
        ("github.com", "github-pages"),
    ];
    for (needle, family) in PATTERNS {
        if lower.contains(needle) {
            return Some((*family).to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{classify_server_product, parse_cookie_audit, server_header_leaks_version};

    #[test]
    fn server_product_classification() {
        assert_eq!(
            classify_server_product("nginx/1.18.0").as_deref(),
            Some("nginx")
        );
        assert_eq!(
            classify_server_product("Apache/2.4.7 (Ubuntu)").as_deref(),
            Some("apache")
        );
        assert_eq!(
            classify_server_product("cloudflare").as_deref(),
            Some("cloudflare")
        );
        assert_eq!(
            classify_server_product("AkamaiGHost").as_deref(),
            Some("akamai-ghost")
        );
        assert_eq!(
            classify_server_product("openresty/1.19.9.1").as_deref(),
            Some("openresty")
        );
        assert_eq!(
            classify_server_product("Microsoft-IIS/10.0").as_deref(),
            Some("iis")
        );
        assert_eq!(
            classify_server_product("gunicorn/19.9.0").as_deref(),
            Some("gunicorn")
        );
        assert_eq!(
            classify_server_product("github.com").as_deref(),
            Some("github-pages")
        );
        // Unknown vendor — returns None instead of misclassifying.
        assert_eq!(classify_server_product("some-bespoke-server/1.0"), None);
        assert_eq!(classify_server_product("Z"), None);
    }

    #[test]
    fn cookie_parses_full_attribute_set() {
        let c = parse_cookie_audit("sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax").unwrap();
        assert_eq!(c.name, "sid");
        assert!(c.secure);
        assert!(c.http_only);
        assert_eq!(c.same_site.as_deref(), Some("lax"));
    }

    #[test]
    fn cookie_misses_attributes() {
        let c = parse_cookie_audit("session=xyz; Path=/").unwrap();
        assert!(!c.secure);
        assert!(!c.http_only);
        assert!(c.same_site.is_none());
    }

    #[test]
    fn cookie_malformed() {
        assert!(parse_cookie_audit("; Secure").is_none());
        assert!(parse_cookie_audit("=value").is_none());
    }

    #[test]
    fn version_leak_detection() {
        assert!(server_header_leaks_version("nginx/1.18.0"));
        assert!(server_header_leaks_version("Apache/2.4.7 (Ubuntu)"));
        assert!(server_header_leaks_version("Microsoft-IIS/10.0"));
        assert!(server_header_leaks_version("openresty/ 1.21"));
        assert!(!server_header_leaks_version("nginx"));
        assert!(!server_header_leaks_version("cloudflare"));
        assert!(!server_header_leaks_version("envoy"));
        // Slash without trailing digit — Caddy at one point used 'Caddy'.
        assert!(!server_header_leaks_version("Caddy"));
        // Slash with no digits after.
        assert!(!server_header_leaks_version("server/(stripped)"));
    }
}

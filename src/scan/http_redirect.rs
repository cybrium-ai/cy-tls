//! HTTP→HTTPS redirect audit. Probes `http://host:80/` with redirects
//! disabled, captures the status + Location, and the caller emits
//! HTTP-NO-REDIRECT-TO-HTTPS when:
//!   - the http endpoint returns 200 OK (serving content directly), or
//!   - it returns a 3xx whose Location does not start with `https://`.
//!
//! This is a PCI DSS 4.0 §4.2.1 requirement (all clear-text channels
//! must be migrated to strong cryptography) and an ASV §6.1 Table 1
//! special-note category.

use std::time::Duration;

use serde::Serialize;

#[derive(Debug, Default, Clone, Serialize)]
pub struct HttpRedirect {
    /// True when we successfully connected to TCP port 80 and got
    /// any HTTP response (regardless of status). False when the host
    /// has no plain-HTTP listener at all — best posture; nothing
    /// further to assess.
    pub tested: bool,
    /// HTTP status code returned by `http://host:80/`. Zero when no
    /// response was received.
    pub status_code: u16,
    /// True when the response is a 3xx whose Location header starts
    /// with `https://`. False when no Location, when status is 2xx,
    /// or when Location points to plain http.
    pub redirects_to_https: bool,
    /// Raw Location header value, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

/// Probe the http://host:80/ endpoint with redirects disabled. Returns
/// the audit result. Never panics — connection failures yield
/// HttpRedirect::default() (tested=false), which the caller treats as
/// "no plain-HTTP surface to flag".
pub fn probe(host: &str, deadline: Duration) -> HttpRedirect {
    let url = format!("http://{host}/");
    let agent = ureq::AgentBuilder::new()
        .timeout(deadline)
        .redirects(0)
        .build();
    let resp = agent.get(&url).call();
    let mut out = HttpRedirect::default();
    // ureq treats 3xx with redirects(0) as a "redirect-error" Err, so
    // we need to handle BOTH the Ok arm (2xx / 4xx / 5xx) AND the
    // Err::Status arm (3xx). Anything else (Transport / IO) means we
    // couldn't even talk to port 80 — leave tested=false.
    match resp {
        Ok(r) => {
            out.tested = true;
            out.status_code = r.status();
            if let Some(loc) = r.header("location") {
                out.location = Some(loc.to_string());
                if loc.to_ascii_lowercase().starts_with("https://") {
                    out.redirects_to_https = true;
                }
            }
        }
        Err(ureq::Error::Status(code, r)) => {
            out.tested = true;
            out.status_code = code;
            if let Some(loc) = r.header("location") {
                out.location = Some(loc.to_string());
                if loc.to_ascii_lowercase().starts_with("https://") {
                    out.redirects_to_https = true;
                }
            }
        }
        Err(_) => {}
    }
    out
}

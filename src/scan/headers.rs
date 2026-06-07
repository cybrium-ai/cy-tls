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
    /// v0.5.1 — HTTP response compression detection. Populated by
    /// observing `Content-Encoding` on a regular GET. Used to emit
    /// TLS-BREACH-ELIGIBLE — BREACH (CVE-2013-3587) requires the
    /// server to compress responses AND the application to reflect
    /// user-controlled input alongside a secret. cy-tls only sees the
    /// transport surface; the reflection axis stays out-of-scope.
    pub http_compression: HttpCompression,
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

    Ok(info)
}

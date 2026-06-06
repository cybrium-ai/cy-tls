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
            findings.push(make("HSTS-MISSING", host, "No Strict-Transport-Security header"));
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
            findings.push(make("HSTS-NO-SUBDOMAINS", host, "HSTS missing includeSubDomains"));
        }
        if self.hsts.preload && !self.hsts.in_preload_list {
            findings.push(make(
                "HSTS-NOT-PRELOADED",
                host,
                "Header declares preload but host not on Chromium preload list",
            ));
        }
        if !self.expect_ct.present {
            findings.push(make("EXPECT-CT-MISSING", host, "Expect-CT absent"));
        }
    }
}

pub fn fetch(target: &str, deadline: Duration) -> anyhow::Result<HeaderInfo> {
    let (host, _) = target.rsplit_once(':').unwrap_or((target, "443"));
    let url = format!("https://{host}/");
    let agent = ureq::AgentBuilder::new().timeout(deadline).build();
    let resp = agent.get(&url).call();

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
        // TODO Phase 2 — populate in_preload_list from embedded
        // Chromium preload list (currently always false; the spec'd
        // verify-preload subcommand exposes the same check standalone).
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

    Ok(info)
}

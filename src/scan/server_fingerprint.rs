//! HTTP `Server` header fingerprint — identify the product behind a
//! TLS endpoint when one is exposed. Lets cy-tls turn eligibility-tier
//! findings (e.g. "TLS 1.2 + CBC cipher accepted") into higher-confidence
//! findings when the fingerprint matches a product known to have the
//! relevant vulnerability un-patched in some shipped version.
//!
//! Pattern: probes the same HTTPS endpoint we already touch in
//! `headers::fetch`, but extracts the `Server` response header AND
//! classifies it against a curated map of known-vulnerable product
//! fingerprints.

use std::time::Duration;

use serde::Serialize;

#[derive(Debug, Default, Clone, Serialize)]
pub struct ServerFingerprint {
    /// Raw `Server` HTTP response header (e.g. "nginx/1.18.0", "Microsoft-IIS/10.0").
    pub raw:        Option<String>,
    /// Canonicalised product family ("nginx" / "apache" / "iis" / "f5" / "netscaler" / etc.).
    pub family:     Option<String>,
    /// Best-effort product version string.
    pub version:    Option<String>,
    /// True if this fingerprint matches a product family known to ship
    /// versions still vulnerable to CBC padding-oracle family attacks
    /// (GOLDENDOODLE / Zombie POODLE / OpenSSL AES-NI / Lucky13).
    pub known_cbc_oracle_family: bool,
}

pub fn classify(server_header: Option<&str>) -> ServerFingerprint {
    let mut out = ServerFingerprint::default();
    let Some(raw) = server_header else { return out; };
    out.raw = Some(raw.to_string());

    let lower = raw.to_ascii_lowercase();
    let (family, vulnerable) = if lower.contains("netscaler") || lower.contains("citrix") {
        // Citrix NetScaler / ADC — historically the textbook GOLDENDOODLE
        // target. Bock 2019 disclosed multiple firmware versions remained
        // vulnerable. Still seen in customer estates.
        ("netscaler", true)
    } else if lower.starts_with("bigip") || lower.contains("f5") {
        // F5 BIG-IP — both Ticketbleed AND various CBC oracle issues.
        ("f5-bigip", true)
    } else if lower.contains("sangfor") {
        // Sangfor SSL VPN appliances — confirmed Zombie POODLE
        // vulnerable in Bock 2019 disclosure.
        ("sangfor", true)
    } else if lower.contains("cisco") || lower.contains("ironport") {
        // Cisco IronPort / older Cisco gateway products — multiple
        // CVEs in CBC padding oracle family across the 9.x line.
        ("cisco", true)
    } else if lower.starts_with("nginx") {
        ("nginx", false)
    } else if lower.starts_with("apache") {
        ("apache", false)
    } else if lower.starts_with("microsoft-iis") || lower.starts_with("microsoft-httpapi") {
        ("iis", false)
    } else if lower.contains("caddy") {
        ("caddy", false)
    } else if lower.contains("cloudfront") {
        ("cloudfront", false)
    } else if lower.contains("cloudflare") {
        ("cloudflare", false)
    } else if lower.starts_with("envoy") {
        ("envoy", false)
    } else if lower.starts_with("traefik") {
        ("traefik", false)
    } else if lower.contains("akamai") || lower.contains("akamaighost") {
        ("akamai", false)
    } else if lower.starts_with("haproxy") {
        ("haproxy", false)
    } else if lower.contains("openresty") {
        ("openresty", false)
    } else if lower.contains("amazons3") {
        ("amazon-s3", false)
    } else {
        ("unknown", false)
    };

    out.family = Some(family.to_string());
    out.version = extract_version(raw);
    out.known_cbc_oracle_family = vulnerable;
    out
}

/// Extract a version string from a `Server` header value if present.
/// e.g. "nginx/1.18.0 (Ubuntu)" → "1.18.0"
fn extract_version(raw: &str) -> Option<String> {
    let slash = raw.find('/')?;
    let after = &raw[slash + 1..];
    // Take up to the first space / paren / null terminator.
    let end = after.find(|c: char| c.is_whitespace() || c == '(' || c == ',')
                   .unwrap_or(after.len());
    let v = after[..end].trim();
    if v.is_empty() { None } else { Some(v.to_string()) }
}

/// Quick HTTP HEAD fetcher — reuses ureq from the existing headers probe.
pub fn fetch(target: &str, deadline: Duration) -> Option<String> {
    let (host, _) = target.rsplit_once(':').unwrap_or((target, "443"));
    let url = format!("https://{host}/");
    let agent = ureq::AgentBuilder::new().timeout(deadline).build();
    let response = agent.head(&url).call().ok()?;
    response.header("server").map(String::from)
}

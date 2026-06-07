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
    pub raw: Option<String>,
    /// Canonicalised product family ("nginx" / "apache" / "iis" / "f5" / "netscaler" / etc.).
    pub family: Option<String>,
    /// Best-effort product version string.
    pub version: Option<String>,
    /// True if this fingerprint matches a product family known to ship
    /// versions still vulnerable to CBC padding-oracle family attacks
    /// (GOLDENDOODLE / Zombie POODLE / OpenSSL AES-NI / Lucky13).
    pub known_cbc_oracle_family: bool,
    /// Best-effort OpenSSL library version parsed out of the `Server`
    /// header (e.g. "1.0.1f", "1.0.2t"). Many Apache / nginx headers
    /// embed the linked OpenSSL version when ServerTokens is Full.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub openssl_version: Option<String>,
    /// True if `openssl_version` is a release published BEFORE the
    /// CVE-2016-2107 (OpenSSL AES-NI padding oracle) fix landed —
    /// 1.0.1t / 1.0.2h / 1.1.0 (May 3 2016). Used by the orchestrator
    /// to upgrade the eligibility-tier TLS-OPENSSL-PADDING-ORACLE
    /// finding to a fingerprint-confirmed verdict.
    pub openssl_vulnerable_padding_oracle: bool,
    /// True if `openssl_version` precedes the constant-time CBC decrypt
    /// rewrite that hardened OpenSSL against the Lucky13 (CVE-2013-0169)
    /// timing distinguisher — landed in 1.0.1g (April 2014). Used by
    /// the orchestrator to emit TLS-LUCKY13-LIKELY when TLS 1.2 + CBC
    /// is also accepted on the endpoint.
    pub openssl_vulnerable_lucky13: bool,
}

pub fn classify(server_header: Option<&str>) -> ServerFingerprint {
    let mut out = ServerFingerprint::default();
    let Some(raw) = server_header else {
        return out;
    };
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

    // OpenSSL version sniff — Apache / nginx with ServerTokens Full or
    // Major typically inlines the linked OpenSSL version.
    // Examples:
    //   "Apache/2.4.18 (Ubuntu) OpenSSL/1.0.2g"
    //   "nginx/1.10.0 (Ubuntu) OpenSSL/1.0.1f"
    if let Some(idx) = lower.find("openssl/") {
        let after = &raw[idx + "openssl/".len()..];
        let end = after
            .find(|c: char| c.is_whitespace() || c == '(' || c == ',' || c == ';')
            .unwrap_or(after.len());
        let v = after[..end].trim_end_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.');
        if !v.is_empty() {
            out.openssl_version = Some(v.to_string());
            out.openssl_vulnerable_padding_oracle = is_openssl_vulnerable_to_cve_2016_2107(v);
            out.openssl_vulnerable_lucky13 = is_openssl_vulnerable_to_lucky13(v);
        }
    }

    out
}

/// Lucky13 (CVE-2013-0169) — TLS CBC timing side-channel that recovers
/// plaintext bytes via response-time differences in MAC verification.
/// OpenSSL hardened against it with a constant-time CBC decrypt path
/// that landed in 1.0.1g (released 2014-04-07). The fix also went into
/// the 1.0.0 line as 1.0.0m and the 0.9.8 line as 0.9.8za.
///
/// Decision table by major.minor branch:
///   0.9.*  — 0.9.8za and later have the fix; earlier are vulnerable.
///            The release letter sequence ends at 'z' then continues
///            'za', 'zb', 'zc', ..., 'zh'. So:
///              0.9.8 [a..z] → vulnerable
///              0.9.8 z then [a..h] (e.g. "za", "zb") → fixed
///   1.0.0* — fixed at 'm'. Earlier letters vulnerable.
///   1.0.1* — fixed at 'g'. Earlier letters vulnerable.
///   1.0.2* — never shipped with the bug (post-fix branch).
///   1.1.*  — never shipped with the bug.
///   3.*    — modern, not vulnerable.
///   anything we can't parse — not flagged (avoid false-positive).
pub fn is_openssl_vulnerable_to_lucky13(v: &str) -> bool {
    let core = v.split(['-', '+']).next().unwrap_or(v);
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    let major: u32 = parts[0].parse().unwrap_or(0);
    let minor: u32 = parts[1].parse().unwrap_or(0);
    let patch_raw = parts.get(2).copied().unwrap_or("0");

    // Split patch number from letter suffix.
    let mut num_end = 0;
    for (i, ch) in patch_raw.char_indices() {
        if ch.is_ascii_digit() {
            num_end = i + ch.len_utf8();
        } else {
            break;
        }
    }
    let patch_num: u32 = patch_raw[..num_end].parse().unwrap_or(0);
    let suffix = &patch_raw[num_end..];

    match (major, minor, patch_num) {
        // pre-0.9 — well past their EOL but treat as vulnerable.
        (0, n, _) if n < 9 => true,

        // 0.9.8 line — fixed at 0.9.8za. Earlier single-letter sequences
        // (a..z) plus a bare 0.9.8 are vulnerable.
        (0, 9, 8) => {
            // Sort the suffix into one of:
            //   "" (bare) → vulnerable
            //   single letter [a..z] → vulnerable
            //   two-letter starting with 'z' → fixed (0.9.8za and later)
            if suffix.is_empty() {
                return true;
            }
            let chars: Vec<char> = suffix.chars().collect();
            if chars.len() == 1 {
                return true; // 0.9.8a..0.9.8z all vulnerable
            }
            // 0.9.8zX — z-series starting at "za" is the fix.
            if chars[0] == 'z' {
                return false;
            }
            false
        }

        // 1.0.0 line — fixed at 1.0.0m.
        (1, 0, 0) => match suffix.chars().next() {
            None => true,
            Some(c) => c < 'm',
        },

        // 1.0.1 line — fixed at 1.0.1g.
        (1, 0, 1) => match suffix.chars().next() {
            None => true,
            Some(c) => c < 'g',
        },

        // 1.0.2+ — branched off after the fix landed.
        (1, 0, 2) | (1, 1, _) | (3, _, _) => false,

        _ => false,
    }
}

/// CVE-2016-2107: OpenSSL AES-NI padding oracle. Fixed in 1.0.1t and
/// 1.0.2h (both released 2016-05-03), and never present in 1.1.0+
/// (which shipped after the fix).
///
/// Decision table by major.minor branch:
///   0.9.*  — predates the AES-NI rewrite. Considered vulnerable.
///   1.0.0* — also vulnerable; the issue was in the constant-time
///            CBC decrypt path which 1.0.0 also has.
///   1.0.1* — vulnerable up to and including 's'; 't' and later fixed.
///   1.0.2* — vulnerable up to and including 'g'; 'h' and later fixed.
///   1.1.*  — never shipped with the bug.
///   3.*    — modern, not vulnerable.
///   anything we can't parse — not flagged (avoid false-positive on
///            the banner-fingerprint signal).
pub fn is_openssl_vulnerable_to_cve_2016_2107(v: &str) -> bool {
    // Strip a trailing -fips / -beta1 / etc suffix; we only care about
    // the canonical MAJOR.MINOR.PATCH[letter] core.
    let core = v.split(['-', '+']).next().unwrap_or(v);

    // Split major.minor.patch parts. The patch part can be plain
    // ("0") or have a letter suffix ("0a", "1s", "2g") — the letter
    // is the per-branch release sequence.
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    let major: u32 = parts[0].parse().unwrap_or(0);
    let minor: u32 = parts[1].parse().unwrap_or(0);
    let patch_raw = parts.get(2).copied().unwrap_or("0");

    // Split patch number from optional release-letter suffix.
    let mut num_end = 0;
    for (i, ch) in patch_raw.char_indices() {
        if ch.is_ascii_digit() {
            num_end = i + ch.len_utf8();
        } else {
            break;
        }
    }
    let patch_num: u32 = patch_raw[..num_end].parse().unwrap_or(0);
    let letter = patch_raw[num_end..].chars().next();

    match (major, minor, patch_num) {
        // ── pre-1.0 ─────────────────────────────────────────────────
        (0, _, _) => true,

        // ── 1.0.0 line ──────────────────────────────────────────────
        (1, 0, 0) => true,

        // ── 1.0.1 line ──────────────────────────────────────────────
        // Vulnerable up to and including 1.0.1s; 1.0.1t is the fix.
        (1, 0, 1) => match letter {
            None => true,       // bare 1.0.1 → vulnerable
            Some(c) => c < 't', // a..s vulnerable, t+ fixed
        },

        // ── 1.0.2 line ──────────────────────────────────────────────
        // Vulnerable up to and including 1.0.2g; 1.0.2h is the fix.
        (1, 0, 2) => match letter {
            None => true,       // bare 1.0.2 → vulnerable
            Some(c) => c < 'h', // a..g vulnerable, h+ fixed
        },

        // ── 1.1.x and later ─────────────────────────────────────────
        (1, 1, _) | (3, _, _) => false,

        // ── unknown branch ──────────────────────────────────────────
        _ => false,
    }
}

/// Extract a version string from a `Server` header value if present.
/// e.g. "nginx/1.18.0 (Ubuntu)" → "1.18.0"
fn extract_version(raw: &str) -> Option<String> {
    let slash = raw.find('/')?;
    let after = &raw[slash + 1..];
    // Take up to the first space / paren / null terminator.
    let end = after
        .find(|c: char| c.is_whitespace() || c == '(' || c == ',')
        .unwrap_or(after.len());
    let v = after[..end].trim();
    if v.is_empty() {
        None
    } else {
        Some(v.to_string())
    }
}

/// Quick HTTP HEAD fetcher — reuses ureq from the existing headers probe.
pub fn fetch(target: &str, deadline: Duration) -> Option<String> {
    let (host, _) = target.rsplit_once(':').unwrap_or((target, "443"));
    let url = format!("https://{host}/");
    let agent = ureq::AgentBuilder::new().timeout(deadline).build();
    let response = agent.head(&url).call().ok()?;
    response.header("server").map(String::from)
}

#[cfg(test)]
mod openssl_version_tests {
    use super::*;

    #[test]
    fn cve_2016_2107_decision_table() {
        // Pre-fix releases — vulnerable.
        assert!(is_openssl_vulnerable_to_cve_2016_2107("0.9.8"));
        assert!(is_openssl_vulnerable_to_cve_2016_2107("1.0.0"));
        assert!(is_openssl_vulnerable_to_cve_2016_2107("1.0.0t")); // 1.0.0 line never got the fix
        assert!(is_openssl_vulnerable_to_cve_2016_2107("1.0.1"));
        assert!(is_openssl_vulnerable_to_cve_2016_2107("1.0.1a"));
        assert!(is_openssl_vulnerable_to_cve_2016_2107("1.0.1f")); // popular Ubuntu 14.04 vintage
        assert!(is_openssl_vulnerable_to_cve_2016_2107("1.0.1s")); // last vulnerable
        assert!(is_openssl_vulnerable_to_cve_2016_2107("1.0.2"));
        assert!(is_openssl_vulnerable_to_cve_2016_2107("1.0.2g")); // last vulnerable

        // Fix releases and later — not vulnerable.
        assert!(!is_openssl_vulnerable_to_cve_2016_2107("1.0.1t"));
        assert!(!is_openssl_vulnerable_to_cve_2016_2107("1.0.1u"));
        assert!(!is_openssl_vulnerable_to_cve_2016_2107("1.0.2h"));
        assert!(!is_openssl_vulnerable_to_cve_2016_2107("1.0.2t"));
        assert!(!is_openssl_vulnerable_to_cve_2016_2107("1.1.0"));
        assert!(!is_openssl_vulnerable_to_cve_2016_2107("1.1.1"));
        assert!(!is_openssl_vulnerable_to_cve_2016_2107("1.1.1w"));
        assert!(!is_openssl_vulnerable_to_cve_2016_2107("3.0.0"));
        assert!(!is_openssl_vulnerable_to_cve_2016_2107("3.0.13"));
        assert!(!is_openssl_vulnerable_to_cve_2016_2107("3.2.1"));

        // Garbage input — not flagged.
        assert!(!is_openssl_vulnerable_to_cve_2016_2107(""));
        assert!(!is_openssl_vulnerable_to_cve_2016_2107("garbage"));
        assert!(!is_openssl_vulnerable_to_cve_2016_2107("2.0.0"));
    }

    #[test]
    fn fips_suffix_stripped() {
        // RHEL / CentOS ships "1.0.1e-fips" — strip the suffix before
        // comparing.
        assert!(is_openssl_vulnerable_to_cve_2016_2107("1.0.1e-fips"));
        assert!(!is_openssl_vulnerable_to_cve_2016_2107("1.0.2k-fips"));
    }

    #[test]
    fn classify_parses_apache_openssl_banner() {
        let fp = classify(Some("Apache/2.4.18 (Ubuntu) OpenSSL/1.0.2g"));
        assert_eq!(fp.family.as_deref(), Some("apache"));
        assert_eq!(fp.openssl_version.as_deref(), Some("1.0.2g"));
        assert!(fp.openssl_vulnerable_padding_oracle);
    }

    #[test]
    fn classify_parses_nginx_openssl_banner_fixed() {
        let fp = classify(Some("nginx/1.18.0 (Ubuntu) OpenSSL/1.1.1f"));
        assert_eq!(fp.family.as_deref(), Some("nginx"));
        assert_eq!(fp.openssl_version.as_deref(), Some("1.1.1f"));
        assert!(!fp.openssl_vulnerable_padding_oracle);
    }

    #[test]
    fn classify_handles_missing_openssl() {
        let fp = classify(Some("nginx/1.18.0"));
        assert_eq!(fp.openssl_version, None);
        assert!(!fp.openssl_vulnerable_padding_oracle);
        assert!(!fp.openssl_vulnerable_lucky13);
    }

    // ── Lucky13 (CVE-2013-0169) decision table ──────────────────────

    #[test]
    fn lucky13_pre_098za_vulnerable() {
        assert!(is_openssl_vulnerable_to_lucky13("0.9.8"));
        assert!(is_openssl_vulnerable_to_lucky13("0.9.8a"));
        assert!(is_openssl_vulnerable_to_lucky13("0.9.8y"));
        assert!(is_openssl_vulnerable_to_lucky13("0.9.8z"));
    }

    #[test]
    fn lucky13_098za_and_later_fixed() {
        assert!(!is_openssl_vulnerable_to_lucky13("0.9.8za"));
        assert!(!is_openssl_vulnerable_to_lucky13("0.9.8zh"));
    }

    #[test]
    fn lucky13_100_line() {
        assert!(is_openssl_vulnerable_to_lucky13("1.0.0"));
        assert!(is_openssl_vulnerable_to_lucky13("1.0.0a"));
        assert!(is_openssl_vulnerable_to_lucky13("1.0.0l")); // last vuln
        assert!(!is_openssl_vulnerable_to_lucky13("1.0.0m")); // fix
        assert!(!is_openssl_vulnerable_to_lucky13("1.0.0t"));
    }

    #[test]
    fn lucky13_101_line() {
        assert!(is_openssl_vulnerable_to_lucky13("1.0.1"));
        assert!(is_openssl_vulnerable_to_lucky13("1.0.1a"));
        assert!(is_openssl_vulnerable_to_lucky13("1.0.1f")); // last vuln
        assert!(!is_openssl_vulnerable_to_lucky13("1.0.1g")); // fix
        assert!(!is_openssl_vulnerable_to_lucky13("1.0.1t"));
    }

    #[test]
    fn lucky13_post_fix_branches_clean() {
        assert!(!is_openssl_vulnerable_to_lucky13("1.0.2"));
        assert!(!is_openssl_vulnerable_to_lucky13("1.0.2g"));
        assert!(!is_openssl_vulnerable_to_lucky13("1.1.0"));
        assert!(!is_openssl_vulnerable_to_lucky13("1.1.1w"));
        assert!(!is_openssl_vulnerable_to_lucky13("3.0.0"));
        assert!(!is_openssl_vulnerable_to_lucky13("3.2.1"));
    }

    #[test]
    fn lucky13_garbage_input() {
        assert!(!is_openssl_vulnerable_to_lucky13(""));
        assert!(!is_openssl_vulnerable_to_lucky13("garbage"));
    }

    #[test]
    fn lucky13_fips_suffix_stripped() {
        assert!(is_openssl_vulnerable_to_lucky13("1.0.1e-fips"));
        assert!(!is_openssl_vulnerable_to_lucky13("1.0.1g-fips"));
    }

    #[test]
    fn classify_populates_lucky13_field() {
        let fp = classify(Some("Apache/2.4.7 (Ubuntu) OpenSSL/1.0.1e"));
        assert_eq!(fp.openssl_version.as_deref(), Some("1.0.1e"));
        assert!(fp.openssl_vulnerable_lucky13);
        let fp = classify(Some("nginx/1.18.0 (Ubuntu) OpenSSL/1.0.1g"));
        assert!(!fp.openssl_vulnerable_lucky13);
    }
}

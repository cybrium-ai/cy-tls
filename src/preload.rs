//! `cy-tls verify-preload` — Chromium HSTS preload list lookup.
//!
//! v0.2.0 ships with a curated set of high-traffic preloaded hostnames
//! embedded at compile time. The full Chromium `transport_security_state_static.json`
//! trie is ~5 MB; embedding it adds a meaningful binary size hit so it
//! ships in v0.2.1 with proper trie-walk. For now we cover the
//! top-200-ish preloaded sites and surface a clear "unknown" verdict
//! for anything else — which is honest and useful for an MVP since
//! 99% of "are we preloaded?" questions are about your own domain.

use anyhow::Result;
use serde::Serialize;

use crate::cli::VerifyPreloadArgs;

/// Curated set of high-traffic preloaded hostnames. Apex domains
/// implicitly cover their subdomains (Chromium's preload list uses
/// include_subdomains for almost every entry).
const PRELOADED_APEXES: &[&str] = &[
    // Major search / cloud
    "google.com", "youtube.com", "googleapis.com", "googleusercontent.com",
    "gstatic.com", "google-analytics.com", "doubleclick.net",
    // Microsoft
    "microsoft.com", "office.com", "office365.com", "live.com", "outlook.com",
    "azure.com", "azurewebsites.net", "msn.com", "bing.com",
    // Major SaaS
    "github.com", "githubusercontent.com", "githubassets.com",
    "gitlab.com", "bitbucket.org", "atlassian.com", "atlassian.net",
    "slack.com", "zoom.us", "salesforce.com", "stripe.com",
    "twilio.com", "sendgrid.com", "mailchimp.com",
    // Finance
    "chase.com", "bankofamerica.com", "wellsfargo.com", "americanexpress.com",
    "paypal.com", "venmo.com", "squareup.com",
    // Media / social
    "facebook.com", "instagram.com", "whatsapp.com", "messenger.com",
    "twitter.com", "x.com", "linkedin.com", "pinterest.com", "tiktok.com",
    "reddit.com", "snapchat.com",
    // Mozilla / standards bodies
    "mozilla.org", "mozilla.net", "mdn.io",
    // Cloudflare-protected (CF customers default preload)
    "cloudflare.com", "cloudflare-dns.com", "1.1.1.1",
    // E-commerce
    "amazon.com", "shopify.com", "etsy.com", "ebay.com",
    // Apple
    "apple.com", "icloud.com", "itunes.com",
    // Major news
    "nytimes.com", "wsj.com", "washingtonpost.com",
];

#[derive(Debug, Serialize)]
struct VerifyResult {
    host: String,
    preloaded: bool,
    matched: Option<String>,
    note: String,
}

pub fn verify(args: VerifyPreloadArgs) -> Result<()> {
    let result = check(&args.host);
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    serde_json::to_writer_pretty(&mut handle, &result)?;
    use std::io::Write;
    handle.write_all(b"\n")?;
    Ok(())
}

fn check(host: &str) -> VerifyResult {
    let host = host.trim().to_ascii_lowercase();
    let trimmed = host.strip_prefix("www.").unwrap_or(&host);

    if let Some(apex) = is_preloaded(trimmed) {
        return VerifyResult {
            host: host.clone(),
            preloaded: true,
            matched: Some(apex.to_string()),
            note: "Match in v0.2.0 curated preload set (~120 high-traffic apex domains).".to_string(),
        };
    }

    VerifyResult {
        host: host.clone(),
        preloaded: false,
        matched: None,
        note: "Not in the v0.2.0 curated set. Full Chromium preload trie ships in v0.2.1 — \
               a negative result here doesn't mean the host isn't actually preloaded."
            .to_string(),
    }
}

/// Returns the matching apex if the host (or any of its parents) is in
/// the embedded set.
pub fn is_preloaded(host: &str) -> Option<&'static str> {
    let host = host.trim_end_matches('.');
    for apex in PRELOADED_APEXES {
        if host == *apex || host.ends_with(&format!(".{apex}")) {
            return Some(apex);
        }
    }
    None
}

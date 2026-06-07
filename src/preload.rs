//! `cy-tls verify-preload` — Chromium HSTS preload list lookup.
//!
//! v0.3.x ships the full Chromium `transport_security_state_static.json`
//! list (94,549 host entries, sorted, ~1.6 MB embedded) — replaces the
//! v0.2.0 curated 120-apex set.
//!
//! Data file: `assets/hsts_preload.txt`. Format: one entry per line,
//! tab-separated, `<host>\t<0|1>` where 1 = `include_subdomains: true`.
//! File is sorted lexicographically so we can binary-search at runtime.
//!
//! Updates: re-run the build-time fetcher (in TODO.md) once per
//! Chromium release cycle to keep the data fresh.

use anyhow::Result;
use serde::Serialize;

use crate::cli::VerifyPreloadArgs;

/// Embedded sorted preload list.
const PRELOAD_TEXT: &str = include_str!("../assets/hsts_preload.txt");

#[derive(Debug, Serialize)]
struct VerifyResult {
    host: String,
    preloaded: bool,
    matched: Option<String>,
    matched_via_subdomain_inheritance: bool,
    note: String,
}

pub fn verify(args: VerifyPreloadArgs) -> Result<()> {
    let host = args.host.trim().to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host);
    let r = check(host);
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    serde_json::to_writer_pretty(&mut handle, &r)?;
    use std::io::Write;
    handle.write_all(b"\n")?;
    Ok(())
}

fn check(host: &str) -> VerifyResult {
    if let Some(matched) = is_preloaded(host) {
        let inheritance = matched != host;
        return VerifyResult {
            host: host.to_string(),
            preloaded: true,
            matched: Some(matched.to_string()),
            matched_via_subdomain_inheritance: inheritance,
            note: if inheritance {
                format!("Host inherits HSTS preload from parent apex '{matched}' which has include_subdomains=true.")
            } else {
                "Exact match in the Chromium HSTS preload list.".to_string()
            },
        };
    }
    VerifyResult {
        host: host.to_string(),
        preloaded: false,
        matched: None,
        matched_via_subdomain_inheritance: false,
        note: "Not in the Chromium HSTS preload list. If the site sends \
               HSTS headers with `preload`, submit to hstspreload.org to \
               be added."
            .to_string(),
    }
}

/// Return the matched preload entry (own name OR a parent apex with
/// include_subdomains=true) if the host is preloaded.
pub fn is_preloaded(host: &str) -> Option<&'static str> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    // Check the host itself, then progressively shorter parent labels.
    // For each candidate we binary-search the embedded sorted list.
    let mut candidate: &str = &host;
    let host_owned = host.to_string();
    loop {
        if let Some((matched, _sub)) = lookup_exact(candidate) {
            // If candidate is the literal queried host, it's an exact match
            // (sub flag doesn't matter — preloaded regardless).
            //
            // If candidate is a parent apex, only consider it a match when
            // the parent's include_subdomains flag is true.
            if candidate == host_owned || _sub {
                return Some(matched);
            }
        }
        match candidate.split_once('.') {
            Some((_, rest)) if rest.contains('.') => candidate = rest,
            _ => return None,
        }
    }
}

/// Binary search the embedded sorted slice for an exact match. Returns
/// the matched name (as a static slice into the embedded text) and the
/// include_subdomains flag.
fn lookup_exact(target: &str) -> Option<(&'static str, bool)> {
    // Pre-built line offsets at static init — built lazily on first call.
    let lines = lines();
    let target_owned = target.to_string();
    let idx = lines.binary_search_by(|line| {
        let name = line.split_once('\t').map(|(n, _)| n).unwrap_or(*line);
        name.cmp(&target_owned)
    });
    match idx {
        Ok(i) => {
            let line = lines[i];
            let (name, sub_str) = line.split_once('\t')?;
            Some((name, sub_str == "1"))
        }
        Err(_) => None,
    }
}

/// Lazy-initialised list of line slices into the embedded text.
fn lines() -> &'static [&'static str] {
    use std::sync::OnceLock;
    static LINES: OnceLock<Vec<&'static str>> = OnceLock::new();
    LINES.get_or_init(|| PRELOAD_TEXT.lines().collect())
}

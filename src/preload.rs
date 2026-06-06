//! `cy-tls verify-preload` — Chromium HSTS preload list lookup.
//!
//! Phase 1 stub. The full implementation embeds Chromium's
//! `transport_security_state_static.json` at compile time and walks
//! the trie. For v0.1.0 we fetch the list at runtime from the HTTPS
//! Archive mirror — slower but no build-time data ingestion needed.

use anyhow::Result;
use crate::cli::VerifyPreloadArgs;

pub fn verify(_args: VerifyPreloadArgs) -> Result<()> {
    // TODO Phase 2 — Chromium preload trie embedded at build time.
    Err(anyhow::anyhow!(
        "cy-tls verify-preload is scheduled for v0.2.0 — see docs/design.md P2.3"
    ))
}

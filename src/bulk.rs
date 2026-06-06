//! `cy-tls bulk` — JSONL streaming for IP-prefix and large host lists.
//!
//! Phase 1 stub. Acceptance criteria from `docs/design.md` P2.2.

use anyhow::Result;
use crate::cli::BulkArgs;

pub async fn run(_args: BulkArgs) -> Result<()> {
    // TODO Phase 2 — fan-out scanner with bounded concurrency.
    Err(anyhow::anyhow!(
        "cy-tls bulk is scheduled for v0.2.0 — see docs/design.md P2.2"
    ))
}

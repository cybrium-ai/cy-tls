//! JSONL emitter — one report per line. Used by `cy-tls bulk` and
//! optionally by `cy-tls scan --format jsonl` when piping into a
//! streaming consumer.

use crate::scan::ScanReport;
use std::io::Write;

pub fn emit(reports: &[ScanReport]) -> anyhow::Result<()> {
    let writer = std::io::stdout();
    let mut handle = writer.lock();
    for report in reports {
        serde_json::to_writer(&mut handle, report)?;
        handle.write_all(b"\n")?;
    }
    Ok(())
}

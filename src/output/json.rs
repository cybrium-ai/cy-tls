//! Canonical JSON emitter — pretty-prints the scan report array.

use crate::scan::ScanReport;

pub fn emit(reports: &[ScanReport]) -> anyhow::Result<()> {
    let writer = std::io::stdout();
    let mut handle = writer.lock();
    serde_json::to_writer_pretty(&mut handle, reports)?;
    use std::io::Write;
    handle.write_all(b"\n")?;
    Ok(())
}

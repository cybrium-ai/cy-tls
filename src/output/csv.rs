//! CSV emitter — one row per finding. Header row matches the column
//! order most operators expect when they paste into Excel / Sheets.

use std::io::Write;

use crate::scan::ScanReport;

const HEADER: &str = "scan_target,ip,host,finding_id,severity,title,evidence,controls\n";

pub fn render(reports: &[ScanReport]) -> String {
    let mut out = String::with_capacity(2048);
    out.push_str(HEADER);
    for r in reports {
        for f in &r.findings {
            out.push_str(&escape(&r.target));
            out.push(',');
            out.push_str(&escape(r.ip.as_deref().unwrap_or("")));
            out.push(',');
            out.push_str(&escape(&f.host));
            out.push(',');
            out.push_str(&escape(f.id));
            out.push(',');
            out.push_str(f.severity.as_str());
            out.push(',');
            out.push_str(&escape(f.title));
            out.push(',');
            out.push_str(&escape(&f.evidence));
            out.push(',');
            out.push_str(&escape(&f.controls.join(", ")));
            out.push('\n');
        }
    }
    out
}

pub fn emit(reports: &[ScanReport]) -> anyhow::Result<()> {
    let writer = std::io::stdout();
    let mut handle = writer.lock();
    handle.write_all(render(reports).as_bytes())?;
    Ok(())
}

/// Quote a field per RFC 4180. We always quote so CSV parsers don't
/// have to guess about commas / newlines / quotes inside content.
fn escape(s: &str) -> String {
    let escaped = s.replace('"', "\"\"");
    format!("\"{escaped}\"")
}

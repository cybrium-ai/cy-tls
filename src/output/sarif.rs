//! SARIF v2.1.0 emitter — for CI/CD and cross-tool ingestion.
//! Phase 1 stub; emits the bare-minimum SARIF document.

use serde_json::json;

use crate::scan::ScanReport;

pub fn emit(reports: &[ScanReport]) -> anyhow::Result<()> {
    let runs: Vec<_> = reports
        .iter()
        .map(|r| {
            let results: Vec<_> = r
                .findings
                .iter()
                .map(|f| {
                    json!({
                        "ruleId":    f.id,
                        "level":     map_level(f.severity.as_str()),
                        "message":   { "text": format!("{}: {}", f.title, f.evidence) },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": { "uri": f.host }
                            }
                        }]
                    })
                })
                .collect();
            json!({
                "tool": {
                    "driver": {
                        "name":     "cy-tls",
                        "version":  env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/cybrium-ai/cy-tls"
                    }
                },
                "results": results
            })
        })
        .collect();

    let doc = json!({
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs":    runs
    });
    let writer = std::io::stdout();
    let mut handle = writer.lock();
    serde_json::to_writer_pretty(&mut handle, &doc)?;
    use std::io::Write;
    handle.write_all(b"\n")?;
    Ok(())
}

fn map_level(sev: &str) -> &'static str {
    match sev {
        "critical" | "high" => "error",
        "medium" => "warning",
        "low" | "info" => "note",
        _ => "none",
    }
}

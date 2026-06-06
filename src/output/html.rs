//! HTML emitter — standalone, self-contained, Cybrium-branded report.
//!
//! No external assets except the logo + wordmark fetched from the Azure
//! Blob CDN at render time. Everything else is inline so the file emails
//! cleanly and archives without breaking.

use std::io::Write;

use chrono::Utc;

use crate::scan::ScanReport;

pub fn render(reports: &[ScanReport]) -> String {
    let total_findings: usize = reports.iter().map(|r| r.findings.len()).sum();
    let critical = count_by(reports, "critical");
    let high     = count_by(reports, "high");
    let medium   = count_by(reports, "medium");
    let low      = count_by(reports, "low");
    let info     = count_by(reports, "info");

    let mut targets_html = String::new();
    for r in reports {
        targets_html.push_str(&render_target(r));
    }

    let header = format!(
        "<header><img class=\"shield\" src=\"https://cybriumstorage.blob.core.windows.net/whitepapers/deck/logo_only.svg\" alt=\"Cybrium\"/>\
         <img class=\"wordmark\" src=\"https://cybriumstorage.blob.core.windows.net/whitepapers/deck/cybrium_word.svg\" alt=\"Cybrium\"/>\
         <span class=\"sep\">/</span><span class=\"toolname\">cy-tls</span>\
         <span class=\"toolversion\">v{}</span><span class=\"grow\"></span>\
         <span class=\"timestamp\">{}</span></header>",
        env!("CARGO_PKG_VERSION"),
        Utc::now().format("%Y-%m-%d %H:%M UTC"),
    );

    let tiles = format!(
        "<section class=\"tiles\">\
         <div class=\"tile critical\"><span class=\"n\">{critical}</span><span class=\"l\">Critical</span></div>\
         <div class=\"tile high\"><span class=\"n\">{high}</span><span class=\"l\">High</span></div>\
         <div class=\"tile medium\"><span class=\"n\">{medium}</span><span class=\"l\">Medium</span></div>\
         <div class=\"tile low\"><span class=\"n\">{low}</span><span class=\"l\">Low</span></div>\
         <div class=\"tile info\"><span class=\"n\">{info}</span><span class=\"l\">Info</span></div>\
         </section>"
    );

    let summary_line = if total_findings == 0 {
        "<p class=\"empty\">No findings — every probe passed cleanly. ✓</p>".to_string()
    } else {
        format!(
            "<p class=\"summary\">{} target{} scanned · {} finding{}</p>",
            reports.len(),
            if reports.len() == 1 { "" } else { "s" },
            total_findings,
            if total_findings == 1 { "" } else { "s" },
        )
    };

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>cy-tls report</title>
<style>{STYLE}</style>
</head>
<body>
{header}
<main>
{summary_line}
{tiles}
{targets_html}
</main>
<footer>cy-tls v{ver} · report generated {now}</footer>
</body>
</html>
"#,
        ver = env!("CARGO_PKG_VERSION"),
        now = Utc::now().format("%Y-%m-%d %H:%M UTC"),
    )
}

pub fn emit(reports: &[ScanReport]) -> anyhow::Result<()> {
    let writer = std::io::stdout();
    let mut handle = writer.lock();
    handle.write_all(render(reports).as_bytes())?;
    Ok(())
}

fn count_by(reports: &[ScanReport], sev: &str) -> usize {
    reports
        .iter()
        .flat_map(|r| r.findings.iter())
        .filter(|f| f.severity.as_str() == sev)
        .count()
}

fn render_target(r: &ScanReport) -> String {
    let mut sect = String::new();
    sect.push_str("<section class=\"target\">");
    sect.push_str(&format!(
        "<h2>{}</h2>\
         <div class=\"meta\">\
            <span><strong>IP:</strong> {}</span>\
            <span><strong>Elapsed:</strong> {} ms</span>\
         </div>\
         <h3>Configuration</h3>\
         <dl class=\"cert\">\
            <dt>TLS 1.3</dt><dd>{}{}</dd>\
            <dt>TLS 1.2</dt><dd>{}{}</dd>\
            <dt>TLS 1.1</dt><dd>{}</dd>\
            <dt>TLS 1.0</dt><dd>{}</dd>\
            <dt>ALPN</dt><dd>{}</dd>\
            <dt>Key Exchange Group</dt><dd>{}</dd>\
            <dt>Forward Secrecy</dt><dd>{}</dd>\
         </dl>",
        esc(&r.target),
        esc(r.ip.as_deref().unwrap_or("—")),
        r.elapsed_ms,
        yes_no(r.protocols.tls13.supported),
        cipher_suffix(&r.protocols.tls13.ciphers),
        yes_no(r.protocols.tls12.supported),
        cipher_suffix(&r.protocols.tls12.ciphers),
        yes_no(r.protocols.tls11.supported),
        yes_no(r.protocols.tls10.supported),
        esc(r.protocols.alpn.as_deref().unwrap_or("not negotiated")),
        esc(r.protocols.key_exchange_group.as_deref().unwrap_or("—")),
        yes_no(r.protocols.forward_secrecy),
    ));

    if let Some(c) = &r.certificate {
        sect.push_str(&format!(
            "<h3>Certificate</h3>\
             <dl class=\"cert\">\
               <dt>Subject</dt><dd>{}</dd>\
               <dt>Issuer</dt><dd>{}</dd>\
               <dt>SAN</dt><dd>{}</dd>\
               <dt>Validity</dt><dd>{} → {} ({} days remaining)</dd>\
               <dt>Signature</dt><dd>{}</dd>\
               <dt>Key</dt><dd>{} ({} bits{})</dd>\
               <dt>SCT count</dt><dd>{}</dd>\
               <dt>OCSP stapled</dt><dd>{}</dd>\
             </dl>",
            esc(&c.subject),
            esc(&c.issuer),
            esc(&c.san.join(", ")),
            c.not_before.format("%Y-%m-%d"),
            c.not_after.format("%Y-%m-%d"),
            c.days_remaining,
            esc(&c.signature_algorithm),
            esc(&c.key_algorithm),
            c.key_bits,
            c.ec_curve.as_deref().map(|n| format!(", {n}")).unwrap_or_default(),
            c.sct_count,
            check(c.ocsp_stapled),
        ));
    }

    if r.findings.is_empty() {
        sect.push_str("<p class=\"clean\">No findings on this target. ✓</p>");
    } else {
        sect.push_str("<h3>Findings</h3><table class=\"findings\"><thead><tr><th>Severity</th><th>ID</th><th>Title</th><th>Evidence</th><th>Controls</th></tr></thead><tbody>");
        let mut sorted = r.findings.clone();
        sorted.sort_by_key(|f| sev_order(f.severity.as_str()));
        for f in &sorted {
            sect.push_str(&format!(
                "<tr><td><span class=\"sev {sev}\">{sev}</span></td><td><code>{id}</code></td><td>{title}</td><td class=\"ev\">{ev}</td><td class=\"ctrl\">{ctrl}</td></tr>",
                sev = f.severity.as_str(),
                id = esc(f.id),
                title = esc(f.title),
                ev = esc(&f.evidence),
                ctrl = esc(&f.controls.join(", ")),
            ));
        }
        sect.push_str("</tbody></table>");
    }

    sect.push_str("</section>");
    sect
}

fn check(b: bool) -> &'static str { if b { "✓" } else { "✗" } }

fn yes_no(b: bool) -> &'static str {
    if b {
        "<span class=\"yes\">Yes</span>"
    } else {
        "<span class=\"no\">No</span>"
    }
}

fn cipher_suffix(ciphers: &[String]) -> String {
    if ciphers.is_empty() {
        String::new()
    } else {
        format!(" · <code>{}</code>", esc(&ciphers.join(", ")))
    }
}

fn sev_order(s: &str) -> u8 {
    match s {
        "critical" => 0,
        "high"     => 1,
        "medium"   => 2,
        "low"      => 3,
        "info"     => 4,
        _          => 9,
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
}

const STYLE: &str = "
:root {
  --bg:#0b0f1a; --panel:#131826; --panel-2:#1c2233; --border:#1f2638;
  --muted:#6b7691; --fg:#d9def0; --fg-bright:#fff; --primary:#6d28d9;
  --critical:#ef4444; --high:#f97316; --medium:#eab308; --low:#38bdf8; --info:#94a3b8;
}
* { box-sizing: border-box; }
body { font-family: -apple-system, 'Segoe UI', Inter, system-ui, sans-serif; background: var(--bg); color: var(--fg); margin: 0; line-height: 1.5; }
header { display: flex; align-items: center; gap: 14px; padding: 14px 28px; border-bottom: 1px solid var(--border); background: linear-gradient(180deg, rgba(109,40,217,0.08), transparent); }
header img.shield { height: 32px; width: 32px; }
header img.wordmark { height: 22px; opacity: 0.95; }
header .sep { color: var(--muted); margin: 0 4px; }
header .toolname { font-weight: 600; color: var(--fg-bright); }
header .toolversion { color: var(--muted); font-size: 12px; font-family: ui-monospace, Menlo, monospace; }
header .timestamp { color: var(--muted); font-size: 12px; font-family: ui-monospace, Menlo, monospace; }
header .grow { flex: 1; }
main { max-width: 1100px; margin: 0 auto; padding: 28px; }
.summary { color: var(--muted); margin: 0 0 18px; }
.empty   { color: var(--muted); margin: 24px 0; padding: 28px; text-align: center; border: 1px dashed var(--border); border-radius: 8px; }
.clean   { color: var(--low); margin: 12px 0; font-size: 14px; }
.tiles { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 16px 0 30px; }
.tile { text-align: center; padding: 14px 8px; background: var(--panel-2); border: 1px solid var(--border); border-radius: 6px; }
.tile .n { font-size: 28px; font-weight: 700; color: var(--fg-bright); display: block; }
.tile .l { font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); margin-top: 2px; }
.tile.critical .n { color: var(--critical); }
.tile.high     .n { color: var(--high); }
.tile.medium   .n { color: var(--medium); }
.tile.low      .n { color: var(--low); }
.tile.info     .n { color: var(--info); }
section.target { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 22px; margin-bottom: 20px; }
section.target h2 { margin: 0 0 12px; font-family: ui-monospace, Menlo, monospace; color: var(--fg-bright); font-size: 16px; }
section.target h3 { margin: 22px 0 10px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
.meta { display: flex; flex-wrap: wrap; gap: 12px 22px; font-size: 13px; color: var(--muted); }
.meta strong { color: var(--fg); font-weight: 500; }
dl.cert { display: grid; grid-template-columns: 140px 1fr; gap: 6px 16px; font-size: 13px; }
dl.cert dt { color: var(--muted); font-weight: 500; }
dl.cert dd { color: var(--fg); margin: 0; font-family: ui-monospace, Menlo, monospace; word-break: break-all; font-size: 12px; }
table.findings { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 6px; }
table.findings th, table.findings td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
table.findings th { color: var(--muted); font-weight: 500; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; }
table.findings code { color: var(--fg-bright); font-family: ui-monospace, Menlo, monospace; font-size: 12px; }
.sev { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; text-transform: capitalize; }
.sev.critical { background: rgba(239,68,68,0.18);  color: var(--critical); }
.sev.high     { background: rgba(249,115,22,0.18); color: var(--high); }
.sev.medium   { background: rgba(234,179,8,0.18);  color: var(--medium); }
.sev.low      { background: rgba(56,189,248,0.18); color: var(--low); }
.sev.info     { background: rgba(148,163,184,0.18);color: var(--info); }
.yes { color: #22c55e; font-weight: 600; }
.no  { color: var(--high); font-weight: 600; }
.ev   { color: var(--muted); max-width: 320px; }
.ctrl { color: var(--muted); font-size: 11px; max-width: 280px; }
footer { padding: 18px 28px; color: var(--muted); font-size: 11px; border-top: 1px solid var(--border); text-align: center; font-family: ui-monospace, Menlo, monospace; }
";

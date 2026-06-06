# Export formats

cy-tls emits scan reports in five formats from a single in-memory data
model. The CLI selects format via `--format <fmt>`, the GUI via the
download buttons in the Findings panel, and library consumers via
`crate::output::*::render(&[ScanReport]) -> String`.

| Format | Extension | MIME | Streaming-safe? |
|--------|-----------|------|-----------------|
| JSON   | `.json`   | `application/json`     | No (single array) |
| JSONL  | `.jsonl`  | `application/x-ndjson` | **Yes** (one report per line) |
| SARIF  | `.sarif`  | `application/json`     | No |
| CSV    | `.csv`    | `text/csv`             | Effectively yes (one row per finding) |
| HTML   | `.html`   | `text/html; charset=utf-8` | No |

## JSON

Default. Pretty-printed array of `ScanReport` objects, one per target.

```sh
cy-tls scan cybrium.ai example.com --format json > scan.json
```

Schema: see [`docs/json-schema.md`](json-schema.md). Stable within a
major version; additive fields only.

## JSONL

One JSON object per line, one line per target. Designed for `cy-tls
bulk` and any tool that ingests newline-delimited JSON (Loki, Filebeat,
Fluent Bit, Splunk).

```sh
cy-tls bulk --targets-file hosts.txt > fleet.jsonl
# or explicit:
cy-tls scan cybrium.ai example.com --format jsonl
```

Same shape as JSON — just serialised without the wrapping array and
without pretty-print.

## SARIF

[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
for GitHub Advanced Security, GitLab code-scanning, or any other
SARIF-aware CI/CD pipeline.

```sh
cy-tls scan target.example.com --format sarif > findings.sarif
```

Each `ScanReport` becomes a `run`, each finding becomes a `result`
with:

- `ruleId` = the finding ID
- `level` = `error` for critical/high, `warning` for medium, `note` for low/info
- `message.text` = "Title: Evidence"
- `locations[0].physicalLocation.artifactLocation.uri` = the host

The driver advertises itself as `cy-tls` with the running binary's
version.

## CSV

One row per finding. Header line is always present, fields are always
RFC-4180-quoted.

```sh
cy-tls scan cybrium.ai chase.com --format csv > findings.csv
```

Columns (in order):

```
scan_target, ip, host, finding_id, severity, title, evidence, controls
```

Multiple controls are joined with `, ` inside the quoted field. Excel,
Google Sheets, and `pandas.read_csv` open this cleanly.

Empty result (no findings) emits only the header row — downstream
tools can detect "no findings" by line count == 1.

## HTML

Standalone Cybrium-branded report. Self-contained — the only external
resources are the Cybrium shield + wordmark SVGs from the
`cybriumstorage.blob.core.windows.net` CDN. The file emails cleanly and
archives cleanly.

```sh
cy-tls scan cybrium.ai --format html > report.html
open report.html        # macOS
xdg-open report.html    # Linux
start report.html       # Windows
```

Structure:

- Header: Cybrium shield + wordmark + `cy-tls vX.Y.Z` + UTC timestamp
- Severity tiles: critical / high / medium / low / info counts
- Per-target section, one per scanned host:
  - Protocol support strip (TLS 1.0/1.1/1.2/1.3 ✓/✗)
  - Certificate dl (subject, issuer, SAN, validity, sig algo, key bits,
    SCT count, OCSP stapled)
  - Findings table sorted by severity, with control-mapping column
- Footer: cy-tls version + generation timestamp

Inline CSS dark-themed, mobile-responsive at narrow widths.

## GUI export

`cy-tls gui` adds five buttons to the Findings panel header. Each
triggers a download via `GET /api/export?format=<fmt>`. Server sets:

- `Content-Type` = the format's canonical MIME type
- `Content-Disposition: attachment; filename="cy-tls-report-YYYY-MM-DD.<ext>"`

Browser handles the rest. The download includes every scan from the
current GUI session — the in-memory history accumulates as you submit
more targets, so a single export can cover many scans.

## Library use

```rust
use cy_tls::output;
use cy_tls::scan::ScanReport;

let reports: Vec<ScanReport> = /* ... */;

let csv = output::csv::render(&reports);
let html = output::html::render(&reports);

// JSON / JSONL / SARIF emit directly to stdout — wrap with
// std::io::Cursor if you need them as Strings.
```

## Format stability

| Format | Stability promise |
|--------|-------------------|
| JSON, JSONL | Within a major version, fields are additive. The `_schema_version` field will be introduced in v1.0.0 to allow future breaking changes. |
| SARIF | Locked to SARIF 2.1.0. cy-tls will only emit valid SARIF as long as that spec exists. |
| CSV | Column order is stable within a major version. New columns are appended, not inserted. |
| HTML | Visual layout may change between minor versions. The Cybrium branding contract is permanent. |

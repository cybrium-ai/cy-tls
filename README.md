# cy-tls — Cybrium SSL/TLS posture scanner

Fast Rust scanner that runs the full TLS posture probe in-process. No
container start-up tax, JSONL streaming for bulk scans, embedded
Chromium HSTS preload lookup, MCP server for AI agents, web UI with
Cybrium-branded reports.

Built as the canonical SSL/TLS engine for the Cybrium platform,
replacing the Docker / K8s-jobbed sslyze pipeline.

## Status

| Version | Highlights |
|---------|-----------|
| **v0.2.4** | CSV + HTML export, GUI download buttons, `/api/export` endpoint |
| v0.2.3 | In-shell secret guards in release pipeline |
| v0.2.0 | TLS 1.0/1.1 raw probes, SCT extraction, cert field overhaul, `cy-tls bulk`, `cy-tls verify-preload` |
| v0.1.1 | `cy-tls gui` (Cybrium-branded local UI), `cy-tls mcp` (Model Context Protocol server) |
| v0.1.0 | Scaffold — TCP + TLS 1.2/1.3, cert hygiene, HSTS, 37 stable finding IDs |

| Subcommand | What it does |
|------------|--------------|
| `cy-tls scan` | Full posture probe — TLS 1.0/1.1/1.2/1.3 detection, cert hygiene with proper sig-algo + key-bit + SCT count, HSTS + preload lookup |
| `cy-tls bulk` | Bounded-concurrency fan-out from `--targets-file`, JSONL streaming |
| `cy-tls verify-preload` | Curated apex lookup with subdomain inheritance |
| `cy-tls gui` | Loopback web UI with Cybrium branding, scan form, 5-format export |
| `cy-tls mcp` | Model Context Protocol server over stdio — exposes `cy_tls_scan` to Claude / Cline / Continue |

## Install

```sh
brew install cybrium-ai/cli/cy-tls          # macOS + Linux
scoop install cybrium-ai/cy-tls             # Windows (signed binary)
cargo install --git https://github.com/cybrium-ai/cy-tls  # any platform
```

Or grab a binary directly from the [releases page](https://github.com/cybrium-ai/cy-tls/releases).

See [`docs/installation.md`](docs/installation.md) for full details including manual install and signature verification.

## Quick start

```sh
# Single host (default: JSON output)
cy-tls scan example.com

# Multiple hosts, CSV for a spreadsheet
cy-tls scan example.com cybrium.ai chase.com --format csv > findings.csv

# Standalone HTML report (Cybrium-branded, emails cleanly)
cy-tls scan example.com --format html > report.html
open report.html

# SARIF for GitHub code-scanning ingestion
cy-tls scan example.com --format sarif > scan.sarif

# Bulk JSONL stream from a host list
cy-tls bulk --targets-file hosts.txt --concurrency 64 > fleet.jsonl

# HSTS preload status
cy-tls verify-preload chase.com

# Local web UI (auto-opens browser at http://127.0.0.1:8992)
cy-tls gui

# MCP server (for Claude Desktop / Cline / Continue)
cy-tls mcp
```

## Output formats

5 formats, all produced from the same scan data:

| Format | Use case | CLI | GUI |
|--------|----------|-----|-----|
| **JSON** | Default — pipeline machine output | `--format json` | `[JSON]` button |
| **JSONL** | Streaming, log pipelines, one-line-per-target | `--format jsonl` | `[JSONL]` button |
| **SARIF** | CI/CD ingestion (GitHub / GitLab code-scanning) | `--format sarif` | `[SARIF]` button |
| **CSV** | Spreadsheet analysis — one row per finding | `--format csv` | `[CSV]` button |
| **HTML** | Cybrium-branded report — self-contained, shareable | `--format html` | `[HTML]` button |

Full schema + per-format details in [`docs/export-formats.md`](docs/export-formats.md).

## Finding catalog

37 stable finding IDs covering protocol, cipher, key exchange, certificate
hygiene, OCSP/SCT, TLS 1.3 surface, padding-oracle families, and HTTP
security headers. Full catalog in [`docs/finding-ids.md`](docs/finding-ids.md).

Each ID maps to NIST 800-53, PCI DSS 4.0, ISO 27001, OWASP ASVS, and CIS
Benchmark controls — see [`docs/control-mapping.md`](docs/control-mapping.md).

## Integration with the Cybrium platform

cy-tls is plumbed via
[`backend/tools_runtime/cytls_runner.py`](https://github.com/cybrium-ai/cybrium/blob/main/backend/tools_runtime/cytls_runner.py)
in the platform repo. The runner:

1. Looks for `cy-tls` on `$PATH`.
2. If present, runs it directly; the JSON is projected into the
   sslyze-compatible `{findings, ssl_results}` shape used by the
   rest of the platform.
3. If missing or non-JSON, falls back to the legacy sslyze Docker /
   K8s path. Single `ScanToolRun` row per phase, relabel-on-fallback.

The platform is cy-tls-ready; landing the binary on `$PATH` is the only
switch needed for the upgrade.

## Use cy-tls as an MCP tool

cy-tls exposes a Model Context Protocol server over stdio, so Claude
Desktop, Cline, Continue, and other MCP-aware agents can run scans as a
tool. See [`docs/mcp.md`](docs/mcp.md) for the Claude Desktop config and
example agent prompts.

## Build from source

```sh
cargo build --release
./target/release/cy-tls scan example.com
```

CI runs on every PR (Linux + macOS + Windows, stable toolchain). Release
pipeline produces signed Windows binaries via Azure Trusted Signing and
(when the Apple Org Developer ID lands) signed + notarized macOS binaries.

## License

Apache-2.0. See [`LICENSE`](LICENSE).

## Security

Issues and CVE reports: security@cybrium.ai

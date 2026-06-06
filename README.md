# cy-tls — Cybrium SSL/TLS posture scanner

Fast Rust scanner that runs the full TLS posture probe in-process. No
container start-up tax, JSONL streaming for bulk scans, Chromium HSTS
preload-list lookup built-in.

Built as the canonical SSL/TLS engine for the Cybrium platform,
replacing the Docker / K8s-jobbed sslyze pipeline.

## Status

**v0.1.0 — scaffold.** Compiles, runs, emits valid output, lays out
every stable finding ID. The "deep" probes (cipher bisection, raw
ServerHello extension parsing, OCSP/SCT extraction, ROBOT/DROWN,
Chromium preload trie) are stubbed for Phase 2 — see `TODO.md`.

| Subcommand | Status |
|------------|--------|
| `cy-tls scan` | TLS 1.0 / 1.1 / 1.2 / 1.3 detection, cert hygiene with proper sig-algo + key-bit + SCT count, HSTS headers + preload lookup, findings + JSON/JSONL/SARIF |
| `cy-tls bulk` | Bounded-concurrency fan-out from `--targets-file`, JSONL streaming |
| `cy-tls verify-preload` | Curated apex lookup (v0.2.0); full Chromium trie in v0.2.1 |
| `cy-tls gui`  | Loopback web UI with Cybrium branding, scan form, findings table |
| `cy-tls mcp`  | Model Context Protocol server over stdio (`cy_tls_scan` tool exposed to Claude / MCP agents) |

## Install

### From source

```sh
cargo install --git https://github.com/cybrium-ai/cy-tls
```

### Homebrew (planned)

```sh
brew install cybrium-ai/tap/cy-tls
```

### Binary releases

Each tag publishes signed `linux-{amd64,arm64}`, `darwin-{amd64,arm64}`,
and `windows-amd64` binaries to the GitHub Releases page.

## Quick start

```sh
# Web UI (loopback HTTP server, default port 8992)
cy-tls gui                          # opens your browser at http://127.0.0.1:8992
cy-tls gui --no-open --port 9000    # for headless / Docker

# Use as an MCP server (Claude Desktop, Cline, Continue, etc.)
cy-tls mcp                          # speaks JSON-RPC 2.0 on stdio

# Single host
cy-tls scan example.com

# Explicit port
cy-tls scan example.com:8443

# Multiple targets, JSON output
cy-tls scan example.com cybrium.ai chase.com > scan.json

# Plain text host list, SARIF for CI
cy-tls scan --targets-file hosts.txt --format sarif > scan.sarif
```

Output for one host (abbreviated):

```json
[
  {
    "target":     "example.com:443",
    "ip":         "93.184.216.34",
    "elapsed_ms": 1247,
    "protocols": {
      "tls12": { "supported": true, "ciphers": ["..."] },
      "tls13": { "supported": true, "ciphers": ["..."], "zero_rtt_accepted": false }
    },
    "certificate": { "subject": "CN=example.com", "...": "..." },
    "findings": [
      { "id": "TLS-WEAK-VERSION-1.1", "severity": "high", "title": "TLS 1.1 accepted", "...": "..." }
    ]
  }
]
```

## Finding catalog

37 stable finding IDs covering protocol, cipher, key exchange,
certificate hygiene, OCSP/SCT, TLS 1.3 surface, padding-oracle
families, and HTTP security headers. Full table in
[`docs/finding-ids.md`](docs/finding-ids.md).

Each ID is keyed to NIST 800-53, PCI DSS 4.0, ISO 27001, OWASP ASVS,
and CIS Benchmark controls — see [`docs/control-mapping.md`](docs/control-mapping.md).

## Integration with the Cybrium platform

cy-tls is plumbed via
[`backend/tools_runtime/cytls_runner.py`](https://github.com/cybrium-ai/cybrium/blob/main/backend/tools_runtime/cytls_runner.py)
in the platform repo. The runner:

1. Looks for `cy-tls` on `$PATH`.
2. If present, runs it directly; the JSON is projected into the
   sslyze-compatible `{findings, ssl_results}` shape used by the
   rest of the platform.
3. If missing or non-JSON, falls back to the legacy sslyze Docker /
   K8s path. Single `ScanToolRun` row per phase, relabel-on-fallback —
   identical pattern to cymail / checkdmarc.

This means **the platform is already cy-tls-ready**; this binary
landing on `$PATH` is the only switch needed for the upgrade.

## Output schema

See [`docs/json-schema.md`](docs/json-schema.md) for the canonical
shape. The schema is additive — new fields are safe; existing fields
will not be renamed inside a major version.

## Build

```sh
cargo build --release
./target/release/cy-tls scan example.com
```

CI runs on every PR (Linux + macOS + Windows, stable + beta toolchains).

## License

Apache-2.0. See `LICENSE`.

## Security

Issues and CVE reports: security@cybrium.ai (PGP key on
[cybrium.ai/security](https://cybrium.ai/security)).

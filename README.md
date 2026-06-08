# cy-tls — Cybrium SSL/TLS posture scanner

Fast Rust scanner with Qualys-class TLS posture coverage. Sub-second
single-host probe, no container start-up tax, JSONL streaming for bulk
scans, embedded Chromium HSTS preload check, MCP server for AI agents,
Cybrium-branded web UI, signed Windows binaries.

Built as the canonical SSL/TLS engine for the Cybrium platform,
replacing the Docker / K8s-jobbed sslyze pipeline.

## Status

**v0.5.70 — full Qualys + SSLyze parity, plus a wider HTTP/DNS audit
surface neither covers.** Single-letter composite grade (A+/A/B/C/D/E/F/T)
matches Qualys SSL Labs. Multi-trust-store chain validation against
Mozilla / Apple / Android / Java matches SSLyze. 100 stable finding
IDs, each with per-finding severity + remediation + reference URL +
compliance control mapping (NIST 800-53, PCI DSS 4.0, ISO 27001,
OWASP ASVS, CIS).

| Subcommand | What it does |
|------------|--------------|
| `cy-tls scan` | Full posture probe |
| `cy-tls bulk` | Bounded-concurrency fan-out over a host list, JSONL streaming |
| `cy-tls verify-preload` | Chromium HSTS preload list lookup |
| `cy-tls gui` | Loopback web UI with Cybrium branding + 5-format export |
| `cy-tls mcp` | Model Context Protocol server over stdio |

## Install

```sh
brew install cybrium-ai/cli/cy-tls          # macOS + Linux
scoop install cybrium-ai/cy-tls             # Windows (signed binary)
cargo install --git https://github.com/cybrium-ai/cy-tls
```

Direct downloads on the [releases page](https://github.com/cybrium-ai/cy-tls/releases). See [`docs/installation.md`](docs/installation.md) for signature verification.

## Quick start

```sh
# Single host (default: JSON output)
cy-tls scan example.com

# Full Qualys-style probe with cipher enum, session probe, OCSP,
# PQC, Heartbleed, ROBOT/DROWN/BEAST eligibility, DHE Logjam check
cy-tls scan example.com --format html > report.html

# Add the 30-client handshake simulation matrix
cy-tls scan example.com --handshake-sim --format json

# Bulk JSONL stream
cy-tls bulk --targets-file hosts.txt --concurrency 64 > fleet.jsonl

# Local web UI (auto-opens browser at http://127.0.0.1:8992)
cy-tls gui

# MCP server for Claude Desktop / Cline / Continue / Cursor
cy-tls mcp
```

## cy-tls vs SSLyze vs Qualys SSL Labs

`✓` full · `~` partial · `✗` absent.

| Capability | cy-tls (v0.5.70) | SSLyze | Qualys |
|---|:---:|:---:|:---:|
| **Headline output** | | | |
| Composite letter grade (A+/A/B/C/D/E/F/T) | ✓ | ✗ | ✓ |
| Per-axis subscores (protocol / key / cipher) | ✓ | ✗ | ✓ |
| Plain-English verdict line | ✓ | ✗ | ✓ |
| Active-breach indicator list | ✓ | ✗ | ~ |
| Per-finding remediation string | ✓ | ✗ | ✓ |
| Per-finding reference URL (CVE / RFC) | ✓ | ✗ | ✓ |
| Compliance mappings (NIST / PCI / OWASP / ISO / CIS) | ✓ | ✗ | ~ |
| **Protocols & ciphers** | | | |
| SSL 2/3 + TLS 1.0/1.1/1.2/1.3 detection | ✓ | ✓ | ✓ |
| Full cipher enumeration | ✓ | ✓ | ✓ |
| TLS 1.3 + 0-RTT detection | ✓ | ✓ | ✓ |
| Cipher preference order | ✓ | ✓ | ✓ |
| Forward Secrecy bucket | ✓ | ~ | ✓ |
| TLS_FALLBACK_SCSV | ✓ | ~ | ✓ |
| GREASE tolerance (RFC 8701) | ✓ | ✗ | ✓ |
| Extended Master Secret (RFC 7627) | ✓ | ✓ | ✓ |
| Post-quantum readiness (ML-KEM hybrid) | ✓ | ✗ | ✗ |
| ECH advertisement (DNS HTTPS rr) | ✓ | ✗ | ✗ |
| HTTP/3 advertisement | ✓ | ✗ | ✓ |
| **Vulnerabilities** | | | |
| Heartbleed (active) | ✓ | ✓ | ✓ |
| ROBOT (active) | ✓ | ✓ | ✓ |
| CCS Injection | ✓ | ✓ | ✓ |
| DROWN | ✓ | ~ | ✓ |
| Ticketbleed | ✓ | ✗ | ✓ |
| OpenSSL AES-NI padding oracle (CVE-2016-2107) | ✓ | ~ | ✓ |
| GOLDENDOODLE / Zombie POODLE (active) | ✓ | ~ | ✓ |
| Lucky13 (fingerprint + heuristic) | ✓ | ~ | ✓ |
| Logjam / DH common-prime | ✓ | ~ | ✓ |
| FREAK / EXPORT cipher | ✓ | ✓ | ✓ |
| CRIME / TLS compression | ✓ | ✓ | ✓ |
| BREACH eligibility | ✓ | ✗ | ✓ |
| CBC-MAC-then-encrypt (Lucky13 surface) | ✓ | ~ | ✓ |
| Insecure renegotiation (CVE-2009-3555) | ✓ | ✓ | ✓ |
| HTTP/2 Rapid Reset (CVE-2023-44487) eligibility | ✓ | ✗ | ~ |
| HTTP/2 header-list DoS (CVE-2019-9516) | ✓ | ✗ | ✗ |
| h2c upgrade smuggling | ✓ | ✗ | ✗ |
| **Certificate** | | | |
| Hostname / SAN match | ✓ | ✓ | ✓ |
| Expired / not-yet-valid | ✓ | ✓ | ✓ |
| Self-signed | ✓ | ✓ | ✓ |
| Weak signature (SHA-1/MD5) | ✓ | ✓ | ✓ |
| Weak key bits | ✓ | ✓ | ✓ |
| Chain completeness + depth + order | ✓ | ✓ | ✓ |
| Intermediate expiry | ✓ | ✓ | ✓ |
| CN-only (no SAN) | ✓ | ✓ | ✓ |
| Dangerous wildcard (public-suffix / multi-label) | ✓ | ✗ | ~ |
| Cert lifetime > 398-day BR cap | ✓ | ~ | ✓ |
| Missing serverAuth EKU | ✓ | ✓ | ✓ |
| Weak serial entropy (<64 bits) | ✓ | ✗ | ✓ |
| Leaf-is-CA (BasicConstraints cA misissuance) | ✓ | ✗ | ✓ |
| Missing AKI / SKI | ✓ | ~ | ✓ |
| SPKI + whole-cert SHA-256 fingerprint | ✓ | ✓ | ✓ |
| Shared-infra cert detection (>100 SANs) | ✓ | ✗ | ✗ |
| Symantec distrust heuristic | ✓ | ✗ | ✓ |
| AIA caIssuers reachability | ✓ | ✗ | ✓ |
| **Trust / OCSP / CT** | | | |
| Mozilla / webpki trust chain | ✓ | ✓ | ✓ |
| Apple / Android / Java trust stores | ✓ | ✓ | ✓ |
| Trust-tolerant probe (sees cert even on validation fail) | ✓ | ✓ | ✓ |
| Grade T for trust failure | ✓ | n/a | ✓ |
| OCSP stapling | ✓ | ✓ | ✓ |
| Active OCSP query | ✓ | ✓ | ~ |
| Must-staple violation | ✓ | ✓ | ✓ |
| SCT presence | ✓ | ✓ | ✓ |
| SCT operator diversity (Chrome 2022 policy) | ✓ | ~ | ✓ |
| SCT count policy (≥2 / ≥3) | ✓ | ~ | ✓ |
| **DNS posture** | | | |
| CAA records + iodef + issuewild check | ✓ | ✗ | ~ |
| DNSSEC publish-side | ✓ | ✗ | ✗ |
| SOA serial freshness (RFC 1912) | ✓ | ✗ | ✗ |
| NS provider redundancy | ✓ | ✗ | ✗ |
| DANE TLSA presence | ✓ | ✓ | ✓ |
| **HTTP / Web headers** | | | |
| HSTS + max-age + includeSubdomains + preload-list lookup | ✓ | ~ | ✓ |
| HSTS preload eligibility | ✓ | ✗ | ✓ |
| HPKP detection (deprecated info) | ✓ | ✓ | ✓ |
| HTTP→HTTPS redirect audit | ✓ | ✗ | ✓ |
| CSP missing / unsafe-inline / unsafe-eval / data: / wildcard | ✓ | ✗ | ✗ |
| X-Frame-Options / CSP frame-ancestors | ✓ | ✗ | ✗ |
| X-Content-Type-Options nosniff | ✓ | ✗ | ✗ |
| Cookie Secure / HttpOnly / SameSite audit | ✓ | ✗ | ✗ |
| Cache-Control on cookie-setting responses | ✓ | ✗ | ✗ |
| TRACE method (XST) | ✓ | ✗ | ✗ |
| Server / X-Powered-By disclosure | ✓ | ✗ | ~ |
| Server-Timing / Via leak | ✓ | ✗ | ✗ |
| Content-Type charset hygiene | ✓ | ✗ | ✗ |
| Reporting-Endpoints / NEL capture | ✓ | ✗ | ✗ |
| Legacy Report-To deprecation flag | ✓ | ✗ | ✗ |
| **Other** | | | |
| Multi-client handshake simulation | ✓ (`--handshake-sim`) | ✗ | ✓ |
| Bulk / fleet streaming | ✓ (`bulk` + `--summary`) | ~ | ✗ |
| Self-hosted / air-gapped | ✓ | ✓ | ✗ |
| Output formats | JSON · JSONL · SARIF · CSV · HTML | JSON · XML | JSON (API) |
| Avg time per host | 3–20 s | 30–60 s | 60–300 s |
| Cost | free, single binary | free, Python lib | free SaaS / paid API |

**Where Qualys still wins:** track record (running since 2009, deep
real-world calibration); handshake-simulation client matrix is broader.

**Where cy-tls leads:** HTTP-layer header audit (CSP, cookies, nosniff,
TRACE, Server, Via, Server-Timing), DNS posture (CAA hygiene, SOA
freshness, NS, DNSSEC, DANE), per-finding remediation + reference +
compliance mapping, breach-indicator list, bulk SIEM-friendly output,
self-hosted single-binary deployment, PQC + ECH + HTTP/3 awareness.

## Output formats

5 formats from one scan:

| Format | CLI | GUI |
|--------|-----|-----|
| JSON | `--format json` | Download button |
| JSONL | `--format jsonl` | Download button |
| SARIF | `--format sarif` | Download button |
| CSV | `--format csv` | Download button |
| HTML (Cybrium-branded, self-contained) | `--format html` | Download button |

Full schema + per-format details in [`docs/export-formats.md`](docs/export-formats.md).

## Finding catalog

100 stable finding IDs covering protocol versions, cipher suites, key
exchange, certificate hygiene, multi-trust-store divergence, OCSP /
SCT, TLS 1.3 surface, padding-oracle families, HTTP security headers,
CSP audit, cookie hygiene, DNS posture (CAA / DNSSEC / DANE / SOA),
and active-probe vulnerabilities. Full catalog:
[`docs/finding-ids.md`](docs/finding-ids.md).

Each ID maps to NIST 800-53, PCI DSS 4.0, ISO 27001, OWASP ASVS, and CIS
Benchmark controls — [`docs/control-mapping.md`](docs/control-mapping.md).

## Use cy-tls as an MCP tool

cy-tls exposes a Model Context Protocol server over stdio. Claude
Desktop, Cline, Continue, Cursor can run scans as a tool. See
[`docs/mcp.md`](docs/mcp.md) for setup.

## Integration with the Cybrium platform

cy-tls is plumbed via
[`backend/tools_runtime/cytls_runner.py`](https://github.com/cybrium-ai/cybrium/blob/main/backend/tools_runtime/cytls_runner.py):

1. Looks for `cy-tls` on `$PATH`.
2. If present, runs it directly; the JSON projects into the
   sslyze-compatible `{findings, ssl_results}` shape used by the platform.
3. If missing or non-JSON, falls back to the legacy sslyze Docker /
   K8s path. Single `ScanToolRun` row per phase.

The platform is cy-tls-ready; landing the binary on `$PATH` is the only
switch needed.

## Build from source

```sh
cargo build --release
./target/release/cy-tls scan example.com
```

CI runs on every PR (Linux + macOS + Windows, stable toolchain). Release
pipeline produces signed Windows binaries via Azure Trusted Signing and
auto-updates Homebrew formula + Scoop manifest. macOS signing pending
Apple Org Developer ID issuance.

## License

Apache-2.0. See [`LICENSE`](LICENSE).

## Security

Issues and CVE reports: security@cybrium.ai

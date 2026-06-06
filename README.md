# cy-tls — Cybrium SSL/TLS posture scanner

Fast Rust scanner with Qualys-class TLS posture coverage. Sub-second
single-host probe, no container start-up tax, JSONL streaming for bulk
scans, embedded Chromium HSTS preload check, MCP server for AI agents,
Cybrium-branded web UI, signed Windows binaries.

Built as the canonical SSL/TLS engine for the Cybrium platform,
replacing the Docker / K8s-jobbed sslyze pipeline.

## Status

**v0.2.18 — Qualys-class parity.** Twelve probe rounds shipped this
release stream covering every Qualys SSL Test row except the full
Chromium preload trie and the active Bleichenbacher oracle (both
deferred to v0.3.x).

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

## Qualys SSL Test parity

Every row Qualys' SSL Server Test surfaces (per the screenshots
labelled `ssltest/analyze.html`) is now produced from a single
`cy-tls scan` invocation:

| Qualys row | cy-tls source |
|------------|---------------|
| Protocol enum (SSLv2 / SSLv3 / TLS 1.0 / 1.1 / 1.2 / 1.3) | `protocols.{sslv2,sslv3,tls10,tls11,tls12,tls13}.supported` |
| Cipher suites with hex codes + names + FS markers | `protocols.tls12.ciphers` + `protocols.tls13.ciphers` |
| Forward Secrecy | `protocols.forward_secrecy` |
| Key Exchange Group (X25519 / secp256r1 / etc.) | `protocols.key_exchange_group` |
| ALPN | `protocols.alpn` |
| Session resumption (caching + tickets) | `extensions.session_resumption.{tls13_psk, tls12_ticket}` |
| Secure Renegotiation | `extensions.renegotiation.secure` |
| Compression (CRIME) | `extensions.compression.offered` → `TLS-COMPRESSION-ENABLED` |
| Heartbeat extension | `extensions.heartbeat.offered` |
| Cert subject / issuer / SAN / validity / sig algo / key bits / EC curve / SCT count | `certificate.{subject, issuer, san, not_before, not_after, signature_algorithm, key_algorithm, key_bits, ec_curve, sct_count}` |
| OCSP Stapling | `certificate.ocsp_stapled` + `certificate.ocsp_status` |
| HSTS / max-age / includeSubDomains / preload | `headers.hsts.{present, max_age, include_subdomains, preload, in_preload_list}` |
| Handshake Simulation (30 reference clients) | `handshake_simulation` (with `--handshake-sim`) |
| Heartbleed (CVE-2014-0160) | Active probe → `TLS-HEARTBLEED` |
| POODLE | SSLv3 detection → `TLS-SSLV3` |
| ROBOT (CVE-2017-13099) eligibility | Cipher enum → `TLS-ROBOT-VULNERABLE` |
| DROWN (CVE-2016-0800) | SSLv2 detection → `TLS-DROWN-VULNERABLE` |
| BEAST (CVE-2011-3389) | TLS 1.0 + CBC → `TLS-CBC-MAC-THEN-ENCRYPT` |
| Logjam / DH common primes | DHE param probe + SHA-256 hash compare → `TLS-DH-WEAK` / `TLS-DH-COMMON-PRIME` |
| PQC Key Exchange | `protocols.pqc.{supported, group}` |

Surface still on the v0.3.x roadmap:

- Full Chromium HSTS preload trie embed (current v0.2.x carries a
  curated ~120-apex set with subdomain inheritance).
- ROBOT active Bleichenbacher oracle test (current is eligibility-tier
  via RSA cipher detection; full active test needs RSA-encrypted
  ClientKeyExchange variants).
- Real Logjam Appendix A common-prime hash list (placeholder hashes
  shipped in v0.2.18).

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

38 stable finding IDs covering protocol, cipher, key exchange, certificate
hygiene, OCSP / SCT, TLS 1.3 surface, padding-oracle families, HTTP
security headers, and active-probe vulnerabilities. Full catalog:
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

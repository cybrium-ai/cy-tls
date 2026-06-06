# cy-tls — Roadmap

## v0.1.0 (scaffold — current)
- [x] Cargo project + workspace
- [x] CLI scaffolding (`scan`, `bulk`, `verify-preload`, `gui`, `mcp`)
- [x] 37 stable finding IDs registered with control mapping
- [x] TCP + TLS 1.2/1.3 handshake via rustls
- [x] Certificate parse (subject/SAN/expiry/key bits/sig algo/self-signed/must-staple)
- [x] HSTS / Expect-CT / HPKP header probe
- [x] JSON / JSONL / SARIF emitters
- [x] **`cy-tls gui`** — loopback-only axum HTTP server + embedded HTML SPA with Cybrium logo/wordmark, scan form, severity tiles, findings table
- [x] **`cy-tls mcp`** — Model Context Protocol server (JSON-RPC 2.0 over stdio) exposing `cy_tls_scan` to Claude / MCP-aware agents
- [x] CI on Linux + macOS + Windows
- [x] Release pipeline scaffold
- [x] Homebrew formula at cybrium-ai/homebrew-cli

## v0.2.0 — first production-ready pass (shipped)

Shipped:
- [x] **TLS 1.0 / 1.1 detection** — raw ClientHello probe over TcpStream (`src/scan/legacy_proto.rs`). Verified against `google.com` which still negotiates both for compat.
- [x] **SCT extraction** — counts SCTs from cert extension OID 1.3.6.1.4.1.11129.2.4.2 (`src/scan/cert.rs::extract_sct_count`).
- [x] **Cert field naming** — OID-to-name lookup for sig algorithm + public key algorithm (`src/scan/oid_names.rs`); proper EC curve bit lengths via curve OID; RSA modulus bits from DER walker (no longer reports 520 for P-256).
- [x] **`cy-tls bulk`** — bounded-concurrency fan-out with JSONL streaming (`src/bulk.rs`).
- [x] **`cy-tls verify-preload`** — curated lookup of high-traffic preloaded apexes with subdomain inheritance (`src/preload.rs`); wired into `headers.hsts.in_preload_list`.

## v0.2.1 — Phase 2 finish-line

- [ ] **SSLv2 / SSLv3 raw probes** — extend `legacy_proto.rs` with the older record layer + ClientHello.v2 dialect. Rare in 2026 but completes the catalog.
- [ ] **Cipher suite enumeration** — bisection over cipher_suites list per protocol version. Populates `protocols.tls12.ciphers` and `protocols.tls13.ciphers` properly.
- [ ] **Weak-cipher findings** — RC4 / 3DES / NULL / EXPORT / Anonymous / CBC-without-EtM detection from the enumerated list.
- [ ] **Key exchange detection** — DHE param bits (Logjam), DHE common-prime check against the known snowden list, ECDHE curves + preferred curve.
- [ ] **OCSP stapling** — rustls 0.23 needs a custom certificate verifier to capture the stapled response; planned via `rasn-ocsp` for the status decode.
- [ ] **Full Chromium HSTS preload trie** — embed `transport_security_state_static.json` at build time and walk the trie. Replaces the v0.2.0 curated apex list.
- [ ] **TLS 1.3 0-RTT** — send PSK + early_data extension; check ServerHello + EncryptedExtensions for acceptance.
- [ ] **Renegotiation probe** — send client-initiated rehandshake over an already-established TLS 1.2 connection; emit `TLS-CLIENT-RENEG-ALLOWED` if accepted.
- [ ] **Compression / heartbeat detection** — parse extensions block of ServerHello.
- [ ] **ROBOT** — send malformed RSA ClientKeyExchange and watch for differentiable error vs valid response.
- [ ] **DROWN** — cross-protocol check: same cert+IP serving SSLv2 anywhere on the network.
- [ ] **End-to-end test against badssl.com** — every BadSSL fixture host emits the expected finding(s).

## v0.3.0 — Qualys-class grading + scoring (the SSL Labs bar)

- [ ] **Letter grade** — A+ / A / B / C / D / F derived from cipher + protocol + cert + key strength following Qualys's published rubric.
- [ ] **Trust grade** — separate from cipher grade; what is the cert chain's intrinsic trust?
- [ ] **Handshake simulation matrix** — what would Chrome / Firefox / Safari / Edge / Java 8 / Java 11 / Android 10 / iOS 16 / Win10 / Win11 / Go / OpenSSL 1.1.1 / OpenSSL 3 actually negotiate? Render the matrix in the GUI + JSON.
- [ ] **Forward secrecy report** — PFS enabled, partial, or absent per cipher suite.
- [ ] **Mixed content warning** — if the host serves HTTP-only links from an HTTPS page (HEAD-fetch probe).
- [ ] **Reused public key detection** — same SubjectPublicKeyInfo on multiple unrelated certs (compromise indicator).
- [ ] **HSTS preload status (Phase 2 prerequisite)** — already specified, just needs the trie embed.
- [ ] **WeakDH / Logjam (Phase 2 prerequisite)** — already specified.

## v0.4.0 — TPM / device attestation

- [ ] **Linux TPM 2.0** via `/dev/tpm0` + tss2-esys — emit `device.tpm` block in scan reports:
  - `manufacturer`, `model`, `firmware_version`
  - `ek_cert` (Endorsement Key certificate, base64)
  - `pcr_quote` over a fresh nonce (PCRs 0-7 by default, configurable)
  - signature over the quote with AK (Attestation Key)
- [ ] **Windows TPM** via `Tbs.dll` (TBS = TPM Base Services) — same JSON shape.
- [ ] **macOS Secure Enclave** via SecKey APIs — limited surface; emit what we can.
- [ ] **No-TPM fallback** — emit `device.tpm: { available: false, reason: "..." }` cleanly.
- [ ] **Optional `--attest` flag** — only run TPM attestation when explicitly requested; default off to keep scans fast and side-effect-free.
- [ ] **Integration**: `cy-tls scan --attest` returns the standard report with an additional `device` block containing the TPM quote. The platform's `cytls_runner.py` enrichment unpacks this into a separate `DeviceAttestation` row for audit chain.

## v0.5.0 — quality of life

- [ ] DTLS support (`--proto dtls`).
- [ ] QUIC (HTTP/3) TLS 1.3 probe (`--quic`).
- [ ] STARTTLS for SMTP / IMAP / POP3 / FTP / LDAP (already-encrypted ports skip).
- [ ] Mutual TLS / client-cert probing (`--client-cert / --client-key`).
- [ ] Per-target retry on transient TCP failure.
- [ ] Configurable cipher exclusion list for "we know this is required, don't flag it" cases.
- [ ] OpenTelemetry trace output for per-stage timing analysis.
- [ ] Cross-signed certificate chain checking (which intermediate is presented to which root).

## v1.0.0 — stability promise

- [ ] JSON schema versioning + `$schema` URL frozen.
- [ ] FIPS 140-3 build variant (replaces `ring` with `aws-lc-rs`).
- [ ] Signed binaries (Cybrium Trusted Signing for Windows; macOS Developer ID; sigstore cosign for Linux).
- [ ] Reproducible builds.
- [ ] Stable subset of finding IDs frozen with semver guarantees.

## Out of scope (handled by other Cybrium binaries)

- Active TLS-MITM proxying — `cyproxy`.
- Endpoint TLS posture — `cyguard`.
- Web vulnerability scanning — `cyweb`.
- SAST / supply chain — `cyscan`.

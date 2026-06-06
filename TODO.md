# cy-tls — Roadmap

## v0.2.x — Qualys-class parity (shipped)

### Foundation (v0.2.0–v0.2.4)
- [x] Cargo project + workspace
- [x] CLI scaffolding (scan, bulk, verify-preload, gui, mcp)
- [x] 38 stable finding IDs registered with control mapping
- [x] TCP + TLS 1.2/1.3 handshake via rustls + ring
- [x] Certificate parse (subject, SAN, expiry, key bits, sig algo,
      self-signed, must-staple, SCT count)
- [x] OID-to-name maps; proper EC curve bit length; RSA modulus parse
- [x] TLS 1.0 / 1.1 detection via raw ClientHello
- [x] HSTS / Expect-CT / HPKP header probe + curated preload lookup
- [x] JSON / JSONL / SARIF / CSV / HTML emitters
- [x] `cy-tls gui` — loopback axum server with Cybrium-branded SPA
- [x] `cy-tls mcp` — JSON-RPC 2.0 over stdio
- [x] `cy-tls bulk` — bounded-concurrency JSONL fan-out
- [x] CI on Linux + macOS + Windows; release matrix builds + signs
- [x] Homebrew + Scoop auto-update on each tag
- [x] Azure Trusted Signing for Windows binaries

### Qualys parity (v0.2.7–v0.2.18 — 12 rounds)
- [x] **#1 — ALPN + Forward Secrecy + named KX group** (v0.2.7)
- [x] **#2 — Cipher suite enumeration** via ClientHello bisection
      (21 modern + legacy suites, weak-cipher findings) (v0.2.8)
- [x] **#3 — Session resumption** (TLS 1.3 PSK + TLS 1.2 ticket) (v0.2.9)
- [x] **#4 — Secure Renegotiation + Compression + Heartbeat** parse
      (TLS 1.2 ServerHello extension walker) (v0.2.10)
- [x] **#5 — Handshake Simulation matrix** (30 reference clients:
      Android 4.4-12, Chrome 49-131, Firefox 47-135, IE 11, Safari 9-17,
      Java 8/11/17, OpenSSL 1.0.1-3.0, Apple ATS, Googlebot, YandexBot)
      (v0.2.11)
- [x] **#6 — OCSP stapling probe** via raw ClientHello + status_request
      extension; CertificateStatus parse across record fragments
      (v0.2.12)
- [x] **#7 — PQC Key Exchange detection** (X25519MLKEM768 +
      X25519Kyber768Draft00 hybrids) (v0.2.13)
- [x] **#8 — Heartbleed active probe** (gated on heartbeat extension;
      pre-handshake malformed heartbeat over-read) (v0.2.14)
- [x] **#9 — ROBOT eligibility** (RSA cipher detection → potentially
      vulnerable) (v0.2.15)
- [x] **#10 — SSLv2 / SSLv3 detection + DROWN** (v2 record-layer
      probe; SSLv2 on same host emits TLS-DROWN-VULNERABLE) (v0.2.16)
- [x] **#11 — BEAST eligibility** (TLS 1.0 + CBC) (v0.2.17)
- [x] **#12 — DHE detection + Logjam common-prime check**
      (DHE-only ClientHello → extract prime → SHA-256 → compare
      against published common-primes set) (v0.2.18)

## v0.3.x — beyond Qualys parity

- [ ] **Full Chromium HSTS preload trie** — embed
      `transport_security_state_static.json` at build time; replaces
      the v0.2.x curated ~120-apex set with the canonical browser list.
- [ ] **ROBOT active Bleichenbacher oracle test** — 5 ClientKeyExchange
      variants with PKCS#1 v1.5 padding errors; observe whether
      server's alert / timing / connection-close differentiates them.
      Needs the `rsa` crate for public-key encryption.
- [ ] **Real Logjam common-prime list** from the original paper's
      Appendix A — replace the placeholder hashes in `dh_params.rs`.
- [ ] **Sweet32 active probe** — actively demonstrate 3DES birthday
      bound; currently we just emit the finding when 3DES is in the
      accepted cipher list.
- [ ] **GOLDENDOODLE / Zombie POODLE** — TLS 1.2 + CBC oracles with
      varied padding manipulation patterns.
- [ ] **OpenSSL CCS Injection (CVE-2014-0224)** — early
      ChangeCipherSpec before completing handshake.
- [ ] **OpenSSL Padding Oracle (CVE-2016-2107)** — AES-NI specific path.
- [ ] **CRIME / TIME** — observation-based; needs HTTP request size
      delta observation, more involved.
- [ ] **TLS Triple Handshake (Logjam-adjacent)** — cross-session
      renegotiation oracle.
- [ ] **Ticketbleed (CVE-2016-9244)** — F5-specific session ticket leak.
- [ ] **Strict ASN.1 OCSP parse** via rasn-ocsp — replaces the loose
      heuristic certStatus detection in v0.2.12.
- [ ] **Custom verifier for full chain trust** — chain validity, CT,
      expiry per intermediate, CRL fetch optional.

## v0.4.x — TPM / device attestation

- [ ] **Linux TPM 2.0** via `/dev/tpm0` + tss2-esys — emit `device.tpm`
      block with manufacturer / model / firmware / EK cert / PCR quote
      / AK signature.
- [ ] **Windows TPM** via `Tbs.dll` — same JSON shape.
- [ ] **macOS Secure Enclave** via SecKey APIs.
- [ ] **No-TPM fallback** with explicit reason.
- [ ] `--attest` flag — opt-in.

## v0.5.x — quality of life

- [ ] DTLS support (`--proto dtls`).
- [ ] QUIC (HTTP/3) TLS 1.3 probe (`--quic`).
- [ ] STARTTLS for SMTP / IMAP / POP3 / FTP / LDAP.
- [ ] mTLS (client certificate auth) probing.
- [ ] Per-target retry on transient TCP failure.
- [ ] Configurable cipher exclusion list ("we know this is required,
      don't flag it").
- [ ] OpenTelemetry trace output for per-stage timing analysis.

## v1.0.0 — stability promise

- [ ] JSON schema versioning + `$schema` URL frozen.
- [ ] FIPS 140-3 build variant (replaces `ring` with `aws-lc-rs`).
- [ ] Signed binaries (macOS Developer ID once Org-account approved;
      Linux via sigstore cosign).
- [ ] Reproducible builds.
- [ ] Stable subset of finding IDs frozen with semver guarantees.

## Out of scope

Handled by other Cybrium binaries:
- `cyproxy` — Active TLS-MITM proxying
- `cyguard` — Endpoint TLS posture
- `cyweb` — Web vulnerability scanning
- `cyscan` — SAST / supply chain
- `cyred` — AI red-teaming
- `cymed` — Hospital protocol scanning

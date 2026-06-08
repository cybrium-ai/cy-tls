# cy-tls — Round #22 Handoff (TLS Triple Handshake)

> Handoff from session prior to `claude --resume cb842aa2-a053-4b7d-b529-33901f181cf9`.
> Repo cloned at `~/Documents/cy-tls`, HEAD `caa200f` (v0.3.6).

## Status recap

### DONE (no action needed)
- **Homebrew tap bumped to v0.3.6.** `cybrium-ai/homebrew-cli/Formula/cy-tls.rb`
  was already at v0.3.6 with correct per-platform SHA256s (all 4 verified against
  the real release binaries). Local brew was just stale — `brew update &&
  brew upgrade cy-tls` took 0.2.1 → 0.3.6. Engine confirmed current via the
  `server_fingerprint` field appearing in scan output.

### Round board (where we are)
- #13–#19 → v0.3.0–v0.3.4 ✅
- #20 ROBOT active Bleichenbacher → v0.3.5 ✅
- #21 Server fingerprint + `TLS-CBC-ORACLE-FAMILY-FP` → v0.3.6 ✅
- **#22 TLS Triple Handshake → THIS ROUND (not started)**

### Honest v0.3.x backlog after #22
- Full GOLDENDOODLE / Zombie POODLE active record-injection (3–4 hr; needs TLS 1.2
  PRF + key block + AES-CBC-HMAC-SHA256). Deferred per v0.3.6 commit.
- Active OpenSSL AES-NI padding oracle (1 hr, same blocker as above).
- CRIME / TIME body-size observation (1–2 hr).
- 0-RTT replay attack (1–2 hr).

## Two bugs to fix in this round (cheap)

1. **Version string stuck at 0.2.1.** `Cargo.toml` still says `version = "0.2.1"`
   at the v0.3.6 tag, so the binary prints `cy-tls 0.2.1`. Bump it (and going
   forward, bump per release — same bug class as v0.2.0→0.1.0).
2. **`key_exchange.ecdhe_curves: []` / `preferred_curve: null`** aren't populating
   even on v0.3.6. Named-curve enumeration isn't writing its JSON fields. Check
   `src/scan/cipher.rs` / `cipher_enum.rs` — the curve data isn't reaching
   `KeyExchangeInfo`. Qualys grades on this, so it's a real parity gap.

## #22 design — TLS Triple Handshake

**Detection strategy: Extended Master Secret (EMS, RFC 7627) absence.**
EMS is the actual defense against the Triple Handshake attack (Bhargavan et al.
2014), and EMS-support is exactly what SSLyze and Qualys SSL Labs check. No risky
active record-splicing needed — this is an extension-presence probe.

A server is **Triple-Handshake-eligible** when:
- it does NOT support Extended Master Secret (ext type `0x0017`), AND
- it supports session resumption (already detected in `src/scan/session.rs`), AND
- it supports secure renegotiation (already detected in `tls12_features.rs`).

### Implementation steps

1. **`src/scan/tls12_features.rs`**
   - Add field to `Tls12Features`:
     ```rust
     pub extended_master_secret: Option<bool>,
     ```
   - In `build_client_hello`, add the EMS extension (empty, type 0x0017):
     ```rust
     let ems_ext: [u8; 4] = [0x00, 0x17, 0x00, 0x00];
     // ...and push into `extensions` alongside reneg/heartbeat/sigalg/groups
     ```
   - In `parse_server_hello`, before the extension loop set
     `feat.extended_master_secret = Some(false);` and inside the `match ext_type`
     add arm `0x0017 => feat.extended_master_secret = Some(true),`.

2. **Surface EMS in JSON** — add `extended_master_secret` to
   `src/scan/extensions.rs::ExtensionInfo` and copy it across in `mod.rs` where
   the other tls12_features fields are copied (around mod.rs:296–306).

3. **`src/finding.rs`** — register new ID(s) in `FINDING_CATALOG`. Suggested:
   ```rust
   ("TLS-NO-EXTENDED-MASTER-SECRET", Severity::Low,    "Extended Master Secret (RFC 7627) not supported"),
   ("TLS-TRIPLE-HANDSHAKE",          Severity::Medium, "Triple Handshake eligible — no EMS + session resumption + renegotiation"),
   ```
   (Per the `finding.rs` header: adding an ID is deliberate — bump minor version,
   update `docs/finding-ids.md`, add enrichment row to the platform runner.)

4. **`src/scan/mod.rs`** — after the tls12_features probe + session resumption
   probe (~line 290–307), emit:
   - `TLS-NO-EXTENDED-MASTER-SECRET` when `extended_master_secret == Some(false)`.
   - `TLS-TRIPLE-HANDSHAKE` when EMS absent AND `session_ticket.offered` (or
     resumption supported) AND `renegotiation.secure`.

5. **Docs / platform**
   - `docs/finding-ids.md` — add the new IDs with control mappings.
   - `docs/control-mapping.md` if it carries per-ID rows.
   - **`backend/tools_runtime/cytls_runner.py`** in the `sentinel-ai` repo —
     STILL HAS NO ENRICHMENT TABLE AT ALL (separate debt the design spec flagged).
     At minimum add rows for the new Triple Handshake IDs; ideally build the full
     `_SPRINT_119`-style enrichment table cymail uses (MITRE/OWASP/CWE/controls).

6. **Build + test + release**
   - `cargo build --release && cargo clippy` clean.
   - Test against a known no-EMS host and a modern EMS host (most modern stacks
     support EMS, so find/confirm a legacy target for the positive case).
   - Bump `Cargo.toml` to `0.3.7`, tag `v0.3.7`, push. Release CI builds raw
     binaries; the tap auto-updates (verify the formula picks up v0.3.7 — and
     remember releases now ship RAW binaries named `cy-tls-<os>-<arch>`, not
     the old target-triple tarballs).

## Control mapping for the new IDs (for docs/finding-ids.md + runner)
- EMS / Triple Handshake → NIST 800-53 SC-8 / SC-23, OWASP ASVS 9.1, ISO 27001
  A.8.24 (cryptography). CWE-757 (selection of less-secure algorithm) is a
  reasonable fit; Triple Handshake itself is CVE-2014-1295-adjacent.

## Gotchas
- The tap auto-update silently stalled at v0.2.1 because the release packaging
  changed from target-triple tarballs to raw binaries; the formula was eventually
  fixed by hand. Keep an eye on the release→tap path on v0.3.7.
- `cytls_runner.py` (sentinel-ai) reads the binary off PATH; deployed scanner
  nodes likely get cy-tls baked into a Docker image, NOT via Homebrew — so the
  tap bump fixes dev machines but the platform scanner image is a separate update.

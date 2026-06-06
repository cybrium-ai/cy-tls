# AGENTS.md — cy-tls

Repo-specific guardrails for AI assistants editing this codebase.

## Repo conventions

- **MSRV** is pinned to `rust-version = "1.75"` in `Cargo.toml`. Don't
  raise without a stated reason.
- **Async runtime** is tokio with `rt-multi-thread`. Don't introduce
  a second runtime (async-std, smol).
- **TLS** is rustls + ring. Don't pull in OpenSSL via `openssl` or
  `native-tls` crates. The legacy protocol probes (SSLv2 / SSLv3 /
  TLS 1.0 / TLS 1.1) get done by hand-rolling minimal ClientHello
  byte sequences over a raw `TcpStream`.
- **No panics in library code.** Use `anyhow::Result` for top-level
  and `thiserror` for typed errors in `src/error.rs`.
- **Finding IDs are frozen.** Adding a new ID requires:
  1. Adding the row to `src/finding.rs::FINDING_CATALOG`.
  2. Adding the control mapping to `src/controls.rs::for_id`.
  3. Updating `docs/finding-ids.md`.
  4. Adding an enrichment row to the platform side at
     `backend/tools_runtime/cytls_runner.py` (in the `cybrium`
     monorepo).
  5. Bumping the cy-tls MINOR version.
- **Output schema** is governed by `docs/json-schema.md`. Additive
  fields are fine within a major; renames or removals require a
  major bump.

## Files NOT to edit without explicit reason

- `Cargo.lock` — let cargo manage it.
- `LICENSE` — Apache-2.0 chosen; don't relicense without
  organisational approval.
- `.github/workflows/release.yml` — release pipeline; changes need
  release-engineer sign-off.

## Style

- `cargo fmt` before committing (CI enforces).
- `cargo clippy --all-targets -- -D warnings` (CI enforces).
- Doc comments (`///`) on every public item.
- Module-level docs (`//!`) explaining what each `src/scan/<thing>.rs`
  probes.
- Errors describe what was attempted and what failed. No `Error: ()`.

## Things to avoid

- **Don't make the binary an HTTP server.** cy-tls is a CLI. The
  platform calls it via subprocess. Long-running daemons go in
  `cyguard` or similar.
- **Don't shell out to `openssl s_client` / `nmap` / etc.** Everything
  is in-process.
- **Don't add machine-learning models.** This is a deterministic
  posture probe.

## How a typical change lands

1. Adding a finding: bump catalog → add detection probe → integration
   test against a fixture host on badssl.com → docs update.
2. Adding a subcommand: stub in `src/cli.rs` first; implement in its
   own `src/<name>.rs`; emits via `output/` not directly.
3. Modifying the JSON shape: bump MINOR (additive) or MAJOR (rename/
   remove); update `docs/json-schema.md`; consumer-test the
   platform's `cytls_runner.py` projection.

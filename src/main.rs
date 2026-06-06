//! cy-tls — Cybrium SSL/TLS posture scanner.
//!
//! Subcommands:
//!   scan            — full posture probe against one or more targets.
//!   bulk            — JSONL streaming for IP-prefix or large host lists.
//!   verify-preload  — Chromium HSTS preload list lookup.
//!
//! See `docs/json-schema.md` for the canonical output shape and
//! `docs/finding-ids.md` for the stable finding ID catalog.

mod cli;
mod finding;
mod output;
mod scan;
mod bulk;
mod preload;
mod controls;
mod error;
mod gui;
mod mcp;

use clap::Parser;
use cli::{Cli, Command};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls 0.23 dropped auto-detection of the crypto provider when
    // multiple features could be active. We pin to ring in Cargo.toml,
    // but still have to register it explicitly before any TLS call.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls ring crypto provider"))?;

    let cli = Cli::parse();
    cli::init_tracing(cli.verbose);

    match cli.command {
        Command::Scan(args) => scan::run(args).await,
        Command::Bulk(args) => bulk::run(args).await,
        Command::VerifyPreload(args) => preload::verify(args),
        Command::Gui(args) => gui::run(args).await,
        Command::Mcp => mcp::run().await,
    }
}

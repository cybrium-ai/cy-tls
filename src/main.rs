//! cy-tls — Cybrium SSL/TLS posture scanner.
//!
//! Subcommands:
//!   scan            — full posture probe against one or more targets.
//!   bulk            — JSONL streaming for IP-prefix or large host lists.
//!   verify-preload  — Chromium HSTS preload list lookup.
//!
//! See `docs/json-schema.md` for the canonical output shape and
//! `docs/finding-ids.md` for the stable finding ID catalog.

mod bulk;
mod cli;
mod controls;
mod error;
mod finding;
mod gui;
mod hardware_rot;
mod mcp;
mod output;
mod preload;
mod reference;
mod remediation;
mod scan;
mod self_update;

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
        Command::Rot => {
            let rot = hardware_rot::detect();
            println!("{}", serde_json::to_string_pretty(&rot)?);
            Ok(())
        }
        Command::Update | Command::Upgrade => {
            // Run sync ureq inside spawn_blocking so we don't block the
            // tokio reactor on the network round-trip + binary write.
            tokio::task::spawn_blocking(self_update::run).await?
        }
    }
}

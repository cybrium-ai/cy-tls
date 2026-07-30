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
mod licensing;
mod mcp;
mod output;
mod preload;
mod reference;
mod remediation;
mod scan;
mod self_update;

use clap::Parser;
use cli::{Cli, Command, LicenseCommand};

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
        Command::Ssh(args) => run_ssh_audit(args).await,
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
        Command::Fingerprint => {
            let fp = licensing::fingerprint();
            println!("{}", serde_json::to_string_pretty(&fp)?);
            Ok(())
        }
        Command::License(sub) => match sub {
            LicenseCommand::Show => {
                match licensing::load_license()? {
                    Some(state) => println!("{}", serde_json::to_string_pretty(&state)?),
                    None => println!("{}", serde_json::json!({"bound": false})),
                }
                Ok(())
            }
            LicenseCommand::Activate { key } => {
                let state = licensing::activate_local(&key)?;
                let path = licensing::license_path()?;
                eprintln!(
                    "Bound to license_id={} at {}",
                    state.license_id,
                    path.display()
                );
                eprintln!(
                    "Phase 1: local-only binding (no server signature). Fingerprint source: {} ({})",
                    state.fingerprint.host_id_source,
                    state.fingerprint.root_of_trust.kind.as_str()
                );
                Ok(())
            }
            LicenseCommand::Deactivate => {
                if licensing::remove_license()? {
                    eprintln!("License removed.");
                } else {
                    eprintln!("No license file to remove.");
                }
                Ok(())
            }
            LicenseCommand::Verify => {
                let ok = licensing::verify_binding()?;
                if ok {
                    eprintln!("OK — current hardware fingerprint matches stored license.");
                    Ok(())
                } else {
                    Err(anyhow::anyhow!(
                        "MISMATCH — current hardware fingerprint differs from the one stored at activation. The license may have been copied between hosts, or this host's TPM / firmware UUID changed."
                    ))
                }
            }
        },
    }
}

/// `cy-tls ssh <host>` — read the server's advertised algorithms and audit them.
async fn run_ssh_audit(args: cli::SshArgs) -> anyhow::Result<()> {
    use scan::ssh_algos;
    use std::time::Duration;

    let target = if args.target.contains(':') {
        args.target.clone()
    } else {
        format!("{}:22", args.target)
    };

    let kex = match ssh_algos::probe(&target, Duration::from_secs(args.timeout)).await {
        Ok(k) => k,
        Err(e) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "target": target, "error": e, "findings": []
                    })
                );
            } else {
                eprintln!("cy-tls: {target}: {e}");
            }
            std::process::exit(2);
        }
    };

    let findings = ssh_algos::audit(&target, &kex);

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "target":       target,
                "banner":       kex.banner,
                "strict_kex":   kex.strict_kex(),
                "algorithms": {
                    "kex":         kex.kex,
                    "host_keys":   kex.host_keys,
                    "ciphers":     kex.ciphers,
                    "macs":        kex.macs,
                    "compression": kex.compression,
                },
                "findings": findings,
            }))?
        );
        return Ok(());
    }

    println!("SSH crypto posture — {target}");
    if !kex.banner.is_empty() {
        println!("  {}", kex.banner);
    }
    println!(
        "  {} kex · {} host key · {} cipher · {} MAC",
        kex.kex.len(),
        kex.host_keys.len(),
        kex.ciphers.len(),
        kex.macs.len()
    );
    println!();
    for f in &findings {
        println!("  [{:>8}] {}", f.severity.as_str(), f.title);
        if !f.evidence.is_empty() {
            println!("             {}", f.evidence);
        }
        if !f.remediation.is_empty() {
            println!("             → {}", f.remediation);
        }
    }
    Ok(())
}

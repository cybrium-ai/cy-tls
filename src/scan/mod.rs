//! `cy-tls scan` — full posture probe.
//!
//! The orchestrator runs every probe module against each target,
//! aggregates findings, and emits the result on stdout.

mod connect;
mod protocol;
mod legacy_proto;
mod cipher_enum;
mod session;
mod tls12_features;
mod cert;
mod cipher;
mod extensions;
mod tls13;
mod headers;
mod timing;
mod oid_names;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use serde::Serialize;

use crate::cli::{OutputFormat, ScanArgs};
use crate::finding::Finding;

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub target:       String,
    pub ip:           Option<String>,
    pub elapsed_ms:   u64,
    pub protocols:    protocol::ProtocolSupport,
    pub certificate:  Option<cert::CertificateInfo>,
    pub key_exchange: cipher::KeyExchangeInfo,
    pub extensions:   extensions::ExtensionInfo,
    pub headers:      headers::HeaderInfo,
    pub timings_ms:   timing::Timings,
    pub findings:     Vec<Finding>,
}

pub async fn run(args: ScanArgs) -> Result<()> {
    let format = args.format.clone();
    let reports = run_to_reports(args).await?;
    emit(&reports, format)
}

/// Library entrypoint used by the GUI + MCP transports — returns the
/// in-memory report vector instead of writing JSON to stdout.
pub async fn run_to_reports(args: ScanArgs) -> Result<Vec<ScanReport>> {
    let mut targets = args.targets;
    if let Some(file) = &args.targets_file {
        targets.extend(read_targets_file(file)?);
    }
    let timeout = Duration::from_secs(args.timeout_seconds);

    let mut reports = Vec::with_capacity(targets.len());
    for target in targets {
        let parsed = parse_target(&target);
        match scan_one(&parsed, timeout, args.no_cipher_enum).await {
            Ok(report) => reports.push(report),
            Err(e) => {
                tracing::error!(target = %parsed, error = %e, "scan failed");
                reports.push(failed_report(parsed.clone(), e.to_string()));
            }
        }
    }
    Ok(reports)
}

async fn scan_one(target: &str, timeout: Duration, skip_cipher_enum: bool) -> Result<ScanReport> {
    let start = std::time::Instant::now();
    let mut findings = Vec::new();
    let mut timings = timing::Timings::default();

    let connect_start = std::time::Instant::now();
    let ip = match connect::resolve_and_connect(target, timeout).await {
        Ok(ip) => Some(ip),
        Err(_) => {
            findings.push(crate::finding::make(
                "TLS-UNREACHABLE",
                target,
                "TCP connect failed",
            ));
            return Ok(stub_report(target.into(), None, start.elapsed().as_millis() as u64, findings));
        }
    };
    timings.connect = connect_start.elapsed().as_millis() as u64;

    // Protocol enumeration — currently rustls-only (TLS 1.2 + 1.3).
    // SSLv2/v3/TLS1.0/1.1 raw-protocol probes are TODO Phase 2.
    let mut protocols = protocol::enumerate(target, timeout, &mut timings).await?;
    protocols.contribute_findings(target, &mut findings);

    // Certificate chain walk.
    let certificate = cert::inspect(target, timeout, &mut timings).await.ok();
    if let Some(c) = &certificate {
        c.contribute_findings(target, &mut findings);
    }

    // Cipher / key exchange.
    let key_exchange = if skip_cipher_enum {
        cipher::KeyExchangeInfo::default()
    } else {
        cipher::inspect(target, timeout).await.unwrap_or_default()
    };

    // TLS 1.2 cipher enumeration via raw ClientHello bisection. Skipped
    // when --no-cipher-enum is set since each enumeration costs ~5-8
    // extra handshakes per host.
    if !skip_cipher_enum {
        let host_str = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target);
        let accepted_at_12 = cipher_enum::enumerate_at_version(
            target, host_str, 0x03, 0x03,
            cipher_enum::TLS12_SUITES, timeout,
        ).await;
        if !accepted_at_12.is_empty() {
            protocols.tls12.supported = true;
        }
        for suite_id in &accepted_at_12 {
            let name = cipher_enum::name(*suite_id);
            // Only add if not already populated by the modern rustls path.
            if !protocols.tls12.ciphers.iter().any(|c| c == name) && name != "UNKNOWN" {
                protocols.tls12.ciphers.push(name.to_string());
            }
            // Weak-cipher findings.
            let weak_id = match *suite_id {
                0x000a => Some("TLS-3DES-CIPHER"),
                0x0005 | 0x0004 => Some("TLS-RC4-CIPHER"),
                0x0001 | 0x0002 => Some("TLS-NULL-CIPHER"),
                _ => None,
            };
            if let Some(fid) = weak_id {
                findings.push(crate::finding::make(fid, target, format!("cipher 0x{:04x} accepted", suite_id)));
            }
        }
    }

    // Extensions: renegotiation, compression, heartbeat. Phase 2.
    let mut extensions = extensions::probe(target, timeout).await.unwrap_or_default();

    // Session resumption probe — second handshake within the same
    // ClientConfig; cheap (2 handshakes, ~200ms total).
    if !skip_cipher_enum {
        let host_str = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target);
        let s = session::probe(target, host_str, timeout).await;
        extensions.session_ticket.offered = s.tls13_psk || s.tls12_ticket;
        extensions.session_resumption = Some(s);
    }

    // TLS 1.2 ServerHello extension parse — renegotiation_info,
    // heartbeat, compression. One extra handshake but cheap.
    if !skip_cipher_enum {
        let host_str = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target);
        let f = tls12_features::probe(target, host_str, timeout).await;
        if let Some(s) = f.secure_renegotiation {
            extensions.renegotiation.secure = s;
        }
        if let Some(c) = f.compression_offered {
            extensions.compression.offered = c;
        }
        if let Some(h) = f.heartbeat_offered {
            extensions.heartbeat.offered = h;
        }
    }
    extensions.contribute_findings(target, &mut findings);

    // HSTS / Expect-CT headers.
    let headers = headers::fetch(target, timeout).unwrap_or_default();
    headers.contribute_findings(target, &mut findings);

    let elapsed_ms = start.elapsed().as_millis() as u64;
    Ok(ScanReport {
        target: target.into(),
        ip,
        elapsed_ms,
        protocols,
        certificate,
        key_exchange,
        extensions,
        headers,
        timings_ms: timings,
        findings,
    })
}

fn parse_target(raw: &str) -> String {
    if raw.contains(':') {
        raw.to_string()
    } else {
        format!("{raw}:443")
    }
}

fn read_targets_file(path: &PathBuf) -> Result<Vec<String>> {
    let body = std::fs::read_to_string(path)?;
    Ok(body
        .lines()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .map(String::from)
        .collect())
}

fn emit(reports: &[ScanReport], format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json  => crate::output::json::emit(reports),
        OutputFormat::Jsonl => crate::output::jsonl::emit(reports),
        OutputFormat::Sarif => crate::output::sarif::emit(reports),
        OutputFormat::Csv   => crate::output::csv::emit(reports),
        OutputFormat::Html  => crate::output::html::emit(reports),
    }
}

fn stub_report(target: String, ip: Option<String>, elapsed_ms: u64, findings: Vec<Finding>) -> ScanReport {
    ScanReport {
        target,
        ip,
        elapsed_ms,
        protocols: protocol::ProtocolSupport::default(),
        certificate: None,
        key_exchange: cipher::KeyExchangeInfo::default(),
        extensions: extensions::ExtensionInfo::default(),
        headers: headers::HeaderInfo::default(),
        timings_ms: timing::Timings::default(),
        findings,
    }
}

fn failed_report(target: String, error: String) -> ScanReport {
    let findings = vec![crate::finding::make("TLS-UNREACHABLE", &target, error)];
    stub_report(target, None, 0, findings)
}

//! `cy-tls bulk` — bounded-concurrency fan-out with JSONL streaming.
//!
//! Reads `--targets-file` (one host[:port] per line, `#` comments OK),
//! runs probe per target with at most `--concurrency` in flight, and
//! emits one JSON object per target on stdout. Buffered writes keep
//! the streaming property.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Mutex;

use crate::cli::BulkArgs;
use crate::scan::{self, ScanReport};

pub async fn run(args: BulkArgs) -> Result<()> {
    let targets = read_targets_file(&args.targets_file)?;
    if targets.is_empty() {
        return Err(anyhow::anyhow!("targets-file contained no entries"));
    }

    let timeout = Duration::from_secs(args.timeout_seconds);
    let stdout = Arc::new(Mutex::new(tokio::io::stdout()));
    let mut in_flight = FuturesUnordered::new();
    let mut queue = targets.into_iter();

    let cap = args.concurrency.max(1);
    for _ in 0..cap {
        if let Some(t) = queue.next() {
            in_flight.push(scan_one(t, timeout, !args.full));
        }
    }

    while let Some(report) = in_flight.next().await {
        emit_jsonl(&stdout, &report).await?;
        if let Some(t) = queue.next() {
            in_flight.push(scan_one(t, timeout, !args.full));
        }
    }
    Ok(())
}

async fn scan_one(target: String, timeout: Duration, fast: bool) -> ScanReport {
    let parsed = if target.contains(':') {
        target.clone()
    } else {
        format!("{target}:443")
    };
    let args = crate::cli::ScanArgs {
        targets: vec![parsed.clone()],
        targets_file: None,
        timeout_seconds: timeout.as_secs(),
        no_cipher_enum: fast,
        handshake_sim: false,
        format: crate::cli::OutputFormat::Json,
    };
    scan::run_to_reports(args)
        .await
        .ok()
        .and_then(|mut v| v.pop())
        .unwrap_or_else(|| failed_report(parsed))
}

fn failed_report(target: String) -> ScanReport {
    ScanReport {
        target: target.clone(),
        ip: None,
        elapsed_ms: 0,
        protocols: Default::default(),
        certificate: None,
        key_exchange: Default::default(),
        extensions: Default::default(),
        headers: Default::default(),
        timings_ms: Default::default(),
        findings: vec![crate::finding::make(
            "TLS-UNREACHABLE",
            &target,
            "Scan internal error",
        )],
        handshake_simulation: Vec::new(),
        server_fingerprint: None,
        cipher_preference: None,
        forward_secrecy: None,
        fallback_scsv: None,
        caa_records: Vec::new(),
        tolerates_grease: false,
        preload_list_refreshed_at: crate::preload::PRELOAD_LIST_REFRESHED_AT,
        dns_soa: None,
        dns_ns: Vec::new(),
        dnssec_signed: false,
        dane_tlsa_count: 0,
        http_redirect: Default::default(),
        grade: Default::default(),
        summary: Default::default(),
    }
}

async fn emit_jsonl(out: &Arc<Mutex<tokio::io::Stdout>>, report: &ScanReport) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let line = serde_json::to_string(report)?;
    let mut handle = out.lock().await;
    handle.write_all(line.as_bytes()).await?;
    handle.write_all(b"\n").await?;
    handle.flush().await?;
    Ok(())
}

fn read_targets_file(path: &std::path::Path) -> Result<Vec<String>> {
    let body = std::fs::read_to_string(path)?;
    Ok(body
        .lines()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .map(String::from)
        .collect())
}

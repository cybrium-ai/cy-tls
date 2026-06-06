//! CLI definition. One enum per subcommand, derived via `clap`.

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "cy-tls", version, about = "Cybrium SSL/TLS posture scanner")]
pub struct Cli {
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Full posture probe against one or more targets.
    Scan(ScanArgs),

    /// JSONL streaming for IP-prefix or large host lists.
    Bulk(BulkArgs),

    /// Chromium HSTS preload list lookup.
    VerifyPreload(VerifyPreloadArgs),

    /// Local web UI for browsing + running scans. Browser-served, 127.0.0.1 only.
    Gui(GuiArgs),

    /// Model Context Protocol server — JSON-RPC over stdio. Lets Claude or
    /// other MCP-aware agents call cy-tls as a tool.
    Mcp,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// host[:port] — port defaults to 443.
    #[arg(required = true, num_args = 1..)]
    pub targets: Vec<String>,

    /// File with one target per line (in addition to positional args).
    #[arg(long)]
    pub targets_file: Option<std::path::PathBuf>,

    /// Per-target wall-clock budget in seconds.
    #[arg(long, default_value = "30")]
    pub timeout_seconds: u64,

    /// Skip cipher suite enumeration (a sizable cost for the full probe).
    #[arg(long)]
    pub no_cipher_enum: bool,

    /// Output format.
    #[arg(long, value_enum, default_value = "json")]
    pub format: OutputFormat,
}

#[derive(Debug, Args)]
pub struct BulkArgs {
    /// One target per line.
    #[arg(long, required = true)]
    pub targets_file: std::path::PathBuf,

    /// Parallel probe count.
    #[arg(long, default_value = "64")]
    pub concurrency: usize,

    /// Per-target budget in seconds. Default 15s in bulk mode.
    #[arg(long, default_value = "15")]
    pub timeout_seconds: u64,

    /// Run the full scan probe set (slow). Default is the fast bulk subset.
    #[arg(long)]
    pub full: bool,
}

#[derive(Debug, Args)]
pub struct VerifyPreloadArgs {
    /// Hostname to look up.
    #[arg(required = true)]
    pub host: String,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum OutputFormat {
    /// Pretty-printed JSON array — default.
    Json,
    /// One JSON object per line (one per target).
    Jsonl,
    /// SARIF 2.1.0 for GitHub / GitLab code-scanning ingestion.
    Sarif,
    /// One CSV row per finding — opens in Excel / Google Sheets natively.
    Csv,
    /// Standalone Cybrium-branded HTML report — emails + archives cleanly.
    Html,
}

impl OutputFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            OutputFormat::Json => "json",
            OutputFormat::Jsonl => "jsonl",
            OutputFormat::Sarif => "sarif",
            OutputFormat::Csv => "csv",
            OutputFormat::Html => "html",
        }
    }

    pub fn content_type(&self) -> &'static str {
        match self {
            OutputFormat::Json | OutputFormat::Sarif => "application/json",
            OutputFormat::Jsonl => "application/x-ndjson",
            OutputFormat::Csv => "text/csv",
            OutputFormat::Html => "text/html; charset=utf-8",
        }
    }
}

#[derive(Debug, Args)]
pub struct GuiArgs {
    /// Port to bind the embedded HTTP server. Always loopback-only.
    #[arg(long, default_value = "8992")]
    pub port: u16,

    /// Don't open the system browser on startup.
    #[arg(long)]
    pub no_open: bool,
}

pub fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| format!("cy_tls={}", level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}

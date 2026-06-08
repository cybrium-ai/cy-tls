//! `cy-tls gui` — local web UI for browsing and triggering scans.
//!
//! Loopback-only HTTP server. Browser POSTs targets to `/api/scan`; the
//! response is the same JSON shape as `cy-tls scan` so the UI's
//! rendering logic is the platform's pipeline rendering logic. No
//! authentication, no TLS — bound to 127.0.0.1 only.
//!
//! v0.1.0: scaffold. Single-page UI with Cybrium-branded header, a
//! scan input form, and a findings table. Multi-target sessions
//! supported via a session-scoped HashMap of `ScanReport`. Phase 2:
//! progress events streamed via SSE while the scan runs.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use tower_http::cors::{Any, CorsLayer};

use crate::cli::{GuiArgs, OutputFormat};
use crate::output;
use crate::scan::{self, ScanReport};

#[derive(Clone)]
struct AppState {
    /// In-memory log of every scan in the session — newest last.
    history: Arc<tokio::sync::RwLock<Vec<ScanReport>>>,
}

pub async fn run(args: GuiArgs) -> Result<()> {
    let state = AppState {
        history: Arc::new(tokio::sync::RwLock::new(Vec::new())),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/api/scan", post(api_scan))
        .route("/api/history", get(api_history))
        .route("/api/findings", get(api_finding_catalog))
        .route("/api/export", get(api_export))
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any))
        .with_state(state);

    let addr: SocketAddr = ([127, 0, 0, 1], args.port).into();
    eprintln!("cy-tls GUI on http://{addr}");
    if !args.no_open {
        let _ = open_browser(&format!("http://{addr}"));
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index() -> Html<String> {
    // v0.5.73 — substitute the live binary version into the header so
    // the GUI never shows a stale hard-coded "v0.1.0".
    Html(INDEX_HTML.replace("{{VERSION}}", env!("CARGO_PKG_VERSION")))
}

#[derive(Debug, Deserialize)]
struct ScanRequest {
    targets: Vec<String>,
    #[serde(default = "default_timeout")]
    timeout_seconds: u64,
    #[serde(default)]
    no_cipher_enum: bool,
}

fn default_timeout() -> u64 {
    30
}

async fn api_scan(
    State(state): State<AppState>,
    Json(req): Json<ScanRequest>,
) -> impl IntoResponse {
    if req.targets.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "no targets provided",
            })),
        )
            .into_response();
    }

    let args = crate::cli::ScanArgs {
        targets: req.targets,
        targets_file: None,
        timeout_seconds: req.timeout_seconds,
        no_cipher_enum: req.no_cipher_enum,
        handshake_sim: false,
        format: crate::cli::OutputFormat::Json,
    };

    match scan::run_to_reports(args).await {
        Ok(reports) => {
            let mut hist = state.history.write().await;
            hist.extend(reports.iter().cloned());
            Json(serde_json::json!({ "reports": reports })).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": e.to_string(),
            })),
        )
            .into_response(),
    }
}

async fn api_history(State(state): State<AppState>) -> impl IntoResponse {
    let hist = state.history.read().await;
    Json(serde_json::json!({ "reports": *hist }))
}

#[derive(Debug, Deserialize)]
struct ExportQuery {
    format: String,
}

async fn api_export(
    State(state): State<AppState>,
    Query(q): Query<ExportQuery>,
) -> impl IntoResponse {
    let format = match q.format.as_str() {
        "json" => OutputFormat::Json,
        "jsonl" => OutputFormat::Jsonl,
        "sarif" => OutputFormat::Sarif,
        "csv" => OutputFormat::Csv,
        "html" => OutputFormat::Html,
        _ => return (StatusCode::BAD_REQUEST, "unsupported format").into_response(),
    };

    let hist = state.history.read().await;
    let body: String = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&*hist).unwrap_or_default() + "\n",
        OutputFormat::Jsonl => {
            hist.iter()
                .filter_map(|r| serde_json::to_string(r).ok())
                .collect::<Vec<_>>()
                .join("\n")
                + "\n"
        }
        OutputFormat::Sarif => render_sarif(&hist),
        OutputFormat::Csv => output::csv::render(&hist),
        OutputFormat::Html => output::html::render(&hist),
    };

    let date = chrono::Utc::now().format("%Y-%m-%d");
    let filename = format!("cy-tls-report-{date}.{}", format.extension());

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, format.content_type().to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        body,
    )
        .into_response()
}

fn render_sarif(reports: &[ScanReport]) -> String {
    // Reuse the SARIF emitter's structure by building the document inline.
    use serde_json::json;
    let runs: Vec<_> = reports
        .iter()
        .map(|r| {
            let results: Vec<_> = r.findings.iter().map(|f| json!({
            "ruleId": f.id,
            "level": match f.severity.as_str() {
                "critical" | "high" => "error",
                "medium" => "warning",
                _ => "note",
            },
            "message": { "text": format!("{}: {}", f.title, f.evidence) },
            "locations": [{ "physicalLocation": { "artifactLocation": { "uri": f.host } } }]
        })).collect();
            json!({
                "tool": { "driver": {
                    "name": "cy-tls",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/cybrium-ai/cy-tls"
                }},
                "results": results
            })
        })
        .collect();
    serde_json::to_string_pretty(&json!({
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": runs
    })).unwrap_or_default() + "\n"
}

async fn api_finding_catalog() -> impl IntoResponse {
    let catalog: Vec<_> = crate::finding::FINDING_CATALOG
        .iter()
        .map(|(id, sev, title)| {
            serde_json::json!({
                "id": id,
                "severity": sev.as_str(),
                "title": title,
            })
        })
        .collect();
    Json(serde_json::json!({ "catalog": catalog }))
}

fn open_browser(url: &str) -> Result<()> {
    let cmd = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(target_os = "windows") {
        "cmd"
    } else {
        "xdg-open"
    };
    let args: Vec<&str> = if cfg!(target_os = "windows") {
        vec!["/C", "start", url]
    } else {
        vec![url]
    };
    std::process::Command::new(cmd).args(args).spawn()?;
    Ok(())
}

const INDEX_HTML: &str = include_str!("../assets/index.html");

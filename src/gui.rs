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
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use tower_http::cors::{Any, CorsLayer};

use crate::cli::GuiArgs;
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

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

#[derive(Debug, Deserialize)]
struct ScanRequest {
    targets: Vec<String>,
    #[serde(default = "default_timeout")]
    timeout_seconds: u64,
    #[serde(default)]
    no_cipher_enum: bool,
}

fn default_timeout() -> u64 { 30 }

async fn api_scan(
    State(state): State<AppState>,
    Json(req): Json<ScanRequest>,
) -> impl IntoResponse {
    if req.targets.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "no targets provided",
        }))).into_response();
    }

    let args = crate::cli::ScanArgs {
        targets: req.targets,
        targets_file: None,
        timeout_seconds: req.timeout_seconds,
        no_cipher_enum: req.no_cipher_enum,
        format: crate::cli::OutputFormat::Json,
    };

    match scan::run_to_reports(args).await {
        Ok(reports) => {
            let mut hist = state.history.write().await;
            hist.extend(reports.iter().cloned());
            Json(serde_json::json!({ "reports": reports })).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": e.to_string(),
        }))).into_response(),
    }
}

async fn api_history(State(state): State<AppState>) -> impl IntoResponse {
    let hist = state.history.read().await;
    Json(serde_json::json!({ "reports": *hist }))
}

async fn api_finding_catalog() -> impl IntoResponse {
    let catalog: Vec<_> = crate::finding::FINDING_CATALOG
        .iter()
        .map(|(id, sev, title)| serde_json::json!({
            "id": id,
            "severity": sev.as_str(),
            "title": title,
        }))
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

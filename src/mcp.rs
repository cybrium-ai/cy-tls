//! `cy-tls mcp` — Model Context Protocol server over stdio.
//!
//! Implements the subset of MCP 2024-11-05 that AI agents need to use
//! cy-tls as a tool:
//!
//!   - `initialize` handshake (capability advertisement)
//!   - `tools/list`  — returns the JSON schema of `cy_tls_scan`
//!   - `tools/call`  — runs a scan and returns the report
//!   - `ping`        — health check
//!
//! Transport is line-delimited JSON-RPC 2.0 on stdin / stdout. Each
//! request is a single JSON object on one line; responses go on stdout.
//! Logging goes to stderr so it doesn't poison the JSON-RPC channel.
//!
//! Phase 2 will add SSE transport (`--transport sse --port N`), tool
//! result streaming, and `cy_tls_verify_preload` / `cy_tls_bulk` once
//! their underlying probes ship.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const PROTOCOL_VERSION: &str = "2024-11-05";

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

pub async fn run() -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();

    eprintln!("cy-tls MCP server listening on stdio (protocol {PROTOCOL_VERSION})");

    while let Some(line) = reader.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = JsonRpcResponse {
                    jsonrpc: "2.0",
                    id: Value::Null,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32700,
                        message: format!("parse error: {e}"),
                        data: None,
                    }),
                };
                write_response(&mut stdout, &resp).await?;
                continue;
            }
        };

        let response = dispatch(request).await;
        if let Some(resp) = response {
            write_response(&mut stdout, &resp).await?;
        }
    }
    Ok(())
}

async fn dispatch(req: JsonRpcRequest) -> Option<JsonRpcResponse> {
    let id = req.id.clone();

    // Notifications (no id) get no response.
    let respond = id.is_some();
    let id = id.unwrap_or(Value::Null);

    let result = match req.method.as_str() {
        "initialize" => Ok(initialize_payload()),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(tools_list_payload()),
        "tools/call" => tools_call(&req.params).await,
        "notifications/initialized" => return None, // notification, no response
        other => Err(JsonRpcError {
            code: -32601,
            message: format!("method not found: {other}"),
            data: None,
        }),
    };

    if !respond {
        return None;
    }

    Some(match result {
        Ok(v) => JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: Some(v),
            error: None,
        },
        Err(e) => JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(e),
        },
    })
}

fn initialize_payload() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "tools": { "listChanged": false }
        },
        "serverInfo": {
            "name":    "cy-tls",
            "version": env!("CARGO_PKG_VERSION"),
        }
    })
}

fn tools_list_payload() -> Value {
    json!({
        "tools": [
            {
                "name":        "cy_tls_scan",
                "description": "Run a full SSL/TLS posture probe against one or more host[:port] targets and return findings with control mapping.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "targets": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Hostnames, optionally with :port. Defaults to 443."
                        },
                        "timeout_seconds": {
                            "type": "integer",
                            "default": 30,
                            "minimum": 1,
                            "maximum": 120
                        },
                        "no_cipher_enum": {
                            "type": "boolean",
                            "default": false
                        }
                    },
                    "required": ["targets"]
                }
            }
        ]
    })
}

async fn tools_call(params: &Value) -> Result<Value, JsonRpcError> {
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    match name {
        "cy_tls_scan" => run_scan(&args).await,
        _ => Err(JsonRpcError {
            code: -32602,
            message: format!("unknown tool: {name}"),
            data: None,
        }),
    }
}

async fn run_scan(args: &Value) -> Result<Value, JsonRpcError> {
    let targets: Vec<String> = args
        .get("targets")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    if targets.is_empty() {
        return Err(JsonRpcError {
            code: -32602,
            message: "targets is required and must be non-empty".to_string(),
            data: None,
        });
    }

    let scan_args = crate::cli::ScanArgs {
        targets,
        targets_file: None,
        timeout_seconds: args
            .get("timeout_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(30),
        no_cipher_enum: args
            .get("no_cipher_enum")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        handshake_sim: args
            .get("handshake_sim")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        format: crate::cli::OutputFormat::Json,
    };

    let reports = crate::scan::run_to_reports(scan_args)
        .await
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("scan failed: {e}"),
            data: None,
        })?;

    let text = serde_json::to_string_pretty(&reports).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize: {e}"),
        data: None,
    })?;

    // MCP tool result shape — array of content blocks.
    Ok(json!({
        "content": [
            { "type": "text", "text": text }
        ],
        "isError": false
    }))
}

async fn write_response<W: AsyncWriteExt + Unpin>(
    out: &mut W,
    resp: &JsonRpcResponse,
) -> Result<()> {
    let bytes = serde_json::to_vec(resp)?;
    out.write_all(&bytes).await?;
    out.write_all(b"\n").await?;
    out.flush().await?;
    Ok(())
}

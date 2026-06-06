use thiserror::Error;

// Will be wired into the public API in Phase 2 (currently every probe
// surfaces errors through `anyhow::Result`). Kept here so the typed
// variants are stable from v0.1.0.
#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum CyTlsError {
    #[error("TCP connect failed: {0}")]
    Connect(#[from] std::io::Error),

    #[error("TLS handshake failed: {0}")]
    Handshake(String),

    #[error("certificate parse error: {0}")]
    CertParse(String),

    #[error("not implemented yet: {0}")]
    NotImplemented(&'static str),
}

//! Extension probes — renegotiation, compression, heartbeat, session
//! resumption. Phase 1 stub (default = "not detected", findings only
//! emitted once raw-protocol probing lands in Phase 2).

use std::time::Duration;
use serde::Serialize;

use crate::finding::{make, Finding};

#[derive(Debug, Default, Clone, Serialize)]
pub struct ExtensionInfo {
    pub alpn:           Vec<String>,
    pub renegotiation:  Reneg,
    pub compression:    Compression,
    pub heartbeat:      Heartbeat,
    pub session_ticket: SessionTicket,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Reneg {
    pub secure: bool,
    pub client_initiated_allowed: bool,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Compression {
    pub offered: bool,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Heartbeat {
    pub offered: bool,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct SessionTicket {
    pub offered: bool,
    pub ttl_seconds: u32,
}

impl ExtensionInfo {
    pub fn contribute_findings(&self, host: &str, findings: &mut Vec<Finding>) {
        if self.renegotiation.client_initiated_allowed {
            findings.push(make("TLS-CLIENT-RENEG-ALLOWED", host, "Client renegotiation accepted"));
        }
        if self.compression.offered {
            findings.push(make("TLS-COMPRESSION-ENABLED", host, "TLS-level compression advertised"));
        }
        if self.heartbeat.offered {
            findings.push(make("TLS-HEARTBEAT-ENABLED", host, "Heartbeat extension advertised"));
        }
    }
}

pub async fn probe(_target: &str, _deadline: Duration) -> anyhow::Result<ExtensionInfo> {
    // TODO Phase 2 — raw ServerHello extension parsing
    Ok(ExtensionInfo::default())
}

//! TLS version enumeration.
//!
//! v0.1.0: rustls handles TLS 1.2 and TLS 1.3 cleanly. SSLv2, SSLv3,
//! TLS 1.0, and TLS 1.1 detection requires raw ClientHello probing —
//! left as a Phase 2 TODO. The probe currently records all four legacy
//! versions as `supported: false` rather than emitting false negatives,
//! and notes the gap in the elapsed timings.

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;

use crate::finding::{make, Finding};
use super::timing::Timings;

#[derive(Debug, Default, Clone, Serialize)]
pub struct ProtocolSupport {
    pub sslv2:  VersionResult,
    pub sslv3:  VersionResult,
    pub tls10:  VersionResult,
    pub tls11:  VersionResult,
    pub tls12:  VersionResult,
    pub tls13:  Tls13Result,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct VersionResult {
    pub supported: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ciphers: Vec<String>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Tls13Result {
    pub supported: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ciphers: Vec<String>,
    pub zero_rtt_accepted: bool,
    pub ech_advertised: bool,
    pub hello_retry_required: bool,
}

impl ProtocolSupport {
    pub fn contribute_findings(&self, host: &str, findings: &mut Vec<Finding>) {
        if self.sslv2.supported {
            findings.push(make("TLS-SSLV2", host, "SSLv2 ClientHello accepted"));
        }
        if self.sslv3.supported {
            findings.push(make("TLS-SSLV3", host, "SSLv3 ClientHello accepted"));
        }
        if self.tls10.supported {
            findings.push(make("TLS-WEAK-VERSION-1.0", host, "TLS 1.0 ClientHello accepted"));
        }
        if self.tls11.supported {
            findings.push(make("TLS-WEAK-VERSION-1.1", host, "TLS 1.1 ClientHello accepted"));
        }
        if !self.tls13.supported {
            findings.push(make("TLS-NO-TLS13", host, "Server did not negotiate TLS 1.3"));
        }
        if self.tls13.zero_rtt_accepted {
            findings.push(make(
                "TLS-ZERO-RTT-ACCEPTED",
                host,
                "TLS 1.3 early-data ticket accepted",
            ));
        }
    }
}

pub async fn enumerate(
    target: &str,
    deadline: Duration,
    timings: &mut Timings,
) -> anyhow::Result<ProtocolSupport> {
    let (host_str, _port) = split_host_port(target)?;
    let mut report = ProtocolSupport::default();

    let hello_start = std::time::Instant::now();

    // Modern path via rustls — gets us TLS 1.2 and TLS 1.3 cleanly.
    if let Ok((negotiated_version, suite)) = try_handshake(target, &host_str, deadline).await {
        match negotiated_version {
            NegotiatedVersion::Tls13 => {
                report.tls13.supported = true;
                report.tls13.ciphers.push(suite);
            }
            NegotiatedVersion::Tls12 => {
                report.tls12.supported = true;
                report.tls12.ciphers.push(suite);
            }
        }
    }

    // Legacy versions via raw ClientHello. rustls 0.23 explicitly drops
    // TLS 1.0 and TLS 1.1 support so we hand-roll a probe per version.
    // We use a short-per-probe deadline (cap each at 3s) so a slow
    // legacy probe doesn't dominate scan latency.
    let per_probe = deadline.min(Duration::from_secs(3));
    report.tls10.supported =
        super::legacy_proto::probe_version(target, &host_str, 0x03, 0x01, per_probe).await;
    report.tls11.supported =
        super::legacy_proto::probe_version(target, &host_str, 0x03, 0x02, per_probe).await;

    timings.client_hello = hello_start.elapsed().as_millis() as u64;
    Ok(report)
}

enum NegotiatedVersion {
    Tls12,
    Tls13,
}

async fn try_handshake(
    target: &str,
    server_name: &str,
    deadline: Duration,
) -> anyhow::Result<(NegotiatedVersion, String)> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = timeout(deadline, TcpStream::connect(target)).await??;
    let server_name = ServerName::try_from(server_name.to_string())?;
    let tls = timeout(deadline, connector.connect(server_name, tcp)).await??;

    let (_, conn) = tls.get_ref();
    let version = conn
        .protocol_version()
        .ok_or_else(|| anyhow::anyhow!("no protocol version negotiated"))?;
    let suite = conn
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()))
        .unwrap_or_else(|| "unknown".to_string());

    let negotiated = match version {
        rustls::ProtocolVersion::TLSv1_3 => NegotiatedVersion::Tls13,
        rustls::ProtocolVersion::TLSv1_2 => NegotiatedVersion::Tls12,
        other => anyhow::bail!("unexpected protocol version: {other:?}"),
    };
    Ok((negotiated, suite))
}

fn split_host_port(target: &str) -> anyhow::Result<(String, u16)> {
    let (h, p) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("target must be host:port"))?;
    Ok((h.to_string(), p.parse()?))
}

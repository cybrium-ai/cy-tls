//! TLS version enumeration.
//!
//! v0.1.0: rustls handles TLS 1.2 and TLS 1.3 cleanly. SSLv2, SSLv3,
//! TLS 1.0, and TLS 1.1 detection requires raw ClientHello probing —
//! left as a Phase 2 TODO. The probe currently records all four legacy
//! versions as `supported: false` rather than emitting false negatives,
//! and notes the gap in the elapsed timings.

use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use serde::Serialize;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use super::timing::Timings;
use crate::finding::{make, Finding};

#[derive(Debug, Default, Clone, Serialize)]
pub struct ProtocolSupport {
    pub sslv2: VersionResult,
    pub sslv3: VersionResult,
    pub tls10: VersionResult,
    pub tls11: VersionResult,
    pub tls12: VersionResult,
    pub tls13: Tls13Result,
    /// Negotiated key exchange group (e.g. `X25519`, `secp256r1`).
    /// TLS 1.3 always populates this; TLS 1.2 sometimes does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_exchange_group: Option<String>,
    /// True when the negotiated cipher provides forward secrecy
    /// (ECDHE/DHE in TLS 1.2; always true in TLS 1.3).
    pub forward_secrecy: bool,
    /// Negotiated ALPN protocol (`h2`, `http/1.1`, etc.). None if the
    /// server doesn't speak ALPN or didn't pick one of our offers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    /// Post-Quantum Cryptography key-exchange support (X25519MLKEM768
    /// and earlier Kyber768 hybrids). Populated by a separate raw
    /// ClientHello probe in scan::pqc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pqc: Option<super::pqc::PqcInfo>,
    /// v0.4.5 — "Special DROWN" eligibility flag. True when the SSLv2
    /// SERVER-HELLO listed at least one EXPORT-grade cipher
    /// (40-bit RC4/RC2 or 56-bit DES), which drops the practical
    /// DROWN decryption cost from days to minutes.
    pub sslv2_special_drown: bool,
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
            // SSLv2 enabled on the same host as a modern TLS port is a
            // textbook DROWN (CVE-2016-0800) exposure — the SSLv2
            // server provides the Bleichenbacher oracle that decrypts
            // TLS sessions on a different port sharing the same key.
            // v0.4.5: evidence text reports whether EXPORT-grade ciphers
            // were observed in the SSLv2 SERVER-HELLO (Special DROWN —
            // CVE-2016-0703 — drops decryption cost from days to mins).
            let evidence = if self.sslv2_special_drown {
                format!(
                    "Special DROWN surface: SSLv2 + EXPORT cipher accepted. Server-offered SSLv2 ciphers: {:?}",
                    self.sslv2.ciphers,
                )
            } else if !self.sslv2.ciphers.is_empty() {
                format!(
                    "SSLv2 enabled on the same host — DROWN attack surface. Server-offered SSLv2 ciphers: {:?}",
                    self.sslv2.ciphers,
                )
            } else {
                "SSLv2 enabled on the same host — DROWN attack surface".to_string()
            };
            findings.push(make("TLS-DROWN-VULNERABLE", host, evidence));
        }
        if self.sslv3.supported {
            findings.push(make("TLS-SSLV3", host, "SSLv3 ClientHello accepted"));
        }
        if self.tls10.supported {
            findings.push(make(
                "TLS-WEAK-VERSION-1.0",
                host,
                "TLS 1.0 ClientHello accepted",
            ));
        }
        if self.tls11.supported {
            findings.push(make(
                "TLS-WEAK-VERSION-1.1",
                host,
                "TLS 1.1 ClientHello accepted",
            ));
        }
        if !self.tls13.supported {
            findings.push(make(
                "TLS-NO-TLS13",
                host,
                "Server did not negotiate TLS 1.3",
            ));
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
    if let Ok(h) = try_handshake(target, &host_str, deadline).await {
        match h.version {
            NegotiatedVersion::Tls13 => {
                report.tls13.supported = true;
                report.tls13.ciphers.push(h.cipher_suite);
            }
            NegotiatedVersion::Tls12 => {
                report.tls12.supported = true;
                report.tls12.ciphers.push(h.cipher_suite);
            }
        }
        report.forward_secrecy = h.forward_secrecy;
        report.key_exchange_group = h.key_exchange_group;
        report.alpn = h.alpn;
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
    report.sslv3.supported =
        super::legacy_proto::probe_version(target, &host_str, 0x03, 0x00, per_probe).await;
    let sslv2_probe = super::legacy_proto::probe_sslv2(target, per_probe).await;
    report.sslv2.supported = sslv2_probe.supported;
    if sslv2_probe.supported {
        report.sslv2.ciphers = sslv2_probe
            .server_cipher_specs
            .iter()
            .map(|id| sslv2_cipher_name(*id).to_string())
            .collect();
        report.sslv2_special_drown = sslv2_probe.special_drown_eligible;
    }

    timings.client_hello = hello_start.elapsed().as_millis() as u64;
    Ok(report)
}

pub(super) enum NegotiatedVersion {
    Tls12,
    Tls13,
}

/// Captured during the rustls handshake — exposes everything the API
/// gives us beyond just the cipher name. Forward Secrecy is derived
/// from the cipher's name (ECDHE / DHE = FS, anything else = no FS).
pub struct HandshakeDetails {
    pub version: NegotiatedVersion,
    pub cipher_suite: String,
    pub forward_secrecy: bool,
    pub key_exchange_group: Option<String>,
    pub alpn: Option<String>,
}

async fn try_handshake(
    target: &str,
    server_name: &str,
    deadline: Duration,
) -> anyhow::Result<HandshakeDetails> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = timeout(deadline, TcpStream::connect(target)).await??;
    let server_name = ServerName::try_from(server_name.to_string())?;
    let tls = timeout(deadline, connector.connect(server_name, tcp)).await??;

    let (_, conn) = tls.get_ref();
    let version = conn
        .protocol_version()
        .ok_or_else(|| anyhow::anyhow!("no protocol version negotiated"))?;
    let suite_name = conn
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()))
        .unwrap_or_else(|| "unknown".to_string());
    let forward_secrecy = suite_name.contains("ECDHE")
        || suite_name.contains("DHE")
        || version == rustls::ProtocolVersion::TLSv1_3;
    let key_exchange_group = conn
        .negotiated_key_exchange_group()
        .map(|g| format!("{:?}", g.name()));
    let alpn = conn
        .alpn_protocol()
        .and_then(|b| std::str::from_utf8(b).ok().map(String::from));

    let negotiated_version = match version {
        rustls::ProtocolVersion::TLSv1_3 => NegotiatedVersion::Tls13,
        rustls::ProtocolVersion::TLSv1_2 => NegotiatedVersion::Tls12,
        other => anyhow::bail!("unexpected protocol version: {other:?}"),
    };
    Ok(HandshakeDetails {
        version: negotiated_version,
        cipher_suite: suite_name,
        forward_secrecy,
        key_exchange_group,
        alpn,
    })
}

fn split_host_port(target: &str) -> anyhow::Result<(String, u16)> {
    let (h, p) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("target must be host:port"))?;
    Ok((h.to_string(), p.parse()?))
}

/// Friendly name for an SSLv2 cipher spec (3-byte ID packed into u32).
fn sslv2_cipher_name(id: u32) -> &'static str {
    match id {
        0x010080 => "SSL_CK_RC4_128_WITH_MD5",
        0x020080 => "SSL_CK_RC4_128_EXPORT40_WITH_MD5",
        0x030080 => "SSL_CK_RC2_128_CBC_WITH_MD5",
        0x040080 => "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5",
        0x050080 => "SSL_CK_IDEA_128_CBC_WITH_MD5",
        0x060040 => "SSL_CK_DES_64_CBC_WITH_MD5",
        0x0700c0 => "SSL_CK_DES_192_EDE3_CBC_WITH_MD5",
        0x000000 => "SSL_CK_NULL",
        0x000001 => "SSL_CK_NULL_WITH_MD5",
        _ => "SSL_CK_UNKNOWN",
    }
}

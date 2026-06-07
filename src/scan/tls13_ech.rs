//! ECH (Encrypted ClientHello) advertisement detection.
//!
//! ECH (RFC 9460 + draft-ietf-tls-esni) wraps the ClientHello in an
//! outer ClientHello whose SNI is the "public name" of the server's
//! ECH config, encrypting the real inner ClientHello + the real SNI.
//! That defeats SNI-based passive traffic classification and the
//! corresponding active-probing fingerprint surface.
//!
//! Server-side ECH eligibility is signaled out-of-band via DNS: an
//! HTTPS record (type 65, RFC 9460) carries SvcParam keys; key 5
//! (`ech`) holds a base64-encoded ECHConfigList. A client that
//! receives an HTTPS record with the `ech=` SvcParam knows it can
//! use ECH on the next TLS handshake.
//!
//! Detection in cy-tls is therefore a single DNS query:
//!   1. Resolve TYPE65 (HTTPS) for the target hostname.
//!   2. Walk the SvcParam list looking for key 5.
//!   3. Presence = ECH advertised → set tls13.ech_advertised = true.
//!
//! Absence is the normal state for most sites — we don't emit a
//! finding for it, but operators who DO publish ECH get the positive
//! signal in the JSON output and can render it on dashboards as a
//! privacy-posture indicator.

use std::time::Duration;

use hickory_resolver::Resolver;
use tokio::time::timeout;

/// Outcome of the HTTPS-record probe. Both flags can be set or unset
/// independently — a domain can publish ECH without HTTP/3, or h3
/// without ECH, or both, or neither.
#[derive(Debug, Default, Clone, Copy)]
pub struct HttpsRecordObserved {
    pub ech_advertised: bool,
    pub http3_advertised: bool,
}

/// Returns the parsed HTTPS-record signal for the given hostname.
/// Default (all false) on DNS failure / absent record.
pub async fn probe_record(host: &str, deadline: Duration) -> HttpsRecordObserved {
    timeout(deadline.min(Duration::from_secs(5)), async {
        let resolver = Resolver::builder_tokio().ok()?.build();
        let lookup = resolver
            .lookup(host, hickory_resolver::proto::rr::RecordType::HTTPS)
            .await
            .ok()?;
        let mut out = HttpsRecordObserved::default();
        for record in lookup.iter() {
            if let hickory_resolver::proto::rr::RData::HTTPS(svcb) = record {
                walk_svc_params(svcb, &mut out);
            }
        }
        Some(out)
    })
    .await
    .ok()
    .flatten()
    .unwrap_or_default()
}

/// Walk a SVCB record's SvcParam list and stamp the observed flags
/// onto the accumulator. Both `ech` (key 5) and `alpn` (key 1, with
/// "h3" listed) cause stamps.
fn walk_svc_params(
    svcb: &hickory_resolver::proto::rr::rdata::svcb::SVCB,
    out: &mut HttpsRecordObserved,
) {
    use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
    for (key, value) in svcb.svc_params().iter() {
        match (key, value) {
            (SvcParamKey::EchConfigList | SvcParamKey::Key(5), _) => {
                out.ech_advertised = true;
            }
            (SvcParamKey::Alpn, SvcParamValue::Alpn(alpn))
                if alpn.0.iter().any(|p| p == "h3" || p.starts_with("h3-")) =>
            {
                out.http3_advertised = true;
            }
            _ => {}
        }
    }
}

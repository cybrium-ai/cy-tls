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

/// Returns true when the target hostname has an HTTPS record (type 65)
/// containing an `ech=` SvcParam (key 5). False on absent record,
/// absent key, or DNS failure.
pub async fn probe(host: &str, deadline: Duration) -> bool {
    let result = timeout(deadline.min(Duration::from_secs(5)), async {
        let resolver = Resolver::builder_tokio().ok()?.build();
        // hickory's high-level `lookup` API queries the requested
        // record type. RecordType::HTTPS is the numeric type 65.
        let lookup = resolver
            .lookup(host, hickory_resolver::proto::rr::RecordType::HTTPS)
            .await
            .ok()?;
        for record in lookup.iter() {
            // The HTTPS record's RData is decoded by hickory into a
            // SVCB struct with a `svc_params` ordered list. SvcParamKey
            // 5 == `ech`. Presence of any non-empty value = advertised.
            if let hickory_resolver::proto::rr::RData::HTTPS(svcb) = record {
                if let Some(_ech_value) = find_ech_param(svcb) {
                    return Some(true);
                }
            }
        }
        Some(false)
    })
    .await;
    result.ok().flatten().unwrap_or(false)
}

/// Walk a SVCB record's SvcParam list for the `ech` key (5).
/// hickory exposes svc_params as an ordered map keyed by SvcParamKey.
fn find_ech_param(
    svcb: &hickory_resolver::proto::rr::rdata::svcb::SVCB,
) -> Option<&hickory_resolver::proto::rr::rdata::svcb::SvcParamValue> {
    use hickory_resolver::proto::rr::rdata::svcb::SvcParamKey;
    svcb.svc_params()
        .iter()
        .find(|(k, _)| matches!(k, SvcParamKey::EchConfigList | SvcParamKey::Key(5)))
        .map(|(_, v)| v)
}

//! DNS CAA (Certification Authority Authorization, RFC 8659) lookup.
//!
//! A CAA record lets a domain owner tell CAs which CAs are AUTHORISED
//! to issue certs for the domain. Modern CAs (Let's Encrypt, Sectigo,
//! DigiCert) MUST honour CAA per CA/B Forum Baseline Requirements
//! §3.2.2.8 (effective Sep 2017). Absence isn't a security defect,
//! but presence is a strong "this org has thought about cert
//! governance" signal that posture dashboards surface.
//!
//! Detection is a single DNS query — TYPE257 (CAA) on the target's
//! apex AND the host itself. Walking up the DNS tree is what real
//! CAs do during issuance (CAA inheritance, RFC 8659 §3), but for
//! cy-tls's posture purposes a single direct lookup is enough — if
//! the apex has CAA, both the apex and any subdomain answer "CAA
//! protected" for issuance purposes.

use std::time::Duration;

use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::Resolver;
use tokio::time::timeout;

/// Returns the list of CAA record value strings observed at the
/// target hostname. Empty when no CAA is published or the DNS query
/// fails.
pub async fn lookup(host: &str, deadline: Duration) -> Vec<String> {
    let result = timeout(deadline.min(Duration::from_secs(5)), async {
        let resolver = Resolver::builder_tokio().ok()?.build();
        let lookup = resolver.lookup(host, RecordType::CAA).await.ok()?;
        let records: Vec<String> = lookup
            .iter()
            .filter_map(|r| {
                if let hickory_resolver::proto::rr::RData::CAA(caa) = r {
                    Some(format_caa(caa))
                } else {
                    None
                }
            })
            .collect();
        Some(records)
    })
    .await
    .ok()
    .flatten()
    .unwrap_or_default();
    result
}

/// Render a CAA record into the canonical `flags tag "value"` text form.
fn format_caa(caa: &hickory_resolver::proto::rr::rdata::caa::CAA) -> String {
    let flags = if caa.issuer_critical() { 128 } else { 0 };
    let tag = caa.tag().as_str();
    let value = caa.raw_value();
    format!("{flags} {tag} \"{}\"", String::from_utf8_lossy(value))
}

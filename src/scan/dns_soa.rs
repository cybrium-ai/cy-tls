//! DNS SOA (Start Of Authority) record lookup.
//!
//! Surfaces the zone-level metadata that operators use to debug DNS
//! propagation: authoritative primary nameserver, hostmaster email
//! (with the standard '.'→'@' substitution per RFC 1035), serial
//! number (zone version), and the refresh/retry/expire/minimum TTL
//! triplet. Useful operational data point — stale serials, mismatched
//! hostmasters, and tiny minimum TTLs all surface here.

use std::time::Duration;

use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::Resolver;
use serde::Serialize;
use tokio::time::timeout;

#[derive(Debug, Default, Clone, Serialize)]
pub struct SoaRecord {
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum: u32,
}

/// Resolve the SOA record for the target hostname. Returns None when
/// the zone has no SOA or DNS fails.
pub async fn lookup(host: &str, deadline: Duration) -> Option<SoaRecord> {
    timeout(deadline.min(Duration::from_secs(5)), async {
        let resolver = Resolver::builder_tokio().ok()?.build();
        let lookup = resolver.lookup(host, RecordType::SOA).await.ok()?;
        for record in lookup.iter() {
            if let hickory_resolver::proto::rr::RData::SOA(soa) = record {
                return Some(SoaRecord {
                    mname: soa.mname().to_string().trim_end_matches('.').to_string(),
                    rname: rname_to_email(&soa.rname().to_string()),
                    serial: soa.serial(),
                    refresh: soa.refresh(),
                    retry: soa.retry(),
                    expire: soa.expire(),
                    minimum: soa.minimum(),
                });
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

/// Convert an SOA rname's first-label-as-local-part DNS form to an
/// email address per RFC 1035 §3.3.13. e.g.
/// "hostmaster.example.com." → "hostmaster@example.com"
fn rname_to_email(rname: &str) -> String {
    let trimmed = rname.trim_end_matches('.');
    match trimmed.split_once('.') {
        Some((local, domain)) => format!("{local}@{domain}"),
        None => trimmed.to_string(),
    }
}

/// v0.5.40 — list authoritative NS records for the target zone.
/// Returns sorted-deduplicated hostnames (trailing-dot stripped) so
/// the output is deterministic across hickory random round-trips.
pub async fn lookup_ns(host: &str, deadline: Duration) -> Vec<String> {
    let result = timeout(deadline.min(Duration::from_secs(5)), async {
        let resolver = Resolver::builder_tokio().ok()?.build();
        let lookup = resolver.lookup(host, RecordType::NS).await.ok()?;
        let mut out: Vec<String> = lookup
            .iter()
            .filter_map(|r| {
                if let hickory_resolver::proto::rr::RData::NS(ns) = r {
                    Some(ns.0.to_string().trim_end_matches('.').to_string())
                } else {
                    None
                }
            })
            .collect();
        out.sort();
        out.dedup();
        Some(out)
    })
    .await;
    result.ok().flatten().unwrap_or_default()
}

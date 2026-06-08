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
    /// v0.5.44 — when the serial parses as the conventional YYYYMMDDNN
    /// form (RFC 1912 §2.2), the YYYY-MM-DD slice extracted from it.
    /// None when the serial doesn't decode as a real calendar date in
    /// the [1970, 2099] window — meaning the zone is using bare
    /// monotonic serials, not the date-prefixed convention.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_yyyymmdd: Option<String>,
    /// v0.5.44 — days between today (UTC) and the date encoded in the
    /// serial. Only populated when serial_yyyymmdd is Some. Negative
    /// values mean the date is in the future (clock skew or staged
    /// rollout); large positive values mean a stagnant zone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_age_days: Option<i64>,
}

/// Resolve the SOA record for the target hostname. Returns None when
/// the zone has no SOA or DNS fails.
pub async fn lookup(host: &str, deadline: Duration) -> Option<SoaRecord> {
    timeout(deadline.min(Duration::from_secs(5)), async {
        let resolver = Resolver::builder_tokio().ok()?.build();
        let lookup = resolver.lookup(host, RecordType::SOA).await.ok()?;
        for record in lookup.iter() {
            if let hickory_resolver::proto::rr::RData::SOA(soa) = record {
                let serial = soa.serial();
                let (serial_yyyymmdd, serial_age_days) = decode_serial_date(serial);
                return Some(SoaRecord {
                    mname: soa.mname().to_string().trim_end_matches('.').to_string(),
                    rname: rname_to_email(&soa.rname().to_string()),
                    serial,
                    refresh: soa.refresh(),
                    retry: soa.retry(),
                    expire: soa.expire(),
                    minimum: soa.minimum(),
                    serial_yyyymmdd,
                    serial_age_days,
                });
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

/// v0.5.44 — try to decode a SOA serial as the conventional
/// YYYYMMDDNN form (RFC 1912 §2.2 — "the recommended format is
/// `YYYYMMDDnn` where nn is a 2-digit revision counter for changes
/// on a single day"). Returns (yyyy-mm-dd, age_in_days) on success,
/// (None, None) when the value doesn't decode as a real calendar
/// date in the [1970, 2099] window or when 'nn' is out of range.
///
/// We don't fire on non-date-formatted serials — many large operators
/// (Cloudflare, AWS Route 53) use bare monotonic counters. The signal
/// only makes sense for zones that DO use the date convention.
pub(crate) fn decode_serial_date(serial: u32) -> (Option<String>, Option<i64>) {
    // Need at least 10 digits (1970010100 = 1,970,010,100) for a valid
    // YYYYMMDDnn. Reject anything below that — it can't be date-formatted.
    if serial < 1_970_010_100 {
        return (None, None);
    }
    let nn = serial % 100;
    let dd = (serial / 100) % 100;
    let mm = (serial / 10_000) % 100;
    let yyyy = (serial / 1_000_000) as i32;
    if nn > 99 || !(2000..=2099).contains(&yyyy) && !(1970..=1999).contains(&yyyy) {
        return (None, None);
    }
    let date = match chrono::NaiveDate::from_ymd_opt(yyyy, mm, dd) {
        Some(d) => d,
        None => return (None, None),
    };
    let today = chrono::Utc::now().date_naive();
    let age = (today - date).num_days();
    (Some(date.format("%Y-%m-%d").to_string()), Some(age))
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

/// v0.5.41 — true when the target zone has a published DNSKEY record.
/// Publishing DNSKEY is the prerequisite for DNSSEC signing — this
/// detects the publish side without validating the parent-DS chain
/// (chain validation needs a DNSSEC-validating resolver, out of
/// scope for a single-binary scanner). False when DNSKEY query
/// fails or no DNSKEY exists.
///
/// hickory's DNSSEC RData variant is gated behind the `__dnssec`
/// feature, so we don't match the RData enum directly. We just
/// inspect the wire-level record_type of each answered record —
/// the resolver reports DNSKEY rows back to us as RecordType::DNSKEY
/// regardless of feature gating.
pub async fn lookup_dnssec(host: &str, deadline: Duration) -> bool {
    let result = timeout(deadline.min(Duration::from_secs(5)), async {
        let resolver = Resolver::builder_tokio().ok()?.build();
        let lookup = resolver.lookup(host, RecordType::DNSKEY).await.ok()?;
        Some(
            lookup
                .record_iter()
                .any(|r| r.record_type() == RecordType::DNSKEY),
        )
    })
    .await;
    result.ok().flatten().unwrap_or(false)
}

/// v0.5.68 — TLSA presence check (RFC 6698 / DANE). DNSSEC-backed
/// TLS certificate pinning. We just count records — semantic
/// alignment vs the actual cert SPKI is a future-release add. Returns
/// 0 when no TLSA records published or DNS fails. Looks at the
/// canonical _443._tcp.<host> name.
pub async fn lookup_tlsa(host: &str, port: u16, deadline: Duration) -> u32 {
    let result = timeout(deadline.min(Duration::from_secs(5)), async {
        let resolver = Resolver::builder_tokio().ok()?.build();
        let qname = format!("_{port}._tcp.{host}");
        let lookup = resolver.lookup(qname, RecordType::TLSA).await.ok()?;
        Some(lookup.record_iter().count() as u32)
    })
    .await;
    result.ok().flatten().unwrap_or(0)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bare_monotonic_serials() {
        // Cloudflare uses small monotonic counters — not date-formatted.
        let (date, age) = decode_serial_date(2_350_000_001);
        // Decodes as year 2350 — out of range → rejected.
        assert_eq!(date, None);
        assert_eq!(age, None);
        let (date, _) = decode_serial_date(42);
        assert_eq!(date, None);
    }

    #[test]
    fn decodes_real_yyyymmddnn_serials() {
        // 2026-05-15 revision 02 → 2026051502
        let (date, age) = decode_serial_date(2_026_051_502);
        assert_eq!(date.as_deref(), Some("2026-05-15"));
        assert!(age.is_some());
    }

    #[test]
    fn rejects_invalid_calendar_dates() {
        // Feb 30 doesn't exist.
        let (date, _) = decode_serial_date(2_026_023_001);
        assert_eq!(date, None);
        // Month 13 doesn't exist.
        let (date, _) = decode_serial_date(2_026_130_101);
        assert_eq!(date, None);
    }
}

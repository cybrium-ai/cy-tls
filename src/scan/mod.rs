//! `cy-tls scan` — full posture probe.
//!
//! The orchestrator runs every probe module against each target,
//! aggregates findings, and emits the result on stdout.

mod cert;
mod cipher;
mod cipher_enum;
mod cipher_pref;
mod connect;
mod dh_params;
mod extensions;
mod fallback_scsv;
mod forward_secrecy;
mod handshake_sim;
mod headers;
mod legacy_proto;
mod ocsp;
mod oid_names;
mod pqc;
mod protocol;
mod server_fingerprint;
mod session;
mod timing;
mod tls12_crypto;
mod tls12_features;
mod tls13;
mod vuln_ccs;
mod vuln_goldendoodle;
mod vuln_goldendoodle_active;
mod vuln_heartbleed;
mod vuln_padding_oracle;
mod vuln_padding_oracle_active;
mod vuln_robot;
mod vuln_ticketbleed;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use serde::Serialize;

use crate::cli::{OutputFormat, ScanArgs};
use crate::finding::Finding;

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub target: String,
    pub ip: Option<String>,
    pub elapsed_ms: u64,
    pub protocols: protocol::ProtocolSupport,
    pub certificate: Option<cert::CertificateInfo>,
    pub key_exchange: cipher::KeyExchangeInfo,
    pub extensions: extensions::ExtensionInfo,
    pub headers: headers::HeaderInfo,
    pub timings_ms: timing::Timings,
    pub findings: Vec<Finding>,
    /// Per-client handshake simulation results. Empty unless the user
    /// passes `--handshake-sim` (because it adds 30 handshakes per host).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub handshake_simulation: Vec<handshake_sim::ClientSim>,
    /// HTTP Server-header fingerprint of the product behind the TLS
    /// endpoint, if one was exposed. Used to upgrade eligibility-tier
    /// findings to higher-confidence findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_fingerprint: Option<server_fingerprint::ServerFingerprint>,
    /// v0.4.1 — cipher-suite preference verdict + Forward-Secrecy bucket +
    /// TLS_FALLBACK_SCSV downgrade-protection verdict. Qualys SSL Labs
    /// reports each of these in its grade.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_preference: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forward_secrecy: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_scsv: Option<&'static str>,
}

pub async fn run(args: ScanArgs) -> Result<()> {
    let format = args.format.clone();
    let reports = run_to_reports(args).await?;
    emit(&reports, format)
}

/// Library entrypoint used by the GUI + MCP transports — returns the
/// in-memory report vector instead of writing JSON to stdout.
pub async fn run_to_reports(args: ScanArgs) -> Result<Vec<ScanReport>> {
    let mut targets = args.targets;
    if let Some(file) = &args.targets_file {
        targets.extend(read_targets_file(file)?);
    }
    let timeout = Duration::from_secs(args.timeout_seconds);

    let mut reports = Vec::with_capacity(targets.len());
    for target in targets {
        let parsed = parse_target(&target);
        match scan_one(&parsed, timeout, args.no_cipher_enum, args.handshake_sim).await {
            Ok(report) => reports.push(report),
            Err(e) => {
                tracing::error!(target = %parsed, error = %e, "scan failed");
                reports.push(failed_report(parsed.clone(), e.to_string()));
            }
        }
    }
    Ok(reports)
}

async fn scan_one(
    target: &str,
    timeout: Duration,
    skip_cipher_enum: bool,
    do_handshake_sim: bool,
) -> Result<ScanReport> {
    let start = std::time::Instant::now();
    let mut findings = Vec::new();
    let mut timings = timing::Timings::default();

    // Padding-oracle eligibility — populated in the cipher-enum block
    // when TLS 1.2 + CBC ciphers are accepted, then resolved into a
    // finding AFTER the server-header fingerprint runs (so we can
    // emit a fingerprint-confirmed verdict when we see an unfixed
    // OpenSSL banner — see CVE-2016-2107 in server_fingerprint.rs).
    let mut cbc_for_padding_oracle: Vec<u16> = Vec::new();

    let connect_start = std::time::Instant::now();
    let ip = match connect::resolve_and_connect(target, timeout).await {
        Ok(ip) => Some(ip),
        Err(_) => {
            findings.push(crate::finding::make(
                "TLS-UNREACHABLE",
                target,
                "TCP connect failed",
            ));
            return Ok(stub_report(
                target.into(),
                None,
                start.elapsed().as_millis() as u64,
                findings,
            ));
        }
    };
    timings.connect = connect_start.elapsed().as_millis() as u64;

    // Protocol enumeration — currently rustls-only (TLS 1.2 + 1.3).
    // SSLv2/v3/TLS1.0/1.1 raw-protocol probes are TODO Phase 2.
    let mut protocols = protocol::enumerate(target, timeout, &mut timings).await?;
    protocols.contribute_findings(target, &mut findings);

    // Certificate chain walk.
    let mut certificate = cert::inspect(target, timeout, &mut timings).await.ok();

    // OCSP stapling probe — always runs (separate cheap handshake)
    // since it tells us whether the cert.ocsp_stapled field is
    // populated truthfully vs the v0.1.x stub default.
    {
        let host_str = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target);
        let o = ocsp::probe(target, host_str, timeout).await;
        if let Some(c) = certificate.as_mut() {
            c.ocsp_stapled = o.stapled;
            c.ocsp_status = o.status;
        }
    }

    // PQC key-exchange probe — single handshake offering X25519MLKEM768
    // alongside X25519 fallback. Cheap enough to always run.
    {
        let host_str = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target);
        let p = pqc::probe(target, host_str, timeout).await;
        protocols.pqc = Some(p);
    }

    if let Some(c) = &certificate {
        c.contribute_findings(target, &mut findings);
    }

    // Cipher / key exchange.
    let mut key_exchange = if skip_cipher_enum {
        cipher::KeyExchangeInfo::default()
    } else {
        cipher::inspect(target, timeout).await.unwrap_or_default()
    };

    // TLS 1.2 cipher enumeration via raw ClientHello bisection. Skipped
    // when --no-cipher-enum is set since each enumeration costs ~5-8
    // extra handshakes per host.
    if !skip_cipher_enum {
        let host_str = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target);
        let accepted_at_12 = cipher_enum::enumerate_at_version(
            target,
            host_str,
            0x03,
            0x03,
            cipher_enum::TLS12_SUITES,
            timeout,
        )
        .await;
        if !accepted_at_12.is_empty() {
            protocols.tls12.supported = true;
        }
        // ROBOT eligibility — any RSA key-exchange cipher (not ECDHE/DHE).
        // Servers in this state are *potentially* vulnerable to
        // Bleichenbacher's RSA padding oracle. Full active oracle test
        // (5 variant ClientKeyExchange messages) is Phase 3.x work.
        let mut robot_eligible = false;
        for suite_id in &accepted_at_12 {
            let name = cipher_enum::name(*suite_id);
            // Only add if not already populated by the modern rustls path.
            if !protocols.tls12.ciphers.iter().any(|c| c == name) && name != "UNKNOWN" {
                protocols.tls12.ciphers.push(name.to_string());
            }
            // Weak-cipher findings.
            let weak_id = match *suite_id {
                0x000a => Some("TLS-3DES-CIPHER"),
                0x0005 | 0x0004 => Some("TLS-RC4-CIPHER"),
                0x0001 | 0x0002 => Some("TLS-NULL-CIPHER"),
                _ => None,
            };
            if let Some(fid) = weak_id {
                findings.push(crate::finding::make(
                    fid,
                    target,
                    format!("cipher 0x{:04x} accepted", suite_id),
                ));
            }
            // TLS_RSA_WITH_* = RSA key exchange, ROBOT-eligible attack surface.
            if matches!(
                *suite_id,
                0x002f | 0x0035 | 0x009c | 0x009d | 0x0001 | 0x0002 | 0x0004 | 0x0005 | 0x000a
            ) {
                robot_eligible = true;
            }
        }
        if robot_eligible {
            // ROBOT active Bleichenbacher oracle probe — sends 5 RSA-CKE
            // variants with deliberately malformed PKCS#1 v1.5 padding,
            // compares server response classes. v0.3.5 upgrade from the
            // v0.2.15 eligibility-tier check.
            let host_str = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target);
            let v = vuln_robot::probe(target, host_str, timeout).await;
            match v {
                vuln_robot::RobotVerdict::Vulnerable => {
                    findings.push(crate::finding::make(
                        "TLS-ROBOT-VULNERABLE",
                        target,
                        "Server distinguishes RSA padding errors across malformed ClientKeyExchange variants — Bleichenbacher oracle confirmed active.",
                    ));
                }
                vuln_robot::RobotVerdict::Indeterminate => {
                    // Probe couldn't run — fall back to the eligibility
                    // signal so we still flag the surface.
                    findings.push(crate::finding::make(
                        "TLS-ROBOT-VULNERABLE",
                        target,
                        "RSA key-exchange cipher accepted; active oracle probe couldn't run (IO/connect issue). Treating eligibility as risk.",
                    ));
                }
                _ => {
                    // NotVulnerable or NotApplicable — no finding emitted.
                }
            }
        }

        // DHE detection — any TLS_DHE_RSA_* cipher enumerated triggers
        // a follow-up DH param probe that extracts prime bits + a
        // common-prime hash compare (Logjam).
        let dhe_accepted = accepted_at_12
            .iter()
            .any(|s| matches!(*s, 0x009e | 0x009f | 0x0033 | 0x0039 | 0x0067 | 0x006b));
        if dhe_accepted {
            let host_str = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target);
            let dh = dh_params::probe(target, host_str, timeout).await;
            if let Some(bits) = dh.bits {
                if bits < 2048 {
                    findings.push(crate::finding::make(
                        "TLS-DH-WEAK",
                        target,
                        format!("DHE parameter is only {bits} bits — Logjam-vulnerable. Recommend ≥2048."),
                    ));
                }
                if dh.common_prime {
                    findings.push(crate::finding::make(
                        "TLS-DH-COMMON-PRIME",
                        target,
                        "DHE uses a publicly-known common prime — precomputation attack feasible.",
                    ));
                }
                if let Some(hash) = &dh.prime_sha256 {
                    key_exchange.dh_param_bits = Some(bits);
                    key_exchange.common_prime_dh = dh.common_prime;
                    tracing::info!(host = target, dh_bits = bits, prime_sha256 = %hash, "DHE params");
                }
            }
        }

        // GOLDENDOODLE / Zombie POODLE eligibility — TLS 1.2 + CBC.
        let cbc_accepted: Vec<u16> = accepted_at_12
            .iter()
            .copied()
            .filter(|s| vuln_goldendoodle::is_cbc_suite(*s))
            .collect();
        vuln_goldendoodle::contribute_findings(target, &cbc_accepted, &mut findings);

        // OpenSSL AES-NI padding oracle (CVE-2016-2107) — defer the
        // emission until AFTER the server-header fingerprint runs so
        // we can emit a fingerprint-confirmed verdict when an unfixed
        // OpenSSL banner is observed. Stash the eligibility signal in
        // a flag for the orchestrator's tail section.
        cbc_for_padding_oracle = cbc_accepted.clone();

        // BEAST eligibility — TLS 1.0 with any CBC cipher exposes the
        // record-layer chosen-plaintext attack (BEAST, CVE-2011-3389).
        // Modern browsers mitigate client-side (1/n-1 split) but
        // server-side mitigation is to not offer TLS 1.0 at all.
        if protocols.tls10.supported {
            let beast_cbc_cipher = accepted_at_12.iter().any(|s| {
                matches!(
                    *s,
                    0xc009
                        | 0xc00a
                        | 0xc013
                        | 0xc014
                        | 0xc023
                        | 0xc024
                        | 0xc027
                        | 0xc028
                        | 0x002f
                        | 0x0035
                )
            });
            if beast_cbc_cipher {
                findings.push(crate::finding::make(
                    "TLS-CBC-MAC-THEN-ENCRYPT",
                    target,
                    "TLS 1.0 + CBC cipher accepted — BEAST attack surface (mitigated client-side by modern browsers).",
                ));
            }
        }
    }

    // Extensions: renegotiation, compression, heartbeat. Phase 2.
    let mut extensions = extensions::probe(target, timeout).await.unwrap_or_default();

    // Session resumption probe — second handshake within the same
    // ClientConfig; cheap (2 handshakes, ~200ms total).
    if !skip_cipher_enum {
        let host_str = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target);
        let s = session::probe(target, host_str, timeout).await;
        extensions.session_ticket.offered = s.tls13_psk || s.tls12_ticket;
        extensions.session_resumption = Some(s);
    }

    // TLS 1.2 ServerHello extension parse — renegotiation_info,
    // heartbeat, compression. One extra handshake but cheap.
    // Preserve the tri-state result so we don't false-positive when
    // the probe couldn't complete a TLS 1.2 ServerHello.
    let mut tls12_features_observed: Option<tls12_features::Tls12Features> = None;
    if !skip_cipher_enum {
        let host_str = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target);
        let f = tls12_features::probe(target, host_str, timeout).await;
        if let Some(s) = f.secure_renegotiation {
            extensions.renegotiation.secure = s;
        }
        if let Some(c) = f.compression_offered {
            extensions.compression.offered = c;
        }
        if let Some(h) = f.heartbeat_offered {
            extensions.heartbeat.offered = h;
        }
        tls12_features_observed = Some(f);
    }
    extensions.contribute_findings(target, &mut findings);

    // v0.4.2 — passive insecure renegotiation surface. Fire ONLY when
    // we definitively observed a TLS 1.2 ServerHello AND that
    // ServerHello did NOT carry the renegotiation_info extension
    // (0xff01) per RFC 5746 §3.6. CVE-2009-3555 plaintext-injection
    // surface. Tri-state preserved so we don't false-positive on
    // probes that couldn't complete (e.g. TLS-1.3-only or rejecting
    // cipher policy).
    if let Some(feat) = &tls12_features_observed {
        if protocols.tls12.supported && feat.secure_renegotiation == Some(false) {
            findings.push(crate::finding::make(
                "TLS-INSECURE-RENEG-LEGACY",
                target,
                "TLS 1.2 ServerHello did not advertise the renegotiation_info extension (0xff01) — legacy CVE-2009-3555 plaintext-injection surface. Any subsequent renegotiation can be hijacked to inject attacker plaintext.",
            ));
        }
    }

    // Heartbleed active probe — only runs when the server advertised
    // the heartbeat extension (the vulnerability is gated on that).
    if extensions.heartbeat.offered {
        let host_str = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target);
        let v = vuln_heartbleed::probe(target, host_str, true, timeout).await;
        if matches!(v, vuln_heartbleed::HeartbleedVerdict::Vulnerable) {
            findings.push(crate::finding::make(
                "TLS-HEARTBLEED",
                target,
                "Server responded to malformed heartbeat with over-read payload",
            ));
        }
    }

    // OpenSSL CCS Injection (CVE-2014-0224) — TLS 1.2 only.
    if protocols.tls12.supported {
        let host_str = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target);
        let v = vuln_ccs::probe(target, host_str, timeout).await;
        if matches!(v, vuln_ccs::CcsVerdict::Vulnerable) {
            findings.push(crate::finding::make(
                "TLS-CCS-INJECTION",
                target,
                "Server accepted ChangeCipherSpec before handshake completion",
            ));
        }
    }

    // Ticketbleed (CVE-2016-9244) — F5 BIG-IP session ID leak.
    if protocols.tls12.supported {
        let host_str = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target);
        let v = vuln_ticketbleed::probe(target, host_str, timeout).await;
        if matches!(v, vuln_ticketbleed::TicketbleedVerdict::Vulnerable) {
            findings.push(crate::finding::make(
                "TLS-TICKETBLEED",
                target,
                "Server echoed partial session ID with leaked process memory",
            ));
        }
    }

    // HSTS / Expect-CT headers.
    let headers = headers::fetch(target, timeout).unwrap_or_default();
    headers.contribute_findings(target, &mut findings);

    // Server-header fingerprint — one extra HEAD request, cheap.
    let server_fingerprint = {
        let raw = server_fingerprint::fetch(target, timeout);
        let fp = server_fingerprint::classify(raw.as_deref());
        if fp.raw.is_none() {
            None
        } else {
            Some(fp)
        }
    };

    // OpenSSL AES-NI padding oracle (CVE-2016-2107) finding emission —
    // tiered detection:
    //   1. (v0.4.0) Active record-layer probe runs against ANY server
    //      that accepted cipher 0x002f (TLS_RSA_WITH_AES_128_CBC_SHA).
    //      Drives a real TLS 1.2 handshake, derives keys, sends two
    //      corrupt records and compares alerts.  Vulnerable verdict
    //      becomes a high-confidence finding.
    //   2. (v0.3.7) When the active probe can't run end-to-end and the
    //      server-header fingerprint reveals a vulnerable OpenSSL
    //      banner, emit a fingerprint-confirmed verdict instead.
    //   3. (v0.3.2) Otherwise emit the eligibility-tier message.
    if !cbc_for_padding_oracle.is_empty() {
        let aes128_cbc_sha_accepted = cbc_for_padding_oracle.contains(&0x002f);

        let active_verdict = if aes128_cbc_sha_accepted {
            let host_str = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target);
            Some(vuln_padding_oracle_active::probe(target, host_str, timeout).await)
        } else {
            None
        };

        match active_verdict {
            Some(vuln_padding_oracle_active::OracleVerdict::Vulnerable) => {
                findings.push(crate::finding::make(
                    "TLS-OPENSSL-PADDING-ORACLE",
                    target,
                    "Active record-layer probe confirmed CVE-2016-2107: server returned distinct alert types for invalid-MAC vs invalid-padding records (bad_record_mac for valid-padding case, decrypt_error for invalid-padding case). AES-NI padding-oracle plaintext recovery is feasible.",
                ));
            }
            Some(vuln_padding_oracle_active::OracleVerdict::NotVulnerable) => {
                // Active probe ran and gave a clean bill — suppress
                // both fingerprint-tier and eligibility-tier findings.
            }
            _ => {
                // Active probe couldn't run (NotApplicable / Indeterminate)
                // — fall back to fingerprint or eligibility tier.
                let confirmed = server_fingerprint
                    .as_ref()
                    .map(|fp| fp.openssl_vulnerable_padding_oracle)
                    .unwrap_or(false);
                if confirmed {
                    let openssl_v = server_fingerprint
                        .as_ref()
                        .and_then(|fp| fp.openssl_version.as_deref())
                        .unwrap_or("?");
                    findings.push(crate::finding::make(
                        "TLS-OPENSSL-PADDING-ORACLE",
                        target,
                        format!(
                            "Server banner advertises OpenSSL/{openssl_v} — predates the CVE-2016-2107 fix (1.0.1t / 1.0.2h, May 2016). TLS 1.2 + CBC suite{} accepted; active probe couldn't run end-to-end. AES-NI padding-oracle plaintext recovery is feasible.",
                            if cbc_for_padding_oracle.len() == 1 { "" } else { "s" },
                        ),
                    ));
                } else {
                    vuln_padding_oracle::contribute_findings(
                        target,
                        &cbc_for_padding_oracle,
                        &mut findings,
                    );
                }
            }
        }

        // v0.5.0 — GOLDENDOODLE / Zombie POODLE active probe. Distinct
        // distinguisher from CVE-2016-2107: tests (bad_mac, good_pad)
        // vs (good_mac, bad_pad) — orthogonal corruption flags. Same
        // gate as the AES-NI probe (cipher 0x002f accepted), runs in
        // sequence to avoid hammering a single endpoint with parallel
        // post-handshake corruption attempts.
        if aes128_cbc_sha_accepted {
            let host_str = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target);
            if matches!(
                vuln_goldendoodle_active::probe(target, host_str, timeout).await,
                vuln_goldendoodle_active::GoldendoodleVerdict::Vulnerable
            ) {
                findings.push(crate::finding::make(
                    "TLS-GOLDENDOODLE-ACTIVE",
                    target,
                    "Active record-layer probe confirmed a GOLDENDOODLE / Zombie POODLE-family CBC oracle: server returned bad_record_mac for the invalid-MAC record but decrypt_error for the invalid-padding record. Vaudenay-style plaintext recovery is feasible. Pattern matches Hanno Böck's 2019 disclosures against Citrix NetScaler, F5 BIG-IP, and Sangfor SSL VPN appliances.",
                ));
            }
        }
    }

    // v0.4.5 — Lucky13 (CVE-2013-0169) fingerprint-confirmed verdict.
    // Fires when TLS 1.2 + CBC is accepted AND the HTTP Server banner
    // reveals an OpenSSL release predating the constant-time CBC
    // decrypt fix (1.0.1g, April 2014). Same pattern as the v0.3.7
    // CVE-2016-2107 fingerprint tier, with its own version-band table.
    if !cbc_for_padding_oracle.is_empty() {
        let lucky13_confirmed = server_fingerprint
            .as_ref()
            .map(|fp| fp.openssl_vulnerable_lucky13)
            .unwrap_or(false);
        if lucky13_confirmed {
            let openssl_v = server_fingerprint
                .as_ref()
                .and_then(|fp| fp.openssl_version.as_deref())
                .unwrap_or("?");
            findings.push(crate::finding::make(
                "TLS-LUCKY13-LIKELY",
                target,
                format!(
                    "Server banner advertises OpenSSL/{openssl_v} — predates the Lucky13 constant-time CBC decrypt fix (1.0.1g, April 2014). TLS 1.2 + CBC accepted on this endpoint. Timing-side-channel plaintext recovery is likely feasible.",
                ),
            ));
        }
    }

    // GOLDENDOODLE / Zombie POODLE high-confidence finding — fires
    // when TLS 1.2 + CBC is accepted AND the server fingerprint matches
    // a known-vulnerable vendor (Citrix NetScaler / F5 BIG-IP / Sangfor
    // / older Cisco). Combines the existing eligibility signal with
    // fingerprint evidence for an operator-actionable severity bump.
    if let Some(fp) = &server_fingerprint {
        if fp.known_cbc_oracle_family {
            let cbc_in_use = !skip_cipher_enum
                && protocols.tls12.ciphers.iter().any(|c| {
                    c.contains("_CBC_")
                        || c.ends_with("_SHA")
                        || c.ends_with("_SHA256")
                        || c.ends_with("_SHA384")
                });
            if cbc_in_use {
                findings.push(crate::finding::make(
                    "TLS-CBC-ORACLE-FAMILY-FP",
                    target,
                    format!(
                        "Server fingerprint '{}' + TLS 1.2 CBC cipher accepted — high-confidence GOLDENDOODLE / Zombie POODLE / Lucky13 exposure. Family: {}{}",
                        fp.raw.as_deref().unwrap_or("?"),
                        fp.family.as_deref().unwrap_or("?"),
                        fp.version.as_deref().map(|v| format!(" v{v}")).unwrap_or_default(),
                    ),
                ));
            }
        }
    }

    // Handshake simulation matrix — opt-in (--handshake-sim). Emulates
    // 30 reference clients (browsers, Java, OpenSSL) and reports what
    // each negotiates. Adds ~30 handshakes per host.
    let handshake_simulation = if do_handshake_sim {
        let host_str = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target);
        handshake_sim::simulate_all(target, host_str, timeout).await
    } else {
        Vec::new()
    };

    // ── v0.4.1 — cipher preference + FS bucket + SCSV ───────────────
    // All three are cheap (combined ~3 handshakes) and ship the Qualys
    // SSL Labs surface the orchestrator was missing. Gated behind the
    // same `skip_cipher_enum` flag because they share cipher-enum
    // infrastructure.
    let mut cipher_preference: Option<&'static str> = None;
    let mut forward_secrecy_bucket: Option<&'static str> = None;
    let mut fallback_scsv_status: Option<&'static str> = None;

    if !skip_cipher_enum {
        let host_str = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target);

        // Cipher preference.
        match cipher_pref::probe(target, host_str, timeout).await {
            cipher_pref::PreferenceVerdict::ServerPreferred => {
                cipher_preference = Some("server-preferred");
            }
            cipher_pref::PreferenceVerdict::ClientPreferred => {
                cipher_preference = Some("client-preferred");
                findings.push(crate::finding::make(
                    "TLS-CIPHER-CLIENT-PREFERENCE-ONLY",
                    target,
                    "Reversing the offered cipher_suites list changed the negotiated suite — server follows client preference order.",
                ));
            }
            cipher_pref::PreferenceVerdict::Indeterminate => {
                cipher_preference = Some("indeterminate");
            }
        }

        // Forward Secrecy classification — re-run TLS 1.2 enumeration
        // here so we have the authoritative accepted list (the earlier
        // enumeration walked the modern superset).
        let accepted_at_12 = cipher_enum::enumerate_at_version(
            target,
            host_str,
            0x03,
            0x03,
            cipher_enum::TLS12_SUITES,
            timeout,
        )
        .await;
        let bucket = forward_secrecy::classify(&accepted_at_12, protocols.tls13.supported);
        forward_secrecy_bucket = Some(bucket.as_str());
        if matches!(
            bucket,
            forward_secrecy::FsBucket::None | forward_secrecy::FsBucket::Some
        ) {
            findings.push(crate::finding::make(
                "TLS-FORWARD-SECRECY-WEAK",
                target,
                format!(
                    "Forward Secrecy bucket: {} — non-FS RSA key-exchange ciphers accepted alongside (or instead of) ECDHE/DHE.",
                    bucket.as_str(),
                ),
            ));
        }

        // TLS_FALLBACK_SCSV — only meaningful when the server actually
        // supports TLS 1.2 or higher.
        if protocols.tls12.supported || protocols.tls13.supported {
            match fallback_scsv::probe(target, host_str, timeout).await {
                fallback_scsv::ScsvVerdict::Honored => {
                    fallback_scsv_status = Some("honored");
                }
                fallback_scsv::ScsvVerdict::NotHonored => {
                    fallback_scsv_status = Some("not-honored");
                    findings.push(crate::finding::make(
                        "TLS-NO-FALLBACK-SCSV",
                        target,
                        "Server completed a TLS 1.1 handshake that advertised TLS_FALLBACK_SCSV — RFC 7507 requires inappropriate_fallback (alert 86). Downgrade attacks are not prevented.",
                    ));
                }
                fallback_scsv::ScsvVerdict::Indeterminate => {
                    fallback_scsv_status = Some("indeterminate");
                }
            }
        }
    }

    let elapsed_ms = start.elapsed().as_millis() as u64;
    Ok(ScanReport {
        target: target.into(),
        ip,
        elapsed_ms,
        protocols,
        certificate,
        key_exchange,
        extensions,
        headers,
        timings_ms: timings,
        findings,
        handshake_simulation,
        server_fingerprint,
        cipher_preference,
        forward_secrecy: forward_secrecy_bucket,
        fallback_scsv: fallback_scsv_status,
    })
}

fn parse_target(raw: &str) -> String {
    if raw.contains(':') {
        raw.to_string()
    } else {
        format!("{raw}:443")
    }
}

fn read_targets_file(path: &PathBuf) -> Result<Vec<String>> {
    let body = std::fs::read_to_string(path)?;
    Ok(body
        .lines()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .map(String::from)
        .collect())
}

fn emit(reports: &[ScanReport], format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => crate::output::json::emit(reports),
        OutputFormat::Jsonl => crate::output::jsonl::emit(reports),
        OutputFormat::Sarif => crate::output::sarif::emit(reports),
        OutputFormat::Csv => crate::output::csv::emit(reports),
        OutputFormat::Html => crate::output::html::emit(reports),
    }
}

fn stub_report(
    target: String,
    ip: Option<String>,
    elapsed_ms: u64,
    findings: Vec<Finding>,
) -> ScanReport {
    ScanReport {
        target,
        ip,
        elapsed_ms,
        protocols: protocol::ProtocolSupport::default(),
        certificate: None,
        key_exchange: cipher::KeyExchangeInfo::default(),
        extensions: extensions::ExtensionInfo::default(),
        headers: headers::HeaderInfo::default(),
        timings_ms: timing::Timings::default(),
        findings,
        handshake_simulation: Vec::new(),
        server_fingerprint: None,
        cipher_preference: None,
        forward_secrecy: None,
        fallback_scsv: None,
    }
}

fn failed_report(target: String, error: String) -> ScanReport {
    let findings = vec![crate::finding::make("TLS-UNREACHABLE", &target, error)];
    stub_report(target, None, 0, findings)
}

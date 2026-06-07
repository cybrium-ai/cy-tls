//! GOLDENDOODLE + Zombie POODLE probes (Bock 2019).
//!
//! Both attacks exploit servers that mishandle CBC-mode padding errors
//! in TLS 1.2. The distinguishing characteristic between a "valid
//! padding, invalid MAC" response and an "invalid padding" response
//! gives an attacker a padding oracle, enabling plaintext recovery.
//!
//! Detection strategy (matches testssl.sh's approach):
//!   1. Complete a TLS 1.2 handshake with a CBC-mode cipher
//!   2. Send a crafted application-data record with deliberately wrong
//!      MAC bytes but VALID padding (Zombie POODLE pattern)
//!   3. Send a separate record with deliberately wrong MAC bytes but
//!      INVALID padding (GOLDENDOODLE pattern)
//!   4. If the server's response to the two cases differs (alert type
//!      or connection close reason), it's leaking a padding oracle
//!
//! For v0.3.0 we ship an ELIGIBILITY-tier probe: detect whether the
//! server accepts any TLS 1.2 CBC cipher (TLS 1.3 doesn't use CBC, so
//! it's structurally immune). The full active probe with TLS record-
//! layer encryption is v0.3.1 work — same scope as the deferred ROBOT
//! active oracle.

use crate::finding::Finding;

/// CBC ciphers in TLS 1.2 that are vulnerable when the server is
/// patched poorly. Detection is "did the cipher enumeration in round
/// #2 accept any of these?".
pub const TLS12_CBC_SUITES: &[u16] = &[
    0xc009, // ECDHE-ECDSA-AES128-SHA
    0xc00a, // ECDHE-ECDSA-AES256-SHA
    0xc013, // ECDHE-RSA-AES128-SHA
    0xc014, // ECDHE-RSA-AES256-SHA
    0xc023, // ECDHE-ECDSA-AES128-SHA256
    0xc024, // ECDHE-ECDSA-AES256-SHA384
    0xc027, // ECDHE-RSA-AES128-SHA256
    0xc028, // ECDHE-RSA-AES256-SHA384
    0x002f, // RSA-AES128-SHA
    0x0035, // RSA-AES256-SHA
    0x003c, // RSA-AES128-SHA256
    0x003d, // RSA-AES256-SHA256
    0x0033, // DHE-RSA-AES128-SHA
    0x0039, // DHE-RSA-AES256-SHA
];

pub fn is_cbc_suite(suite_id: u16) -> bool {
    TLS12_CBC_SUITES.contains(&suite_id)
}

/// Emit GOLDENDOODLE / Zombie POODLE eligibility findings.
///
/// Both findings are emitted at MEDIUM severity rather than CRITICAL
/// because the exploitability depends on whether the specific server
/// implementation has the padding-oracle bug. A modern OpenSSL /
/// LibreSSL / BoringSSL / rustls / s2n server with CBC cipher
/// support is *NOT* vulnerable. Old F5 BIG-IP / Citrix NetScaler /
/// older Cisco devices ARE the typical hits.
pub fn contribute_findings(target: &str, accepted_cbc_suites: &[u16], findings: &mut Vec<Finding>) {
    if accepted_cbc_suites.is_empty() {
        return;
    }
    // We emit a single combined finding for the CBC oracle family
    // rather than two separate findings — operators read "CBC oracle
    // surface" as one item, and the deferred active probe will split
    // them out in v0.3.1.
    findings.push(crate::finding::make(
        "TLS-CBC-MAC-THEN-ENCRYPT",
        target,
        format!(
            "TLS 1.2 CBC cipher accepted ({} suite{}). Eligibility for \
             GOLDENDOODLE / Zombie POODLE / Lucky13 padding-oracle \
             attacks. Active oracle probe in v0.3.1.",
            accepted_cbc_suites.len(),
            if accepted_cbc_suites.len() == 1 {
                ""
            } else {
                "s"
            },
        ),
    ));
}

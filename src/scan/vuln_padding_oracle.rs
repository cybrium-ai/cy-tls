//! OpenSSL Padding Oracle on AES-NI / Lucky13 mitigation (CVE-2016-2107).
//!
//! OpenSSL 1.0.1t / 1.0.2h fixes a padding oracle on the AES-NI
//! constant-time CBC decryption path: when the server receives an
//! invalid-padding record on a CBC suite, it generates a different
//! alert if AES-NI is in use vs not — letting an attacker distinguish
//! padding-valid from padding-invalid responses and recover plaintext.
//!
//! For v0.3.x we ship eligibility tier — detect TLS 1.2 + CBC +
//! likely-OpenSSL-server fingerprint and emit the finding. Active
//! probe requires sending crafted CBC ciphertexts post-handshake with
//! the TLS record encryption keys, same multi-day effort as the
//! deferred ROBOT active oracle.

use crate::finding::Finding;

/// Emit eligibility finding when TLS 1.2 + CBC cipher accepted.
/// Distinct ID from TLS-CBC-MAC-THEN-ENCRYPT (which covers BEAST /
/// GOLDENDOODLE / Zombie POODLE family) — this one is the specific
/// AES-NI / Lucky13-mitigation oracle.
pub fn contribute_findings(
    target: &str,
    accepted_cbc_suites: &[u16],
    findings: &mut Vec<Finding>,
) {
    if accepted_cbc_suites.is_empty() {
        return;
    }
    findings.push(crate::finding::make(
        "TLS-OPENSSL-PADDING-ORACLE",
        target,
        format!(
            "TLS 1.2 + CBC cipher accepted ({} suite{}). Server is eligible \
             for OpenSSL AES-NI padding oracle (CVE-2016-2107) if running \
             OpenSSL <1.0.1t / <1.0.2h. Active probe in v0.4.x.",
            accepted_cbc_suites.len(),
            if accepted_cbc_suites.len() == 1 { "" } else { "s" },
        ),
    ));
}

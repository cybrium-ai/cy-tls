//! Cipher suite enumeration + key exchange strength.
//!
//! Phase 1: leave as a stub. rustls only tells us the negotiated
//! cipher, not the full server-accepted set. Full enumeration needs
//! a bisection over ClientHello cipher_suites lists — Phase 2.

use std::time::Duration;
use serde::Serialize;

#[derive(Debug, Default, Serialize)]
pub struct KeyExchangeInfo {
    pub dh_param_bits: Option<u32>,
    pub ecdhe_curves: Vec<String>,
    pub preferred_curve: Option<String>,
    pub common_prime_dh: bool,
}

pub async fn inspect(_target: &str, _deadline: Duration) -> anyhow::Result<KeyExchangeInfo> {
    // TODO Phase 2 — implement ClientHello bisection
    Ok(KeyExchangeInfo::default())
}

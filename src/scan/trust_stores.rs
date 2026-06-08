//! v0.5.70 — Multi-trust-store chain validation. Closes the
//! Apple/Android/Java gap vs SSLyze + Qualys SSL Labs.
//!
//! Each store is a curated bundle vendored at `data/trust_stores/`
//! and sourced from the trust_stores_observatory project (the same
//! source SSLyze uses). The bundles are static — refresh them by
//! re-running `tools/refresh_trust_stores.sh` quarterly.
//!
//! Per-store outcome surfaces as a `TrustStoreOutcomes` block on
//! `CertificateInfo`. When validation fails against any store we
//! also emit a dedicated finding (`TLS-CHAIN-NOT-TRUSTED-{APPLE,
//! ANDROID,JAVA}`) so dashboards + Cymind's auto-fix layer can
//! ladder severity per-store.

use std::sync::OnceLock;

use rustls::client::danger::ServerCertVerifier;
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::RootCertStore;
use serde::Serialize;
use std::sync::Arc;

#[derive(Debug, Default, Clone, Serialize)]
pub struct TrustStoreOutcomes {
    /// Mozilla NSS root store (also covers most Linux distros). True
    /// when the cert chain validates.
    pub mozilla: bool,
    /// Apple platform trust store (macOS / iOS / iPadOS / tvOS /
    /// watchOS / visionOS).
    pub apple: bool,
    /// Android system trust store (AOSP).
    pub android: bool,
    /// OpenJDK / Java cacerts.
    pub java: bool,
}

static MOZILLA: OnceLock<RootCertStore> = OnceLock::new();
static APPLE: OnceLock<RootCertStore> = OnceLock::new();
static ANDROID: OnceLock<RootCertStore> = OnceLock::new();
static JAVA: OnceLock<RootCertStore> = OnceLock::new();

const MOZILLA_PEM: &[u8] = include_bytes!("../../data/trust_stores/mozilla.pem");
const APPLE_PEM: &[u8] = include_bytes!("../../data/trust_stores/apple.pem");
const ANDROID_PEM: &[u8] = include_bytes!("../../data/trust_stores/android.pem");
const JAVA_PEM: &[u8] = include_bytes!("../../data/trust_stores/java.pem");

fn load_store(pem_bytes: &[u8]) -> RootCertStore {
    let mut store = RootCertStore::empty();
    let mut reader = std::io::BufReader::new(pem_bytes);
    for cert in rustls_pemfile::certs(&mut reader).flatten() {
        // Some bundled certs may be flagged for non-TLS usage. Errors
        // here just mean the cert can't be a TLS trust anchor — skip,
        // don't fail the whole store.
        let _ = store.add(cert);
    }
    store
}

fn mozilla() -> &'static RootCertStore {
    MOZILLA.get_or_init(|| load_store(MOZILLA_PEM))
}
fn apple() -> &'static RootCertStore {
    APPLE.get_or_init(|| load_store(APPLE_PEM))
}
fn android() -> &'static RootCertStore {
    ANDROID.get_or_init(|| load_store(ANDROID_PEM))
}
fn java() -> &'static RootCertStore {
    JAVA.get_or_init(|| load_store(JAVA_PEM))
}

/// Validate the presented cert chain against all four major trust
/// stores. Returns a TrustStoreOutcomes block — one boolean per
/// store. `chain` is the cert chain as presented by the server
/// (leaf at position 0, intermediates after).
pub fn validate_all(chain: &[CertificateDer<'static>], host: &str) -> TrustStoreOutcomes {
    if chain.is_empty() {
        return TrustStoreOutcomes::default();
    }
    let server_name = match ServerName::try_from(host.to_string()) {
        Ok(s) => s,
        Err(_) => return TrustStoreOutcomes::default(),
    };
    let now = UnixTime::now();
    let intermediates = &chain[1..];
    TrustStoreOutcomes {
        mozilla: verify_against(mozilla(), &chain[0], intermediates, &server_name, now),
        apple: verify_against(apple(), &chain[0], intermediates, &server_name, now),
        android: verify_against(android(), &chain[0], intermediates, &server_name, now),
        java: verify_against(java(), &chain[0], intermediates, &server_name, now),
    }
}

fn verify_against(
    store: &RootCertStore,
    leaf: &CertificateDer<'static>,
    intermediates: &[CertificateDer<'static>],
    server_name: &ServerName<'_>,
    now: UnixTime,
) -> bool {
    let verifier = match WebPkiServerVerifier::builder(Arc::new(store.clone())).build() {
        Ok(v) => v,
        Err(_) => return false,
    };
    verifier
        .verify_server_cert(leaf, intermediates, server_name, &[], now)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_load_without_panic() {
        // Just exercising the OnceLock init. If any bundle is
        // malformed, this surfaces immediately.
        assert!(!mozilla().is_empty());
        assert!(!apple().is_empty());
        assert!(!android().is_empty());
        assert!(!java().is_empty());
    }

    #[test]
    fn empty_chain_returns_all_false() {
        let outcomes = validate_all(&[], "example.com");
        assert!(!outcomes.mozilla && !outcomes.apple && !outcomes.android && !outcomes.java);
    }
}

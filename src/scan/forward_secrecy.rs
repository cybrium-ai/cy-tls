//! Forward Secrecy bucket classifier.
//!
//! Qualys SSL Labs grades FS along four levels:
//!
//!   None           — server only accepts non-FS ciphers (RSA key
//!                    exchange). Any session compromise lets an
//!                    attacker decrypt prior captured traffic with the
//!                    server's private key.
//!   Yes (some)     — server accepts a MIX of FS and non-FS. Clients
//!                    that prefer non-FS (legacy) won't get FS even
//!                    though it's available.
//!   Yes (modern)   — ECDHE / DHE only. No TLS_RSA_WITH_*.
//!   Robust         — TLS 1.3 supported AND TLS 1.2 path uses only
//!                    ECDHE (no DHE — Logjam surface). Browsers' "A+"
//!                    bar.
//!
//! Pure classifier — no extra handshakes. Consumes the already-
//! enumerated `accepted_at_12` list from cipher_enum + a `tls13`
//! boolean. Maps cipher suite IDs to their key-exchange family.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsBucket {
    None,
    Some,
    Modern,
    Robust,
}

impl FsBucket {
    pub fn as_str(self) -> &'static str {
        match self {
            FsBucket::None => "none",
            FsBucket::Some => "some-clients",
            FsBucket::Modern => "modern-clients",
            FsBucket::Robust => "robust",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Kx {
    Rsa,
    Dhe,
    Ecdhe,
}

fn classify_kx(suite: u16) -> Option<Kx> {
    Some(match suite {
        // RSA key exchange (no FS).
        0x002f | 0x0035 | 0x009c | 0x009d | 0x003c | 0x003d | 0x000a | 0x0005 | 0x0004 | 0x0001
        | 0x0002 => Kx::Rsa,

        // DHE-RSA (FS but Logjam-relevant).
        0x009e | 0x009f | 0x0033 | 0x0039 | 0x0067 | 0x006b => Kx::Dhe,

        // ECDHE family.
        0xc02b | 0xc02c | 0xc02f | 0xc030 | 0xcca8 | 0xcca9 | 0xc023 | 0xc024 | 0xc027 | 0xc028
        | 0xc009 | 0xc00a | 0xc013 | 0xc014 => Kx::Ecdhe,

        _ => return None,
    })
}

pub fn classify(accepted_at_12: &[u16], tls13_supported: bool) -> FsBucket {
    let mut has_rsa = false;
    let mut has_dhe = false;
    let mut has_ecdhe = false;

    for s in accepted_at_12 {
        match classify_kx(*s) {
            Some(Kx::Rsa) => has_rsa = true,
            Some(Kx::Dhe) => has_dhe = true,
            Some(Kx::Ecdhe) => has_ecdhe = true,
            None => {}
        }
    }

    // If TLS 1.3 alone is offered without any TLS 1.2 ciphers, treat
    // that as Robust — TLS 1.3 mandates (EC)DHE.
    if !has_rsa && !has_dhe && !has_ecdhe && tls13_supported {
        return FsBucket::Robust;
    }

    if has_rsa && (has_dhe || has_ecdhe) {
        return FsBucket::Some;
    }
    if has_rsa {
        return FsBucket::None;
    }
    if has_dhe {
        // DHE without RSA — modern-ish but Logjam-exposed.
        return FsBucket::Modern;
    }
    // Only ECDHE (or nothing).
    if has_ecdhe {
        if tls13_supported {
            FsBucket::Robust
        } else {
            FsBucket::Modern
        }
    } else {
        // No cipher data at all — be conservative.
        FsBucket::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_no_tls13_is_none() {
        // Edge: server didn't accept any TLS 1.2 cipher we tried and
        // no TLS 1.3 — treat as None.
        assert_eq!(classify(&[], false), FsBucket::None);
    }

    #[test]
    fn rsa_only_is_none() {
        // TLS_RSA_WITH_AES_128_GCM_SHA256.
        assert_eq!(classify(&[0x009c], false), FsBucket::None);
    }

    #[test]
    fn rsa_plus_ecdhe_is_some() {
        assert_eq!(classify(&[0x009c, 0xc02f], false), FsBucket::Some);
    }

    #[test]
    fn ecdhe_only_no_tls13_is_modern() {
        assert_eq!(classify(&[0xc02f, 0xc030], false), FsBucket::Modern);
    }

    #[test]
    fn ecdhe_plus_tls13_is_robust() {
        assert_eq!(classify(&[0xc02f, 0xc030], true), FsBucket::Robust);
    }

    #[test]
    fn dhe_only_is_modern_not_robust() {
        // Even with TLS 1.3, DHE on the 1.2 path keeps us at modern —
        // Logjam-relevant surface.
        assert_eq!(classify(&[0x009e], true), FsBucket::Modern);
    }
}

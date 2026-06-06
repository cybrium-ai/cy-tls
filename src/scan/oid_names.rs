//! OID → friendly-name lookup for cert signature algorithms, public-key
//! algorithms, and named elliptic curves. Replaces the `OID(...)` debug
//! output from x509-parser with the names operators expect to see.

pub fn signature_algorithm(oid: &str) -> &'static str {
    match oid {
        "1.2.840.113549.1.1.5"  => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.113549.1.1.4"  => "md5WithRSAEncryption",
        "1.2.840.10045.4.1"     => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.2"   => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3"   => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4"   => "ecdsa-with-SHA512",
        "1.3.101.112"           => "Ed25519",
        "1.3.101.113"           => "Ed448",
        _ => "unknown",
    }
}

pub fn public_key_algorithm(oid: &str) -> &'static str {
    match oid {
        "1.2.840.113549.1.1.1" => "rsaEncryption",
        "1.2.840.10045.2.1"    => "ecPublicKey",
        "1.3.101.112"          => "Ed25519",
        "1.3.101.113"          => "Ed448",
        "1.2.840.10040.4.1"    => "dsa",
        _ => "unknown",
    }
}

/// Named-curve OID → bit length (for the public-key-strength finding).
pub fn ec_curve_bits(oid: &str) -> Option<u32> {
    Some(match oid {
        "1.2.840.10045.3.1.7"  => 256,  // prime256v1 / NIST P-256 / secp256r1
        "1.3.132.0.34"         => 384,  // secp384r1 / NIST P-384
        "1.3.132.0.35"         => 521,  // secp521r1 / NIST P-521
        "1.3.132.0.10"         => 256,  // secp256k1
        "1.3.6.1.4.1.11591.15.1" => 256, // Curve25519 (some certs use this OID)
        _ => return None,
    })
}

pub fn ec_curve_name(oid: &str) -> &'static str {
    match oid {
        "1.2.840.10045.3.1.7"  => "secp256r1",
        "1.3.132.0.34"         => "secp384r1",
        "1.3.132.0.35"         => "secp521r1",
        "1.3.132.0.10"         => "secp256k1",
        "1.3.6.1.4.1.11591.15.1" => "Curve25519",
        _ => "unknown",
    }
}

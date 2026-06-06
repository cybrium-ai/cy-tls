# cy-tls JSON output schema

The `cy-tls scan` command emits an array of `ScanReport` objects on
stdout. One element per target.

## Top-level shape

```json
[
  {
    "target": "example.com:443",
    "ip": "93.184.216.34",
    "elapsed_ms": 1247,
    "protocols":    { /* ProtocolSupport */ },
    "certificate":  { /* CertificateInfo or null */ },
    "key_exchange": { /* KeyExchangeInfo */ },
    "extensions":   { /* ExtensionInfo */ },
    "headers":      { /* HeaderInfo */ },
    "timings_ms":   { /* Timings */ },
    "findings":     [ /* Finding[] */ ]
  }
]
```

## ProtocolSupport

```json
{
  "sslv2":  { "supported": false, "ciphers": [] },
  "sslv3":  { "supported": false, "ciphers": [] },
  "tls10":  { "supported": false, "ciphers": [] },
  "tls11":  { "supported": false, "ciphers": [] },
  "tls12":  { "supported": true,  "ciphers": ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"] },
  "tls13": {
    "supported": true,
    "ciphers": ["TLS_AES_256_GCM_SHA384"],
    "zero_rtt_accepted": false,
    "ech_advertised": false,
    "hello_retry_required": false
  }
}
```

## CertificateInfo

```json
{
  "subject":             "CN=example.com",
  "issuer":              "CN=DigiCert RSA TLS CA G1, O=DigiCert Inc",
  "san":                 ["example.com", "www.example.com"],
  "not_before":          "2025-12-01T00:00:00Z",
  "not_after":           "2026-12-31T23:59:59Z",
  "days_remaining":      211,
  "signature_algorithm": "sha256WithRSAEncryption",
  "key_algorithm":       "rsaEncryption",
  "key_bits":            2048,
  "chain_complete":      true,
  "self_signed":         false,
  "ev":                  false,
  "must_staple":         false,
  "sct_count":           2,
  "ocsp_stapled":        true,
  "ocsp_status":         "good"
}
```

## Finding

```json
{
  "id": "TLS-WEAK-VERSION-1.1",
  "host": "example.com:443",
  "severity": "high",
  "title": "Server accepts TLS 1.1",
  "evidence": "ClientHello TLS 1.1 negotiated successfully",
  "controls": ["NIST SC-13", "PCI DSS 4.2.1", "ISO 27001 A.8.24"]
}
```

Severity is one of `critical | high | medium | low | info`. The
canonical ID and default severity for every finding are in the
[finding catalog](finding-ids.md).

## Stability

Within a major version, fields will only be **added**, never renamed
or removed. Within a minor version, finding IDs will only be added.
Across major versions, the `_schema_version` field is bumped at the
top level (added in v1.0.0).

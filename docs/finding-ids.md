# cy-tls finding ID catalog

The 38 stable finding IDs cy-tls will emit. These IDs **MUST NOT** be
renamed across cy-tls releases — the platform's `cytls_runner.py`
enrichment table keys off them for control mapping.

## Reachability

| ID | Default severity | Description |
|----|------------------|-------------|
| `TLS-UNREACHABLE` | high | Target did not accept TCP connection within timeout |

## Protocol versions

| ID | Default severity | Description |
|----|------------------|-------------|
| `TLS-SSLV2` | critical | SSLv2 accepted |
| `TLS-SSLV3` | critical | SSLv3 accepted (POODLE) |
| `TLS-WEAK-VERSION-1.0` | high | TLS 1.0 accepted |
| `TLS-WEAK-VERSION-1.1` | high | TLS 1.1 accepted |
| `TLS-NO-TLS13` | info | TLS 1.3 unavailable |

## Cipher suites

| ID | Default severity | Description |
|----|------------------|-------------|
| `TLS-RC4-CIPHER` | critical | RC4 cipher suite accepted |
| `TLS-3DES-CIPHER` | high | 3DES (SWEET32) accepted |
| `TLS-NULL-CIPHER` | critical | NULL cipher accepted |
| `TLS-EXPORT-CIPHER` | critical | EXPORT-grade cipher accepted (FREAK) |
| `TLS-ANON-CIPHER` | critical | Anonymous DH/ECDH cipher accepted |
| `TLS-CBC-MAC-THEN-ENCRYPT` | medium | TLS 1.0 + CBC accepted — BEAST surface |

## Key exchange

| ID | Default severity | Description |
|----|------------------|-------------|
| `TLS-DH-WEAK` | high | DHE params <2048 bits (Logjam) |
| `TLS-DH-COMMON-PRIME` | high | DHE using known common prime |
| `TLS-CURVE-WEAK` | medium | ECDHE curve <256 bits |

## Certificate hygiene

| ID | Default severity | Description |
|----|------------------|-------------|
| `TLS-CERT-EXPIRED` | critical | Certificate expired |
| `TLS-CERT-NEAR-EXPIRY` | medium | Certificate expires within 30 days |
| `TLS-CERT-HOSTNAME-MISMATCH` | high | Subject/SAN does not include target hostname |
| `TLS-CERT-SELF-SIGNED` | critical | Certificate self-signed |
| `TLS-CERT-WEAK-SIGNATURE` | high | Signature algorithm SHA-1 or MD5 |
| `TLS-CERT-WEAK-KEY` | high | RSA key <2048 or ECC <256 bits |
| `TLS-CHAIN-INCOMPLETE` | high | Intermediate certificate missing from chain |

## OCSP / SCT

| ID | Default severity | Description |
|----|------------------|-------------|
| `TLS-OCSP-NOT-STAPLED` | low | OCSP stapling not offered |
| `TLS-OCSP-REVOKED` | critical | OCSP response says certificate revoked |
| `TLS-SCT-MISSING` | medium | No SCT in cert, OCSP, or TLS extension |
| `TLS-MUST-STAPLE-VIOLATED` | high | Cert has must-staple but stapling not offered |

## TLS 1.3 surface

| ID | Default severity | Description |
|----|------------------|-------------|
| `TLS-ZERO-RTT-ACCEPTED` | medium | TLS 1.3 0-RTT early-data accepted on state-changing endpoint |

## Renegotiation / compression / heartbeat

| ID | Default severity | Description |
|----|------------------|-------------|
| `TLS-CLIENT-RENEG-ALLOWED` | high | Insecure client-initiated renegotiation accepted |
| `TLS-COMPRESSION-ENABLED` | high | TLS-level compression enabled (CRIME) |
| `TLS-HEARTBEAT-ENABLED` | medium | Heartbeat extension offered (Heartbleed surface) |

## Padding oracle / cross-protocol — eligibility AND active probes

| ID | Default severity | Description |
|----|------------------|-------------|
| `TLS-ROBOT-VULNERABLE` | critical | RSA padding oracle (ROBOT) — eligibility detected via RSA cipher acceptance |
| `TLS-DROWN-VULNERABLE` | critical | SSLv2 enabled on the same host — DROWN attack surface |
| `TLS-HEARTBLEED` | critical | Heartbleed (CVE-2014-0160) — server leaks memory via heartbeat over-read (**active probe**) |

## HSTS

| ID | Default severity | Description |
|----|------------------|-------------|
| `HSTS-MISSING` | medium | Strict-Transport-Security header not sent |
| `HSTS-SHORT-MAX-AGE` | low | HSTS max-age <6 months |
| `HSTS-NO-SUBDOMAINS` | low | HSTS missing includeSubDomains |
| `HSTS-NOT-PRELOADED` | info | HSTS-preload-eligible site not on Chromium preload list |

## Deprecated trust hardening

| ID | Default severity | Description |
|----|------------------|-------------|
| `EXPECT-CT-MISSING` | info | Expect-CT header absent (deprecated) |

---

**Total: 38 finding IDs in v0.2.18.** TLS-HEARTBLEED was added in v0.2.14
for the active over-read probe.

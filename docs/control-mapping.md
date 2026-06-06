# cy-tls control mapping

Each finding ID maps to a curated set of compliance and framework
controls. The mapping lives in `src/controls.rs` so the SARIF and JSON
output are self-describing — downstream consumers (auditors, reports,
the platform's `cytls_runner.py` enrichment) don't need to bring their
own table.

## Surfaces and frameworks

| Surface | Controls |
|---------|----------|
| TLS version | NIST 800-53 SC-8 / SC-13 / SC-23 · PCI DSS 4.2.1 · ISO 27001 A.8.24 · CIS Benchmark §3.1 |
| Cipher / key exchange | NIST 800-53 SC-13 · PCI DSS 4.2.1 · ISO 27001 A.8.24 |
| Certificate hygiene | NIST 800-53 SC-12 / SC-17 · PCI DSS 4.2.1.1 · ISO 27001 A.10.1.2 |
| OCSP / SCT | NIST 800-53 SC-17 · CA/B Forum Baseline Requirements §4.9 |
| TLS 1.3 0-RTT | NIST SP 800-52 Rev. 2 §3.3.4 · OWASP ASVS 9.2.4 |
| Cross-protocol | NIST 800-53 SC-13 · PCI DSS 4.2.1 |
| HSTS | NIST 800-53 SC-8 · OWASP ASVS 9.1 |

Reachability findings (`TLS-UNREACHABLE`), informational signals
(`TLS-NO-TLS13`, `EXPECT-CT-MISSING`) intentionally carry empty
control lists — they describe state, not a control failure.

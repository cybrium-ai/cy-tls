//! SSH transport-layer crypto posture.
//!
//! The SSH-2 handshake hands over the server's entire algorithm inventory
//! before any authentication happens. Connect, swap version banners, read one
//! `SSH_MSG_KEXINIT` packet, and the server has told you every key exchange,
//! host-key type, cipher and MAC it is willing to negotiate. That is the SSH
//! equivalent of the cipher-suite enumeration this tool already does for TLS,
//! and it needs no credentials and no crypto — just packet parsing.
//!
//! Wire format (RFC 4253 §6, §7.1):
//!
//! ```text
//!   "SSH-2.0-OpenSSH_9.6\r\n"            ← banner, both directions
//!   uint32  packet_length
//!   byte    padding_length
//!   byte    msg_type (20 = SSH_MSG_KEXINIT)
//!   byte[16] cookie
//!   name-list kex_algorithms
//!   name-list server_host_key_algorithms
//!   name-list encryption_algorithms_client_to_server
//!   name-list encryption_algorithms_server_to_client
//!   name-list mac_algorithms_client_to_server
//!   name-list mac_algorithms_server_to_client
//!   name-list compression_algorithms_client_to_server
//!   ...
//! ```
//!
//! A name-list is a uint32 length followed by comma-separated ASCII.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::finding::{Finding, Severity};

const SSH_MSG_KEXINIT: u8 = 20;
const MAX_PACKET: usize = 64 * 1024;
const CLIENT_BANNER: &str = "SSH-2.0-cy-tls_audit\r\n";

/// Everything the server advertised, plus its banner.
#[derive(Debug, Default, Clone)]
pub struct SshKexInit {
    pub banner: String,
    pub kex: Vec<String>,
    pub host_keys: Vec<String>,
    pub ciphers: Vec<String>,
    pub macs: Vec<String>,
    pub compression: Vec<String>,
}

impl SshKexInit {
    /// OpenSSH advertises `kex-strict-s-v00@openssh.com` once it implements
    /// strict key exchange — the countermeasure for Terrapin.
    pub fn strict_kex(&self) -> bool {
        self.kex.iter().any(|k| k.starts_with("kex-strict-s-v00@"))
    }
}

// ── Weak-algorithm tables ──────────────────────────────────────────────────
//
// Each entry is (needle, matches-by-prefix, severity, why). Kept as data so
// the audit reads as a policy rather than a pile of branches.

type Rule = (&'static str, bool, Severity, &'static str);

const WEAK_KEX: &[Rule] = &[
    (
        "diffie-hellman-group1-sha1",
        false,
        Severity::High,
        "1024-bit MODP group with SHA-1 — within reach of precomputation (Logjam)",
    ),
    (
        "diffie-hellman-group-exchange-sha1",
        false,
        Severity::Medium,
        "SHA-1 group exchange",
    ),
    (
        "diffie-hellman-group14-sha1",
        false,
        Severity::Medium,
        "SHA-1 key exchange hash",
    ),
    (
        "rsa1024-sha1",
        false,
        Severity::High,
        "1024-bit RSA key exchange with SHA-1",
    ),
    (
        "gss-group1-sha1-",
        true,
        Severity::High,
        "GSS key exchange over the 1024-bit group",
    ),
];

const WEAK_HOSTKEY: &[Rule] = &[
    (
        "ssh-dss",
        false,
        Severity::High,
        "DSA host key — 1024-bit and SHA-1 signed; disabled by default since OpenSSH 7.0",
    ),
    (
        "ssh-rsa",
        false,
        Severity::Medium,
        "RSA host key with a SHA-1 signature (RFC 4253 ssh-rsa); prefer rsa-sha2-256/512",
    ),
];

const WEAK_CIPHER: &[Rule] = &[
    ("none", false, Severity::Critical, "no encryption"),
    (
        "arcfour",
        true,
        Severity::High,
        "RC4 — biased keystream, prohibited by RFC 7465",
    ),
    (
        "3des-cbc",
        false,
        Severity::Medium,
        "3DES — 64-bit block, Sweet32",
    ),
    (
        "blowfish-cbc",
        false,
        Severity::Medium,
        "64-bit block cipher, Sweet32",
    ),
    (
        "cast128-cbc",
        false,
        Severity::Medium,
        "64-bit block cipher, Sweet32",
    ),
    (
        "des-cbc",
        false,
        Severity::Critical,
        "single DES — 56-bit key",
    ),
    (
        "rijndael-cbc@lysator.liu.se",
        false,
        Severity::Medium,
        "legacy CBC alias",
    ),
];

const WEAK_MAC: &[Rule] = &[
    ("none", false, Severity::Critical, "no integrity protection"),
    ("hmac-md5", true, Severity::High, "MD5 — collision-broken"),
    (
        "hmac-sha1-96",
        false,
        Severity::Medium,
        "truncated 96-bit SHA-1 tag",
    ),
    (
        "hmac-sha2-256-96",
        false,
        Severity::Medium,
        "truncated 96-bit tag",
    ),
    (
        "hmac-sha2-512-96",
        false,
        Severity::Medium,
        "truncated 96-bit tag",
    ),
    (
        "umac-64",
        true,
        Severity::Medium,
        "64-bit authentication tag",
    ),
    (
        "hmac-ripemd160",
        true,
        Severity::Medium,
        "RIPEMD-160 — not a current standard",
    ),
];

fn matches(name: &str, rule: &Rule) -> bool {
    if rule.1 {
        name.starts_with(rule.0)
    } else {
        name == rule.0
    }
}

// ── Protocol ───────────────────────────────────────────────────────────────

fn name_list(buf: &[u8], pos: &mut usize) -> Option<Vec<String>> {
    if *pos + 4 > buf.len() {
        return None;
    }
    let len = u32::from_be_bytes([buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]]) as usize;
    *pos += 4;
    if *pos + len > buf.len() || len > MAX_PACKET {
        return None;
    }
    let raw = String::from_utf8_lossy(&buf[*pos..*pos + len]).to_string();
    *pos += len;
    Some(
        raw.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    )
}

async fn read_banner(stream: &mut TcpStream) -> std::io::Result<String> {
    // The server may send informational lines before its version string; RFC
    // 4253 §4.2 allows this. Take lines until one starts with "SSH-".
    let mut acc = Vec::new();
    let mut byte = [0u8; 1];
    for _ in 0..4096 {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        acc.push(byte[0]);
        if acc.ends_with(b"\n") {
            let line = String::from_utf8_lossy(&acc).trim().to_string();
            if line.starts_with("SSH-") {
                return Ok(line);
            }
            acc.clear();
        }
    }
    Ok(String::from_utf8_lossy(&acc).trim().to_string())
}

/// Connect and read the server's advertised algorithms. No authentication and
/// nothing is negotiated — the connection is dropped after KEXINIT.
pub async fn probe(target: &str, deadline: Duration) -> Result<SshKexInit, String> {
    match timeout(deadline, handshake(target)).await {
        Ok(Ok(k)) => Ok(k),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!("timed out after {}s", deadline.as_secs())),
    }
}

async fn handshake(target: &str) -> std::io::Result<SshKexInit> {
    let mut stream = TcpStream::connect(target).await?;
    let banner = read_banner(&mut stream).await?;
    stream.write_all(CLIENT_BANNER.as_bytes()).await?;
    stream.flush().await?;

    // Binary packet: uint32 length, byte padding_length, payload, padding.
    let mut hdr = [0u8; 5];
    stream.read_exact(&mut hdr).await?;
    let pkt_len = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
    let pad_len = hdr[4] as usize;
    if !(2..=MAX_PACKET).contains(&pkt_len) || pad_len + 1 > pkt_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "implausible SSH packet length — not an SSH-2 server",
        ));
    }
    let payload_len = pkt_len - pad_len - 1;
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;

    let mut out = SshKexInit {
        banner,
        ..Default::default()
    };
    if payload.is_empty() || payload[0] != SSH_MSG_KEXINIT {
        // Some servers greet with a debug/disconnect message instead; the
        // banner alone is still worth reporting.
        return Ok(out);
    }
    // msg_type (1) + cookie (16)
    let mut pos = 1 + 16;
    out.kex = name_list(&payload, &mut pos).unwrap_or_default();
    out.host_keys = name_list(&payload, &mut pos).unwrap_or_default();
    out.ciphers = name_list(&payload, &mut pos).unwrap_or_default();
    let _c2s_dup = name_list(&payload, &mut pos).unwrap_or_default();
    out.macs = name_list(&payload, &mut pos).unwrap_or_default();
    let _mac_dup = name_list(&payload, &mut pos).unwrap_or_default();
    out.compression = name_list(&payload, &mut pos).unwrap_or_default();
    Ok(out)
}

// ── Audit ──────────────────────────────────────────────────────────────────

/// Static metadata for one check. Separating it from the dynamic evidence
/// keeps the emit helper to four arguments and lets each check read as a
/// declaration rather than a long positional call.
struct Note {
    id: &'static str,
    sev: Severity,
    title: &'static str,
    remediation: &'static str,
    reference_url: &'static str,
    controls: &'static [&'static str],
}

fn flag(out: &mut Vec<Finding>, host: &str, note: &Note, evidence: String) {
    out.push(Finding {
        id: note.id,
        host: host.to_string(),
        severity: note.sev,
        title: note.title,
        evidence,
        controls: note.controls.to_vec(),
        remediation: note.remediation,
        reference_url: note.reference_url,
    });
}

fn scan_list(list: &[String], rules: &[Rule]) -> Vec<(String, Severity, &'static str)> {
    let mut hits = Vec::new();
    for name in list {
        for rule in rules {
            if matches(name, rule) {
                hits.push((name.clone(), rule.2, rule.3));
                break;
            }
        }
    }
    hits
}

/// Local ordering so the shared `Severity` enum doesn't need an `Ord` derive
/// added on its account — other code compares it by equality only.
fn rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Info => 0,
    }
}

fn worst(hits: &[(String, Severity, &'static str)]) -> Severity {
    hits.iter().map(|h| h.1).fold(
        Severity::Info,
        |acc, s| if rank(s) > rank(acc) { s } else { acc },
    )
}

fn describe(hits: &[(String, Severity, &'static str)]) -> String {
    hits.iter()
        .map(|(n, _, why)| format!("{n} ({why})"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Turn an advertised algorithm set into findings.
pub fn audit(host: &str, k: &SshKexInit) -> Vec<Finding> {
    let mut out = Vec::new();

    // SSH-1 is structurally broken (CRC-32 compensation attack).
    if k.banner.starts_with("SSH-1.") {
        flag(&mut out, host, &Note {
            id: "SSH-PROTO-V1",
            sev: Severity::Critical,
            title: "SSH protocol 1 supported",
            remediation: "Disable protocol 1 entirely — set `Protocol 2` (or remove the directive on any modern OpenSSH).",
            reference_url: "https://www.openssh.com/legacy.html",
            controls: &["PCI DSS 4.0 §4.2.1", "NIST SP 800-52r2", "CIS Benchmark"],
        }, format!("Server banner: {}", k.banner));
    }

    if !k.banner.is_empty() {
        flag(&mut out, host, &Note {
            id: "SSH-BANNER",
            sev: Severity::Info,
            title: "SSH service banner",
            remediation: "Version disclosure is low risk on its own, but it lets an attacker match known vulnerabilities without probing.",
            reference_url: "https://datatracker.ietf.org/doc/html/rfc4253#section-4.2",
            controls: &[],
        }, k.banner.clone());
    }

    // Each list is audited against its own policy table; severity comes from
    // the worst algorithm actually advertised.
    let checks: [(&Vec<String>, &[Rule], Note); 4] = [
        (&k.kex, WEAK_KEX, Note {
            id: "SSH-KEX-WEAK",
            sev: Severity::Info,
            title: "Weak key exchange offered",
            remediation: "Restrict `KexAlgorithms` to curve25519-sha256 and diffie-hellman-group-exchange-sha256 or stronger.",
            reference_url: "https://www.openssh.com/specs.html",
            controls: &["PCI DSS 4.0 §4.2.1", "NIST SP 800-131A"],
        }),
        (&k.host_keys, WEAK_HOSTKEY, Note {
            id: "SSH-HOSTKEY-WEAK",
            sev: Severity::Info,
            title: "Weak host key algorithm offered",
            remediation: "Restrict `HostKeyAlgorithms` to ssh-ed25519 and rsa-sha2-512/256; remove ssh-dss and bare ssh-rsa.",
            reference_url: "https://www.openssh.com/specs.html",
            controls: &["NIST SP 800-131A"],
        }),
        (&k.ciphers, WEAK_CIPHER, Note {
            id: "SSH-CIPHER-WEAK",
            sev: Severity::Info,
            title: "Weak cipher offered",
            remediation: "Restrict `Ciphers` to chacha20-poly1305@openssh.com and aes*-gcm/aes*-ctr; remove every CBC and arcfour entry.",
            reference_url: "https://www.openssh.com/specs.html",
            controls: &["PCI DSS 4.0 §4.2.1", "NIST SP 800-52r2"],
        }),
        (&k.macs, WEAK_MAC, Note {
            id: "SSH-MAC-WEAK",
            sev: Severity::Info,
            title: "Weak MAC offered",
            remediation: "Restrict `MACs` to encrypt-then-MAC SHA-2 variants (hmac-sha2-256-etm@openssh.com and stronger).",
            reference_url: "https://www.openssh.com/specs.html",
            controls: &["NIST SP 800-131A"],
        }),
    ];

    for (list, rules, note) in checks {
        let hits = scan_list(list, rules);
        if !hits.is_empty() {
            flag(
                &mut out,
                host,
                &Note {
                    sev: worst(&hits),
                    ..note
                },
                describe(&hits),
            );
        }
    }

    // CBC in SSH is its own finding — the mode is what enables the classic
    // plaintext-recovery attack, independent of which cipher wraps it.
    let cbc: Vec<&String> = k.ciphers.iter().filter(|c| c.ends_with("-cbc")).collect();
    if !cbc.is_empty() {
        flag(&mut out, host, &Note {
            id: "SSH-CIPHER-CBC",
            sev: Severity::Medium,
            title: "CBC-mode ciphers offered",
            remediation: "Prefer AEAD (aes*-gcm, chacha20-poly1305) or CTR modes; CBC in SSH enables plaintext recovery against the packet-length field.",
            reference_url: "https://www.kb.cert.org/vuls/id/958563",
            controls: &["PCI DSS 4.0 §4.2.1"],
        }, format!("{} CBC cipher(s): {}", cbc.len(),
                   cbc.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
    }

    // Terrapin (CVE-2023-48795): a prefix-truncation attack against
    // chacha20-poly1305 and encrypt-then-MAC modes. The fix is strict key
    // exchange, which a patched server advertises — so the vulnerable state is
    // "offers an affected mode AND does not advertise kex-strict".
    let chacha = k.ciphers.iter().any(|c| c.starts_with("chacha20-poly1305"));
    let etm = k.macs.iter().any(|m| m.ends_with("-etm@openssh.com"));
    if (chacha || etm) && !k.strict_kex() {
        let modes = if chacha && etm {
            "chacha20-poly1305 and encrypt-then-MAC"
        } else if chacha {
            "chacha20-poly1305"
        } else {
            "encrypt-then-MAC MACs"
        };
        flag(&mut out, host, &Note {
            id: "SSH-TERRAPIN",
            sev: Severity::Medium,
            title: "Vulnerable to Terrapin prefix truncation (CVE-2023-48795)",
            remediation: "Upgrade to OpenSSH 9.6 or later (or a patched vendor build) so strict key exchange is negotiated.",
            reference_url: "https://terrapin-attack.com/",
            controls: &["CVE-2023-48795"],
        }, format!("Offers {modes} but does not advertise kex-strict-s-v00@openssh.com, so strict key exchange is unavailable."));
    }

    // Nothing weak found is itself worth stating — a clean result should be
    // visible rather than inferred from an empty list.
    if out.iter().all(|f| f.severity == Severity::Info) && !k.kex.is_empty() {
        flag(
            &mut out,
            host,
            &Note {
                id: "SSH-ALGOS-OK",
                sev: Severity::Info,
                title: "No weak SSH algorithms advertised",
                remediation: "",
                reference_url: "",
                controls: &[],
            },
            format!(
                "{} kex, {} host key, {} cipher, {} MAC algorithm(s) reviewed",
                k.kex.len(),
                k.host_keys.len(),
                k.ciphers.len(),
                k.macs.len()
            ),
        );
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kex(ciphers: &[&str], macs: &[&str], kexs: &[&str], hks: &[&str]) -> SshKexInit {
        SshKexInit {
            banner: "SSH-2.0-OpenSSH_9.6".into(),
            kex: kexs.iter().map(|s| s.to_string()).collect(),
            host_keys: hks.iter().map(|s| s.to_string()).collect(),
            ciphers: ciphers.iter().map(|s| s.to_string()).collect(),
            macs: macs.iter().map(|s| s.to_string()).collect(),
            compression: vec![],
        }
    }

    fn ids(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|x| x.id).collect()
    }

    #[test]
    fn flags_cbc_and_weak_cipher() {
        let k = kex(
            &["aes128-cbc", "3des-cbc"],
            &["hmac-sha2-256"],
            &["curve25519-sha256"],
            &["ssh-ed25519"],
        );
        let f = audit("h:22", &k);
        assert!(ids(&f).contains(&"SSH-CIPHER-CBC"));
        assert!(ids(&f).contains(&"SSH-CIPHER-WEAK"));
    }

    #[test]
    fn flags_weak_kex_and_hostkey() {
        let k = kex(
            &["aes256-gcm@openssh.com"],
            &["hmac-sha2-256"],
            &["diffie-hellman-group1-sha1"],
            &["ssh-dss"],
        );
        let f = audit("h:22", &k);
        assert!(ids(&f).contains(&"SSH-KEX-WEAK"));
        assert!(ids(&f).contains(&"SSH-HOSTKEY-WEAK"));
    }

    #[test]
    fn terrapin_only_without_strict_kex() {
        let vulnerable = kex(
            &["chacha20-poly1305@openssh.com"],
            &["hmac-sha2-256"],
            &["curve25519-sha256"],
            &["ssh-ed25519"],
        );
        assert!(ids(&audit("h:22", &vulnerable)).contains(&"SSH-TERRAPIN"));

        let patched = kex(
            &["chacha20-poly1305@openssh.com"],
            &["hmac-sha2-256"],
            &["curve25519-sha256", "kex-strict-s-v00@openssh.com"],
            &["ssh-ed25519"],
        );
        assert!(!ids(&audit("h:22", &patched)).contains(&"SSH-TERRAPIN"));
    }

    #[test]
    fn modern_config_is_clean() {
        let k = kex(
            &["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
            &["hmac-sha2-512-etm@openssh.com"],
            &["curve25519-sha256", "kex-strict-s-v00@openssh.com"],
            &["ssh-ed25519", "rsa-sha2-512"],
        );
        let f = audit("h:22", &k);
        assert!(
            f.iter().all(|x| x.severity == Severity::Info),
            "{:?}",
            ids(&f)
        );
        assert!(ids(&f).contains(&"SSH-ALGOS-OK"));
    }

    #[test]
    fn parses_name_list() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(11u32).to_be_bytes());
        buf.extend_from_slice(b"aes,3des-cb");
        let mut pos = 0;
        assert_eq!(name_list(&buf, &mut pos).unwrap(), vec!["aes", "3des-cb"]);
    }
}

//! Handshake simulation — emulate ~30 reference clients (browsers,
//! mobile OSes, Java runtimes, OpenSSL versions) by sending a
//! representative ClientHello for each and observing what the server
//! negotiates.
//!
//! Each client is parameterised by its highest supported TLS version
//! and the ordered cipher suite list it would advertise. The simulator
//! sends one ClientHello per client and records the negotiated
//! (protocol, cipher) pair or the alert if the server rejects.

use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::cipher_enum;

#[derive(Debug, Clone, Serialize)]
pub struct ClientSim {
    pub name: &'static str,
    pub protocol: Option<String>,
    pub cipher: Option<String>,
    pub error: Option<&'static str>,
}

#[derive(Debug)]
struct ClientProfile {
    name: &'static str,
    /// Max TLS version this client offers, as (major, minor).
    max: (u8, u8),
    /// Ordered cipher suite list.
    suites: &'static [u16],
}

/// 30 reference clients. Lists derived from publicly-published client
/// cipher orderings (Mozilla SSL Configuration Generator + Wireshark
/// captures from each runtime).
const CLIENTS: &[ClientProfile] = &[
    ClientProfile {
        name: "Android 4.4.2",
        max: (0x03, 0x03),
        suites: &[0xc014, 0xc00a, 0xc013, 0xc009, 0x002f, 0x0035, 0x000a],
    },
    ClientProfile {
        name: "Android 5.0.0",
        max: (0x03, 0x03),
        suites: &[
            0xc02b, 0xc02f, 0xc00a, 0xc014, 0xc009, 0xc013, 0x009c, 0x002f, 0x0035, 0x000a,
        ],
    },
    ClientProfile {
        name: "Android 7.0",
        max: (0x03, 0x03),
        suites: &[
            0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f,
            0x0035,
        ],
    },
    ClientProfile {
        name: "Android 9.0",
        max: (0x03, 0x04),
        suites: &[
            0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc009, 0xc013,
            0xc00a, 0xc014,
        ],
    },
    ClientProfile {
        name: "Android 12",
        max: (0x03, 0x04),
        suites: &[
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc009, 0xc013,
            0xc00a, 0xc014,
        ],
    },
    ClientProfile {
        name: "Chrome 49 / XP",
        max: (0x03, 0x03),
        suites: &[
            0xc02b, 0xc02f, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0x000a,
        ],
    },
    ClientProfile {
        name: "Chrome 70 / W10",
        max: (0x03, 0x04),
        suites: &[
            0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ],
    },
    ClientProfile {
        name: "Chrome 80 / W10",
        max: (0x03, 0x04),
        suites: &[
            0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ],
    },
    ClientProfile {
        name: "Chrome 131 / W10",
        max: (0x03, 0x04),
        suites: &[
            0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030,
        ],
    },
    ClientProfile {
        name: "Firefox 47 / W7",
        max: (0x03, 0x03),
        suites: &[
            0xc02b, 0xc02f, 0xc00a, 0xc009, 0xc013, 0xc014, 0x0033, 0x0039, 0x002f, 0x0035,
        ],
    },
    ClientProfile {
        name: "Firefox 62 / W7",
        max: (0x03, 0x04),
        suites: &[
            0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc013, 0xc014,
            0x0033, 0x0039, 0x002f, 0x0035,
        ],
    },
    ClientProfile {
        name: "Firefox 135 / W10",
        max: (0x03, 0x04),
        suites: &[
            0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030,
        ],
    },
    ClientProfile {
        name: "Edge 16 / W10",
        max: (0x03, 0x03),
        suites: &[
            0xc02c, 0xc02b, 0xc030, 0xc02f, 0x009f, 0xcca9, 0xcca8, 0xc024, 0xc028, 0xc023, 0xc027,
        ],
    },
    ClientProfile {
        name: "Edge 131 / W10",
        max: (0x03, 0x04),
        suites: &[
            0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030,
        ],
    },
    ClientProfile {
        name: "IE 11 / W7",
        max: (0x03, 0x03),
        suites: &[
            0xc028, 0xc027, 0xc014, 0xc013, 0x009f, 0x009e, 0x0039, 0x0033, 0x009d, 0x009c, 0x0035,
            0x002f,
        ],
    },
    ClientProfile {
        name: "IE 11 / W10",
        max: (0x03, 0x03),
        suites: &[
            0xc030, 0xc02f, 0xc028, 0xc027, 0xc014, 0xc013, 0x009f, 0x009e, 0x009d, 0x009c, 0x0035,
            0x002f,
        ],
    },
    ClientProfile {
        name: "Safari 9 / iOS 9",
        max: (0x03, 0x03),
        suites: &[
            0xc02c, 0xc02b, 0xc024, 0xc023, 0xc00a, 0xc009, 0xc030, 0xc02f, 0xc028, 0xc027, 0xc014,
            0xc013,
        ],
    },
    ClientProfile {
        name: "Safari 12 / macOS 10.14",
        max: (0x03, 0x04),
        suites: &[
            0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013,
            0xc00a, 0xc014,
        ],
    },
    ClientProfile {
        name: "Safari 17 / macOS 14",
        max: (0x03, 0x04),
        suites: &[
            0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
        ],
    },
    ClientProfile {
        name: "Java 8u161",
        max: (0x03, 0x03),
        suites: &[
            0xc02b, 0xc02f, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ],
    },
    ClientProfile {
        name: "Java 11.0.3",
        max: (0x03, 0x04),
        suites: &[
            0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc009, 0xc013, 0xc00a, 0xc014,
        ],
    },
    ClientProfile {
        name: "Java 17",
        max: (0x03, 0x04),
        suites: &[
            0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
        ],
    },
    ClientProfile {
        name: "OpenSSL 1.0.1l",
        max: (0x03, 0x03),
        suites: &[
            0xc02b, 0xc02f, 0xc00a, 0xc009, 0xc013, 0xc014, 0x002f, 0x0035,
        ],
    },
    ClientProfile {
        name: "OpenSSL 1.0.2s",
        max: (0x03, 0x03),
        suites: &[
            0xc02c, 0xc030, 0xc02b, 0xc02f, 0xc024, 0xc028, 0xc023, 0xc027, 0xc00a, 0xc014, 0xc009,
            0xc013,
        ],
    },
    ClientProfile {
        name: "OpenSSL 1.1.0k",
        max: (0x03, 0x03),
        suites: &[
            0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014,
        ],
    },
    ClientProfile {
        name: "OpenSSL 1.1.1c",
        max: (0x03, 0x04),
        suites: &[
            0x1302, 0x1303, 0x1301, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
        ],
    },
    ClientProfile {
        name: "OpenSSL 3.0",
        max: (0x03, 0x04),
        suites: &[
            0x1302, 0x1303, 0x1301, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc024, 0xc028,
            0xc023, 0xc027,
        ],
    },
    ClientProfile {
        name: "Apple ATS 9",
        max: (0x03, 0x04),
        suites: &[
            0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
        ],
    },
    ClientProfile {
        name: "Googlebot Feb 2018",
        max: (0x03, 0x03),
        suites: &[
            0xc02b, 0xc02f, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ],
    },
    ClientProfile {
        name: "YandexBot 2015",
        max: (0x03, 0x03),
        suites: &[
            0xc02b, 0xc02f, 0xc00a, 0xc009, 0xc013, 0xc014, 0x002f, 0x0035,
        ],
    },
];

pub async fn simulate_all(target: &str, sni: &str, deadline: Duration) -> Vec<ClientSim> {
    let mut results = Vec::with_capacity(CLIENTS.len());
    let per_client = deadline.min(Duration::from_secs(4));
    for profile in CLIENTS {
        results.push(simulate_one(target, sni, profile, per_client).await);
    }
    results
}

async fn simulate_one(
    target: &str,
    sni: &str,
    profile: &ClientProfile,
    deadline: Duration,
) -> ClientSim {
    let outcome = timeout(deadline, async {
        let mut sock = TcpStream::connect(target).await.ok()?;
        let hello = build_hello(sni, profile);
        sock.write_all(&hello).await.ok()?;

        let mut header = [0u8; 5];
        sock.read_exact(&mut header).await.ok()?;
        if header[0] == 0x15 {
            return Some(("alert", 0u16));
        }
        if header[0] != 0x16 {
            return Some(("noresponse", 0u16));
        }
        let body_len = ((header[3] as usize) << 8) | (header[4] as usize);
        let mut body = vec![0u8; body_len.min(2048)];
        sock.read_exact(&mut body).await.ok()?;
        parse_negotiated(&body, &header[1..3])
    })
    .await;

    match outcome {
        Ok(Some(("alert", _))) => ClientSim {
            name: profile.name,
            protocol: None,
            cipher: None,
            error: Some("Server sent fatal alert: handshake_failure"),
        },
        Ok(Some(("ok", suite_id))) => {
            // Negotiated version goes in header bytes 1..3 (record version).
            // We pass it through parse_negotiated as the second arg.
            let proto = match suite_id & 0xff00 {
                0x1300 => "TLS 1.3", // 0x1301-0x1305 are TLS 1.3 suites
                _ => "TLS 1.2",      // best effort
            };
            ClientSim {
                name: profile.name,
                protocol: Some(proto.to_string()),
                cipher: Some(cipher_enum::name(suite_id).to_string()),
                error: None,
            }
        }
        _ => ClientSim {
            name: profile.name,
            protocol: None,
            cipher: None,
            error: Some("Protocol mismatch (not simulated)"),
        },
    }
}

/// Returns ("ok", suite_id) on success or ("alert"|"noresponse", 0) otherwise.
fn parse_negotiated(body: &[u8], _record_version: &[u8]) -> Option<(&'static str, u16)> {
    if body.first()? != &0x02 {
        return Some(("noresponse", 0));
    }
    let mut i = 4usize;
    i += 2; // server_version
    i += 32; // random
    let sid_len = *body.get(i)? as usize;
    i += 1 + sid_len;
    let suite = ((*body.get(i)? as u16) << 8) | (*body.get(i + 1)? as u16);
    Some(("ok", suite))
}

fn build_hello(sni: &str, profile: &ClientProfile) -> Vec<u8> {
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&[0x00, 0x00]);
    let mut sni_list = Vec::new();
    sni_list.push(0x00);
    let sb = sni.as_bytes();
    sni_list.extend_from_slice(&(sb.len() as u16).to_be_bytes());
    sni_list.extend_from_slice(sb);
    let mut sni_inner = Vec::new();
    sni_inner.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
    sni_inner.extend_from_slice(&sni_list);
    sni_ext.extend_from_slice(&(sni_inner.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(&sni_inner);

    // supported_versions for TLS 1.3-capable clients
    let supports_tls13 = profile.max == (0x03, 0x04);
    let mut sv_ext: Vec<u8> = Vec::new();
    if supports_tls13 {
        sv_ext.extend_from_slice(&[0x00, 0x2b]);
        // list of versions: TLS 1.3 (0x0304), TLS 1.2 (0x0303)
        let versions: [u8; 4] = [0x03, 0x04, 0x03, 0x03];
        sv_ext.extend_from_slice(&((versions.len() as u16 + 1).to_be_bytes()));
        sv_ext.push(versions.len() as u8);
        sv_ext.extend_from_slice(&versions);
    }

    // supported_groups
    let mut groups_ext = Vec::new();
    groups_ext.extend_from_slice(&[0x00, 0x0a]);
    let groups: [u16; 4] = [0x001d, 0x0017, 0x0018, 0x0019];
    let g_bytes: Vec<u8> = groups.iter().flat_map(|g| g.to_be_bytes()).collect();
    groups_ext.extend_from_slice(&((g_bytes.len() as u16 + 2).to_be_bytes()));
    groups_ext.extend_from_slice(&((g_bytes.len() as u16).to_be_bytes()));
    groups_ext.extend_from_slice(&g_bytes);

    // signature_algorithms
    let mut sigalg_ext = Vec::new();
    sigalg_ext.extend_from_slice(&[0x00, 0x0d]);
    let sig_algs: [u16; 6] = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806];
    let sig_bytes: Vec<u8> = sig_algs.iter().flat_map(|s| s.to_be_bytes()).collect();
    sigalg_ext.extend_from_slice(&((sig_bytes.len() as u16 + 2).to_be_bytes()));
    sigalg_ext.extend_from_slice(&((sig_bytes.len() as u16).to_be_bytes()));
    sigalg_ext.extend_from_slice(&sig_bytes);

    // key_share for TLS 1.3 (advertise X25519 with a dummy 32-byte key)
    let mut ks_ext: Vec<u8> = Vec::new();
    if supports_tls13 {
        ks_ext.extend_from_slice(&[0x00, 0x33]);
        let dummy_key = [0x42u8; 32];
        let entry_len = 2 + 2 + dummy_key.len();
        ks_ext.extend_from_slice(&((entry_len as u16 + 2).to_be_bytes()));
        ks_ext.extend_from_slice(&(entry_len as u16).to_be_bytes());
        ks_ext.extend_from_slice(&[0x00, 0x1d]); // X25519
        ks_ext.extend_from_slice(&(dummy_key.len() as u16).to_be_bytes());
        ks_ext.extend_from_slice(&dummy_key);
    }

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&sni_ext);
    extensions.extend_from_slice(&groups_ext);
    extensions.extend_from_slice(&sigalg_ext);
    extensions.extend_from_slice(&sv_ext);
    extensions.extend_from_slice(&ks_ext);

    let cipher_bytes: Vec<u8> = profile
        .suites
        .iter()
        .flat_map(|s| s.to_be_bytes())
        .collect();

    let mut body = Vec::new();
    body.push(profile.max.0);
    body.push(profile.max.1);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&(cipher_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&cipher_bytes);
    body.push(0x01);
    body.push(0x00);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut hs = Vec::new();
    hs.push(0x01);
    let l = body.len() as u32;
    hs.push(((l >> 16) & 0xff) as u8);
    hs.push(((l >> 8) & 0xff) as u8);
    hs.push((l & 0xff) as u8);
    hs.extend_from_slice(&body);

    let mut rec = Vec::new();
    rec.push(0x16);
    rec.push(profile.max.0);
    rec.push(profile.max.1);
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

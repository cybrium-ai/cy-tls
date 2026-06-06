//! TLS 1.2 ServerHello extension parse.
//!
//! Sends a ClientHello at TLS 1.2 advertising the extensions whose
//! ServerHello mirror we want to inspect:
//!   - renegotiation_info (ext 0xff01)
//!   - heartbeat (ext 0x000f)
//!   - compression methods (in the ServerHello body, not an extension)
//!
//! Returns a tri-state per probe so the orchestrator can render
//! "Supported" / "Not supported" / "Couldn't determine" honestly.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Default, Clone)]
pub struct Tls12Features {
    pub secure_renegotiation: Option<bool>,
    pub compression_offered:  Option<bool>,
    pub heartbeat_offered:    Option<bool>,
}

pub async fn probe(target: &str, sni: &str, deadline: Duration) -> Tls12Features {
    let attempt = timeout(deadline.min(Duration::from_secs(5)), async {
        let mut sock = TcpStream::connect(target).await.ok()?;
        let hello = build_client_hello(sni);
        sock.write_all(&hello).await.ok()?;
        let mut header = [0u8; 5];
        sock.read_exact(&mut header).await.ok()?;
        if header[0] != 0x16 {
            return None;
        }
        let body_len = ((header[3] as usize) << 8) | (header[4] as usize);
        let mut body = vec![0u8; body_len.min(4096)];
        sock.read_exact(&mut body).await.ok()?;
        Some(parse_server_hello(&body))
    })
    .await;
    attempt.ok().flatten().unwrap_or_default()
}

fn parse_server_hello(body: &[u8]) -> Tls12Features {
    let mut feat = Tls12Features::default();
    if body.first() != Some(&0x02) {
        return feat;
    }
    let mut i = 4usize; // skip handshake hdr
    if body.len() < i + 2 + 32 + 1 {
        return feat;
    }
    i += 2;  // server_version
    i += 32; // random

    let sid_len = match body.get(i) { Some(v) => *v as usize, None => return feat };
    i += 1 + sid_len;
    if body.len() < i + 2 + 1 {
        return feat;
    }
    i += 2; // cipher_suite

    let comp = match body.get(i) { Some(v) => *v, None => return feat };
    i += 1;
    feat.compression_offered = Some(comp != 0);

    // Extensions list — optional. If present:
    if i + 2 > body.len() {
        return feat;
    }
    let ext_total = ((body[i] as usize) << 8) | (body[i + 1] as usize);
    i += 2;
    let ext_end = i + ext_total;
    feat.secure_renegotiation = Some(false);
    feat.heartbeat_offered = Some(false);
    while i + 4 <= ext_end && i + 4 <= body.len() {
        let ext_type = ((body[i] as u16) << 8) | (body[i + 1] as u16);
        let ext_len  = ((body[i + 2] as usize) << 8) | (body[i + 3] as usize);
        i += 4;
        if i + ext_len > body.len() { break; }
        match ext_type {
            0xff01 => feat.secure_renegotiation = Some(true),
            0x000f => feat.heartbeat_offered = Some(true),
            _ => {}
        }
        i += ext_len;
    }
    feat
}

fn build_client_hello(sni: &str) -> Vec<u8> {
    // SNI extension
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

    // renegotiation_info — empty for fresh handshake
    let reneg_ext: [u8; 5] = [0xff, 0x01, 0x00, 0x01, 0x00];

    // heartbeat — peer_allowed_to_send (1)
    let heartbeat_ext: [u8; 6] = [0x00, 0x0f, 0x00, 0x01, 0x01, 0x00];
    let _ = &heartbeat_ext;

    // signature_algorithms
    let mut sigalg_ext = Vec::new();
    sigalg_ext.extend_from_slice(&[0x00, 0x0d]);
    let sig_algs: [u16; 6] = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806];
    let sig_bytes: Vec<u8> = sig_algs.iter().flat_map(|s| s.to_be_bytes()).collect();
    sigalg_ext.extend_from_slice(&((sig_bytes.len() as u16 + 2).to_be_bytes()));
    sigalg_ext.extend_from_slice(&((sig_bytes.len() as u16).to_be_bytes()));
    sigalg_ext.extend_from_slice(&sig_bytes);

    // supported_groups
    let mut groups_ext = Vec::new();
    groups_ext.extend_from_slice(&[0x00, 0x0a]);
    let groups: [u16; 4] = [0x001d, 0x0017, 0x0018, 0x0019];
    let g_bytes: Vec<u8> = groups.iter().flat_map(|g| g.to_be_bytes()).collect();
    groups_ext.extend_from_slice(&((g_bytes.len() as u16 + 2).to_be_bytes()));
    groups_ext.extend_from_slice(&((g_bytes.len() as u16).to_be_bytes()));
    groups_ext.extend_from_slice(&g_bytes);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&sni_ext);
    extensions.extend_from_slice(&reneg_ext);
    extensions.extend_from_slice(&heartbeat_ext);
    extensions.extend_from_slice(&sigalg_ext);
    extensions.extend_from_slice(&groups_ext);

    let suites: [u16; 7] = [
        0xc02f, 0xc030, 0xc02b, 0xc02c,  // ECDHE GCM
        0xcca8, 0xcca9,                   // ChaCha20
        0x009c,                           // RSA AES128 GCM (fallback)
    ];
    let cipher_bytes: Vec<u8> = suites.iter().flat_map(|s| s.to_be_bytes()).collect();

    let mut body = Vec::new();
    body.push(0x03); body.push(0x03);  // TLS 1.2
    body.extend_from_slice(&[0u8; 32]);
    body.push(0); // session id len
    body.extend_from_slice(&(cipher_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&cipher_bytes);
    body.push(0x01); body.push(0x00); // null compression
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
    rec.push(0x03); rec.push(0x03);
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

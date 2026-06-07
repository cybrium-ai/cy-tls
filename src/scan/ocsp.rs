//! OCSP stapling probe.
//!
//! Send a raw TLS 1.2 ClientHello that includes the `status_request`
//! extension (type 0x05). Watch the wire for a `CertificateStatus`
//! handshake message (type 0x16). When present, the body is the
//! OCSP DER which we minimally walk for cert-status tags.
//!
//! Why raw bytes instead of rustls: rustls 0.23's high-level
//! `verify_server_cert` callback only receives stapled OCSP when the
//! default ClientConfig path advertises status_request, and that
//! interacts poorly with the `with_custom_certificate_verifier` mode
//! we'd need to intercept it. Sending the ClientHello ourselves
//! sidesteps the whole API question.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct OcspProbe {
    pub stapled: bool,
    pub status: Option<String>,
    /// Stapled OCSP payload length in bytes. Recorded for future
    /// "OCSP response size out-of-band" findings; not yet consumed.
    #[allow(dead_code)]
    pub size: usize,
}

pub async fn probe(target: &str, sni: &str, deadline: Duration) -> OcspProbe {
    let result = timeout(deadline.min(Duration::from_secs(8)), async {
        let mut sock = TcpStream::connect(target).await.ok()?;
        let hello = build_client_hello(sni);
        sock.write_all(&hello).await.ok()?;

        // Accumulate the full handshake stream across however many
        // records the server fragments it into. Handshake messages
        // can span record boundaries — Certificate is often 8 KB+
        // and CertificateStatus rides in its own record afterwards.
        let mut handshake_bytes: Vec<u8> = Vec::with_capacity(32 * 1024);
        for _ in 0..32 {
            let mut header = [0u8; 5];
            if sock.read_exact(&mut header).await.is_err() {
                break;
            }
            if header[0] != 0x16 {
                break; // Alert or app data — stop reading.
            }
            let len = ((header[3] as usize) << 8) | (header[4] as usize);
            if len == 0 || len > 18 * 1024 {
                break;
            }
            let mut body = vec![0u8; len];
            if sock.read_exact(&mut body).await.is_err() {
                break;
            }
            handshake_bytes.extend_from_slice(&body);
            // Try to find CertificateStatus + check whether
            // ServerHelloDone has arrived (no more cert status coming).
            if let Some(ocsp_bytes) = scan_for_certificate_status(&handshake_bytes) {
                return Some(ocsp_bytes);
            }
            if has_handshake_type(&handshake_bytes, 0x0e) {
                break;
            }
        }
        None
    })
    .await;

    let bytes: Vec<u8> = result.ok().flatten().unwrap_or_default();
    if bytes.is_empty() {
        return OcspProbe {
            stapled: false,
            status: None,
            size: 0,
        };
    }
    OcspProbe {
        size: bytes.len(),
        status: parse_status(&bytes),
        stapled: true,
    }
}

/// Walk a TLS record body looking for a CertificateStatus handshake
/// message (handshake type 0x16). Returns the embedded OCSP response
/// DER if found.
fn scan_for_certificate_status(body: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0;
    while i + 4 <= body.len() {
        let msg_type = body[i];
        let msg_len =
            ((body[i + 1] as usize) << 16) | ((body[i + 2] as usize) << 8) | (body[i + 3] as usize);
        i += 4;
        if i + msg_len > body.len() {
            return None;
        }
        if msg_type == 0x16 {
            // CertificateStatus body:
            //   status_type (1 byte; 0x01 = OCSP)
            //   OCSPResponse:
            //     length (3 bytes)
            //     bytes
            if body.get(i) == Some(&0x01) {
                let resp_len = ((body[i + 1] as usize) << 16)
                    | ((body[i + 2] as usize) << 8)
                    | (body[i + 3] as usize);
                let start = i + 4;
                let end = start + resp_len;
                if end <= body.len() {
                    return Some(body[start..end].to_vec());
                }
            }
        }
        i += msg_len;
    }
    None
}

fn has_handshake_type(body: &[u8], typ: u8) -> bool {
    let mut i = 0;
    while i + 4 <= body.len() {
        let msg_len =
            ((body[i + 1] as usize) << 16) | ((body[i + 2] as usize) << 8) | (body[i + 3] as usize);
        if body[i] == typ {
            return true;
        }
        i += 4 + msg_len;
    }
    false
}

fn build_client_hello(sni: &str) -> Vec<u8> {
    // SNI
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

    // status_request extension (type 0x05) — RFC 6066 §8
    //   CertificateStatusRequest:
    //     status_type = 0x01 (OCSP)
    //     OCSPStatusRequest:
    //       responder_id_list = empty
    //       request_extensions = empty
    let status_req_inner: [u8; 5] = [0x01, 0x00, 0x00, 0x00, 0x00];
    let mut status_req_ext = Vec::new();
    status_req_ext.extend_from_slice(&[0x00, 0x05]); // ext type
    status_req_ext.extend_from_slice(&(status_req_inner.len() as u16).to_be_bytes());
    status_req_ext.extend_from_slice(&status_req_inner);

    // supported_groups + signature_algorithms (so most servers cooperate)
    let mut groups_ext = Vec::new();
    groups_ext.extend_from_slice(&[0x00, 0x0a]);
    let groups: [u16; 4] = [0x001d, 0x0017, 0x0018, 0x0019];
    let g_bytes: Vec<u8> = groups.iter().flat_map(|g| g.to_be_bytes()).collect();
    groups_ext.extend_from_slice(&((g_bytes.len() as u16 + 2).to_be_bytes()));
    groups_ext.extend_from_slice(&((g_bytes.len() as u16).to_be_bytes()));
    groups_ext.extend_from_slice(&g_bytes);

    let mut sigalg_ext = Vec::new();
    sigalg_ext.extend_from_slice(&[0x00, 0x0d]);
    let sig_algs: [u16; 6] = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806];
    let sig_bytes: Vec<u8> = sig_algs.iter().flat_map(|s| s.to_be_bytes()).collect();
    sigalg_ext.extend_from_slice(&((sig_bytes.len() as u16 + 2).to_be_bytes()));
    sigalg_ext.extend_from_slice(&((sig_bytes.len() as u16).to_be_bytes()));
    sigalg_ext.extend_from_slice(&sig_bytes);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&sni_ext);
    extensions.extend_from_slice(&status_req_ext);
    extensions.extend_from_slice(&groups_ext);
    extensions.extend_from_slice(&sigalg_ext);

    let suites: [u16; 7] = [0xc02f, 0xc030, 0xc02b, 0xc02c, 0xcca8, 0xcca9, 0x009c];
    let cipher_bytes: Vec<u8> = suites.iter().flat_map(|s| s.to_be_bytes()).collect();

    let mut body = Vec::new();
    body.push(0x03);
    body.push(0x03);
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
    rec.push(0x03);
    rec.push(0x03);
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// Strict OCSP cert-status parse — v0.3.x rewrite that walks the
/// actual ASN.1 structure rather than searching for OID patterns.
///
/// OCSPResponse ::= SEQUENCE {
///     responseStatus       OCSPResponseStatus,
///     responseBytes    [0] EXPLICIT ResponseBytes OPTIONAL
/// }
///
/// We:
/// 1. Enter the outer SEQUENCE
/// 2. Read responseStatus ENUMERATED (must be 0 = successful)
/// 3. Enter [0] EXPLICIT ResponseBytes → SEQUENCE
/// 4. Skip responseType OID
/// 5. Enter response OCTET STRING containing BasicOCSPResponse
/// 6. Enter BasicOCSPResponse SEQUENCE → tbsResponseData SEQUENCE
/// 7. Skip optional version [0], skip responderID CHOICE, skip
///    producedAt GeneralizedTime
/// 8. Enter responses SEQUENCE OF
/// 9. Enter first SingleResponse SEQUENCE
/// 10. Skip certID SEQUENCE
/// 11. Read certStatus tag — that's our answer
fn parse_status(der: &[u8]) -> Option<String> {
    let mut p = Parser::new(der);
    p.enter_seq()?; // OCSPResponse
    let status = p.read_enumerated()?; // responseStatus
    if status != 0 {
        return None;
    }
    p.enter_context_explicit(0)?; // [0] EXPLICIT
    p.enter_seq()?; // ResponseBytes
    p.skip_one()?; // OBJECT IDENTIFIER responseType
    let response_bytes = p.read_octet_string()?;

    let mut inner = Parser::new(response_bytes);
    inner.enter_seq()?; // BasicOCSPResponse
    inner.enter_seq()?; // tbsResponseData
                        // version [0] EXPLICIT — optional, may or may not be present.
    inner.skip_optional_context(0);
    inner.skip_one()?; // responderID CHOICE
    inner.skip_one()?; // producedAt
    inner.enter_seq()?; // responses SEQUENCE OF
    inner.enter_seq()?; // SingleResponse
    inner.skip_one()?; // certID SEQUENCE

    // certStatus tag is now at the cursor.
    let (tag, _) = inner.peek_tag_and_len()?;
    Some(match tag {
        0xA0 | 0x80 => "good".to_string(),    // [0] IMPLICIT NULL
        0xA1 | 0x81 => "revoked".to_string(), // [1] IMPLICIT RevokedInfo
        0xA2 | 0x82 => "unknown".to_string(), // [2] IMPLICIT UnknownInfo
        _ => return None,
    })
}

/// Minimal DER cursor — enough for the OCSP walk above.
struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn peek_tag_and_len(&self) -> Option<(u8, usize)> {
        let tag = *self.bytes.get(self.pos)?;
        let mut i = self.pos + 1;
        let lb = *self.bytes.get(i)? as usize;
        i += 1;
        let len = if lb < 0x80 {
            lb
        } else {
            let nl = lb & 0x7f;
            if nl == 0 || nl > 4 {
                return None;
            }
            let mut v = 0usize;
            for _ in 0..nl {
                v = (v << 8) | (*self.bytes.get(i)? as usize);
                i += 1;
            }
            v
        };
        let _ = len; // peek only — caller decides what to do
        Some((tag, i - self.pos))
    }

    fn read_tlv(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = *self.bytes.get(self.pos)?;
        self.pos += 1;
        let len = self.read_len()?;
        let content = self.bytes.get(self.pos..self.pos + len)?;
        self.pos += len;
        Some((tag, content))
    }

    fn read_len(&mut self) -> Option<usize> {
        let lb = *self.bytes.get(self.pos)? as usize;
        self.pos += 1;
        if lb < 0x80 {
            return Some(lb);
        }
        let nl = lb & 0x7f;
        if nl == 0 || nl > 4 {
            return None;
        }
        let mut v = 0usize;
        for _ in 0..nl {
            v = (v << 8) | (*self.bytes.get(self.pos)? as usize);
            self.pos += 1;
        }
        Some(v)
    }

    fn enter_seq(&mut self) -> Option<()> {
        let (tag, content) = self.read_tlv()?;
        if tag != 0x30 {
            return None;
        }
        // Replace our view with the inner content. Anchored by lifetime,
        // we hop the cursor INTO the sequence by resetting bytes+pos.
        self.bytes = content;
        self.pos = 0;
        Some(())
    }

    /// Enter a `[N] EXPLICIT` wrapper (context-specific constructed).
    fn enter_context_explicit(&mut self, n: u8) -> Option<()> {
        let expected = 0xA0 | (n & 0x1F);
        let (tag, content) = self.read_tlv()?;
        if tag != expected {
            return None;
        }
        self.bytes = content;
        self.pos = 0;
        Some(())
    }

    fn read_enumerated(&mut self) -> Option<u32> {
        let (tag, content) = self.read_tlv()?;
        if tag != 0x0A {
            return None;
        }
        let mut v = 0u32;
        for b in content {
            v = (v << 8) | (*b as u32);
        }
        Some(v)
    }

    fn read_octet_string(&mut self) -> Option<&'a [u8]> {
        let (tag, content) = self.read_tlv()?;
        if tag != 0x04 {
            return None;
        }
        Some(content)
    }

    fn skip_one(&mut self) -> Option<()> {
        let _ = self.read_tlv()?;
        Some(())
    }

    fn skip_optional_context(&mut self, n: u8) {
        let expected = 0xA0 | (n & 0x1F);
        if self.bytes.get(self.pos) == Some(&expected) {
            let _ = self.skip_one();
        }
    }
}

#[allow(dead_code)]
fn find_subseq(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

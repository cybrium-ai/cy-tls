//! Per-stage handshake timings, milliseconds.

use serde::Serialize;

#[derive(Debug, Default, Serialize, Clone, Copy)]
pub struct Timings {
    pub connect: u64,
    pub client_hello: u64,
    pub cert: u64,
    pub key_exchange: u64,
    pub finish: u64,
}

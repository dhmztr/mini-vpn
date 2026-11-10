use serde::{Deserialize, Serialize};
use std::net::{AddrParseError, SocketAddr};
use tokio::task::JoinError;

#[derive(Serialize, Deserialize)]
pub struct InitialClientMessage {
    pub my_key: KeyType,
}
#[derive(Serialize, Deserialize)]
pub struct InitialServerResponse {
    pub my_key: KeyType,
    pub ip: String,
}

pub type KeyType = [u8; 32];
pub type NonceType = [u8; 12];

#[derive(thiserror::Error, Debug)]
pub enum Errors {
    #[error("{0}")]
    ConfigError(String),
    #[error("Address you provided isnt an ip with port")]
    IncorrectIp(#[from] AddrParseError),
    #[error("{0}")]
    IOError(#[from] std::io::Error),
    #[error("{0}")]
    SerializationError(#[from] rmp_serde::encode::Error),
    #[error("{0}")]
    DeserializationError(#[from] rmp_serde::decode::Error),
    #[error("{0}")]
    TaskError(#[from] JoinError),
    #[error("{0}")]
    CryptographicError(#[from] chacha20poly1305::Error),
    #[error("{0}")]
    Other(String),
    #[error("Replay attack from host {0}! ")]
    Replay(SocketAddr),
    #[error("{0}")]
    VpnError(#[from] tun2::Error),
}

#[derive(Serialize, Deserialize)]
pub struct Message {
    pub message: Vec<u8>,
    pub counter: u64,
}

pub struct Cmd(pub (SocketAddr, String));

pub struct ReplayWindow {
    highest_seen: u64,
    bitmap: u64,
}
impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            highest_seen: 0,
            bitmap: 0,
        }
    }
    pub fn check(&mut self, counter: u64) -> bool {
        if counter > self.highest_seen {
            let diff = counter - self.highest_seen;
            if diff >= 64 {
                self.bitmap = 0;
                self.bitmap |= 1;
            } else {
                self.bitmap <<= diff;
                self.bitmap |= 1;
            }
            self.highest_seen = counter;
            return true;
        }
        let diff = self.highest_seen - counter;

        if diff >= 64 {
            return false;
        }
        if (self.bitmap >> diff) & 1 == 1 {
            return false;
        }
        self.bitmap |= 1 << diff;

        true
    }
}

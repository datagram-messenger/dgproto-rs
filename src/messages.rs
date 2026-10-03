//! Typed DGProto v1 message structs and their parse/serialize implementations.
//!
//! Message type registry (MVP):
//!
//! | ID   | Name                | Direction       | Encrypted? |
//! |------|---------------------|-----------------|------------|
//! | 0x01 | HandshakeInit       | Client → Server | No         |
//! | 0x02 | HandshakeResponse   | Server → Client | No         |
//! | 0x03 | HandshakeFinish     | Client → Server | No         |
//! | 0x03 | EncryptedData       | Both            | Yes        |
//! | 0x04 | Ping / Pong         | Both            | Yes        |
//! | 0x05 | SessionClose        | Both            | Yes        |
//! | 0x06 | Ack                 | Both            | Yes        |
//! | 0x07 | (reserved)          | —               | —          |
//! | 0x08 | RekeyInit           | Both            | Yes        |
//! | 0x09 | ErrorMessage        | Both            | Yes        |
//!
//! Type 0x07 is always rejected by `Session`.
//!
//! See `docs/protocol/dgproto-v1.md` §5 for the normative specification.

use crate::Error;

// ── Public types (re-exported from lib.rs) ────────────────────────────────────

/// An application-layer encrypted payload (message type 0x03, post-handshake).
#[derive(Debug, Clone)]
pub struct EncryptedData {
    /// Logical stream identifier within the session.
    pub stream_id: u16,
    /// Application-defined message type byte.
    pub app_message_type: u8,
    /// Raw application payload bytes (TLV-encoded fields).
    pub fields: Vec<u8>,
}

/// An acknowledgement message (type 0x06).
#[derive(Debug, Clone)]
pub struct Ack {
    /// Sequence numbers being acknowledged (1–255 entries).
    pub sequences: Vec<u64>,
}

/// An application-layer error message (type 0x09).
#[derive(Debug, Clone)]
pub struct ErrorMessage {
    /// Error code byte.
    pub code: u8,
    /// Human-readable reason string (valid UTF-8, ≤ `MaxReasonSize` bytes).
    pub reason: String,
}

/// A session-close message (type 0x05).
#[derive(Debug, Clone)]
pub struct SessionClose {
    /// Close code (0–3 for MVP).
    pub code: CloseCode,
    /// Optional human-readable reason (valid UTF-8, ≤ `MaxReasonSize` bytes).
    pub reason: String,
}

/// MVP session-close codes (0–3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CloseCode {
    /// Normal closure.
    Normal = 0,
    /// Closed due to an error.
    Error = 1,
    /// Closed due to a protocol violation.
    Protocol = 2,
    /// Closed due to resource exhaustion.
    ResourceLimit = 3,
}

impl TryFrom<u8> for CloseCode {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(CloseCode::Normal),
            1 => Ok(CloseCode::Error),
            2 => Ok(CloseCode::Protocol),
            3 => Ok(CloseCode::ResourceLimit),
            _ => Err(Error::InvalidCloseCode),
        }
    }
}

// TODO: implement parse/serialize for all message types.
// Reference: dgproto-go/messages.go

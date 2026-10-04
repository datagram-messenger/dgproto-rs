//! Rust client library for the DGProto v1 secure transport protocol.
//!
//! `dgproto` implements the client (initiator) side of the DGProto v1 wire
//! protocol over async TCP. It is a pure library crate — no binary, no server.
//!
//! # Layers
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │ L4  Application Messages                                     │
//! │     (EncryptedData, Ack, ErrorMessage, SessionClose)         │
//! ├──────────────────────────────────────────────────────────────┤
//! │ L3  DGP Session Layer                                        │
//! │     (directional epochs, sequences, rekeying, replay window) │
//! ├──────────────────────────────────────────────────────────────┤
//! │ L2  DGP Cryptographic Layer                                  │
//! │     (Noise XX initiator, ChaCha20-Poly1305, HMAC-SHA256)     │
//! ├──────────────────────────────────────────────────────────────┤
//! │ L1  DGP Framing Layer                                        │
//! │     (40-byte fixed header, TLV envelope, optional padding)   │
//! ├──────────────────────────────────────────────────────────────┤
//! │ L0  Transport Layer                                          │
//! │     (async TCP via Tokio — no outer length prefix)           │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Quick start
//!
//! ```rust,no_run
//! use dgproto::{ClientConfig, Connection, EncryptedData, StaticKey};
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), dgproto::Error> {
//!     let key = StaticKey::load(&[0u8; 32])?; // replace with real key bytes
//!     let config = ClientConfig {
//!         static_key: key,
//!         handshake_timeout: Duration::from_secs(10),
//!         ..Default::default()
//!     };
//!     let conn = Connection::connect("127.0.0.1:8090", config).await?;
//!     conn.send(EncryptedData {
//!         stream_id: 1,
//!         app_message_type: 0x01,
//!         fields: b"hello".to_vec(),
//!     })?;
//!     conn.close().await
//! }
//! ```
//!
//! The [DGProto v1 specification] is normative for wire behavior.
//!
//! [DGProto v1 specification]: https://github.com/datagram-messenger/dgproto-go/blob/main/docs/protocol/dgproto-v1.md

// ── Internal modules (pub(crate) — not part of the public API) ────────────────
// When building with `cargo fuzz` the fuzzing cfg flag is set, and we need
// these modules to be fully public so that lib.rs can re-export their types
// to the fuzz targets.  In every other build they remain crate-private.

#[cfg_attr(fuzzing, allow(unreachable_pub))]
pub(crate) mod codec;
#[cfg(not(fuzzing))]
pub(crate) mod frame;
#[cfg(fuzzing)]
pub mod frame;
#[cfg(not(fuzzing))]
pub(crate) mod handshake;
#[cfg(fuzzing)]
pub mod handshake;
#[cfg(not(fuzzing))]
pub(crate) mod header;
#[cfg(fuzzing)]
pub mod header;
#[cfg(not(fuzzing))]
pub(crate) mod messages;
#[cfg(fuzzing)]
pub mod messages;
pub(crate) mod rekey;
pub(crate) mod replay;
pub(crate) mod session;
#[cfg(not(fuzzing))]
pub(crate) mod tlv;
#[cfg(fuzzing)]
pub mod tlv;
pub(crate) mod transport;

// ── Public modules ────────────────────────────────────────────────────────────

pub mod connection;
pub mod error;

// ── Public re-exports — the complete stable API surface ───────────────────────

pub use error::Error;

// Key management
pub use handshake::StaticKey;

// Connection and configuration
pub use connection::{ClientConfig, Connection, MessageHandler};

// Application messages (L4)
pub use messages::{Ack, CloseCode, EncryptedData, ErrorMessage, SessionClose};

// ── Crate-level constants (re-exported for callers that need them) ─────────────

/// Protocol version encoded in every DGProto v1 header.
pub const VERSION: u8 = 1;

/// Fixed header size in bytes.
pub const HEADER_SIZE: usize = 40;

/// Maximum total frame size (header + payload + tag + padding).
pub const MAX_FRAME_SIZE: usize = 65535;

/// AEAD authentication tag size in bytes.
pub const AEAD_TAG_SIZE: usize = 16;

/// Maximum padding length in bytes (fits in a `u8`).
pub const MAX_PAD_LENGTH: u8 = 255;

/// Traffic key size in bytes.
pub const KEY_SIZE: usize = 32;

/// Replay window size in sequence-number slots.
pub const REPLAY_WINDOW_SIZE: usize = 2048;

/// Default rekey frame limit per epoch (2^32).
pub const DEFAULT_REKEY_FRAME_LIMIT: u64 = 1 << 32;

/// Default rekey interval per epoch (10 minutes in seconds).
pub const DEFAULT_REKEY_INTERVAL_SECS: u64 = 600;

/// Default rekey grace window in frames.
pub const DEFAULT_REKEY_GRACE_FRAMES: u64 = REPLAY_WINDOW_SIZE as u64;

/// Default rekey grace period in seconds.
pub const DEFAULT_REKEY_GRACE_SECS: u64 = 30;

// ── Fuzzing re-exports ────────────────────────────────────────────────────────
// Exposed only when building with `cargo fuzz` (RUSTFLAGS="--cfg fuzzing").
// These are internal parser entry points — not part of the stable public API.

#[cfg(fuzzing)]
pub use frame::Frame;
#[cfg(fuzzing)]
pub use header::Header;
#[cfg(fuzzing)]
pub use messages::{
    Ack as FuzzAck, ErrorMessage as FuzzErrorMessage, HandshakeFinish, HandshakeInit,
    HandshakeResponse, PingPong, RekeyInit, SessionClose as FuzzSessionClose,
};
#[cfg(fuzzing)]
pub use tlv::decode_tlvs;

// ── Integration-test helpers ──────────────────────────────────────────────────
// Always compiled but hidden from rustdoc. Integration tests (tests/*.rs) are
// compiled as separate crates that link the library in its normal (non-test)
// build, so `#[cfg(test)]` is NOT active in the library when integration tests
// run. We therefore expose this module unconditionally and rely on `#[doc(hidden)]`
// to keep it out of the public API surface.

#[doc(hidden)]
pub mod test_wire {
    use crate::{
        frame::Frame,
        header::Header,
        messages::{
            Ack, EncryptedData, ErrorMessage, HandshakeFinish, HandshakeInit, HandshakeResponse,
            PingPong, RekeyInit, SessionClose,
        },
        tlv::{decode_tlvs, encode_tlvs},
        Error,
    };

    // ── Header ────────────────────────────────────────────────────────────────

    /// Parse the header bytes from `wire` (must be exactly `HEADER_SIZE` bytes).
    /// Returns `Ok(())` on success.
    pub fn header_parse(wire: &[u8]) -> Result<(), Error> {
        Header::unmarshal_binary(wire)?;
        Ok(())
    }

    /// Parse then re-marshal a header. `wire` must be exactly `HEADER_SIZE` bytes.
    /// Uses `marshal_binary_raw` so that reserved bytes are preserved verbatim.
    pub fn header_roundtrip(wire: &[u8]) -> Result<Vec<u8>, Error> {
        let h = Header::unmarshal_binary(wire)?;
        Ok(h.marshal_binary_raw().to_vec())
    }

    // ── Frame ─────────────────────────────────────────────────────────────────

    /// Parse a complete frame from `wire`. Returns `Ok(())` on success.
    pub fn frame_parse(wire: &[u8]) -> Result<(), Error> {
        Frame::unmarshal_binary(wire)?;
        Ok(())
    }

    /// Parse then re-marshal a frame. Returns the re-encoded bytes.
    ///
    /// Returns `Err(Error::FrameLengthMismatch)` if `wire` contains trailing
    /// bytes beyond the frame declared by the header (Go rejects this too).
    pub fn frame_roundtrip(wire: &[u8]) -> Result<Vec<u8>, Error> {
        let f = Frame::unmarshal_binary(wire)?;
        // Reject trailing bytes — the frame must consume exactly `frame_size` bytes.
        let expected_len = f.header.frame_size() as usize;
        if wire.len() != expected_len {
            return Err(Error::FrameLengthMismatch);
        }
        f.marshal_binary()
    }

    // ── TLV ───────────────────────────────────────────────────────────────────

    /// Parse a TLV sequence from `wire`. Returns `Ok(())` on success.
    pub fn tlv_parse(wire: &[u8]) -> Result<(), Error> {
        decode_tlvs(wire, wire.len())?;
        Ok(())
    }

    /// Parse then re-encode a TLV sequence. Returns the re-encoded bytes.
    pub fn tlv_roundtrip(wire: &[u8]) -> Result<Vec<u8>, Error> {
        let tlvs = decode_tlvs(wire, wire.len())?;
        encode_tlvs(&tlvs)
    }

    // ── Messages ──────────────────────────────────────────────────────────────

    /// Parse a message of the given wire type from `wire`, then re-serialise it.
    /// Returns the re-serialised bytes (must be byte-for-byte identical to `wire`).
    ///
    /// Type 0x07 is reserved and always returns `Err(Error::MessageType)`.
    pub fn message_roundtrip(msg_type: u8, wire: &[u8]) -> Result<Vec<u8>, Error> {
        match msg_type {
            0x01 => HandshakeInit::unmarshal_binary(wire)?.marshal_binary(),
            0x02 => HandshakeResponse::unmarshal_binary(wire)?.marshal_binary(),
            0x03 => {
                // Post-handshake EncryptedData (session ID is non-zero in real
                // frames; the vector uses type 0x03 for EncryptedData).
                EncryptedData::unmarshal_binary(wire)?.marshal_binary()
            }
            0x04 => PingPong::unmarshal_binary(wire)?.marshal_binary(),
            0x05 => SessionClose::unmarshal_binary(wire)?.marshal_binary(),
            0x06 => Ack::unmarshal_binary(wire)?.marshal_binary(),
            0x07 => Err(Error::MessageType),
            0x08 => RekeyInit::unmarshal_binary(wire)?.marshal_binary(),
            0x09 => ErrorMessage::unmarshal_binary(wire)?.marshal_binary(),
            _ => Err(Error::MessageType),
        }
    }

    // ── Handshake finish (type 0x03 with zero session ID) ─────────────────────

    /// Parse a HandshakeFinish payload (64-byte Noise message 3).
    #[allow(dead_code)]
    pub fn handshake_finish_roundtrip(wire: &[u8]) -> Result<Vec<u8>, Error> {
        HandshakeFinish::unmarshal_binary(wire)?.marshal_binary()
    }
}

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

pub(crate) mod codec;
pub(crate) mod frame;
pub(crate) mod handshake;
pub(crate) mod header;
pub(crate) mod messages;
pub(crate) mod replay;
pub(crate) mod rekey;
pub(crate) mod session;
pub(crate) mod tlv;
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

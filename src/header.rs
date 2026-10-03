//! 40-byte fixed DGProto v1 frame header.
//!
//! Wire layout (all multi-byte fields little-endian):
//!
//! ```text
//! Offset  Size  Field
//! ──────  ────  ─────────────────────────────────────────────────
//!  0       4    Magic: b"DGP1" (0x44 0x47 0x50 0x31)
//!  4       1    Version: 0x01
//!  5       1    Flags (bit 1 = FlagPadding; bits 0,2+ reserved)
//!  6       1    MessageType (0x01–0x09; 0x07 reserved/rejected)
//!  7       1    Reserved (must be zero on send; preserved on receive)
//!  8      16    SessionID (zero for handshake frames)
//! 24       8    Sequence (u64 LE; zero for handshake frames)
//! 32       4    PayloadLength (u32 LE)
//! 36       1    PadLength (u8; 0–255)
//! 37       3    Reserved (must be zero on send; preserved on receive)
//! ──────  ────
//! Total: 40 bytes
//! ```
//!
//! See `docs/protocol/dgproto-v1.md` §3 for the normative specification.

// TODO: implement Header, Flags, MessageType, constants, marshal/unmarshal.
// Reference: dgproto-go/header.go

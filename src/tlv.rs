//! TLV (Type-Length-Value) codec for DGProto v1 application-layer fields.
//!
//! Wire layout per TLV element:
//!
//! ```text
//! Offset  Size  Field
//! ──────  ────  ──────────────────────────────────────────────────
//!  0       1    Type (u8, field identifier scoped to message)
//!  1       2    Length (u16 LE, byte count of Value, excl. padding)
//!  3     len    Value (raw bytes)
//!  3+len  pad   Zero-padding to next 4-byte boundary (not in Length)
//! ```
//!
//! Unknown types are preserved. Padding bytes are ignored by parsers.
//!
//! See `docs/protocol/dgproto-v1.md` §2.3 for the normative specification.

// TODO: implement Tlv struct, encode_tlvs, decode_tlvs, EncodedLen, constants.
// Reference: dgproto-go/tlv.go

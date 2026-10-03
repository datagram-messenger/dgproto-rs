//! Stateless ChaCha20-Poly1305 AEAD codec for DGProto v1 data frames.
//!
//! # Nonce construction
//!
//! ```text
//! nonce = [0x00, 0x00, 0x00, 0x00] || sequence.to_le_bytes()   (12 bytes)
//! ```
//!
//! # Associated data (AAD)
//!
//! ```text
//! aad = marshal_binary(header) || padding_bytes
//! ```
//!
//! The full 40-byte header (including reserved bytes) and the cleartext random
//! padding are both authenticated. This means every transmitted byte is covered
//! by the AEAD tag.
//!
//! # Key/nonce reuse
//!
//! The codec is stateless — it does not track sequences. The caller (`Session`)
//! is responsible for sequence allocation and ensuring no key/nonce pair is
//! ever reused.
//!
//! See `docs/protocol/dgproto-v1.md` §4.3 for the normative specification.

// TODO: implement Codec struct (wraps chacha20poly1305::ChaCha20Poly1305),
//       encrypt(header, plaintext, padding) -> Frame,
//       decrypt(frame) -> Vec<u8>.
// Reference: dgproto-go/crypto.go

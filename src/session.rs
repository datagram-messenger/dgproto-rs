//! DGProto v1 session: directional codec pair, epoch/sequence state,
//! replay window, and rekey transitions.
//!
//! `Session` is the single entry point for all data-frame cryptography.
//! It owns:
//! - A **send** `Codec` + send epoch + send sequence counter + `RekeyState`
//! - A **receive** `Codec` + receive epoch + `ReplayWindow` + optional
//!   previous-epoch `Codec` + grace window state
//!
//! # Concurrency
//!
//! Send state and receive state are protected by **separate** `tokio::sync::Mutex`
//! guards. The two locks MUST NOT be acquired simultaneously.
//!
//! # Sequence numbers
//!
//! - Start at **1**. Sequence 0 is always invalid.
//! - Nonce: `[0u8; 4] || sequence.to_le_bytes()` (12 bytes).
//! - On exhaustion (`u64::MAX`), `encrypt_frame` returns `Error::SequenceExhausted`.
//!   The connection must be closed immediately.
//!
//! # Rekey
//!
//! `Session` checks the rekey trigger on every `encrypt_frame` call. When the
//! trigger fires, it returns `NeedsRekey` so the write loop can emit `RekeyInit`
//! as the last frame of the current epoch before advancing state.
//!
//! See `docs/protocol/dgproto-v1.md` §4 for the normative specification.

// TODO: implement Session struct with:
//   - new(secrets: HandshakeSecrets) -> Result<Session>
//   - encrypt_frame(msg_type, plaintext, pad_len) -> Result<EncryptResult>
//   - decrypt_frame(frame) -> Result<Vec<u8>>
//   - begin_rekey() -> Result<RekeyInitPayload>   (send side)
//   - accept_rekey(payload) -> Result<()>          (receive side)
//   - session_id() -> [u8; 16]
// Reference: dgproto-go/session.go, rekey.go, replay.go

//! Rekey epoch transitions for DGProto v1.
//!
//! Rekeying is **directional**: each send direction manages its own epoch
//! independently. The handshake establishes epoch 1 for both directions.
//!
//! # Trigger conditions (either is sufficient)
//!
//! - `2^32` frames sent in the current epoch, OR
//! - 10 minutes elapsed since the epoch started.
//!
//! # Key derivation labels (exact byte strings, no NUL terminator)
//!
//! ```text
//! KeyConfirm = HMAC-SHA256(K, b"DGPv1 Rekey Confirm" || epoch.to_le_bytes())
//! K_next     = HMAC-SHA256(K, b"DGPv1 Rekey Send Key")
//! ```
//!
//! Both peers use the **send label** on the wire, so the sender's next send
//! key equals the receiver's next receive key.
//!
//! # Send-before-commit ordering
//!
//! `RekeyInit` MUST be the last frame of epoch `E-1`. The sender installs
//! `K_next`, sets epoch to `E`, and resets sequence to 1 — all under the
//! send lock — before any new-epoch frame is written.
//!
//! # Grace window
//!
//! After accepting a rekey, the receiver MAY accept previous-epoch frames for:
//! - at most **2048 current-epoch frames**, AND
//! - at most **30 seconds**
//! (whichever expires first). Previous-epoch frames remain subject to their
//! own replay window.
//!
//! # Invariants
//!
//! - Epoch 0 is invalid. Epochs start at 1.
//! - Epoch advances by exactly +1. Skipped, duplicate, and rollback epochs
//!   are rejected.
//! - An invalid `KeyConfirm` MUST be rejected without changing any state.
//! - Epoch overflow past `u32::MAX` is rejected (`EpochExhausted`).
//!
//! See `docs/protocol/dgproto-v1.md` §4.4.1 for the normative specification.

/// Default rekey frame limit per epoch (2^32).
pub(crate) const REKEY_FRAME_LIMIT: u64 = crate::DEFAULT_REKEY_FRAME_LIMIT;

/// Default rekey interval per epoch (10 minutes).
pub(crate) const REKEY_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(crate::DEFAULT_REKEY_INTERVAL_SECS);

/// Default grace window in current-epoch frames.
pub(crate) const REKEY_GRACE_FRAMES: u64 = crate::DEFAULT_REKEY_GRACE_FRAMES;

/// Default grace period.
pub(crate) const REKEY_GRACE_PERIOD: std::time::Duration =
    std::time::Duration::from_secs(crate::DEFAULT_REKEY_GRACE_SECS);

/// Directional rekey state. Epoch 1 is established by the handshake.
pub(crate) struct RekeyState {
    pub epoch: u32,
}

impl RekeyState {
    /// Create initial rekey state at handshake epoch 1.
    pub(crate) const fn new() -> Self {
        Self { epoch: 1 }
    }

    /// Compute the HMAC-SHA256 key-confirmation value for the next epoch.
    ///
    /// `secret` is the current directional traffic key (32 bytes).
    /// `next_epoch` must equal `self.epoch + 1`.
    pub(crate) fn compute_key_confirm(
        &self,
        secret: &[u8; 32],
        next_epoch: u32,
    ) -> Result<[u8; 32], crate::Error> {
        // TODO: implement — mirror Go RekeyState.ComputeKeyConfirm exactly.
        // Label: b"DGPv1 Rekey Confirm" || next_epoch.to_le_bytes()
        todo!("RekeyState::compute_key_confirm")
    }

    /// Derive the next traffic key from the current secret.
    ///
    /// `K_next = HMAC-SHA256(current_secret, b"DGPv1 Rekey Send Key")`
    pub(crate) fn derive_next_key(current_secret: &[u8; 32]) -> [u8; 32] {
        // TODO: implement — mirror Go DeriveNextKeys (send label only).
        todo!("RekeyState::derive_next_key")
    }
}

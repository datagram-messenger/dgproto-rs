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
//!
//! Whichever expires first. Previous-epoch frames remain subject to their
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

// This completed layer is wired into Session once that layer is implemented.
#![allow(dead_code)]

use hmac::{Hmac, Mac};
use sha2::Sha256;

const CONFIRM_LABEL: &[u8] = b"DGPv1 Rekey Confirm";
const SEND_KEY_LABEL: &[u8] = b"DGPv1 Rekey Send Key";

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
        let expected_epoch = self
            .epoch
            .checked_add(1)
            .ok_or(crate::Error::EpochExhausted)?;
        if next_epoch != expected_epoch {
            return Err(crate::Error::InvalidEpoch {
                got: next_epoch,
                want: expected_epoch,
            });
        }

        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret).expect("HMAC-SHA256 accepts keys of any length");
        mac.update(CONFIRM_LABEL);
        mac.update(&next_epoch.to_le_bytes());
        Ok(mac.finalize().into_bytes().into())
    }

    /// Derive the next traffic key from the current secret.
    ///
    /// `K_next = HMAC-SHA256(current_secret, b"DGPv1 Rekey Send Key")`
    pub(crate) fn derive_next_key(current_secret: &[u8; 32]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(current_secret)
            .expect("HMAC-SHA256 accepts keys of any length");
        mac.update(SEND_KEY_LABEL);
        mac.finalize().into_bytes().into()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RekeyState, REKEY_FRAME_LIMIT, REKEY_GRACE_FRAMES, REKEY_GRACE_PERIOD, REKEY_INTERVAL,
    };
    use crate::Error;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use std::time::Duration;

    #[test]
    fn test_rekey_defaults_match_protocol() {
        assert_eq!(REKEY_FRAME_LIMIT, 1 << 32);
        assert_eq!(REKEY_INTERVAL, Duration::from_secs(600));
        assert_eq!(REKEY_GRACE_FRAMES, 2048);
        assert_eq!(REKEY_GRACE_PERIOD, Duration::from_secs(30));
    }

    #[test]
    fn test_rekey_state_starts_at_epoch_one() {
        assert_eq!(RekeyState::new().epoch, 1);
    }

    #[test]
    fn test_rekey_compute_key_confirm_matches_hmac() {
        let secret = [0x42; 32];
        let actual = RekeyState::new()
            .compute_key_confirm(&secret, 2)
            .expect("next epoch should be valid");

        let mut expected = Hmac::<Sha256>::new_from_slice(&secret)
            .expect("HMAC-SHA256 accepts keys of any length");
        expected.update(b"DGPv1 Rekey Confirm");
        expected.update(&2u32.to_le_bytes());
        let expected: [u8; 32] = expected.finalize().into_bytes().into();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_rekey_rejects_non_successor_epochs() {
        let state = RekeyState::new();
        for epoch in [0, 1, 3, u32::MAX] {
            assert!(matches!(
                state.compute_key_confirm(&[0; 32], epoch),
                Err(Error::InvalidEpoch { got, want: 2 }) if got == epoch
            ));
        }
    }

    #[test]
    fn test_rekey_rejects_epoch_exhaustion() {
        let state = RekeyState { epoch: u32::MAX };
        assert!(matches!(
            state.compute_key_confirm(&[0; 32], 0),
            Err(Error::EpochExhausted)
        ));
    }

    #[test]
    fn test_rekey_derive_next_key_matches_send_label() {
        let secret = [0xa5; 32];
        let actual = RekeyState::derive_next_key(&secret);

        let mut expected = Hmac::<Sha256>::new_from_slice(&secret)
            .expect("HMAC-SHA256 accepts keys of any length");
        expected.update(b"DGPv1 Rekey Send Key");
        let expected: [u8; 32] = expected.finalize().into_bytes().into();
        assert_eq!(actual, expected);
        assert_ne!(actual, secret);
    }
}

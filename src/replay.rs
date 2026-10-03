//! 64-bit sliding replay window for DGProto v1 receive-side protection.
//!
//! Mirrors `dgproto-go/replay.go` exactly — same algorithm, same constants.
//!
//! # Algorithm (identical to IPsec ESP / WireGuard)
//!
//! Given an incoming frame with sequence number `n`:
//!
//! 1. `n > highest_seq`:
//!    Accept. Shift bitmap by `n - highest_seq`. Set `highest_seq = n`. Mark bit.
//!
//! 2. `n <= highest_seq` AND `n > highest_seq - WINDOW_SIZE`:
//!    Check bitmap. If already marked → **reject** (`ReplayDuplicate`).
//!    Otherwise accept and mark.
//!
//! 3. `n <= highest_seq - WINDOW_SIZE`:
//!    **Reject** unconditionally (`ReplayTooOld`).
//!
//! # Check-then-commit protocol
//!
//! Replay check PRECEDES authentication. The window is only committed after
//! successful AEAD decryption. A `ReplayToken` carries a generation counter
//! that is invalidated by any intervening commit, preventing TOCTOU races.
//!
//! See `docs/protocol/dgproto-v1.md` §4.5 for the normative specification.

/// Number of sequence-number slots tracked by the window.
pub(crate) const WINDOW_SIZE: usize = crate::REPLAY_WINDOW_SIZE; // 2048
const WORD_COUNT: usize = WINDOW_SIZE / 64;                       // 32

/// A 2048-entry sliding bitmap replay window.
///
/// Not `Send` or `Sync` on its own — `Session` wraps it in a `Mutex`.
pub(crate) struct ReplayWindow {
    highest:    u64,
    bitmap:     [u64; WORD_COUNT],
    generation: u64,
}

/// An opaque token returned by [`ReplayWindow::check`].
///
/// Must be passed to [`ReplayWindow::commit`] after successful authentication.
/// Becomes stale after any intervening commit.
pub(crate) struct ReplayToken {
    sequence:   u64,
    generation: u64,
}

impl ReplayWindow {
    /// Create a new, empty replay window.
    pub(crate) const fn new() -> Self {
        Self {
            highest:    0,
            bitmap:     [0u64; WORD_COUNT],
            generation: 0,
        }
    }

    /// Validate `sequence` without mutating the window.
    ///
    /// Returns a `ReplayToken` on success. The token must be passed to
    /// [`commit`](Self::commit) after the frame is authenticated.
    pub(crate) fn check(&self, sequence: u64) -> Result<ReplayToken, crate::Error> {
        // TODO: implement — mirror Go ReplayWindow.Check exactly.
        todo!("ReplayWindow::check")
    }

    /// Record `sequence` after the frame has been authenticated.
    ///
    /// Returns `Err(Error::ReplayStale)` if the token was invalidated by a
    /// concurrent commit.
    pub(crate) fn commit(&mut self, token: ReplayToken) -> Result<(), crate::Error> {
        // TODO: implement — mirror Go ReplayWindow.Commit exactly.
        todo!("ReplayWindow::commit")
    }
}

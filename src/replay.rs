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
const WORD_COUNT: usize = WINDOW_SIZE / 64; // 32

/// A 2048-entry sliding bitmap replay window.
///
/// Not `Send` or `Sync` on its own — `Session` wraps it in a `Mutex`.
pub(crate) struct ReplayWindow {
    highest: u64,
    bitmap: [u64; WORD_COUNT],
    generation: u64,
}

/// An opaque token returned by [`ReplayWindow::check`].
///
/// Must be passed to [`ReplayWindow::commit`] after successful authentication.
/// Becomes stale after any intervening commit.
pub(crate) struct ReplayToken {
    sequence: u64,
    generation: u64,
}

impl ReplayWindow {
    /// Create a new, empty replay window.
    pub(crate) const fn new() -> Self {
        Self {
            highest: 0,
            bitmap: [0u64; WORD_COUNT],
            generation: 0,
        }
    }

    /// Validate `sequence` without mutating the window.
    ///
    /// Returns a `ReplayToken` on success. The token must be passed to
    /// [`commit`](Self::commit) after the frame is authenticated.
    pub(crate) fn check(&self, sequence: u64) -> Result<ReplayToken, crate::Error> {
        if sequence == 0 {
            return Err(crate::Error::ReplayZero);
        }

        if sequence <= self.highest {
            let distance = self.highest - sequence;
            if distance >= WINDOW_SIZE as u64 {
                return Err(crate::Error::ReplayTooOld);
            }
            if self.marked(distance) {
                return Err(crate::Error::ReplayDuplicate);
            }
        }

        Ok(ReplayToken {
            sequence,
            generation: self.generation,
        })
    }

    /// Record `sequence` after the frame has been authenticated.
    ///
    /// Returns `Err(Error::ReplayStale)` if the token was invalidated by a
    /// concurrent commit.
    pub(crate) fn commit(&mut self, token: ReplayToken) -> Result<(), crate::Error> {
        if token.sequence == 0 || token.generation != self.generation {
            return Err(crate::Error::ReplayStale);
        }

        let sequence = token.sequence;
        if sequence <= self.highest {
            let distance = self.highest - sequence;
            if distance >= WINDOW_SIZE as u64 || self.marked(distance) {
                return Err(crate::Error::ReplayStale);
            }
            self.set(distance);
        } else {
            self.advance(sequence - self.highest);
            self.highest = sequence;
            self.set(0);
        }

        self.generation = self.generation.wrapping_add(1);
        Ok(())
    }

    fn marked(&self, distance: u64) -> bool {
        let word = (distance / 64) as usize;
        let bit = distance % 64;
        self.bitmap[word] & (1u64 << bit) != 0
    }

    fn set(&mut self, distance: u64) {
        let word = (distance / 64) as usize;
        let bit = distance % 64;
        self.bitmap[word] |= 1u64 << bit;
    }

    fn advance(&mut self, shift: u64) {
        if shift >= WINDOW_SIZE as u64 {
            self.bitmap.fill(0);
            return;
        }

        let word_shift = (shift / 64) as usize;
        let bit_shift = (shift % 64) as u32;
        for destination in (0..WORD_COUNT).rev() {
            let value = destination.checked_sub(word_shift).map_or(0, |source| {
                let mut value = self.bitmap[source] << bit_shift;
                if bit_shift != 0 && source > 0 {
                    value |= self.bitmap[source - 1] >> (64 - bit_shift);
                }
                value
            });
            self.bitmap[destination] = value;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ReplayWindow, WINDOW_SIZE};
    use crate::Error;

    fn commit(window: &mut ReplayWindow, sequence: u64) {
        let token = window.check(sequence).expect("sequence should pass check");
        window
            .commit(token)
            .expect("checked sequence should commit");
    }

    #[test]
    fn test_replay_first_in_order_and_duplicate() {
        let mut window = ReplayWindow::new();
        commit(&mut window, 1);
        commit(&mut window, 2);
        commit(&mut window, 3);
        assert!(matches!(window.check(1), Err(Error::ReplayDuplicate)));
    }

    #[test]
    fn test_replay_out_of_order_and_boundary() {
        let mut window = ReplayWindow::new();
        commit(&mut window, 3000);
        commit(&mut window, 953);
        assert!(matches!(window.check(952), Err(Error::ReplayTooOld)));
        assert!(matches!(window.check(953), Err(Error::ReplayDuplicate)));
    }

    #[test]
    fn test_replay_large_jump_clears_window() {
        let mut window = ReplayWindow::new();
        commit(&mut window, 7);
        commit(&mut window, 1 << 40);
        assert!(matches!(window.check(7), Err(Error::ReplayTooOld)));
        commit(&mut window, (1 << 40) - 1);
    }

    #[test]
    fn test_replay_rejects_zero() {
        let window = ReplayWindow::new();
        assert!(matches!(window.check(0), Err(Error::ReplayZero)));
    }

    #[test]
    fn test_replay_stale_token_requires_recheck() {
        let mut window = ReplayWindow::new();
        let old = window.check(10).expect("first token");
        let newer = window.check(11).expect("second token");
        window.commit(newer).expect("newer token should commit");
        assert!(matches!(window.commit(old), Err(Error::ReplayStale)));

        let rechecked = window.check(10).expect("sequence should be recheckable");
        window
            .commit(rechecked)
            .expect("rechecked token should commit");
    }

    #[test]
    fn test_replay_word_shifts_preserve_marks() {
        let mut window = ReplayWindow::new();
        let sequences = [1, 2, 63, 64, 65, 127, 128, 129, 2048];
        for sequence in sequences {
            commit(&mut window, sequence);
        }
        for sequence in sequences {
            assert!(matches!(
                window.check(sequence),
                Err(Error::ReplayDuplicate)
            ));
        }

        commit(&mut window, 2049);
        assert!(matches!(window.check(1), Err(Error::ReplayTooOld)));
        assert!(matches!(window.check(2), Err(Error::ReplayDuplicate)));
        commit(&mut window, 3);
        assert_eq!(WINDOW_SIZE, 2048);
    }

    #[test]
    fn test_replay_handles_u64_max() {
        let mut window = ReplayWindow::new();
        commit(&mut window, u64::MAX - 1);
        commit(&mut window, u64::MAX);
        commit(&mut window, u64::MAX - 2);
        assert!(matches!(
            window.check(u64::MAX),
            Err(Error::ReplayDuplicate)
        ));
        assert!(matches!(
            window.check(u64::MAX - WINDOW_SIZE as u64),
            Err(Error::ReplayTooOld)
        ));
    }
}

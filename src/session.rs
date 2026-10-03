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
//! trigger fires, it returns `EncryptResult::NeedsRekey` so the write loop can
//! emit `RekeyInit` as the last frame of the current epoch before advancing state.
//!
//! See `docs/protocol/dgproto-v1.md` §4 for the normative specification.

use std::time::Instant;

use subtle::ConstantTimeEq;
use tokio::sync::Mutex;

use crate::{
    codec::Codec,
    frame::Frame,
    handshake::HandshakeSecrets,
    header::MessageType,
    messages::RekeyInit,
    rekey::{
        RekeyState, REKEY_FRAME_LIMIT, REKEY_GRACE_FRAMES, REKEY_GRACE_PERIOD, REKEY_INTERVAL,
    },
    replay::{ReplayToken, ReplayWindow},
    Error, KEY_SIZE,
};

// ── EncryptResult ─────────────────────────────────────────────────────────────

/// Result of `Session::encrypt_frame`.
#[derive(Debug)]
pub(crate) enum EncryptResult {
    /// Normal encrypted frame ready to transmit.
    Frame(Frame),
    /// Rekey boundary reached. The caller MUST:
    /// 1. Transmit this `RekeyInit` frame.
    /// 2. Call `Session::mark_rekey_sent` with the same frame.
    /// 3. Retry the original `encrypt_frame` call.
    NeedsRekey(Frame),
}

// ── Internal state structs ────────────────────────────────────────────────────

struct PendingSendRekey {
    /// The RekeyInit frame that was returned to the caller.
    frame: Frame,
    /// The next traffic key (installed after `mark_rekey_sent`).
    key: [u8; KEY_SIZE],
    /// The next codec (installed after `mark_rekey_sent`).
    codec: Codec,
    /// The next epoch number.
    epoch: u32,
}

struct SendState {
    codec: Codec,
    key: [u8; KEY_SIZE],
    epoch: u32,
    /// Next sequence to allocate. 0 means exhausted.
    next_sequence: u64,
    /// Frames sent in the current epoch (for rekey trigger).
    sent_in_epoch: u64,
    /// When the current epoch started (for rekey timer).
    epoch_started: Instant,
    /// Pending rekey: set when a RekeyInit has been generated but not yet
    /// confirmed as transmitted.
    pending_rekey: Option<PendingSendRekey>,
    closed: bool,
}

struct RecvState {
    codec: Codec,
    key: [u8; KEY_SIZE],
    epoch: u32,
    replay: ReplayWindow,
    /// Previous-epoch codec retained during the grace window.
    previous_codec: Option<Codec>,
    /// Previous-epoch replay window.
    previous_replay: ReplayWindow,
    /// Remaining current-epoch frames in the grace window.
    grace_remaining: u64,
    /// Wall-clock deadline for the grace window.
    grace_until: Option<Instant>,
    closed: bool,
}

// ── Session ───────────────────────────────────────────────────────────────────

/// DGProto v1 session. Owns directional codecs, sequence allocation, and
/// receive replay state. All methods are safe for concurrent use.
pub(crate) struct Session {
    session_id: [u8; 16],
    send: Mutex<SendState>,
    recv: Mutex<RecvState>,
}

impl Session {
    /// Open a session from handshake secrets.
    ///
    /// Returns `Err(Error::InvalidSessionID)` if `secrets.session_id` is all-zero.
    pub(crate) fn new(secrets: HandshakeSecrets) -> Result<Self, Error> {
        if secrets.session_id == [0u8; 16] {
            return Err(Error::InvalidSessionId);
        }
        let send_codec = Codec::new(&secrets.send_key)?;
        let recv_codec = Codec::new(&secrets.receive_key)?;
        let now = Instant::now();
        Ok(Self {
            session_id: secrets.session_id,
            send: Mutex::new(SendState {
                codec: send_codec,
                key: secrets.send_key,
                epoch: 1,
                next_sequence: 1,
                sent_in_epoch: 0,
                epoch_started: now,
                pending_rekey: None,
                closed: false,
            }),
            recv: Mutex::new(RecvState {
                codec: recv_codec,
                key: secrets.receive_key,
                epoch: 1,
                replay: ReplayWindow::new(),
                previous_codec: None,
                previous_replay: ReplayWindow::new(),
                grace_remaining: 0,
                grace_until: None,
                closed: false,
            }),
        })
    }

    /// Return the 16-byte session identifier.
    pub(crate) fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    /// Close the session. Idempotent. Subsequent `encrypt_frame` /
    /// `decrypt_frame` calls return `Error::SessionClosed`.
    pub(crate) async fn close(&self) {
        let mut s = self.send.lock().await;
        s.closed = true;
        drop(s);
        let mut r = self.recv.lock().await;
        r.closed = true;
    }

    /// Encrypt a plaintext payload into a frame.
    ///
    /// Returns `EncryptResult::NeedsRekey` when the rekey trigger fires.
    /// The caller must transmit the returned `RekeyInit` frame, call
    /// `mark_rekey_sent`, then retry.
    ///
    /// Returns `Err(Error::RekeyPending)` if a previous `NeedsRekey` frame
    /// has not yet been confirmed via `mark_rekey_sent`.
    pub(crate) async fn encrypt_frame(
        &self,
        msg_type: MessageType,
        plaintext: &[u8],
        pad_len: u8,
    ) -> Result<EncryptResult, Error> {
        if !valid_session_msg_type(msg_type) {
            return Err(Error::MessageType);
        }

        let mut s = self.send.lock().await;
        if s.closed {
            return Err(Error::SessionClosed);
        }
        if s.pending_rekey.is_some() {
            return Err(Error::RekeyPending);
        }
        if rekey_due(&s) {
            let rekey_frame = begin_rekey_locked(&mut s, self.session_id)?;
            return Ok(EncryptResult::NeedsRekey(rekey_frame));
        }
        let frame = encrypt_locked(&mut s, self.session_id, msg_type, plaintext, pad_len)?;
        Ok(EncryptResult::Frame(frame))
    }

    /// Confirm that the pending `RekeyInit` frame was successfully transmitted.
    ///
    /// Installs the next key/codec, advances the epoch, and resets the sequence.
    /// Returns `Err(Error::RekeyPending)` if `frame` does not match the pending
    /// rekey frame.
    pub(crate) async fn mark_rekey_sent(&self, frame: &Frame) -> Result<(), Error> {
        let mut s = self.send.lock().await;
        if s.closed {
            return Err(Error::SessionClosed);
        }
        let pending = s.pending_rekey.take().ok_or(Error::RekeyPending)?;
        if !frames_equal(&pending.frame, frame) {
            s.pending_rekey = Some(pending);
            return Err(Error::RekeyPending);
        }
        s.codec = pending.codec;
        s.key = pending.key;
        s.epoch = pending.epoch;
        s.next_sequence = 1;
        s.sent_in_epoch = 0;
        s.epoch_started = Instant::now();
        Ok(())
    }

    /// Decrypt and authenticate an inbound frame.
    ///
    /// Returns the plaintext on success. Handles `RekeyInit` frames by
    /// validating and atomically committing the key transition.
    pub(crate) async fn decrypt_frame(&self, frame: &Frame) -> Result<Vec<u8>, Error> {
        // valid_session_msg_type rejects 0x07 (ResumptionTicket) and all
        // handshake types — they are never valid in a session context.
        if !valid_session_msg_type(frame.header.msg_type) {
            return Err(Error::MessageType);
        }
        if frame.header.session_id != self.session_id {
            return Err(Error::WrongSession);
        }

        let mut r = self.recv.lock().await;
        if r.closed {
            return Err(Error::SessionClosed);
        }

        let candidate = decrypt_epoch_locked(&mut r, frame)?;

        if !candidate.current && frame.header.msg_type == MessageType::RekeyInit {
            return Err(Error::InvalidEpoch {
                got: r.epoch,
                want: r.epoch + 1,
            });
        }

        if candidate.current && frame.header.msg_type == MessageType::RekeyInit {
            // Parse and validate the rekey payload.
            let init = RekeyInit::unmarshal_binary(&candidate.plaintext)?;
            let (next_key, next_codec) = prepare_rekey_locked(&r, &init)?;

            // Commit replay for the RekeyInit frame itself.
            let mut committed_replay = r.replay.clone();
            committed_replay.commit(candidate.token)?;

            // Atomic transition.
            r.previous_codec = Some(std::mem::replace(&mut r.codec, next_codec));
            r.previous_replay = committed_replay;
            r.key = next_key;
            r.epoch = init.epoch;
            r.replay = ReplayWindow::new();
            r.grace_remaining = REKEY_GRACE_FRAMES;
            r.grace_until = Some(Instant::now() + REKEY_GRACE_PERIOD);
            expire_grace_locked(&mut r);
            return Ok(candidate.plaintext);
        }

        // Normal frame (current or previous epoch).
        if candidate.current {
            let mut committed = r.replay.clone();
            committed.commit(candidate.token)?;
            r.replay = committed;
            if r.previous_codec.is_some() {
                if r.grace_remaining > 0 {
                    r.grace_remaining -= 1;
                }
                expire_grace_locked(&mut r);
            }
        } else {
            let mut committed = r.previous_replay.clone();
            committed.commit(candidate.token)?;
            r.previous_replay = committed;
        }
        Ok(candidate.plaintext)
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Returns `true` if `msg_type` is a valid session-layer message type.
///
/// Accepts 0x03–0x09 excluding 0x07 (reserved).
fn valid_session_msg_type(msg_type: MessageType) -> bool {
    matches!(
        msg_type,
        MessageType::EncryptedData
            | MessageType::PingPong
            | MessageType::SessionClose
            | MessageType::Ack
            | MessageType::RekeyInit
            | MessageType::Error
    )
}

/// Returns `true` if the rekey trigger has fired for the send state.
fn rekey_due(s: &SendState) -> bool {
    (REKEY_FRAME_LIMIT != 0 && s.sent_in_epoch >= REKEY_FRAME_LIMIT)
        || s.epoch_started.elapsed() >= REKEY_INTERVAL
}

/// Allocate a sequence number and encrypt a frame. Called under send lock.
fn encrypt_locked(
    s: &mut SendState,
    session_id: [u8; 16],
    msg_type: MessageType,
    plaintext: &[u8],
    pad_len: u8,
) -> Result<Frame, Error> {
    if s.next_sequence == 0 {
        return Err(Error::SequenceExhausted);
    }
    let sequence = s.next_sequence;
    let padding = vec![0u8; pad_len as usize];
    let frame = s
        .codec
        .encrypt(msg_type, session_id, sequence, plaintext, &padding)?;
    // Advance sequence; 0 signals exhaustion on the next call.
    s.next_sequence = if sequence == u64::MAX {
        0
    } else {
        sequence + 1
    };
    s.sent_in_epoch += 1;
    Ok(frame)
}

/// Generate a `RekeyInit` frame and store pending rekey state. Called under
/// send lock.
fn begin_rekey_locked(s: &mut SendState, session_id: [u8; 16]) -> Result<Frame, Error> {
    if s.epoch == u32::MAX {
        return Err(Error::EpochExhausted);
    }
    let next_epoch = s.epoch + 1;
    let rekey_state = RekeyState { epoch: s.epoch };
    let confirm = rekey_state.compute_key_confirm(&s.key, next_epoch)?;
    let init = RekeyInit {
        epoch: next_epoch,
        key_confirm: confirm,
    };
    let payload = init.marshal_binary()?;
    // Encrypt the RekeyInit as the last frame of the current epoch.
    let frame = encrypt_locked(s, session_id, MessageType::RekeyInit, &payload, 0)?;
    let next_key = RekeyState::derive_next_key(&s.key);
    let next_codec = Codec::new(&next_key)?;
    s.pending_rekey = Some(PendingSendRekey {
        frame: frame.clone(),
        key: next_key,
        codec: next_codec,
        epoch: next_epoch,
    });
    Ok(frame)
}

struct DecryptCandidate {
    plaintext: Vec<u8>,
    /// `true` = decrypted with current epoch codec.
    current: bool,
    token: ReplayToken,
}

/// Try to decrypt `frame` under the current epoch, then (if grace window is
/// active) under the previous epoch. Returns the first successful candidate.
fn decrypt_epoch_locked(r: &mut RecvState, frame: &Frame) -> Result<DecryptCandidate, Error> {
    let seq = frame.header.sequence;

    // Try current epoch.
    let current_check = r.replay.check(seq);
    if let Ok(ref token) = current_check {
        match r.codec.decrypt(frame) {
            Ok(plaintext) => {
                return Ok(DecryptCandidate {
                    plaintext,
                    current: true,
                    token: token.clone(),
                });
            }
            Err(e) if !matches!(e, Error::Authentication) => return Err(e),
            _ => {}
        }
    }

    // Try previous epoch if grace window is active.
    let grace_active = r.previous_codec.is_some()
        && r.grace_remaining > 0
        && r.grace_until.map_or(false, |d| Instant::now() < d);

    if grace_active {
        let prev_check = r.previous_replay.check(seq);
        if let Ok(prev_token) = prev_check {
            if let Some(prev_codec) = &r.previous_codec {
                match prev_codec.decrypt(frame) {
                    Ok(plaintext) => {
                        return Ok(DecryptCandidate {
                            plaintext,
                            current: false,
                            token: prev_token,
                        });
                    }
                    Err(e) if !matches!(e, Error::Authentication) => return Err(e),
                    _ => {}
                }
            }
        }
        // Both epochs failed — return the current-epoch error.
        if let Err(e) = current_check {
            return Err(e);
        }
        return Err(Error::Authentication);
    }

    // No grace window — return current-epoch error.
    match current_check {
        Err(e) => Err(e),
        Ok(_) => Err(Error::Authentication),
    }
}

/// Validate a `RekeyInit` payload and derive the next key/codec.
/// Does NOT mutate any state (pure validation).
fn prepare_rekey_locked(r: &RecvState, init: &RekeyInit) -> Result<([u8; KEY_SIZE], Codec), Error> {
    if r.epoch == u32::MAX {
        return Err(Error::EpochExhausted);
    }
    let want_epoch = r.epoch + 1;
    if init.epoch != want_epoch {
        return Err(Error::InvalidEpoch {
            got: init.epoch,
            want: want_epoch,
        });
    }
    let rekey_state = RekeyState { epoch: r.epoch };
    let expected = rekey_state.compute_key_confirm(&r.key, init.epoch)?;
    // Constant-time comparison.
    if expected.ct_eq(&init.key_confirm).unwrap_u8() != 1 {
        return Err(Error::KeyConfirmFailed);
    }
    let next_key = RekeyState::derive_next_key(&r.key);
    let next_codec = Codec::new(&next_key)?;
    Ok((next_key, next_codec))
}

/// Expire the grace window if either budget is exhausted.
fn expire_grace_locked(r: &mut RecvState) {
    if r.previous_codec.is_none() {
        return;
    }
    let time_expired = r.grace_until.map_or(true, |d| Instant::now() >= d);
    if r.grace_remaining == 0 || time_expired {
        r.previous_codec = None;
        r.previous_replay = ReplayWindow::new();
        r.grace_remaining = 0;
        r.grace_until = None;
    }
}

/// Compare two frames for equality (used to verify `mark_rekey_sent`).
fn frames_equal(a: &Frame, b: &Frame) -> bool {
    a.header == b.header && a.tag == b.tag && a.payload == b.payload && a.padding == b.padding
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::HandshakeSecrets;

    fn make_secrets(send_key: [u8; 32], recv_key: [u8; 32]) -> HandshakeSecrets {
        HandshakeSecrets {
            session_id: [1u8; 16],
            send_key,
            receive_key: recv_key,
            peer_static: [0u8; 32],
        }
    }

    #[tokio::test]
    async fn test_session_new_rejects_zero_session_id() {
        let mut s = make_secrets([1u8; 32], [2u8; 32]);
        s.session_id = [0u8; 16];
        assert!(matches!(Session::new(s), Err(Error::InvalidSessionId)));
    }

    #[tokio::test]
    async fn test_session_encrypt_decrypt_roundtrip() {
        let send_key = [0x11u8; 32];
        let recv_key = [0x22u8; 32];
        // Sender session: send_key for encrypt, recv_key for decrypt.
        let sender = Session::new(make_secrets(send_key, recv_key)).expect("sender session");
        // Receiver session: recv_key for decrypt (uses sender's send_key).
        let receiver = Session::new(HandshakeSecrets {
            session_id: [1u8; 16],
            send_key: recv_key,
            receive_key: send_key,
            peer_static: [0u8; 32],
        })
        .expect("receiver session");

        let plaintext = b"hello dgproto";
        let result = sender
            .encrypt_frame(MessageType::EncryptedData, plaintext, 0)
            .await
            .expect("encrypt");
        let frame = match result {
            EncryptResult::Frame(f) => f,
            EncryptResult::NeedsRekey(_) => panic!("unexpected rekey on first frame"),
        };

        let decrypted = receiver.decrypt_frame(&frame).await.expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_session_sequence_starts_at_one() {
        let session = Session::new(make_secrets([1u8; 32], [2u8; 32])).expect("session");
        let result = session
            .encrypt_frame(MessageType::EncryptedData, b"x", 0)
            .await
            .expect("encrypt");
        let frame = match result {
            EncryptResult::Frame(f) => f,
            EncryptResult::NeedsRekey(_) => panic!("unexpected rekey"),
        };
        assert_eq!(frame.header.sequence, 1, "first sequence must be 1");
    }

    #[tokio::test]
    async fn test_session_rejects_handshake_types_in_encrypt() {
        let session = Session::new(make_secrets([1u8; 32], [2u8; 32])).expect("session");
        // HandshakeInit and HandshakeResponse are not valid session message types.
        for mt in [MessageType::HandshakeInit, MessageType::HandshakeResponse] {
            let err = session
                .encrypt_frame(mt, b"x", 0)
                .await
                .expect_err("handshake type should be rejected");
            assert!(matches!(err, Error::MessageType));
        }
    }

    #[tokio::test]
    async fn test_session_closed_returns_error() {
        let session = Session::new(make_secrets([1u8; 32], [2u8; 32])).expect("session");
        session.close().await;
        let err = session
            .encrypt_frame(MessageType::EncryptedData, b"x", 0)
            .await
            .expect_err("should be closed");
        assert!(matches!(err, Error::SessionClosed));
    }

    #[tokio::test]
    async fn test_session_rekey_pending_blocks_send() {
        let session = Session::new(HandshakeSecrets {
            session_id: [1u8; 16],
            send_key: [0xAAu8; 32],
            receive_key: [0xBBu8; 32],
            peer_static: [0u8; 32],
        })
        .expect("session");

        // Force rekey by exhausting the epoch frame limit.
        {
            let mut s = session.send.lock().await;
            s.sent_in_epoch = REKEY_FRAME_LIMIT;
        }

        // First call should return NeedsRekey.
        let result = session
            .encrypt_frame(MessageType::EncryptedData, b"data", 0)
            .await
            .expect("first encrypt");
        assert!(matches!(result, EncryptResult::NeedsRekey(_)));

        // Second call before mark_rekey_sent should return RekeyPending.
        let err = session
            .encrypt_frame(MessageType::EncryptedData, b"data", 0)
            .await
            .expect_err("should be pending");
        assert!(matches!(err, Error::RekeyPending));
    }
}

//! Unified error type for the `dgproto` crate.
//!
//! All fallible operations in this crate return `Result<T, Error>`.
//! No other error type is exported.

use thiserror::Error;

/// The single error type returned by all fallible operations in this crate.
///
/// The enum is `#[non_exhaustive]` — callers must handle a `_` arm so that
/// new variants can be added without a breaking change.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    // ── L1: Header ────────────────────────────────────────────────────────────
    /// Input is shorter than the 40-byte fixed header.
    ///
    /// Go equivalent: `ErrHeaderTooShort`
    #[error("dgproto: header too short")]
    HeaderTooShort,

    /// Header does not begin with the magic bytes `DGP1`.
    ///
    /// Go equivalent: `ErrInvalidMagic`
    #[error("dgproto: invalid magic")]
    InvalidMagic,

    /// Header version field is not `0x01`.
    ///
    /// Go equivalent: `ErrUnsupportedVersion`
    #[error("dgproto: unsupported version: got {got}, want 1")]
    UnsupportedVersion { got: u8 },

    /// An outbound header has reserved flag bits set (only `FlagPadding` is
    /// permitted on send).
    ///
    /// Go equivalent: `ErrReservedFlags`
    #[error("dgproto: reserved flag bits set")]
    ReservedFlags,

    /// `FlagPadding` is set but `pad_length` is zero, or vice-versa.
    ///
    /// Go equivalent: `ErrPaddingFlag`
    #[error("dgproto: padding flag does not match pad_length")]
    PaddingFlag,

    // ── L1: Frame ─────────────────────────────────────────────────────────────
    /// Input cannot contain a complete fixed header (< 40 bytes).
    ///
    /// Go equivalent: `ErrFrameTooShort`
    #[error("dgproto: frame too short")]
    FrameTooShort,

    /// The total frame size derived from the header exceeds 65535 bytes.
    ///
    /// Go equivalent: `ErrFrameTooLarge`
    #[error("dgproto: frame exceeds maximum size")]
    FrameTooLarge,

    /// Actual body lengths differ from the values declared in the header.
    ///
    /// Go equivalent: `ErrFrameLengthMismatch`
    #[error("dgproto: frame length does not match header")]
    FrameLengthMismatch,

    /// A payload would exceed the maximum frame size.
    ///
    /// Go equivalent: `ErrPayloadTooLarge`
    #[error("dgproto: payload exceeds maximum frame size")]
    PayloadTooLarge,

    /// An outer AEAD tag has an invalid length (must be exactly 16 bytes).
    ///
    /// Go equivalent: `ErrTagLength`
    #[error("dgproto: AEAD tag must be 16 bytes")]
    TagLength,

    /// Padding length exceeds the `u8` wire limit (255 bytes).
    ///
    /// Go equivalent: `ErrPaddingLength`
    #[error("dgproto: padding length exceeds 255 bytes")]
    PaddingLength,

    // ── L1: TLV ───────────────────────────────────────────────────────────────
    /// Input cannot contain a complete TLV header (< 3 bytes).
    ///
    /// Go equivalent: `ErrTLVTooShort`
    #[error("dgproto: TLV too short")]
    TlvTooShort,

    /// A TLV value or its alignment padding is incomplete.
    ///
    /// Go equivalent: `ErrTLVTruncated`
    #[error("dgproto: truncated TLV")]
    TlvTruncated,

    /// A TLV value exceeds the `u16` wire length (65535 bytes).
    ///
    /// Go equivalent: `ErrTLVValueTooLarge`
    #[error("dgproto: TLV value exceeds u16 length")]
    TlvValueTooLarge,

    /// Input exceeds the caller-supplied positive decode limit.
    ///
    /// Go equivalent: `ErrTLVDecodeLimit`
    #[error("dgproto: TLV input exceeds decode limit")]
    TlvDecodeLimit,

    /// An encoded TLV sequence exceeds `MaxTLVSequenceSize`.
    ///
    /// Go equivalent: `ErrTLVSequenceLimit`
    #[error("dgproto: TLV sequence exceeds size limit")]
    TlvSequenceLimit,

    /// A TLV sequence exceeds `MaxTLVElements`.
    ///
    /// Go equivalent: `ErrTLVElementLimit`
    #[error("dgproto: TLV sequence exceeds element limit")]
    TlvElementLimit,

    // ── L4: Messages ──────────────────────────────────────────────────────────
    /// A message payload is shorter than its required fixed prefix.
    ///
    /// Go equivalent: `ErrMessageTooShort`
    #[error("dgproto: message payload too short")]
    MessageTooShort,

    /// A message payload has an invalid encoded length.
    ///
    /// Go equivalent: `ErrMessageLength`
    #[error("dgproto: invalid message payload length")]
    MessageLength,

    /// A reserved message field is nonzero.
    ///
    /// Go equivalent: `ErrMessageReserved`
    #[error("dgproto: reserved message field must be zero")]
    MessageReserved,

    /// A message type is reserved or unavailable through the strict-MVP API.
    /// In particular, type `0x07` (`ResumptionTicket`) is always rejected.
    ///
    /// Go equivalent: `ErrMessageType`
    #[error("dgproto: message type is reserved or unsupported")]
    MessageType,

    /// An `Ack` message contains fewer than 1 or more than 255 sequence entries.
    ///
    /// Go equivalent: `ErrAckCount`
    #[error("dgproto: acknowledgement count must be between 1 and 255")]
    AckCount,

    /// A textual message field is not valid UTF-8.
    ///
    /// Go equivalent: `ErrInvalidUTF8`
    #[error("dgproto: text is not valid UTF-8")]
    InvalidUtf8,

    /// A textual message field exceeds `MaxReasonSize`.
    ///
    /// Go equivalent: `ErrReasonTooLong`
    #[error("dgproto: reason exceeds maximum length")]
    ReasonTooLong,

    /// An unknown TLV type was encountered in a typed protocol message.
    ///
    /// Go equivalent: `ErrUnknownMessageTLV`
    #[error("dgproto: unknown message TLV")]
    UnknownMessageTlv,

    /// A duplicate TLV type was encountered where uniqueness is required.
    ///
    /// Go equivalent: `ErrDuplicateMessageTLV`
    #[error("dgproto: duplicate message TLV")]
    DuplicateMessageTlv,

    /// A `SessionClose` code is outside the MVP range (0–3).
    ///
    /// Go equivalent: `ErrInvalidCloseCode`
    #[error("dgproto: invalid close code")]
    InvalidCloseCode,

    /// A handshake payload is not 4-byte aligned.
    ///
    /// Go equivalent: `ErrHandshakeAlignment`
    #[error("dgproto: handshake payload must be 4-byte aligned")]
    HandshakeAlignment,

    /// An unregistered Noise pattern value was encountered.
    ///
    /// Go equivalent: `ErrInvalidNoisePattern`
    #[error("dgproto: invalid Noise pattern")]
    InvalidNoisePattern,

    /// A Noise XX initial wrapper carries extra payload (must be empty).
    ///
    /// Go equivalent: `ErrUnexpectedNoiseData`
    #[error("dgproto: Noise XX initial payload must be empty")]
    UnexpectedNoiseData,

    /// A ping response byte is neither 0 nor 1.
    ///
    /// Go equivalent: `ErrInvalidPingResponse`
    #[error("dgproto: invalid ping response flag")]
    InvalidPingResponse,

    // ── L2: Crypto / Codec ────────────────────────────────────────────────────
    /// A traffic key is not exactly 32 bytes.
    ///
    /// Go equivalent: `ErrInvalidKeySize`
    #[error("dgproto: invalid key size: got {got}, want 32")]
    InvalidKeySize { got: usize },

    /// AEAD authenticated decryption failed.
    ///
    /// Go equivalent: `ErrAuthentication`
    #[error("dgproto: authentication failed")]
    Authentication,

    /// An encrypted frame uses sequence number zero.
    ///
    /// Go equivalent: `ErrInvalidSequence`
    #[error("dgproto: encrypted frame sequence must be nonzero")]
    InvalidSequence,

    /// An encrypted frame uses the all-zero session ID.
    ///
    /// Go equivalent: `ErrInvalidSessionID`
    #[error("dgproto: encrypted frame session ID must be nonzero")]
    InvalidSessionId,

    // ── L2: Handshake ─────────────────────────────────────────────────────────
    /// A Noise handshake operation failed or was called out of order.
    ///
    /// Go equivalent: `ErrHandshake`
    #[error("dgproto: handshake failed")]
    Handshake,

    /// The static key is missing or internally inconsistent.
    ///
    /// Go equivalent: `ErrInvalidStaticKey`
    #[error("dgproto: invalid static key")]
    InvalidStaticKey,

    // ── L3: Replay ────────────────────────────────────────────────────────────
    /// Sequence number zero was presented to the replay window.
    ///
    /// Go equivalent: `ErrReplayZero`
    #[error("dgproto: sequence number is zero")]
    ReplayZero,

    /// A sequence number has already been accepted (duplicate frame).
    ///
    /// Go equivalent: `ErrReplayDuplicate`
    #[error("dgproto: duplicate sequence number")]
    ReplayDuplicate,

    /// A sequence number is outside the replay window (frame too old).
    ///
    /// Go equivalent: `ErrReplayTooOld`
    #[error("dgproto: sequence number is outside replay window")]
    ReplayTooOld,

    /// A `ReplayToken` was invalidated by a subsequent commit.
    ///
    /// Go equivalent: `ErrReplayStale`
    #[error("dgproto: stale replay commit token")]
    ReplayStale,

    // ── L3: Session ───────────────────────────────────────────────────────────
    /// An operation was attempted on a closed or nil session.
    ///
    /// Go equivalent: `ErrSessionClosed`
    #[error("dgproto: session is closed")]
    SessionClosed,

    /// A frame carries a different session ID than the active session.
    ///
    /// Go equivalent: `ErrWrongSession`
    #[error("dgproto: frame belongs to another session")]
    WrongSession,

    /// No further send sequence number can be allocated (`u64` exhausted).
    ///
    /// Go equivalent: `ErrSequenceExhausted`
    #[error("dgproto: send sequence exhausted")]
    SequenceExhausted,

    /// A `RekeyInit` frame was generated but not yet confirmed as transmitted.
    /// All sends are blocked until `mark_rekey_sent` is called.
    ///
    /// Go equivalent: `ErrRekeyPending`
    #[error("dgproto: rekey frame has not been marked sent")]
    RekeyPending,

    // ── L3: Rekey ─────────────────────────────────────────────────────────────
    /// A rekey epoch is not the immediate successor of the current epoch.
    ///
    /// Go equivalent: `ErrInvalidEpoch`
    #[error("dgproto: invalid rekey epoch: got {got}, want {want}")]
    InvalidEpoch { got: u32, want: u32 },

    /// The `u32` rekey epoch counter cannot advance further.
    ///
    /// Go equivalent: `ErrEpochExhausted`
    #[error("dgproto: rekey epoch exhausted")]
    EpochExhausted,

    /// A `RekeyInit` key-confirmation HMAC does not match.
    ///
    /// Go equivalent: `ErrKeyConfirmFailed`
    #[error("dgproto: rekey confirmation failed")]
    KeyConfirmFailed,

    // ── L0: Transport / Connection ────────────────────────────────────────────
    /// A transport frame is shorter than the 40-byte minimum.
    ///
    /// Go equivalent: `ErrTransportFrameTooShort`
    #[error("dgproto: transport frame too short")]
    TransportFrameTooShort,

    /// A transport frame exceeds the 65535-byte maximum.
    ///
    /// Go equivalent: `ErrTransportFrameTooLarge`
    #[error("dgproto: transport frame too large")]
    TransportFrameTooLarge,

    /// The underlying transport is closed.
    ///
    /// Go equivalent: `ErrTransportClosed`
    #[error("dgproto: transport closed")]
    TransportClosed,

    /// The connection runtime has terminated.
    ///
    /// Go equivalent: `ErrConnectionClosed`
    #[error("dgproto: connection closed")]
    ConnectionClosed,

    /// The connection was idle for longer than the configured idle timeout.
    ///
    /// Go equivalent: `ErrIdleTimeout`
    #[error("dgproto: connection idle timeout")]
    IdleTimeout,

    /// An outstanding keepalive ping was not acknowledged in time.
    ///
    /// Go equivalent: `ErrKeepaliveTimeout`
    #[error("dgproto: keepalive timeout")]
    KeepaliveTimeout,

    /// The outbound queue is full; the non-blocking send was rejected.
    ///
    /// Go equivalent: `ErrOutboundQueueFull`
    #[error("dgproto: outbound queue full")]
    OutboundQueueFull,

    // ── I/O ───────────────────────────────────────────────────────────────────
    /// An unclassified I/O error from the underlying TCP socket.
    #[error("dgproto: I/O error: {0}")]
    Io(#[from] std::io::Error),
}

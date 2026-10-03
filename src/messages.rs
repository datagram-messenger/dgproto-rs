//! Typed DGProto v1 message structs and their parse/serialize implementations.
//!
//! Message type registry (MVP):
//!
//! | ID   | Name                | Direction       | Encrypted? |
//! |------|---------------------|-----------------|------------|
//! | 0x01 | HandshakeInit       | Client → Server | No         |
//! | 0x02 | HandshakeResponse   | Server → Client | No         |
//! | 0x03 | HandshakeFinish     | Client → Server | No         |
//! | 0x03 | EncryptedData       | Both            | Yes        |
//! | 0x04 | Ping / Pong         | Both            | Yes        |
//! | 0x05 | SessionClose        | Both            | Yes        |
//! | 0x06 | Ack                 | Both            | Yes        |
//! | 0x07 | (reserved)          | —               | —          |
//! | 0x08 | RekeyInit           | Both            | Yes        |
//! | 0x09 | ErrorMessage        | Both            | Yes        |
//!
//! Type 0x07 is always rejected by `Session`.
//!
//! See `docs/protocol/dgproto-v1.md` §5 for the normative specification.

use crate::{
    tlv::{decode_tlvs, encode_tlvs, Tlv, TLV_HEADER_SIZE},
    Error, AEAD_TAG_SIZE, HEADER_SIZE, MAX_FRAME_SIZE,
};

// ── Size constants (mirror dgproto-go/messages.go) ────────────────────────────

/// Fixed size of the HandshakeInit payload (4-byte reserved prefix + 32-byte ephemeral).
pub(crate) const HANDSHAKE_INIT_FIXED_SIZE: usize = 36;

/// Fixed prefix size of the HandshakeResponse payload (32-byte server ephemeral).
pub(crate) const HANDSHAKE_RESPONSE_FIXED_SIZE: usize = 32;

/// Fixed size of the HandshakeFinish payload (64-byte Noise message 3).
pub(crate) const HANDSHAKE_FINISH_FIXED_SIZE: usize = 64;

/// Fixed size of a Ping or Pong payload.
pub(crate) const PING_PONG_SIZE: usize = 9;

/// Fixed size of a RekeyInit payload.
pub(crate) const REKEY_INIT_SIZE: usize = 36;

/// Maximum number of sequence numbers in an Ack (fits in u8).
pub(crate) const MAX_ACK_SEQUENCES: usize = 255;

/// Maximum encrypted payload size (excludes header and AEAD tag).
pub(crate) const MAX_ENCRYPTED_PAYLOAD_SIZE: usize = MAX_FRAME_SIZE - HEADER_SIZE - AEAD_TAG_SIZE;

/// Maximum handshake payload size (excludes header; no outer tag).
pub(crate) const MAX_HANDSHAKE_PAYLOAD_SIZE: usize = MAX_FRAME_SIZE - HEADER_SIZE;

/// Maximum UTF-8 reason/context string size.
pub(crate) const MAX_REASON_SIZE: usize = MAX_ENCRYPTED_PAYLOAD_SIZE - 2 - TLV_HEADER_SIZE - 1;

/// TLV type for the text field in SessionClose and ErrorMessage.
const TEXT_TLV_TYPE: u8 = 1;

/// Noise pattern identifier for Noise XX (the only MVP-permitted pattern).
const NOISE_PATTERN_XX: u8 = 1;

// ── Handshake messages ────────────────────────────────────────────────────────

/// The outer wrapper around Noise message 1 (client → server, type 0x01).
///
/// Wire: `[pattern u8][reserved 3 bytes][client_ephemeral 32 bytes]` = 36 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HandshakeInit {
    /// 32-byte client ephemeral public key.
    pub client_ephemeral: [u8; 32],
    /// Additional Noise payload bytes (must be empty for MVP).
    pub noise_payload: Vec<u8>,
}

impl HandshakeInit {
    pub(crate) fn marshal_binary(&self) -> Result<Vec<u8>, Error> {
        if !self.noise_payload.is_empty() {
            return Err(Error::MessageLength);
        }
        let total = HANDSHAKE_INIT_FIXED_SIZE + self.noise_payload.len();
        if total > MAX_HANDSHAKE_PAYLOAD_SIZE {
            return Err(Error::MessageLength);
        }
        if total % 4 != 0 {
            return Err(Error::HandshakeAlignment);
        }
        let mut buf = vec![0u8; total];
        buf[0] = NOISE_PATTERN_XX;
        // bytes 1–3: reserved (zero)
        buf[4..36].copy_from_slice(&self.client_ephemeral);
        Ok(buf)
    }

    pub(crate) fn unmarshal_binary(data: &[u8]) -> Result<Self, Error> {
        if data.len() < HANDSHAKE_INIT_FIXED_SIZE {
            return Err(Error::MessageTooShort);
        }
        if data.len() > MAX_HANDSHAKE_PAYLOAD_SIZE {
            return Err(Error::MessageLength);
        }
        if data.len() % 4 != 0 {
            return Err(Error::HandshakeAlignment);
        }
        if data[0] != NOISE_PATTERN_XX {
            return Err(Error::InvalidNoisePattern);
        }
        if data[1] != 0 || data[2] != 0 || data[3] != 0 {
            return Err(Error::MessageReserved);
        }
        if data.len() != HANDSHAKE_INIT_FIXED_SIZE {
            return Err(Error::UnexpectedNoiseData);
        }
        let mut ephemeral = [0u8; 32];
        ephemeral.copy_from_slice(&data[4..36]);
        Ok(Self {
            client_ephemeral: ephemeral,
            noise_payload: vec![],
        })
    }
}

/// The outer wrapper around the server Noise flight (server → client, type 0x02).
///
/// Wire: `[server_ephemeral 32 bytes][noise_payload 64 bytes]` = 96 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HandshakeResponse {
    /// 32-byte server ephemeral public key.
    pub server_ephemeral: [u8; 32],
    /// 64-byte Noise message 2 payload.
    pub noise_payload: Vec<u8>,
}

impl HandshakeResponse {
    pub(crate) fn marshal_binary(&self) -> Result<Vec<u8>, Error> {
        let total = HANDSHAKE_RESPONSE_FIXED_SIZE + self.noise_payload.len();
        if total != HANDSHAKE_RESPONSE_FIXED_SIZE + 64 {
            return Err(Error::MessageLength);
        }
        let mut buf = vec![0u8; total];
        buf[..32].copy_from_slice(&self.server_ephemeral);
        buf[32..].copy_from_slice(&self.noise_payload);
        Ok(buf)
    }

    pub(crate) fn unmarshal_binary(data: &[u8]) -> Result<Self, Error> {
        if data.len() != HANDSHAKE_RESPONSE_FIXED_SIZE + 64 {
            return Err(Error::MessageLength);
        }
        let mut ephemeral = [0u8; 32];
        ephemeral.copy_from_slice(&data[..32]);
        Ok(Self {
            server_ephemeral: ephemeral,
            noise_payload: data[32..].to_vec(),
        })
    }
}

/// The third and final Noise XX flight (client → server, type 0x03, zero session ID).
///
/// Wire: `[noise_payload 64 bytes]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HandshakeFinish {
    /// 64-byte Noise message 3.
    pub noise_payload: Vec<u8>,
}

impl HandshakeFinish {
    pub(crate) fn marshal_binary(&self) -> Result<Vec<u8>, Error> {
        if self.noise_payload.len() != HANDSHAKE_FINISH_FIXED_SIZE {
            return Err(Error::MessageLength);
        }
        Ok(self.noise_payload.clone())
    }

    pub(crate) fn unmarshal_binary(data: &[u8]) -> Result<Self, Error> {
        if data.len() != HANDSHAKE_FINISH_FIXED_SIZE {
            return Err(Error::MessageLength);
        }
        Ok(Self {
            noise_payload: data.to_vec(),
        })
    }
}

// ── Application messages (public, re-exported from lib.rs) ───────────────────

/// An application-layer encrypted payload (message type 0x03, post-handshake).
///
/// Wire: `[stream_id u16 LE][app_message_type u8][reserved u8=0][fields TLV...]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedData {
    /// Logical stream identifier within the session.
    pub stream_id: u16,
    /// Application-defined message type byte.
    pub app_message_type: u8,
    /// Raw application payload bytes (TLV-encoded fields).
    pub fields: Vec<u8>,
}

impl EncryptedData {
    pub(crate) fn marshal_binary(&self) -> Result<Vec<u8>, Error> {
        // Parse fields as TLVs to validate and check for duplicates.
        let tlvs = decode_tlvs(&self.fields, MAX_ENCRYPTED_PAYLOAD_SIZE - 4)?;
        reject_duplicate_tlvs(&tlvs)?;
        let encoded_fields = encode_tlvs(&tlvs)?;
        if encoded_fields.len() > MAX_ENCRYPTED_PAYLOAD_SIZE - 4 {
            return Err(Error::MessageLength);
        }
        let mut buf = Vec::with_capacity(4 + encoded_fields.len());
        buf.extend_from_slice(&self.stream_id.to_le_bytes());
        buf.push(self.app_message_type);
        buf.push(0u8); // reserved
        buf.extend_from_slice(&encoded_fields);
        Ok(buf)
    }

    pub(crate) fn unmarshal_binary(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 4 {
            return Err(Error::MessageTooShort);
        }
        if data[3] != 0 {
            return Err(Error::MessageReserved);
        }
        let stream_id = u16::from_le_bytes(data[..2].try_into().expect("2 bytes"));
        let app_message_type = data[2];
        let tlvs = decode_tlvs(&data[4..], MAX_ENCRYPTED_PAYLOAD_SIZE - 4)?;
        reject_duplicate_tlvs(&tlvs)?;
        // Re-encode to get canonical fields bytes.
        let fields = encode_tlvs(&tlvs)?;
        Ok(Self {
            stream_id,
            app_message_type,
            fields,
        })
    }
}

/// A keepalive ping or pong message (type 0x04).
///
/// Wire: `[is_response u8 (0 or 1)][nonce u64 LE]` = 9 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PingPong {
    /// `true` for a pong (response), `false` for a ping (request).
    pub is_response: bool,
    /// Nonce correlating a pong with its ping.
    pub nonce: u64,
}

impl PingPong {
    pub(crate) fn marshal_binary(&self) -> Result<Vec<u8>, Error> {
        let mut buf = [0u8; PING_PONG_SIZE];
        buf[0] = if self.is_response { 1 } else { 0 };
        buf[1..].copy_from_slice(&self.nonce.to_le_bytes());
        Ok(buf.to_vec())
    }

    pub(crate) fn unmarshal_binary(data: &[u8]) -> Result<Self, Error> {
        if data.len() != PING_PONG_SIZE {
            return Err(Error::MessageLength);
        }
        if data[0] > 1 {
            return Err(Error::InvalidPingResponse);
        }
        let nonce = u64::from_le_bytes(data[1..].try_into().expect("8 bytes"));
        Ok(Self {
            is_response: data[0] == 1,
            nonce,
        })
    }
}

/// An acknowledgement message (type 0x06).
///
/// Wire: `[count u8][sequence u64 LE] × count`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack {
    /// Sequence numbers being acknowledged (1–255 entries).
    pub sequences: Vec<u64>,
}

impl Ack {
    pub(crate) fn marshal_binary(&self) -> Result<Vec<u8>, Error> {
        if self.sequences.is_empty() || self.sequences.len() > MAX_ACK_SEQUENCES {
            return Err(Error::AckCount);
        }
        let mut buf = Vec::with_capacity(1 + 8 * self.sequences.len());
        buf.push(self.sequences.len() as u8);
        for &seq in &self.sequences {
            buf.extend_from_slice(&seq.to_le_bytes());
        }
        Ok(buf)
    }

    pub(crate) fn unmarshal_binary(data: &[u8]) -> Result<Self, Error> {
        if data.is_empty() {
            return Err(Error::MessageTooShort);
        }
        let count = data[0] as usize;
        if count < 1 || count > MAX_ACK_SEQUENCES {
            return Err(Error::AckCount);
        }
        if data.len() != 1 + 8 * count {
            return Err(Error::MessageLength);
        }
        let mut sequences = Vec::with_capacity(count);
        for i in 0..count {
            let seq = u64::from_le_bytes(
                data[1 + 8 * i..1 + 8 * (i + 1)]
                    .try_into()
                    .expect("8 bytes"),
            );
            sequences.push(seq);
        }
        Ok(Self { sequences })
    }
}

/// A rekey-init message (type 0x08).
///
/// Wire: `[epoch u32 LE][key_confirm 32 bytes]` = 36 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RekeyInit {
    /// Proposed new epoch number (must be current + 1).
    pub epoch: u32,
    /// HMAC-SHA256 key confirmation for the new epoch.
    pub key_confirm: [u8; 32],
}

impl RekeyInit {
    pub(crate) fn marshal_binary(&self) -> Result<Vec<u8>, Error> {
        if self.epoch == 0 {
            return Err(Error::InvalidEpoch { got: 0, want: 1 });
        }
        let mut buf = [0u8; REKEY_INIT_SIZE];
        buf[..4].copy_from_slice(&self.epoch.to_le_bytes());
        buf[4..].copy_from_slice(&self.key_confirm);
        Ok(buf.to_vec())
    }

    pub(crate) fn unmarshal_binary(data: &[u8]) -> Result<Self, Error> {
        if data.len() != REKEY_INIT_SIZE {
            return Err(Error::MessageLength);
        }
        let epoch = u32::from_le_bytes(data[..4].try_into().expect("4 bytes"));
        if epoch == 0 {
            return Err(Error::InvalidEpoch { got: 0, want: 1 });
        }
        let mut confirm = [0u8; 32];
        confirm.copy_from_slice(&data[4..]);
        Ok(Self {
            epoch,
            key_confirm: confirm,
        })
    }
}

/// A session-close message (type 0x05).
///
/// Wire: `[code u16 LE][text TLV (optional)]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionClose {
    /// Close code (0–3 for MVP).
    pub code: CloseCode,
    /// Optional human-readable reason (valid UTF-8, ≤ `MAX_REASON_SIZE` bytes).
    pub reason: String,
}

impl SessionClose {
    pub(crate) fn marshal_binary(&self) -> Result<Vec<u8>, Error> {
        marshal_text_message(self.code as u16, &self.reason)
    }

    pub(crate) fn unmarshal_binary(data: &[u8]) -> Result<Self, Error> {
        let (code_u16, text) = unmarshal_text_message(data)?;
        if code_u16 > 3 {
            return Err(Error::InvalidCloseCode);
        }
        let code = CloseCode::try_from(code_u16 as u8)?;
        Ok(Self { code, reason: text })
    }
}

/// An application-layer error message (type 0x09).
///
/// Wire: `[code u16 LE][text TLV (optional)]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorMessage {
    /// Error code (u16 on the wire).
    pub code: u8,
    /// Human-readable reason string (valid UTF-8, ≤ `MAX_REASON_SIZE` bytes).
    pub reason: String,
}

impl ErrorMessage {
    pub(crate) fn marshal_binary(&self) -> Result<Vec<u8>, Error> {
        marshal_text_message(self.code as u16, &self.reason)
    }

    pub(crate) fn unmarshal_binary(data: &[u8]) -> Result<Self, Error> {
        let (code_u16, text) = unmarshal_text_message(data)?;
        Ok(Self {
            code: code_u16 as u8,
            reason: text,
        })
    }
}

/// MVP session-close codes (0–3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CloseCode {
    /// Normal closure.
    Normal = 0,
    /// Closed due to an error.
    Error = 1,
    /// Closed due to a protocol violation.
    Protocol = 2,
    /// Closed due to resource exhaustion.
    ResourceLimit = 3,
}

impl TryFrom<u8> for CloseCode {
    type Error = crate::Error;
    fn try_from(v: u8) -> Result<Self, crate::Error> {
        match v {
            0 => Ok(CloseCode::Normal),
            1 => Ok(CloseCode::Error),
            2 => Ok(CloseCode::Protocol),
            3 => Ok(CloseCode::ResourceLimit),
            _ => Err(crate::Error::InvalidCloseCode),
        }
    }
}

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Encode a code + optional UTF-8 text into the wire format used by
/// `SessionClose` and `ErrorMessage`.
fn marshal_text_message(code: u16, text: &str) -> Result<Vec<u8>, Error> {
    if !text.is_empty() && !std::str::from_utf8(text.as_bytes()).is_ok() {
        return Err(Error::InvalidUtf8);
    }
    if text.len() > MAX_REASON_SIZE {
        return Err(Error::ReasonTooLong);
    }
    let mut buf = Vec::with_capacity(2 + if text.is_empty() { 0 } else { 8 + text.len() });
    buf.extend_from_slice(&code.to_le_bytes());
    if !text.is_empty() {
        let tlv = Tlv::new(TEXT_TLV_TYPE, text.as_bytes())?;
        buf.extend_from_slice(&tlv.marshal_binary()?);
    }
    Ok(buf)
}

/// Decode the wire format used by `SessionClose` and `ErrorMessage`.
fn unmarshal_text_message(data: &[u8]) -> Result<(u16, String), Error> {
    if data.len() < 2 {
        return Err(Error::MessageTooShort);
    }
    let code = u16::from_le_bytes(data[..2].try_into().expect("2 bytes"));
    if data.len() == 2 {
        return Ok((code, String::new()));
    }
    // Compute the max_bytes limit for the text TLV.
    let text_limit = align4(TLV_HEADER_SIZE + MAX_REASON_SIZE);
    let tlvs = decode_tlvs(&data[2..], text_limit)?;
    reject_duplicate_tlvs(&tlvs)?;
    if tlvs.len() != 1 {
        return Err(Error::UnknownMessageTlv);
    }
    if tlvs[0].typ != TEXT_TLV_TYPE {
        return Err(Error::UnknownMessageTlv);
    }
    let text = std::str::from_utf8(&tlvs[0].value)
        .map_err(|_| Error::InvalidUtf8)?
        .to_owned();
    Ok((code, text))
}

/// Reject a TLV slice that contains duplicate type bytes.
fn reject_duplicate_tlvs(tlvs: &[Tlv]) -> Result<(), Error> {
    let mut seen = [false; 256];
    for t in tlvs {
        if seen[t.typ as usize] {
            return Err(Error::DuplicateMessageTlv);
        }
        seen[t.typ as usize] = true;
    }
    Ok(())
}

/// Round `n` up to the next multiple of 4.
#[inline]
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── HandshakeInit ─────────────────────────────────────────────────────────

    #[test]
    fn test_messages_handshake_init_roundtrip() {
        let m = HandshakeInit {
            client_ephemeral: [0xABu8; 32],
            noise_payload: vec![],
        };
        let wire = m.marshal_binary().expect("marshal");
        assert_eq!(wire.len(), HANDSHAKE_INIT_FIXED_SIZE);
        assert_eq!(wire[0], NOISE_PATTERN_XX);
        assert_eq!(wire[1..4], [0, 0, 0]);
        assert_eq!(&wire[4..36], &[0xABu8; 32]);
        let m2 = HandshakeInit::unmarshal_binary(&wire).expect("unmarshal");
        assert_eq!(m, m2);
    }

    #[test]
    fn test_messages_handshake_init_rejects_wrong_pattern() {
        let m = HandshakeInit {
            client_ephemeral: [0u8; 32],
            noise_payload: vec![],
        };
        let mut wire = m.marshal_binary().expect("marshal");
        wire[0] = 2; // NoisePatternIK
        assert!(matches!(
            HandshakeInit::unmarshal_binary(&wire),
            Err(Error::InvalidNoisePattern)
        ));
    }

    #[test]
    fn test_messages_handshake_init_rejects_nonzero_reserved() {
        let m = HandshakeInit {
            client_ephemeral: [0u8; 32],
            noise_payload: vec![],
        };
        let mut wire = m.marshal_binary().expect("marshal");
        wire[1] = 0xFF;
        assert!(matches!(
            HandshakeInit::unmarshal_binary(&wire),
            Err(Error::MessageReserved)
        ));
    }

    #[test]
    fn test_messages_handshake_init_too_short() {
        assert!(matches!(
            HandshakeInit::unmarshal_binary(&[0u8; 10]),
            Err(Error::MessageTooShort)
        ));
    }

    // ── HandshakeResponse ─────────────────────────────────────────────────────

    #[test]
    fn test_messages_handshake_response_roundtrip() {
        let m = HandshakeResponse {
            server_ephemeral: [0xCDu8; 32],
            noise_payload: vec![0xEFu8; 64],
        };
        let wire = m.marshal_binary().expect("marshal");
        assert_eq!(wire.len(), 96);
        let m2 = HandshakeResponse::unmarshal_binary(&wire).expect("unmarshal");
        assert_eq!(m, m2);
    }

    #[test]
    fn test_messages_handshake_response_wrong_length() {
        assert!(matches!(
            HandshakeResponse::unmarshal_binary(&[0u8; 64]),
            Err(Error::MessageLength)
        ));
    }

    // ── HandshakeFinish ───────────────────────────────────────────────────────

    #[test]
    fn test_messages_handshake_finish_roundtrip() {
        let m = HandshakeFinish {
            noise_payload: vec![0x11u8; 64],
        };
        let wire = m.marshal_binary().expect("marshal");
        assert_eq!(wire.len(), 64);
        let m2 = HandshakeFinish::unmarshal_binary(&wire).expect("unmarshal");
        assert_eq!(m, m2);
    }

    #[test]
    fn test_messages_handshake_finish_wrong_length() {
        assert!(matches!(
            HandshakeFinish::unmarshal_binary(&[0u8; 32]),
            Err(Error::MessageLength)
        ));
    }

    // ── PingPong ──────────────────────────────────────────────────────────────

    #[test]
    fn test_messages_ping_roundtrip() {
        let m = PingPong {
            is_response: false,
            nonce: 0xDEADBEEF_CAFEBABE,
        };
        let wire = m.marshal_binary().expect("marshal");
        assert_eq!(wire.len(), PING_PONG_SIZE);
        assert_eq!(wire[0], 0);
        let m2 = PingPong::unmarshal_binary(&wire).expect("unmarshal");
        assert_eq!(m, m2);
    }

    #[test]
    fn test_messages_pong_roundtrip() {
        let m = PingPong {
            is_response: true,
            nonce: 42,
        };
        let wire = m.marshal_binary().expect("marshal");
        assert_eq!(wire[0], 1);
        let m2 = PingPong::unmarshal_binary(&wire).expect("unmarshal");
        assert_eq!(m, m2);
    }

    #[test]
    fn test_messages_ping_invalid_response_byte() {
        let mut wire = PingPong {
            is_response: false,
            nonce: 0,
        }
        .marshal_binary()
        .expect("marshal");
        wire[0] = 2;
        assert!(matches!(
            PingPong::unmarshal_binary(&wire),
            Err(Error::InvalidPingResponse)
        ));
    }

    #[test]
    fn test_messages_ping_wrong_length() {
        assert!(matches!(
            PingPong::unmarshal_binary(&[0u8; 8]),
            Err(Error::MessageLength)
        ));
    }

    // ── Ack ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_messages_ack_roundtrip() {
        let m = Ack {
            sequences: vec![1, 2, 3, 100],
        };
        let wire = m.marshal_binary().expect("marshal");
        assert_eq!(wire[0], 4);
        let m2 = Ack::unmarshal_binary(&wire).expect("unmarshal");
        assert_eq!(m, m2);
    }

    #[test]
    fn test_messages_ack_empty_sequences() {
        let m = Ack { sequences: vec![] };
        assert!(matches!(m.marshal_binary(), Err(Error::AckCount)));
    }

    #[test]
    fn test_messages_ack_too_many_sequences() {
        let m = Ack {
            sequences: vec![1u64; 256],
        };
        assert!(matches!(m.marshal_binary(), Err(Error::AckCount)));
    }

    #[test]
    fn test_messages_ack_length_mismatch() {
        let m = Ack {
            sequences: vec![1, 2],
        };
        let mut wire = m.marshal_binary().expect("marshal");
        wire[0] = 3; // claim 3 sequences but only 2 are present
        assert!(matches!(
            Ack::unmarshal_binary(&wire),
            Err(Error::MessageLength)
        ));
    }

    // ── RekeyInit ─────────────────────────────────────────────────────────────

    #[test]
    fn test_messages_rekey_init_roundtrip() {
        let m = RekeyInit {
            epoch: 2,
            key_confirm: [0x55u8; 32],
        };
        let wire = m.marshal_binary().expect("marshal");
        assert_eq!(wire.len(), REKEY_INIT_SIZE);
        let m2 = RekeyInit::unmarshal_binary(&wire).expect("unmarshal");
        assert_eq!(m, m2);
    }

    #[test]
    fn test_messages_rekey_init_epoch_zero_rejected() {
        let m = RekeyInit {
            epoch: 0,
            key_confirm: [0u8; 32],
        };
        assert!(matches!(
            m.marshal_binary(),
            Err(Error::InvalidEpoch { .. })
        ));
    }

    #[test]
    fn test_messages_rekey_init_wrong_length() {
        assert!(matches!(
            RekeyInit::unmarshal_binary(&[0u8; 10]),
            Err(Error::MessageLength)
        ));
    }

    // ── SessionClose ──────────────────────────────────────────────────────────

    #[test]
    fn test_messages_session_close_roundtrip_no_reason() {
        let m = SessionClose {
            code: CloseCode::Normal,
            reason: String::new(),
        };
        let wire = m.marshal_binary().expect("marshal");
        assert_eq!(wire.len(), 2);
        let m2 = SessionClose::unmarshal_binary(&wire).expect("unmarshal");
        assert_eq!(m, m2);
    }

    #[test]
    fn test_messages_session_close_roundtrip_with_reason() {
        let m = SessionClose {
            code: CloseCode::Error,
            reason: "bye".to_owned(),
        };
        let wire = m.marshal_binary().expect("marshal");
        let m2 = SessionClose::unmarshal_binary(&wire).expect("unmarshal");
        assert_eq!(m, m2);
    }

    #[test]
    fn test_messages_session_close_invalid_code() {
        // Manually craft a wire with code = 4.
        let wire = [4u8, 0u8]; // code = 4 LE
        assert!(matches!(
            SessionClose::unmarshal_binary(&wire),
            Err(Error::InvalidCloseCode)
        ));
    }

    // ── ErrorMessage ──────────────────────────────────────────────────────────

    #[test]
    fn test_messages_error_message_roundtrip() {
        let m = ErrorMessage {
            code: 7,
            reason: "oops".to_owned(),
        };
        let wire = m.marshal_binary().expect("marshal");
        let m2 = ErrorMessage::unmarshal_binary(&wire).expect("unmarshal");
        assert_eq!(m, m2);
    }

    #[test]
    fn test_messages_error_message_no_reason() {
        let m = ErrorMessage {
            code: 0,
            reason: String::new(),
        };
        let wire = m.marshal_binary().expect("marshal");
        assert_eq!(wire.len(), 2);
        let m2 = ErrorMessage::unmarshal_binary(&wire).expect("unmarshal");
        assert_eq!(m, m2);
    }

    // ── EncryptedData ─────────────────────────────────────────────────────────

    #[test]
    fn test_messages_encrypted_data_roundtrip_empty_fields() {
        let m = EncryptedData {
            stream_id: 1,
            app_message_type: 0x42,
            fields: vec![],
        };
        let wire = m.marshal_binary().expect("marshal");
        assert_eq!(wire.len(), 4);
        assert_eq!(wire[3], 0); // reserved byte
        let m2 = EncryptedData::unmarshal_binary(&wire).expect("unmarshal");
        assert_eq!(m, m2);
    }

    #[test]
    fn test_messages_encrypted_data_reserved_byte_rejected() {
        let m = EncryptedData {
            stream_id: 1,
            app_message_type: 0x01,
            fields: vec![],
        };
        let mut wire = m.marshal_binary().expect("marshal");
        wire[3] = 0xFF; // reserved byte must be zero
        assert!(matches!(
            EncryptedData::unmarshal_binary(&wire),
            Err(Error::MessageReserved)
        ));
    }
}

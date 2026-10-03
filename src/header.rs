//! 40-byte fixed DGProto v1 frame header.
//!
//! Wire layout (all multi-byte fields little-endian):
//!
//! ```text
//! Offset  Size  Field
//! ──────  ────  ─────────────────────────────────────────────────
//!  0       4    Magic: b"DGP1" (0x44 0x47 0x50 0x31)
//!  4       1    Version: 0x01
//!  5       1    Flags (bit 1 = FlagPadding; bits 0,2+ reserved)
//!  6       1    MessageType (0x01–0x09; 0x07 reserved/rejected)
//!  7       1    Reserved (must be zero on send; preserved on receive)
//!  8      16    SessionID (zero for handshake frames)
//! 24       8    Sequence (u64 LE; zero for handshake frames)
//! 32       4    PayloadLength (u32 LE)
//! 36       1    PadLength (u8; 0–255)
//! 37       3    Reserved (must be zero on send; preserved on receive)
//! ──────  ────
//! Total: 40 bytes
//! ```
//!
//! See `docs/protocol/dgproto-v1.md` §3 for the normative specification.

use crate::Error;

/// DGProto v1 magic bytes: `b"DGP1"`.
pub(crate) const MAGIC: [u8; 4] = [b'D', b'G', b'P', b'1'];

/// Protocol version encoded in every DGProto v1 header.
pub(crate) const VERSION: u8 = 1;

/// Only `FlagPadding` may be set by MVP senders.
const MVP_SENDER_FLAGS: u8 = Flags::PADDING;

/// Frame flag bits.
pub(crate) struct Flags;

impl Flags {
    /// Bit 0 — reserved for post-MVP obfuscation. MUST NOT be sent.
    #[allow(dead_code)]
    pub(crate) const OBFUSCATED: u8 = 1 << 0;
    /// Bit 1 — set iff `pad_length > 0`.
    pub(crate) const PADDING: u8 = 1 << 1;
    /// Bit 2 — reserved for post-MVP 0-RTT. MUST NOT be sent.
    #[allow(dead_code)]
    pub(crate) const ZERO_RTT: u8 = 1 << 2;
}

/// Message type identifier carried in every DGProto v1 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum MessageType {
    HandshakeInit = 0x01,
    HandshakeResponse = 0x02,
    /// Used for both `HandshakeFinish` (zero session ID) and `EncryptedData`
    /// (non-zero session ID) — distinguished by context.
    EncryptedData = 0x03,
    PingPong = 0x04,
    SessionClose = 0x05,
    Ack = 0x06,
    // 0x07 is reserved and always rejected.
    RekeyInit = 0x08,
    Error = 0x09,
}

impl MessageType {
    /// Parse a raw byte into a `MessageType`.
    ///
    /// Returns `Err(Error::MessageType)` for `0x07` (reserved) and any
    /// unrecognised value.
    pub(crate) fn from_u8(v: u8) -> Result<Self, Error> {
        match v {
            0x01 => Ok(Self::HandshakeInit),
            0x02 => Ok(Self::HandshakeResponse),
            0x03 => Ok(Self::EncryptedData),
            0x04 => Ok(Self::PingPong),
            0x05 => Ok(Self::SessionClose),
            0x06 => Ok(Self::Ack),
            0x08 => Ok(Self::RekeyInit),
            0x09 => Ok(Self::Error),
            _ => Err(Error::MessageType),
        }
    }

    /// Returns `true` for message types that carry an outer AEAD tag.
    ///
    /// `HandshakeInit` (0x01) and `HandshakeResponse` (0x02) are the only
    /// types that do NOT carry a tag.
    #[inline]
    pub(crate) fn has_aead_tag(self) -> bool {
        !matches!(self, Self::HandshakeInit | Self::HandshakeResponse)
    }
}

/// The 40-byte fixed DGProto v1 frame header.
///
/// `reserved` preserves the received wire octets at offsets 7 and 37–39 so
/// that AEAD authenticates the exact header. Senders must leave `reserved`
/// zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Header {
    /// Protocol version — always `VERSION` (0x01).
    pub version: u8,
    /// Frame flags byte (see `Flags` constants).
    pub flags: u8,
    /// Message type.
    pub msg_type: MessageType,
    /// Reserved bytes at offsets 7 and 37–39 (4 bytes total).
    /// Senders write zero; receivers preserve and authenticate.
    pub reserved: [u8; 4],
    /// Session identifier (16 bytes; zero for handshake frames).
    pub session_id: [u8; 16],
    /// Per-direction sequence number (zero for handshake frames).
    pub sequence: u64,
    /// Byte length of the payload (ciphertext only, excluding tag and padding).
    pub payload_length: u32,
    /// Byte length of the cleartext random padding (0–255).
    pub pad_length: u8,
}

impl Header {
    /// Construct a new outbound header.
    ///
    /// `FlagPadding` is set automatically when `pad_length > 0`.
    pub(crate) fn new(
        msg_type: MessageType,
        session_id: [u8; 16],
        sequence: u64,
        payload_length: u32,
        pad_length: u8,
    ) -> Self {
        let flags = if pad_length != 0 { Flags::PADDING } else { 0 };
        Self {
            version: VERSION,
            flags,
            msg_type,
            reserved: [0u8; 4],
            session_id,
            sequence,
            payload_length,
            pad_length,
        }
    }

    /// Total wire-frame size derived from this header (header + payload + optional
    /// tag + padding). DGProto v1 has no outer length prefix.
    pub(crate) fn frame_size(&self) -> u64 {
        let mut size =
            crate::HEADER_SIZE as u64 + self.payload_length as u64 + self.pad_length as u64;
        if self.msg_type.has_aead_tag() {
            size += crate::AEAD_TAG_SIZE as u64;
        }
        size
    }

    /// Validate an **outbound** header (strict: reserved flag bits must be zero).
    pub(crate) fn validate(&self) -> Result<(), Error> {
        self.validate_common()?;
        // Outbound: only FlagPadding is permitted.
        if self.flags & !MVP_SENDER_FLAGS != 0 {
            return Err(Error::ReservedFlags);
        }
        Ok(())
    }

    /// Validate an **inbound** header (lenient: reserved flag bits are preserved).
    pub(crate) fn validate_receive(&self) -> Result<(), Error> {
        self.validate_common()
    }

    fn validate_common(&self) -> Result<(), Error> {
        if self.version != VERSION {
            return Err(Error::UnsupportedVersion { got: self.version });
        }
        let has_padding_flag = self.flags & Flags::PADDING != 0;
        if has_padding_flag != (self.pad_length != 0) {
            return Err(Error::PaddingFlag);
        }
        if self.frame_size() > crate::MAX_FRAME_SIZE as u64 {
            return Err(Error::FrameTooLarge);
        }
        Ok(())
    }

    /// Encode the header to its 40-byte wire representation.
    ///
    /// Validates the header before encoding. Use `marshal_binary_raw` to skip
    /// validation (for receive-path re-encoding where reserved bytes must be
    /// preserved verbatim).
    pub(crate) fn marshal_binary(&self) -> Result<[u8; crate::HEADER_SIZE], Error> {
        self.validate()?;
        Ok(self.marshal_binary_raw())
    }

    /// Encode the header to its 40-byte wire representation **without**
    /// outbound validation. Used on the receive path to reconstruct the exact
    /// authenticated bytes (including preserved reserved bytes).
    pub(crate) fn marshal_binary_raw(&self) -> [u8; crate::HEADER_SIZE] {
        let mut buf = [0u8; crate::HEADER_SIZE];
        buf[0..4].copy_from_slice(&MAGIC);
        buf[4] = self.version;
        buf[5] = self.flags;
        buf[6] = self.msg_type as u8;
        buf[7] = self.reserved[0];
        buf[8..24].copy_from_slice(&self.session_id);
        buf[24..32].copy_from_slice(&self.sequence.to_le_bytes());
        buf[32..36].copy_from_slice(&self.payload_length.to_le_bytes());
        buf[36] = self.pad_length;
        buf[37] = self.reserved[1];
        buf[38] = self.reserved[2];
        buf[39] = self.reserved[3];
        buf
    }

    /// Decode a 40-byte wire buffer into a `Header`.
    ///
    /// Validates magic and version. Preserves reserved bytes verbatim.
    pub(crate) fn unmarshal_binary(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < crate::HEADER_SIZE {
            return Err(Error::HeaderTooShort);
        }
        let buf = &buf[..crate::HEADER_SIZE];

        if buf[0..4] != MAGIC {
            return Err(Error::InvalidMagic);
        }
        let version = buf[4];
        if version != VERSION {
            return Err(Error::UnsupportedVersion { got: version });
        }

        let flags = buf[5];
        let msg_type = MessageType::from_u8(buf[6])?;
        let reserved0 = buf[7];

        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&buf[8..24]);

        let sequence = u64::from_le_bytes(buf[24..32].try_into().expect("slice is 8 bytes"));
        let payload_length = u32::from_le_bytes(buf[32..36].try_into().expect("slice is 4 bytes"));
        let pad_length = buf[36];
        let reserved1 = buf[37];
        let reserved2 = buf[38];
        let reserved3 = buf[39];

        let header = Self {
            version,
            flags,
            msg_type,
            reserved: [reserved0, reserved1, reserved2, reserved3],
            session_id,
            sequence,
            payload_length,
            pad_length,
        };

        // Validate inbound invariants (lenient on reserved flag bits).
        header.validate_receive()?;
        Ok(header)
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header() -> Header {
        Header::new(MessageType::EncryptedData, [0x11u8; 16], 42, 100, 0)
    }

    #[test]
    fn test_header_roundtrip_basic() {
        let h = make_header();
        let wire = h.marshal_binary().expect("marshal");
        assert_eq!(wire.len(), crate::HEADER_SIZE);
        let h2 = Header::unmarshal_binary(&wire).expect("unmarshal");
        assert_eq!(h, h2);
    }

    #[test]
    fn test_header_magic_bytes() {
        let h = make_header();
        let wire = h.marshal_binary().expect("marshal");
        assert_eq!(&wire[0..4], b"DGP1");
    }

    #[test]
    fn test_header_version_byte() {
        let h = make_header();
        let wire = h.marshal_binary().expect("marshal");
        assert_eq!(wire[4], 1);
    }

    #[test]
    fn test_header_little_endian_sequence() {
        let h = Header::new(
            MessageType::EncryptedData,
            [0u8; 16],
            0x0102030405060708,
            0,
            0,
        );
        let wire = h.marshal_binary().expect("marshal");
        assert_eq!(
            &wire[24..32],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
    }

    #[test]
    fn test_header_padding_flag_auto_set() {
        let h = Header::new(MessageType::EncryptedData, [0u8; 16], 1, 10, 5);
        assert_eq!(h.flags & Flags::PADDING, Flags::PADDING);
        let wire = h.marshal_binary().expect("marshal");
        assert_eq!(wire[5] & Flags::PADDING, Flags::PADDING);
    }

    #[test]
    fn test_header_padding_flag_not_set_when_zero() {
        let h = Header::new(MessageType::EncryptedData, [0u8; 16], 1, 10, 0);
        assert_eq!(h.flags & Flags::PADDING, 0);
    }

    #[test]
    fn test_header_unmarshal_invalid_magic() {
        let mut wire = make_header().marshal_binary().expect("marshal");
        wire[0] = 0xFF;
        assert!(matches!(
            Header::unmarshal_binary(&wire),
            Err(Error::InvalidMagic)
        ));
    }

    #[test]
    fn test_header_unmarshal_unsupported_version() {
        let mut wire = make_header().marshal_binary().expect("marshal");
        wire[4] = 2;
        assert!(matches!(
            Header::unmarshal_binary(&wire),
            Err(Error::UnsupportedVersion { got: 2 })
        ));
    }

    #[test]
    fn test_header_unmarshal_too_short() {
        let wire = [0u8; 10];
        assert!(matches!(
            Header::unmarshal_binary(&wire),
            Err(Error::HeaderTooShort)
        ));
    }

    #[test]
    fn test_header_unmarshal_reserved_msg_type_0x07() {
        let mut wire = make_header().marshal_binary().expect("marshal");
        wire[6] = 0x07;
        assert!(matches!(
            Header::unmarshal_binary(&wire),
            Err(Error::MessageType)
        ));
    }

    #[test]
    fn test_header_validate_reserved_flags() {
        let mut h = make_header();
        h.flags = Flags::OBFUSCATED; // reserved bit — must be rejected on send
        assert!(matches!(h.validate(), Err(Error::ReservedFlags)));
    }

    #[test]
    fn test_header_validate_receive_allows_reserved_flags() {
        let mut h = make_header();
        h.flags = Flags::OBFUSCATED; // reserved bit — allowed on receive
        assert!(h.validate_receive().is_ok());
    }

    #[test]
    fn test_header_padding_flag_mismatch_flag_set_len_zero() {
        let mut h = make_header();
        h.flags = Flags::PADDING;
        h.pad_length = 0;
        assert!(matches!(h.validate_receive(), Err(Error::PaddingFlag)));
    }

    #[test]
    fn test_header_padding_flag_mismatch_flag_clear_len_nonzero() {
        let mut h = make_header();
        h.flags = 0;
        h.pad_length = 5;
        assert!(matches!(h.validate_receive(), Err(Error::PaddingFlag)));
    }

    #[test]
    fn test_header_frame_size_no_tag_for_handshake_init() {
        let h = Header::new(MessageType::HandshakeInit, [0u8; 16], 0, 36, 0);
        // No AEAD tag for handshake init.
        assert_eq!(h.frame_size(), (crate::HEADER_SIZE + 36) as u64);
    }

    #[test]
    fn test_header_frame_size_with_tag_for_encrypted_data() {
        let h = Header::new(MessageType::EncryptedData, [0u8; 16], 1, 50, 0);
        assert_eq!(
            h.frame_size(),
            (crate::HEADER_SIZE + 50 + crate::AEAD_TAG_SIZE) as u64
        );
    }

    #[test]
    fn test_header_reserved_bytes_preserved_on_receive() {
        let mut wire = make_header().marshal_binary().expect("marshal");
        // Set reserved bytes at offsets 7, 37, 38, 39.
        wire[7] = 0xAB;
        wire[37] = 0xCD;
        wire[38] = 0xEF;
        wire[39] = 0x12;
        let h = Header::unmarshal_binary(&wire).expect("unmarshal");
        assert_eq!(h.reserved, [0xAB, 0xCD, 0xEF, 0x12]);
        // Re-encoding must reproduce the exact same bytes.
        let wire2 = h.marshal_binary_raw();
        assert_eq!(wire2[7], 0xAB);
        assert_eq!(wire2[37], 0xCD);
        assert_eq!(wire2[38], 0xEF);
        assert_eq!(wire2[39], 0x12);
    }

    #[test]
    fn test_message_type_from_u8_all_valid() {
        for (byte, expected) in [
            (0x01u8, MessageType::HandshakeInit),
            (0x02, MessageType::HandshakeResponse),
            (0x03, MessageType::EncryptedData),
            (0x04, MessageType::PingPong),
            (0x05, MessageType::SessionClose),
            (0x06, MessageType::Ack),
            (0x08, MessageType::RekeyInit),
            (0x09, MessageType::Error),
        ] {
            assert_eq!(
                MessageType::from_u8(byte).expect("valid"),
                expected,
                "byte 0x{byte:02x}"
            );
        }
    }

    #[test]
    fn test_message_type_from_u8_reserved_0x07() {
        assert!(matches!(
            MessageType::from_u8(0x07),
            Err(Error::MessageType)
        ));
    }

    #[test]
    fn test_message_type_from_u8_unknown() {
        assert!(matches!(
            MessageType::from_u8(0xFF),
            Err(Error::MessageType)
        ));
    }

    #[test]
    fn test_has_aead_tag() {
        assert!(!MessageType::HandshakeInit.has_aead_tag());
        assert!(!MessageType::HandshakeResponse.has_aead_tag());
        assert!(MessageType::EncryptedData.has_aead_tag());
        assert!(MessageType::PingPong.has_aead_tag());
        assert!(MessageType::SessionClose.has_aead_tag());
        assert!(MessageType::Ack.has_aead_tag());
        assert!(MessageType::RekeyInit.has_aead_tag());
        assert!(MessageType::Error.has_aead_tag());
    }
}

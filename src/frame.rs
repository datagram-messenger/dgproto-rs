//! DGProto v1 frame: Header + payload + AEAD tag + padding.
//!
//! Wire order: `[40-byte header][payload][16-byte AEAD tag*][padding]`
//! (* tag is absent for HandshakeInit and HandshakeResponse frames)
//!
//! Frame length is derived from the header — there is no outer length prefix.
//!
//! See `docs/protocol/dgproto-v1.md` §3 for the normative specification.

use crate::{
    header::{Header, MessageType},
    Error, AEAD_TAG_SIZE, HEADER_SIZE, MAX_FRAME_SIZE,
};

/// A complete DGProto v1 frame.
///
/// `payload` contains the ciphertext only (for encrypted frames) or the raw
/// Noise message bytes (for handshake frames). `tag` is the 16-byte AEAD
/// authentication tag; it is all-zero and ignored for handshake frames.
/// `padding` is the cleartext random padding (0–255 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Frame {
    pub header: Header,
    /// Ciphertext payload (or Noise message for handshake frames).
    pub payload: Vec<u8>,
    /// AEAD authentication tag (16 bytes). Zero for handshake frames.
    pub tag: [u8; AEAD_TAG_SIZE],
    /// Cleartext random padding (0–255 bytes).
    pub padding: Vec<u8>,
}

impl Frame {
    /// Construct a new frame, copying all caller-owned byte slices.
    ///
    /// For handshake frames (`HandshakeInit`, `HandshakeResponse`) `tag` must
    /// be empty or all-zero (no outer AEAD tag on the wire). For all other
    /// types `tag` must be exactly `AEAD_TAG_SIZE` bytes.
    pub(crate) fn new(
        msg_type: MessageType,
        session_id: [u8; 16],
        sequence: u64,
        payload: &[u8],
        tag: &[u8],
        padding: &[u8],
    ) -> Result<Self, Error> {
        if padding.len() > 255 {
            return Err(Error::PaddingLength);
        }
        if payload.len() > u32::MAX as usize {
            return Err(Error::PayloadTooLarge);
        }

        let header = Header::new(
            msg_type,
            session_id,
            sequence,
            payload.len() as u32,
            padding.len() as u8,
        );

        let mut tag_arr = [0u8; AEAD_TAG_SIZE];
        if header.msg_type.has_aead_tag() {
            if tag.len() != AEAD_TAG_SIZE {
                return Err(Error::TagLength);
            }
            tag_arr.copy_from_slice(tag);
        } else {
            // Handshake frames: accept empty tag or all-zero tag; never emit one.
            if !tag.is_empty() && (tag.len() != AEAD_TAG_SIZE || !tag.iter().all(|&b| b == 0)) {
                return Err(Error::TagLength);
            }
        }

        if header.frame_size() > MAX_FRAME_SIZE as u64 {
            return Err(Error::PayloadTooLarge);
        }

        Ok(Self {
            header,
            payload: payload.to_vec(),
            tag: tag_arr,
            padding: padding.to_vec(),
        })
    }

    /// Validate an **outbound** frame (strict flag rules).
    pub(crate) fn validate(&self) -> Result<(), Error> {
        self.header.validate()?;
        self.validate_lengths()
    }

    /// Validate an **inbound** frame (lenient flag rules).
    pub(crate) fn validate_receive(&self) -> Result<(), Error> {
        self.header.validate_receive()?;
        self.validate_lengths()
    }

    fn validate_lengths(&self) -> Result<(), Error> {
        if self.payload.len() != self.header.payload_length as usize {
            return Err(Error::FrameLengthMismatch);
        }
        if self.padding.len() != self.header.pad_length as usize {
            return Err(Error::FrameLengthMismatch);
        }
        Ok(())
    }

    /// Encode the frame to its canonical wire representation.
    ///
    /// Wire order: `[40-byte header][payload][16-byte AEAD tag*][padding]`
    pub(crate) fn marshal_binary(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let header_bytes = self.header.marshal_binary()?;
        let total = self.header.frame_size() as usize;
        let mut buf = Vec::with_capacity(total);
        buf.extend_from_slice(&header_bytes);
        buf.extend_from_slice(&self.payload);
        if self.header.msg_type.has_aead_tag() {
            buf.extend_from_slice(&self.tag);
        }
        buf.extend_from_slice(&self.padding);
        Ok(buf)
    }

    /// Decode exactly one frame from `wire`.
    ///
    /// The buffer must contain at least `HEADER_SIZE` bytes. The body length
    /// is derived from the header — there is no outer length prefix.
    pub(crate) fn unmarshal_binary(wire: &[u8]) -> Result<Self, Error> {
        if wire.len() < HEADER_SIZE {
            return Err(Error::FrameTooShort);
        }

        let header = Header::unmarshal_binary(&wire[..HEADER_SIZE])?;
        let frame_size = header.frame_size() as usize;

        if wire.len() < frame_size {
            return Err(Error::FrameLengthMismatch);
        }

        let body = &wire[HEADER_SIZE..frame_size];
        let payload_len = header.payload_length as usize;
        let pad_len = header.pad_length as usize;

        if header.msg_type.has_aead_tag() {
            // body = payload || tag (16 bytes) || padding
            let expected_body = payload_len + AEAD_TAG_SIZE + pad_len;
            if body.len() != expected_body {
                return Err(Error::FrameLengthMismatch);
            }
            let payload = body[..payload_len].to_vec();
            let mut tag = [0u8; AEAD_TAG_SIZE];
            tag.copy_from_slice(&body[payload_len..payload_len + AEAD_TAG_SIZE]);
            let padding = body[payload_len + AEAD_TAG_SIZE..].to_vec();

            let frame = Self { header, payload, tag, padding };
            frame.validate_receive()?;
            Ok(frame)
        } else {
            // Handshake frames: body = payload || padding (no tag)
            let expected_body = payload_len + pad_len;
            if body.len() != expected_body {
                return Err(Error::FrameLengthMismatch);
            }
            let payload = body[..payload_len].to_vec();
            let padding = body[payload_len..].to_vec();

            let frame = Self {
                header,
                payload,
                tag: [0u8; AEAD_TAG_SIZE],
                padding,
            };
            frame.validate_receive()?;
            Ok(frame)
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn encrypted_frame(payload: &[u8], pad: &[u8]) -> Frame {
        let tag = [0xAAu8; AEAD_TAG_SIZE];
        Frame::new(
            MessageType::EncryptedData,
            [0x11u8; 16],
            1,
            payload,
            &tag,
            pad,
        )
        .expect("new frame")
    }

    #[test]
    fn test_frame_roundtrip_encrypted() {
        let payload = b"hello world";
        let tag = [0xBBu8; AEAD_TAG_SIZE];
        let padding = b"pad";
        let f = Frame::new(
            MessageType::EncryptedData,
            [0x22u8; 16],
            7,
            payload,
            &tag,
            padding,
        )
        .expect("new");
        let wire = f.marshal_binary().expect("marshal");
        let f2 = Frame::unmarshal_binary(&wire).expect("unmarshal");
        assert_eq!(f, f2);
    }

    #[test]
    fn test_frame_roundtrip_handshake_init() {
        let payload = vec![0u8; 36]; // HandshakeInit fixed size
        let f = Frame::new(
            MessageType::HandshakeInit,
            [0u8; 16],
            0,
            &payload,
            &[],
            &[],
        )
        .expect("new");
        let wire = f.marshal_binary().expect("marshal");
        // No AEAD tag in wire for handshake init.
        assert_eq!(wire.len(), HEADER_SIZE + 36);
        let f2 = Frame::unmarshal_binary(&wire).expect("unmarshal");
        assert_eq!(f.payload, f2.payload);
    }

    #[test]
    fn test_frame_wire_order() {
        let payload = b"PAYLOAD";
        let tag = [0xCCu8; AEAD_TAG_SIZE];
        let padding = b"PAD";
        let f = Frame::new(
            MessageType::EncryptedData,
            [0u8; 16],
            1,
            payload,
            &tag,
            padding,
        )
        .expect("new");
        let wire = f.marshal_binary().expect("marshal");
        // Header
        assert_eq!(&wire[..4], b"DGP1");
        // Payload
        assert_eq!(&wire[HEADER_SIZE..HEADER_SIZE + 7], b"PAYLOAD");
        // Tag
        assert_eq!(&wire[HEADER_SIZE + 7..HEADER_SIZE + 7 + AEAD_TAG_SIZE], &[0xCCu8; 16]);
        // Padding
        assert_eq!(&wire[HEADER_SIZE + 7 + AEAD_TAG_SIZE..], b"PAD");
    }

    #[test]
    fn test_frame_unmarshal_too_short() {
        let wire = [0u8; 10];
        assert!(matches!(Frame::unmarshal_binary(&wire), Err(Error::FrameTooShort)));
    }

    #[test]
    fn test_frame_unmarshal_length_mismatch() {
        let f = encrypted_frame(b"data", b"");
        let mut wire = f.marshal_binary().expect("marshal");
        // Truncate the body.
        wire.truncate(wire.len() - 1);
        // Re-parse: header will declare more bytes than available.
        assert!(matches!(
            Frame::unmarshal_binary(&wire),
            Err(Error::FrameLengthMismatch)
        ));
    }

    #[test]
    fn test_frame_new_padding_too_long() {
        let tag = [0u8; AEAD_TAG_SIZE];
        let padding = vec![0u8; 256]; // exceeds u8 max
        assert!(matches!(
            Frame::new(MessageType::EncryptedData, [0u8; 16], 1, b"x", &tag, &padding),
            Err(Error::PaddingLength)
        ));
    }

    #[test]
    fn test_frame_new_tag_wrong_length_for_encrypted() {
        assert!(matches!(
            Frame::new(MessageType::EncryptedData, [0u8; 16], 1, b"x", &[0u8; 8], &[]),
            Err(Error::TagLength)
        ));
    }

    #[test]
    fn test_frame_new_handshake_accepts_empty_tag() {
        let f = Frame::new(MessageType::HandshakeInit, [0u8; 16], 0, &[0u8; 36], &[], &[]);
        assert!(f.is_ok());
    }

    #[test]
    fn test_frame_new_handshake_rejects_nonzero_tag() {
        let tag = [0xFFu8; AEAD_TAG_SIZE];
        assert!(matches!(
            Frame::new(MessageType::HandshakeInit, [0u8; 16], 0, &[0u8; 36], &tag, &[]),
            Err(Error::TagLength)
        ));
    }
}

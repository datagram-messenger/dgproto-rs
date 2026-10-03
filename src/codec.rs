//! Stateless ChaCha20-Poly1305 AEAD codec for DGProto v1 data frames.
//!
//! # Nonce construction
//!
//! ```text
//! nonce = [0x00, 0x00, 0x00, 0x00] || sequence.to_le_bytes()   (12 bytes)
//! ```
//!
//! # Associated data (AAD)
//!
//! ```text
//! aad = marshal_binary(header) || padding_bytes
//! ```
//!
//! The full 40-byte header (including reserved bytes) and the cleartext random
//! padding are both authenticated. This means every transmitted byte is covered
//! by the AEAD tag.
//!
//! # Key/nonce reuse
//!
//! The codec is stateless — it does not track sequences. The caller (`Session`)
//! is responsible for sequence allocation and ensuring no key/nonce pair is
//! ever reused.
//!
//! See `docs/protocol/dgproto-v1.md` §4.3 for the normative specification.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use zeroize::ZeroizeOnDrop;

use crate::{
    frame::Frame,
    header::{Header, MessageType},
    Error, AEAD_TAG_SIZE, KEY_SIZE,
};

/// Stateless ChaCha20-Poly1305 AEAD codec.
///
/// The codec is stateless — it does not track sequences or epochs. The caller
/// (`Session`) owns sequencing and ensures no key/nonce pair is ever reused.
#[derive(ZeroizeOnDrop)]
pub(crate) struct Codec {
    #[zeroize(skip)]
    aead: ChaCha20Poly1305,
    key: [u8; KEY_SIZE],
}

impl Codec {
    /// Construct a new codec from a 32-byte traffic key.
    pub(crate) fn new(key: &[u8; KEY_SIZE]) -> Result<Self, Error> {
        let aead = ChaCha20Poly1305::new(Key::from_slice(key));
        Ok(Self { aead, key: *key })
    }

    /// Encrypt `plaintext` into an authenticated frame.
    ///
    /// `msg_type` must be an encrypted type (not `HandshakeInit` or
    /// `HandshakeResponse`). `session_id` must be non-zero. `sequence` must
    /// be non-zero. `padding` is the cleartext random padding (0–255 bytes).
    pub(crate) fn encrypt(
        &self,
        msg_type: MessageType,
        session_id: [u8; 16],
        sequence: u64,
        plaintext: &[u8],
        padding: &[u8],
    ) -> Result<Frame, Error> {
        validate_encrypted_header(msg_type, session_id, sequence)?;

        let pad_len = padding.len();
        if pad_len > 255 {
            return Err(Error::PaddingLength);
        }

        // Check total frame size before allocating.
        let total = crate::HEADER_SIZE as u64
            + plaintext.len() as u64
            + AEAD_TAG_SIZE as u64
            + pad_len as u64;
        if total > crate::MAX_FRAME_SIZE as u64 {
            return Err(Error::PayloadTooLarge);
        }

        let header = Header::new(
            msg_type,
            session_id,
            sequence,
            plaintext.len() as u32,
            pad_len as u8,
        );
        // Use marshal_binary_raw so reserved bytes are preserved verbatim in AAD.
        let header_bytes = header.marshal_binary_raw();
        let nonce = build_nonce(sequence);

        // AAD = header bytes || padding
        let mut aad = Vec::with_capacity(crate::HEADER_SIZE + pad_len);
        aad.extend_from_slice(&header_bytes);
        aad.extend_from_slice(padding);

        let sealed = self
            .aead
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Authentication)?;

        // `sealed` = ciphertext || 16-byte tag
        let ciphertext = &sealed[..plaintext.len()];
        let tag = &sealed[plaintext.len()..];

        Frame::new(msg_type, session_id, sequence, ciphertext, tag, padding)
    }

    /// Decrypt and authenticate an encrypted frame.
    ///
    /// Returns the plaintext on success. All authentication failures return
    /// `Error::Authentication` without revealing AEAD details.
    pub(crate) fn decrypt(&self, frame: &Frame) -> Result<Vec<u8>, Error> {
        frame.validate_receive()?;
        validate_encrypted_header(
            frame.header.msg_type,
            frame.header.session_id,
            frame.header.sequence,
        )?;

        let header_bytes = frame.header.marshal_binary_raw();
        let nonce = build_nonce(frame.header.sequence);

        // AAD = header bytes || padding
        let mut aad = Vec::with_capacity(crate::HEADER_SIZE + frame.padding.len());
        aad.extend_from_slice(&header_bytes);
        aad.extend_from_slice(&frame.padding);

        // Reconstruct `sealed` = ciphertext || tag
        let mut sealed = Vec::with_capacity(frame.payload.len() + AEAD_TAG_SIZE);
        sealed.extend_from_slice(&frame.payload);
        sealed.extend_from_slice(&frame.tag);

        self.aead
            .decrypt(
                &nonce,
                Payload {
                    msg: &sealed,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Authentication)
    }
}

/// Build the 12-byte ChaCha20-Poly1305 nonce from a sequence number.
///
/// `nonce = [0x00, 0x00, 0x00, 0x00] || sequence.to_le_bytes()`
#[inline]
fn build_nonce(sequence: u64) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&sequence.to_le_bytes());
    *Nonce::from_slice(&nonce)
}

/// Validate that a header is suitable for an encrypted frame.
fn validate_encrypted_header(
    msg_type: MessageType,
    session_id: [u8; 16],
    sequence: u64,
) -> Result<(), Error> {
    if !msg_type.has_aead_tag() {
        return Err(Error::MessageType);
    }
    if sequence == 0 {
        return Err(Error::InvalidSequence);
    }
    if session_id == [0u8; 16] {
        return Err(Error::InvalidSessionId);
    }
    Ok(())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; KEY_SIZE] {
        [0x42u8; KEY_SIZE]
    }

    fn test_session_id() -> [u8; 16] {
        [0x11u8; 16]
    }

    #[test]
    fn test_codec_encrypt_decrypt_roundtrip() {
        let codec = Codec::new(&test_key()).expect("new codec");
        let plaintext = b"hello, dgproto!";
        let frame = codec
            .encrypt(
                MessageType::EncryptedData,
                test_session_id(),
                1,
                plaintext,
                &[],
            )
            .expect("encrypt");
        let decrypted = codec.decrypt(&frame).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_codec_encrypt_decrypt_with_padding() {
        let codec = Codec::new(&test_key()).expect("new codec");
        let plaintext = b"padded message";
        let padding = [0xFFu8; 8];
        let frame = codec
            .encrypt(
                MessageType::EncryptedData,
                test_session_id(),
                2,
                plaintext,
                &padding,
            )
            .expect("encrypt");
        assert_eq!(frame.padding, padding);
        let decrypted = codec.decrypt(&frame).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_codec_decrypt_tampered_ciphertext() {
        let codec = Codec::new(&test_key()).expect("new codec");
        let mut frame = codec
            .encrypt(
                MessageType::EncryptedData,
                test_session_id(),
                1,
                b"secret",
                &[],
            )
            .expect("encrypt");
        // Flip a bit in the ciphertext.
        frame.payload[0] ^= 0xFF;
        assert!(matches!(codec.decrypt(&frame), Err(Error::Authentication)));
    }

    #[test]
    fn test_codec_decrypt_tampered_tag() {
        let codec = Codec::new(&test_key()).expect("new codec");
        let mut frame = codec
            .encrypt(
                MessageType::EncryptedData,
                test_session_id(),
                1,
                b"secret",
                &[],
            )
            .expect("encrypt");
        frame.tag[0] ^= 0xFF;
        assert!(matches!(codec.decrypt(&frame), Err(Error::Authentication)));
    }

    #[test]
    fn test_codec_decrypt_tampered_padding() {
        let codec = Codec::new(&test_key()).expect("new codec");
        let padding = [0xAAu8; 4];
        let mut frame = codec
            .encrypt(
                MessageType::EncryptedData,
                test_session_id(),
                1,
                b"data",
                &padding,
            )
            .expect("encrypt");
        // Flip a bit in the padding (which is part of AAD).
        frame.padding[0] ^= 0xFF;
        assert!(matches!(codec.decrypt(&frame), Err(Error::Authentication)));
    }

    #[test]
    fn test_codec_nonce_uses_sequence() {
        let codec = Codec::new(&test_key()).expect("new codec");
        // Two frames with different sequences must produce different ciphertexts.
        let f1 = codec
            .encrypt(
                MessageType::EncryptedData,
                test_session_id(),
                1,
                b"same",
                &[],
            )
            .expect("encrypt 1");
        let f2 = codec
            .encrypt(
                MessageType::EncryptedData,
                test_session_id(),
                2,
                b"same",
                &[],
            )
            .expect("encrypt 2");
        assert_ne!(
            f1.payload, f2.payload,
            "different sequences must produce different ciphertexts"
        );
    }

    #[test]
    fn test_codec_encrypt_sequence_zero_rejected() {
        let codec = Codec::new(&test_key()).expect("new codec");
        assert!(matches!(
            codec.encrypt(MessageType::EncryptedData, test_session_id(), 0, b"x", &[]),
            Err(Error::InvalidSequence)
        ));
    }

    #[test]
    fn test_codec_encrypt_zero_session_id_rejected() {
        let codec = Codec::new(&test_key()).expect("new codec");
        assert!(matches!(
            codec.encrypt(MessageType::EncryptedData, [0u8; 16], 1, b"x", &[]),
            Err(Error::InvalidSessionId)
        ));
    }

    #[test]
    fn test_codec_encrypt_handshake_type_rejected() {
        let codec = Codec::new(&test_key()).expect("new codec");
        assert!(matches!(
            codec.encrypt(MessageType::HandshakeInit, test_session_id(), 1, b"x", &[]),
            Err(Error::MessageType)
        ));
    }

    #[test]
    fn test_codec_nonce_layout() {
        let nonce = build_nonce(0x0102030405060708u64);
        // First 4 bytes must be zero.
        assert_eq!(&nonce[..4], &[0u8; 4]);
        // Next 8 bytes are the sequence in little-endian.
        assert_eq!(
            &nonce[4..],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
    }
}

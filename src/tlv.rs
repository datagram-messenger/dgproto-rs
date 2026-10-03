//! TLV (Type-Length-Value) codec for DGProto v1 application-layer fields.
//!
//! Wire layout per TLV element:
//!
//! ```text
//! Offset  Size  Field
//! ──────  ────  ──────────────────────────────────────────────────
//!  0       1    Type (u8, field identifier scoped to message)
//!  1       2    Length (u16 LE, byte count of Value, excl. padding)
//!  3     len    Value (raw bytes)
//!  3+len  pad   Zero-padding to next 4-byte boundary (not in Length)
//! ```
//!
//! Unknown types are preserved. Padding bytes are ignored by parsers.
//!
//! See `docs/protocol/dgproto-v1.md` §2.3 for the normative specification.

use crate::{Error, MAX_FRAME_SIZE};

/// Byte size of the TLV header (type u8 + length u16 LE).
pub(crate) const TLV_HEADER_SIZE: usize = 3;

/// Maximum value size representable by the u16 wire length field.
pub(crate) const MAX_TLV_VALUE_SIZE: usize = (1 << 16) - 1; // 65535

/// Maximum total encoded size of one TLV sequence (bounded by frame limit).
pub(crate) const MAX_TLV_SEQUENCE_SIZE: usize = MAX_FRAME_SIZE; // 65535

/// Maximum number of TLV elements in one sequence (most empty aligned TLVs
/// that fit in `MAX_TLV_SEQUENCE_SIZE`).
pub(crate) const MAX_TLV_ELEMENTS: usize = MAX_TLV_SEQUENCE_SIZE / 4;

/// One application field: a type byte, a value, and no padding (padding is
/// only present on the wire).
///
/// `value` is owned and does not alias caller input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tlv {
    pub typ: u8,
    pub value: Vec<u8>,
}

impl Tlv {
    /// Construct a `Tlv`, copying `value`.
    pub(crate) fn new(typ: u8, value: &[u8]) -> Result<Self, Error> {
        if value.len() > MAX_TLV_VALUE_SIZE {
            return Err(Error::TlvValueTooLarge);
        }
        Ok(Self {
            typ,
            value: value.to_vec(),
        })
    }

    /// Encoded wire length including zero-alignment padding to a 4-byte boundary.
    pub(crate) fn encoded_len(&self) -> Result<usize, Error> {
        if self.value.len() > MAX_TLV_VALUE_SIZE {
            return Err(Error::TlvValueTooLarge);
        }
        Ok(align4(TLV_HEADER_SIZE + self.value.len()))
    }

    /// Encode this TLV to its wire representation (zero-padded to 4-byte boundary).
    pub(crate) fn marshal_binary(&self) -> Result<Vec<u8>, Error> {
        let n = self.encoded_len()?;
        let mut buf = vec![0u8; n];
        buf[0] = self.typ;
        let len_u16 = self.value.len() as u16;
        buf[1..3].copy_from_slice(&len_u16.to_le_bytes());
        buf[TLV_HEADER_SIZE..TLV_HEADER_SIZE + self.value.len()].copy_from_slice(&self.value);
        // Remaining bytes are already zero (alignment padding).
        Ok(buf)
    }
}

/// Encode a slice of TLVs into a single byte buffer.
///
/// Returns `Err(Error::TlvSequenceLimit)` if the total encoded size would
/// exceed `MAX_TLV_SEQUENCE_SIZE`, or `Err(Error::TlvElementLimit)` if there
/// are more than `MAX_TLV_ELEMENTS` elements.
pub(crate) fn encode_tlvs(tlvs: &[Tlv]) -> Result<Vec<u8>, Error> {
    if tlvs.len() > MAX_TLV_ELEMENTS {
        return Err(Error::TlvElementLimit);
    }
    let mut total = 0usize;
    for t in tlvs {
        total += t.encoded_len()?;
        if total > MAX_TLV_SEQUENCE_SIZE {
            return Err(Error::TlvSequenceLimit);
        }
    }
    let mut buf = Vec::with_capacity(total);
    for t in tlvs {
        buf.extend_from_slice(&t.marshal_binary()?);
    }
    Ok(buf)
}

/// Decode a TLV sequence from `data`.
///
/// Protocol-wide size and element limits always apply. A positive `max_bytes`
/// imposes a tighter caller limit. Unknown types are preserved; padding is
/// ignored; values are copied.
pub(crate) fn decode_tlvs(data: &[u8], max_bytes: usize) -> Result<Vec<Tlv>, Error> {
    if data.len() > MAX_TLV_SEQUENCE_SIZE {
        return Err(Error::TlvSequenceLimit);
    }
    if max_bytes > 0 && data.len() > max_bytes {
        return Err(Error::TlvDecodeLimit);
    }

    let capacity = (data.len() / 4).min(MAX_TLV_ELEMENTS);
    let mut out = Vec::with_capacity(capacity);
    let mut offset = 0usize;

    while offset < data.len() {
        if out.len() == MAX_TLV_ELEMENTS {
            return Err(Error::TlvElementLimit);
        }
        let remaining = data.len() - offset;
        if remaining < TLV_HEADER_SIZE {
            return Err(Error::TlvTooShort);
        }

        let typ = data[offset];
        let value_len = u16::from_le_bytes(
            data[offset + 1..offset + TLV_HEADER_SIZE]
                .try_into()
                .expect("slice is 2 bytes"),
        ) as usize;

        if value_len > remaining - TLV_HEADER_SIZE {
            return Err(Error::TlvTruncated);
        }

        let unpadded = TLV_HEADER_SIZE + value_len;
        let padding_len = (4 - unpadded % 4) % 4;
        if padding_len > remaining - unpadded {
            return Err(Error::TlvTruncated);
        }

        let value = data[offset + TLV_HEADER_SIZE..offset + TLV_HEADER_SIZE + value_len].to_vec();
        out.push(Tlv { typ, value });
        offset += unpadded + padding_len;
    }

    Ok(out)
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

    #[test]
    fn test_tlv_roundtrip_basic() {
        let t = Tlv::new(1, b"hello").expect("new");
        let wire = t.marshal_binary().expect("marshal");
        // type(1) + len_u16(2) + value(5) = 8 bytes (aligned to 4: 8)
        assert_eq!(wire.len(), 8);
        let decoded = decode_tlvs(&wire, 0).expect("decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].typ, 1);
        assert_eq!(decoded[0].value, b"hello");
    }

    #[test]
    fn test_tlv_alignment_padding() {
        // value length 1 → unpadded = 4 → aligned = 4 (no extra padding)
        let t = Tlv::new(2, b"x").expect("new");
        let wire = t.marshal_binary().expect("marshal");
        assert_eq!(wire.len(), 4);
        assert_eq!(wire[3], 0); // padding byte is zero
    }

    #[test]
    fn test_tlv_alignment_padding_2() {
        // value length 2 → unpadded = 5 → aligned = 8
        let t = Tlv::new(3, b"ab").expect("new");
        let wire = t.marshal_binary().expect("marshal");
        assert_eq!(wire.len(), 8);
    }

    #[test]
    fn test_tlv_empty_value() {
        let t = Tlv::new(0, b"").expect("new");
        let wire = t.marshal_binary().expect("marshal");
        // type(1) + len(2) + value(0) = 3 → aligned to 4
        assert_eq!(wire.len(), 4);
        let decoded = decode_tlvs(&wire, 0).expect("decode");
        assert_eq!(decoded[0].value, b"");
    }

    #[test]
    fn test_encode_decode_multiple_tlvs() {
        let tlvs = vec![
            Tlv::new(1, b"foo").expect("new"),
            Tlv::new(2, b"bar").expect("new"),
            Tlv::new(3, b"").expect("new"),
        ];
        let wire = encode_tlvs(&tlvs).expect("encode");
        let decoded = decode_tlvs(&wire, 0).expect("decode");
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0].value, b"foo");
        assert_eq!(decoded[1].value, b"bar");
        assert_eq!(decoded[2].value, b"");
    }

    #[test]
    fn test_tlv_decode_too_short_header() {
        let data = [0x01u8, 0x00]; // only 2 bytes — missing length byte
        assert!(matches!(decode_tlvs(&data, 0), Err(Error::TlvTooShort)));
    }

    #[test]
    fn test_tlv_decode_truncated_value() {
        // type=1, length=10, but only 2 value bytes follow
        let mut data = vec![0x01u8, 0x0A, 0x00]; // length = 10
        data.extend_from_slice(b"ab"); // only 2 bytes
        assert!(matches!(decode_tlvs(&data, 0), Err(Error::TlvTruncated)));
    }

    #[test]
    fn test_tlv_decode_max_bytes_limit() {
        let t = Tlv::new(1, b"hello").expect("new");
        let wire = t.marshal_binary().expect("marshal");
        // Limit to 4 bytes — wire is 8 bytes → should fail.
        assert!(matches!(decode_tlvs(&wire, 4), Err(Error::TlvDecodeLimit)));
    }

    #[test]
    fn test_tlv_value_too_large() {
        let big = vec![0u8; MAX_TLV_VALUE_SIZE + 1];
        assert!(matches!(Tlv::new(1, &big), Err(Error::TlvValueTooLarge)));
    }

    #[test]
    fn test_tlv_unknown_type_preserved() {
        let t = Tlv::new(0xFF, b"data").expect("new");
        let wire = t.marshal_binary().expect("marshal");
        let decoded = decode_tlvs(&wire, 0).expect("decode");
        assert_eq!(decoded[0].typ, 0xFF);
        assert_eq!(decoded[0].value, b"data");
    }

    #[test]
    fn test_encode_tlvs_empty() {
        let wire = encode_tlvs(&[]).expect("encode");
        assert!(wire.is_empty());
        let decoded = decode_tlvs(&wire, 0).expect("decode");
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_align4() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(3), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
        assert_eq!(align4(8), 8);
    }
}

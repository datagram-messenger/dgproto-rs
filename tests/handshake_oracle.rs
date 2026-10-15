//! Independent handshake-envelope oracle for the v0.4.2 interoperability fix.
//!
//! These tests intentionally encode the responder-side wire contract rather
//! than deriving the expected third-flight type from the Rust client.

const MAGIC: &[u8; 4] = b"DGP1";
const VERSION: u8 = 1;
const HANDSHAKE_RESPONSE: u8 = 0x02;
const HEADER_SIZE: usize = 40;
const HANDSHAKE_FINISH_SIZE: u32 = 64;

fn independent_responder_accepts_finish(header: &[u8; HEADER_SIZE], payload_len: usize) -> bool {
    header[0..4] == MAGIC[..]
        && header[4] == VERSION
        && header[5] == HANDSHAKE_RESPONSE
        && header[6] & 0x01 == 0
        && header[8..24] == [0; 16]
        && u64::from_le_bytes(header[24..32].try_into().expect("sequence")) == 0
        && u32::from_le_bytes(header[32..36].try_into().expect("payload length"))
            == HANDSHAKE_FINISH_SIZE
        && header[36] == 0
        && payload_len == HANDSHAKE_FINISH_SIZE as usize
}

fn finish_header(message_type: u8) -> [u8; HEADER_SIZE] {
    let mut header = [0u8; HEADER_SIZE];
    header[0..4].copy_from_slice(MAGIC);
    header[4] = VERSION;
    header[5] = message_type;
    header[32..36].copy_from_slice(&HANDSHAKE_FINISH_SIZE.to_le_bytes());
    header
}

#[test]
fn responder_oracle_accepts_canonical_handshake_finish_envelope() {
    assert!(independent_responder_accepts_finish(
        &finish_header(HANDSHAKE_RESPONSE),
        HANDSHAKE_FINISH_SIZE as usize,
    ));
}

#[test]
fn responder_oracle_rejects_legacy_encrypted_data_assumption() {
    assert!(!independent_responder_accepts_finish(
        &finish_header(0x03),
        HANDSHAKE_FINISH_SIZE as usize,
    ));
}

#[test]
fn responder_oracle_rejects_noncanonical_finish_fields() {
    let canonical = finish_header(HANDSHAKE_RESPONSE);
    for mutate in [
        |h: &mut [u8; HEADER_SIZE]| h[6] = 1,
        |h: &mut [u8; HEADER_SIZE]| h[8] = 1,
        |h: &mut [u8; HEADER_SIZE]| h[24] = 1,
        |h: &mut [u8; HEADER_SIZE]| h[36] = 1,
    ] {
        let mut malformed = canonical;
        mutate(&mut malformed);
        assert!(!independent_responder_accepts_finish(
            &malformed,
            HANDSHAKE_FINISH_SIZE as usize,
        ));
    }
}

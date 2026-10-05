#![no_main]

use libfuzzer_sys::fuzz_target;

// Invariant: no parser may panic on arbitrary input — only Ok or Err.
// Each call exercises a different message type parser.
//
// The first byte of `data` is used as a selector so that the fuzzer can
// explore each parser independently with targeted mutations.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let selector = data[0];
    let payload = &data[1..];

    match selector % 9 {
        // Handshake messages (no outer AEAD tag).
        0 => {
            let _ = dgproto::HandshakeInit::unmarshal_binary(payload);
        }
        1 => {
            let _ = dgproto::HandshakeResponse::unmarshal_binary(payload);
        }
        2 => {
            let _ = dgproto::HandshakeFinish::unmarshal_binary(payload);
        }
        // Application messages (post-handshake, inside encrypted frames).
        3 => {
            let _ = dgproto::EncryptedData::unmarshal_binary(payload);
        }
        4 => {
            let _ = dgproto::PingPong::unmarshal_binary(payload);
        }
        5 => {
            let _ = dgproto::FuzzAck::unmarshal_binary(payload);
        }
        6 => {
            let _ = dgproto::RekeyInit::unmarshal_binary(payload);
        }
        7 => {
            let _ = dgproto::FuzzSessionClose::unmarshal_binary(payload);
        }
        _ => {
            let _ = dgproto::FuzzErrorMessage::unmarshal_binary(payload);
        }
    }
});

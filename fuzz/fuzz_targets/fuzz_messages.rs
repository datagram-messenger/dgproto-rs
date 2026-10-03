#![no_main]

use libfuzzer_sys::fuzz_target;

// Invariant: no parser may panic on arbitrary input — only Ok or Err.
// Each call exercises a different message type parser.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let payload = &data[1..];
    // Handshake messages (no outer AEAD tag).
    let _ = dgproto::HandshakeInit::unmarshal_binary(payload);
    let _ = dgproto::HandshakeResponse::unmarshal_binary(payload);
    let _ = dgproto::HandshakeFinish::unmarshal_binary(payload);
    // Application messages (post-handshake, inside encrypted frames).
    let _ = dgproto::PingPong::unmarshal_binary(payload);
    let _ = dgproto::FuzzAck::unmarshal_binary(payload);
    let _ = dgproto::RekeyInit::unmarshal_binary(payload);
    let _ = dgproto::FuzzSessionClose::unmarshal_binary(payload);
    let _ = dgproto::FuzzErrorMessage::unmarshal_binary(payload);
});

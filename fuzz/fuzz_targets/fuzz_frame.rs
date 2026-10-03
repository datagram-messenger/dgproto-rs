#![no_main]

use libfuzzer_sys::fuzz_target;

// Invariant: the parser MUST NOT panic on any input, regardless of length
// or content. It must return Ok or Err — never panic or abort.
fuzz_target!(|data: &[u8]| {
    let _ = dgproto::Frame::unmarshal_binary(data);
});

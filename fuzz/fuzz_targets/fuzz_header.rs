#![no_main]

use libfuzzer_sys::fuzz_target;

// TODO: replace with the real parser once src/header.rs is implemented.
//
// Invariant: the parser MUST NOT panic on any input, regardless of length
// or content. It must return Ok or Err — never panic or abort.
//
// When src/header.rs is ready, replace the body with:
//
//   fuzz_target!(|data: &[u8]| {
//       let _ = dgproto::header::Header::unmarshal_binary(data);
//   });

fuzz_target!(|_data: &[u8]| {
    // Stub — no-op until header.rs is implemented.
});

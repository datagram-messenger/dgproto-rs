#![no_main]

use libfuzzer_sys::fuzz_target;

// TODO: replace with the real parser once src/frame.rs is implemented.
//
// When src/frame.rs is ready, replace the body with:
//
//   fuzz_target!(|data: &[u8]| {
//       let _ = dgproto::frame::Frame::unmarshal_binary(data);
//   });

fuzz_target!(|_data: &[u8]| {
    // Stub — no-op until frame.rs is implemented.
});

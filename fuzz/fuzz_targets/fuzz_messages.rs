#![no_main]

use libfuzzer_sys::fuzz_target;

// TODO: replace with the real parser once src/messages.rs is implemented.
//
// When src/messages.rs is ready, replace the body with something like:
//
//   fuzz_target!(|data: &[u8]| {
//       if data.is_empty() { return; }
//       let msg_type = data[0];
//       let payload  = &data[1..];
//       let _ = dgproto::messages::parse_message(msg_type, payload);
//   });

fuzz_target!(|_data: &[u8]| {
    // Stub — no-op until messages.rs is implemented.
});

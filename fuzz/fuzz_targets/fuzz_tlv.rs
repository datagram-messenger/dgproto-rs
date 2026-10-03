#![no_main]

use libfuzzer_sys::fuzz_target;

// TODO: replace with the real parser once src/tlv.rs is implemented.
//
// When src/tlv.rs is ready, replace the body with:
//
//   fuzz_target!(|data: &[u8]| {
//       let _ = dgproto::tlv::decode_tlvs(data, 0);
//   });

fuzz_target!(|_data: &[u8]| {
    // Stub — no-op until tlv.rs is implemented.
});

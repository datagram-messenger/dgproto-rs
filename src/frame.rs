//! DGProto v1 frame: Header + payload + AEAD tag + padding.
//!
//! Wire order: `[40-byte header][payload][16-byte AEAD tag*][padding]`
//! (* tag is absent for HandshakeInit and HandshakeResponse frames)
//!
//! Frame length is derived from the header — there is no outer length prefix.
//!
//! See `docs/protocol/dgproto-v1.md` §3 for the normative specification.

// TODO: implement Frame struct, marshal_binary, unmarshal_binary, validate,
//       validate_receive, frame_size helpers.
// Reference: dgproto-go/frame.go

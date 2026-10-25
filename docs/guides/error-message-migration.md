# ErrorMessage wire migration

Error (`0x09`) is now `code:u16 LE || context:raw UTF-8`, without TLV,
length prefix, alignment padding, heuristic fallback or negotiation.
SessionClose remains optional type-1 TLV. Header version/size, handshake,
cryptography and session/rekey transactions are unchanged.

Code 9 and `oops`: old `09000104006f6f707300`, new `09006f6f7073`.
Code 3 and `hi`: old `03000102006869000000`, new `03006869`.
Empty context remains just the code and cannot prove migration. Old TLV bytes
can themselves be valid raw UTF-8 (including NUL and control characters), so
new decoders cannot always reject old payloads or identify unknown generation.

## Rebuild, deploy and roll back as a pair

Inventory every Error sender/receiver and establish exact revisions out of band.
Rebuild Go and Rust peers together; verify nonempty Error and unchanged Close.
Drain existing connections and prevent mixed-generation admission using deployment
controls, deploy both binaries, then reconnect. No wire generation negotiation or
automatic reconnect is introduced. Rollback requires the same drain and rollback
of both peer generations as a pair before reconnecting. Label persisted old
payloads separately; a successful handshake is not a generation check.

## Source-compatible adapter and byte limits

Rust retains `code: u8` and `reason: String`, with no new exhaustive
`ApplicationMessage` variant. The private helper accepts raw u16 codes, but the
public adapter checks narrowing after length and UTF-8 validation, returning
existing `InvalidErrorCode` above 255. This is **not full-u16 interoperability**.
Go retains `Code uint16` and `Context string`; public paired use is codes 0–255.

Raw context is at most **65477 UTF-8 bytes** at zero frame padding:
`65535 - 40 - 16 - 2`. Subtract actual frame padding from this budget.
Close retains its separate 65473-byte aligned-TLV limit. Embedded NUL and empty
context are valid. Oversized decode returns `MessageLength` before copying or
UTF-8 checks; short input returns `MessageTooShort`, invalid text `InvalidUtf8`.
Raw Error produces no TLV validation errors. Decoded text is owned.

Hand-authored shared Error vectors cover nonempty ASCII, Unicode, NUL, short
input and invalid UTF-8. Go `0x1234`/`hi` is `34126869`; Rust-specific tests
prove private acceptance and public rejection, not contradictory shared validity.
The retained empty vector and codec oracles do not prove live cross-language
session interoperability or deployment readiness.

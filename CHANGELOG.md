# Changelog

All notable changes to `dgproto` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.2] — unreleased

### Added

- `Connection::is_closed()` — inspect connection state without attempting a send.
- `Connection::send_and_wait_padded()` — async send with explicit padding and
  write-loop confirmation, completing the send-API symmetry
  (`send` / `send_padded` / `send_and_wait` / `send_and_wait_padded`).
- `Error` now implements `PartialEq`. Two `Error::Io` values compare equal when
  their `std::io::ErrorKind`s match. This makes error assertions in tests
  significantly more ergonomic (`assert_eq!` instead of `matches!`).

### Changed

- `StaticKey::private()` visibility narrowed from `pub(crate)` to
  module-private (`fn`). The method was only ever used inside `handshake.rs`
  and must not be callable from outside that module.

---

## [0.1.1] — 2026-10-07

### Fixed

- CI: `github-release` job now runs independently of the `publish` (crates.io)
  job, so a GitHub Release is always created even when the crates.io publish
  step is pending manual approval.
- CI: replaced `git-cliff` + `softprops/action-gh-release` with
  `gh release create --generate-notes` (matching `dgproto-go`), eliminating
  an external action dependency.

---

## [0.1.0] — 2026-09-28

### Added

- Initial public release of the Rust client library for DGProto v1.
- Full Noise XX initiator handshake (`Noise_XX_25519_ChaChaPoly_SHA256`).
- ChaCha20-Poly1305 AEAD data-frame codec with per-direction sequence numbers.
- Directional epoch/rekey state machine (HMAC-SHA256 key derivation).
- 2048-bit sliding replay window.
- Async TCP transport via Tokio with independent read/write mutex guards.
- `Connection` runtime: read loop, write loop, maintenance loop.
- Keepalive ping/pong with configurable interval and timeout.
- Idle timeout.
- Graceful `SessionClose` exchange (`Connection::close`).
- Immediate abort (`Connection::abort`).
- Bounded outbound channel with `send` / `send_padded` / `send_and_wait`.
- Wire-vector test suite against shared `testdata/vectors/`.
- Fuzz targets for header, frame, TLV, and message parsing.
- Full CI matrix: Ubuntu, Windows, macOS; MSRV 1.80.

[0.1.2]: https://github.com/datagram-messenger/dgproto-rs/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/datagram-messenger/dgproto-rs/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/datagram-messenger/dgproto-rs/releases/tag/v0.1.0

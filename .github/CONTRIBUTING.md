# Contributing to dgproto-rs

Thank you for helping improve the Rust client implementation of DGProto v1. Framing, parsing, authentication, replay, rekey, and connection-lifecycle changes are security-sensitive. Keep changes narrow, reviewable, and backed by tests.

## Prerequisites

- Rust **1.80 or newer**. CI also checks the declared MSRV with Rust 1.80.
- The `rustfmt` and `clippy` components.
- Git.
- For fuzzing only: a nightly Rust toolchain and `cargo-fuzz`.
- A local checkout of `dgproto-go` is useful when validating cross-language behavior. Its `docs/protocol/dgproto-v1.md` is the normative protocol specification.

Install the Rust components and optional fuzzing tools with:

```sh
rustup component add rustfmt clippy
rustup toolchain install nightly
cargo install cargo-fuzz --locked
```

## Setup

```sh
git clone https://github.com/datagram-messenger/dgproto-rs.git
cd dgproto-rs
cargo fetch --locked
```

`Cargo.lock` and `fuzz/Cargo.lock` are tracked. Do not delete, ignore, or update them incidentally. Never commit generated `target/` trees, fuzz artifacts, private keys, credentials, user data, or production captures.

## Build and validation

Run commands from the repository root.

```sh
cargo build --all-features
cargo check --all-features
cargo test --all-features
cargo test --release --all-features
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo doc --all-features --no-deps
```

To apply Rust formatting locally:

```sh
cargo fmt --all
```

CI runs formatting, Clippy, and debug/release tests on Linux, Windows, and macOS, plus `cargo check --all-features` on Rust 1.80.

### Fuzzing

The fuzz package defines four parser targets. Run them from the repository root:

```sh
cargo +nightly fuzz run fuzz_header -- -max_total_time=60
cargo +nightly fuzz run fuzz_frame -- -max_total_time=60
cargo +nightly fuzz run fuzz_tlv -- -max_total_time=60
cargo +nightly fuzz run fuzz_messages -- -max_total_time=60
```

CI uses 30-second smoke runs. Longer local runs are encouraged for parser changes. Do not commit `fuzz/target/`, `fuzz/artifacts/`, or local corpora unless a reviewed deterministic regression fixture is intentionally being added.

## Protocol and wire compatibility

The normative specification is maintained in [`dgproto-go`](https://github.com/datagram-messenger/dgproto-go/blob/main/docs/protocol/dgproto-v1.md). The protocol is still a draft and is versioned independently from this crate. Do not claim wire compatibility from a crate version alone.

Before changing wire-visible behavior:

1. Read the relevant specification section, Rust implementation, callers, tests, shared vectors, and CI.
2. Classify the effect on bytes, limits, derivations, state transitions, concurrency, public API, and interoperability.
3. Preserve exact DGProto v1 invariants unless the normative specification changes: `DGP1`, version 1, the 40-byte little-endian header, no outer length prefix, the 65535-byte frame limit, Noise XX flight order and prologue, ChaCha20-Poly1305, sequence/nonce rules, replay check-then-commit, and directional rekey ordering.
4. Do not introduce negotiation, alternative suites, resumption, 0-RTT, obfuscation, or a responder/server API into the strict MVP client.
5. Add focused success, malformed-input, boundary, and invalid-state tests. Lifecycle changes also need cancellation, queue-bound, shutdown, and terminal-error coverage.

Senders must zero reserved fields and emit only permitted flags. Receivers must preserve and authenticate the exact received header where required. Never weaken authentication, replay protection, key/nonce uniqueness, or constant-time secret comparisons.

## Test vectors and cross-language parity

`testdata/vectors/*.json` contains deterministic interoperability fixtures shared with `dgproto-go`. Treat these files as immutable compatibility evidence:

- Compare the Rust and Go vector directories byte-for-byte before changing fixtures.
- Do not regenerate or rewrite unrelated vectors.
- For an intentional vector change, identify whether it tests frame-level parsing/encoding or semantic protocol state, update focused tests in both implementations, and explain the normative specification basis.
- A frame that parses is not necessarily semantically valid; handshake, replay, epoch, and message-state rules require semantic tests.
- For wire-visible changes, demonstrate Rust-to-Go and Go-to-Rust parity, including exact bytes and rejection behavior. Record the Rust and Go revisions and commands used in the pull request.

The current checkout contains the shared vector files but no dedicated Rust `tests/wire_vectors.rs` integration test. Do not describe fixture presence alone as executed cross-language interoperability coverage.

## Documentation

Update documentation when behavior, public API, defaults, lifecycle semantics, or compatibility claims change:

- `README.md` for user-facing setup and guarantees.
- `docs/architecture/overview.md` for implementation structure and concurrency.
- Rustdoc on public items for API contracts.
- `testdata/vectors/README.md` for fixture scope.

Do not copy the normative protocol into this repository. Link to the canonical `dgproto-go` specification and clearly distinguish normative requirements from implementation notes.

## Pull request checklist

- [ ] The change is scoped and its protocol/security impact is described.
- [ ] Relevant specification sections, implementation, tests, vectors, and CI were reviewed.
- [ ] `cargo fmt --all -- --check` passes.
- [ ] `cargo clippy --all-targets -- -D warnings` passes.
- [ ] `cargo test --all-features` and, when relevant, release tests pass.
- [ ] `cargo doc --all-features --no-deps` succeeds without warnings.
- [ ] Parser changes include malformed, truncated, boundary, and fuzz coverage.
- [ ] Wire-visible changes include deterministic vectors and cross-language parity evidence.
- [ ] Public API, lifecycle, and error-contract changes are documented.
- [ ] No secrets, private keys, production captures, generated build output, or unrelated lockfile changes are included.
- [ ] The final diff and repository status contain only intended changes.

## Reporting security issues

Do not report suspected vulnerabilities in a public issue or pull request. Use the repository's private GitHub security advisory form:

<https://github.com/datagram-messenger/dgproto-rs/security/advisories/new>

Include affected crate versions and, for wire-level behavior, the relevant protocol draft or `dgproto-go` revision, impact, and reproduction details. Do not include real credentials, private keys, user data, or production captures.

# Contributing to dgproto-rs

Thank you for your interest in contributing! `dgproto-rs` is a security-sensitive
Rust implementation of the DGProto v1 client transport. We welcome bug reports,
documentation improvements, test coverage, and code fixes. Please keep changes
narrow and reviewable.

## Table of contents

- [Ways to contribute](#ways-to-contribute)
- [Prerequisites](#prerequisites)
- [Getting started](#getting-started)
- [Building and testing](#building-and-testing)
- [Making changes](#making-changes)
- [Commit convention](#commit-convention)
- [Opening a pull request](#opening-a-pull-request)
- [Reporting security issues](#reporting-security-issues)

## Ways to contribute

- **Bug reports** — open a GitHub issue with a minimal reproduction.
- **Documentation** — fix typos, clarify rustdoc, improve guides.
- **Tests** — add missing coverage, especially for error paths and edge cases.
- **Bug fixes** — see open issues labelled `bug`.
- **Protocol correctness** — if you find a deviation from the
  [DGProto v1 spec](https://github.com/datagram-messenger/dgproto-go/blob/main/docs/protocol/dgproto-v1.md),
  please open an issue before sending a PR.

For larger changes, open an issue first to discuss the approach.

## Prerequisites

**Required:**

- Rust **1.80 or newer** (`rustup update stable`)
- `rustfmt` and `clippy` components (`rustup component add rustfmt clippy`)
- Git

**Optional — for fuzzing only:**

- A nightly Rust toolchain (`rustup toolchain install nightly`)
- `cargo-fuzz` (`cargo install cargo-fuzz --locked`)
- A local checkout of [`dgproto-go`](https://github.com/datagram-messenger/dgproto-go)
  is useful when validating cross-language behavior; its
  `docs/protocol/dgproto-v1.md` is the normative protocol specification.

## Getting started

```sh
git clone https://github.com/datagram-messenger/dgproto-rs.git
cd dgproto-rs
cargo fetch --locked
```

`Cargo.lock` and `fuzz/Cargo.lock` are tracked. Please do not delete or update
them incidentally. Never commit generated `target/` trees, fuzz artifacts,
private keys, credentials, or production captures.

## Building and testing

Run all checks from the repository root before opening a PR:

```sh
cargo fmt --all -- --check        # formatting
cargo clippy --all-targets -- -D warnings  # lints
cargo test --all-features         # tests
cargo doc --all-features --no-deps         # docs
```

To auto-format locally:

```sh
cargo fmt --all
```

CI runs the same checks on Linux, Windows, and macOS, plus a release-mode test
run and an MSRV check on Rust 1.80.

### Fuzzing

The fuzz package defines four parser targets:

```sh
cargo +nightly fuzz run fuzz_header   -- -max_total_time=60
cargo +nightly fuzz run fuzz_frame    -- -max_total_time=60
cargo +nightly fuzz run fuzz_tlv      -- -max_total_time=60
cargo +nightly fuzz run fuzz_messages -- -max_total_time=60
```

CI uses 30-second smoke runs. Longer local runs are encouraged for parser
changes. Please do not commit `fuzz/target/`, `fuzz/artifacts/`, or local
corpora unless you are intentionally adding a reviewed regression fixture.

## Making changes

### Protocol and wire compatibility

This crate implements a security-sensitive wire protocol. Please keep the
following in mind:

- The normative specification lives in
  [`dgproto-go/docs/protocol/dgproto-v1.md`](https://github.com/datagram-messenger/dgproto-go/blob/main/docs/protocol/dgproto-v1.md).
  Read the relevant section before changing any wire-visible behavior.
- Core invariants — the 40-byte header layout, Noise XX flight order, ChaCha20-Poly1305
  AEAD, nonce construction, replay check-then-commit, and rekey ordering — must not
  change without an explicit protocol decision and updated test vectors.
- Please do not introduce new protocol extensions, negotiation, or a server/responder
  role; this crate is strictly a client (initiator) implementation.

### Test vectors

`testdata/vectors/*.json` contains interoperability fixtures shared with `dgproto-go`.
Run `cargo test wire_vectors` to execute them. Please treat these files as
immutable compatibility evidence — if a wire-visible change requires updating
vectors, explain the normative basis in the PR and verify parity with the Go
implementation.

### Documentation

Please update documentation when you change public behavior, API, or defaults:

- `README.md` for user-facing setup and guarantees.
- `docs/architecture/overview.md` for structural or concurrency changes.
- Rustdoc on public items for API contracts.

## Commit convention

All commits must follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

<body — explain what and why, not how>
```

Permitted types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `chore`, `ci`.  
Scope is the affected module (e.g. `connection`, `session`, `replay`, `codec`,
`handshake`, `transport`, `header`, `frame`, `tlv`, `messages`).

Breaking changes must include a `BREAKING CHANGE:` footer. Release notes are
generated automatically from commit history by
[git-cliff](https://git-cliff.org/); commits that do not follow the convention
will be omitted from the changelog.

## Opening a pull request

GitHub pre-fills the PR body from `.github/pull_request_template.md` when you
use the web UI. The checklist there covers all the things we look for in a
review.

If you prefer the `gh` CLI, supply the body explicitly — the template is not
applied automatically by the CLI:

```sh
# Copy the template, fill it in, then open the PR.
cp .github/pull_request_template.md .pr-body.md
# ... edit .pr-body.md ...
gh pr create \
  --base main \
  --head <your-branch> \
  --title "fix(connection): short description" \
  --body-file .pr-body.md

# Verify the result, then delete the temporary file.
gh pr view --json title,body
rm .pr-body.md   # or: del .pr-body.md on Windows
```

Please use **squash** or **rebase** merges — no merge commits on `main`.

---

## Reporting security issues

Please do not report suspected vulnerabilities in a public issue or pull
request. Use the repository's private GitHub security advisory form:

<https://github.com/datagram-messenger/dgproto-rs/security/advisories/new>

Include affected crate versions and, for wire-level issues, the relevant
protocol draft or `dgproto-go` revision, impact, and reproduction steps. Please
do not include real credentials, private keys, user data, or production
captures.

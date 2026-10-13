# dgproto-rs — Release Roadmap: v0.1.x → v1.0.0

> **Current:** v0.3.3 · **Target:** v1.0.0 — stable, production-ready, developer-friendly  
> **Active milestones:** v0.3.x (patch) · v0.4.0 (next)  
> **Reference implementation:** [`dgproto-go`](https://github.com/datagram-messenger/dgproto-go)  
> **Protocol spec:** `dgproto-go/docs/protocol/dgproto-v1.md` (normative)

---

## 1. Where We Are

All 15 implementation steps from `AGENTS.md §11` are complete. The library is
**functionally correct** — wire-compatible with `dgproto-go`, fully tested, CI-green,
and already used by `dgproto-chat`. The path to v1.0.0 is entirely about **DX polish,
documentation, hardening, and API stability** — not new protocol features.

We are currently **actively working on v0.2.0 and v0.3.0**. v0.2.0 is the first
post-MVP release and its core changes (public `Tlv`, `Vec<Tlv>` fields, root
re-exports) are implemented in `Cargo.toml` at version `0.2.0`. Work continues on
the remaining checklist items (tests, docs, README). v0.3.0 (key persistence) begins
immediately after v0.2.0 is tagged.

```
v0.1.2 ✅ DONE   — MVP complete: all 15 modules, CI green, wire-vectors pass
v0.2.0 ✅ DONE   — API ergonomics: public Tlv, Vec<Tlv> fields, re-exports
v0.2.2 ✅ DONE   — Patch release under v0.2.x milestone
v0.3.0 ✅ DONE   — Key management: StaticKey persistence + public_hex
v0.3.3 ✅ DONE   — Patch releases under v0.3.x milestone
v0.3.4 ✅ DONE   — Security and correctness fixes (see §v0.3.4 below)
v0.4.0 🔧 ACTIVE — Connection lifecycle: wait_for_close, on_connect/on_disconnect
v0.5.0           — Documentation: getting-started guide, examples, handler_fn
v0.6.0           — Security hardening: TOFU docs, property tests, fuzz_session
v0.7.0           — Performance: criterion benchmarks, hot-path allocation review
v0.8.0           — Pre-1.0 API audit: final breaking changes, CHANGELOG, MSRV bump
v0.9.0           — Release candidate: interop validation, freeze, crates.io RC
v1.0.0           — Stable: SemVer guarantees locked, production supported
```

---

## 1a. Versioning Model: pre-v1, patch releases, and what v1.0.0 means

### What "pre-v1" means for this library

`dgproto-rs` is in the **pre-v1 phase** (0.x.y). During this phase:

- **Minor version bumps (0.x.0)** are milestone releases. Each milestone has a named
  theme (see the roadmap above). A minor bump MAY include **breaking public API
  changes** — callers must review the CHANGELOG before upgrading.
- **No backward-compatibility promise** is made between 0.x.0 releases until v1.0.0.
  `dgproto-chat` is the primary integration target and will be updated alongside each
  milestone.
- **Wire format stability is NOT governed by semver.** The wire format is governed by
  the DGProto v1 protocol specification (`dgproto-go/docs/protocol/dgproto-v1.md`).
  Any pre-v1 release that changes wire bytes is a protocol regression and a blocker —
  this is a hard invariant that exists outside semver.
- The API is converging toward the stable v1.0.0 surface. Changes at each milestone
  are deliberate, well-documented, and validated against `dgproto-chat`.

### Patch releases (v0.x.z, z > 0)

A patch release is triggered only when:

| Trigger | Example |
|---|---|
| Confirmed bug affecting correctness | AEAD nonce constructed incorrectly for sequence N |
| Panic or UB in non-test library code | Slice index out of bounds in frame parser |
| Wire-compatibility regression introduced by a prior commit | Re-encode test fails against `dgproto-go` vectors |
| Security advisory on a direct dependency | `cargo audit` reports a vulnerability in `snow` |
| Incorrect behaviour relative to the protocol spec | Sequence 0 not rejected as per §3.3 |

A patch release does **not** change the public API, introduce new features, or update
documentation beyond fixing incorrect statements. Patch versions within a milestone
branch are committed with conventional type `fix` and a descriptive scope. The `z`
in `v0.x.z` is planned reactively — it is impossible to schedule bugfixes in advance.

### What v1.0.0 means

v1.0.0 is the first release under full SemVer guarantees. To earn this tag:

**Protocol:**
- Wire format, constants, and AEAD parameters are frozen and validated against the
  final DGProto v1 specification (non-draft).
- End-to-end interop with `dgproto-go` server confirmed across all message types
  (handshake, data, rekey, keepalive, close, error).

**API stability (post-1.0 contract):**
- All types and functions re-exported from the crate root (`lib.rs` `pub use`)
  are stable. No type may be removed or renamed without a major version bump.
- `Error` is `#[non_exhaustive]` — new variants in a minor release are non-breaking.
- `ClientConfig` fields may be added with `Default` values in minor releases.
- `Connection`, `Tlv`, `StaticKey`, `ApplicationMessage` and all their public methods
  are stable.
- Calling code that compiles against v1.0.0 compiles against any v1.x.y without changes.

**Quality gates:**
- All CI gates green across ubuntu / windows / macOS.
- All four fuzz targets have been run for ≥ 1 hour each on recent code.
- Full `docs.rs` render — every public item has a doc comment, no broken intra-doc links.
- `CHANGELOG.md` covers every breaking change from v0.1.0 to v1.0.0.
- `README.md` quick-start uses the v1.0.0 API exactly.
- `cargo semver-checks` passes (no accidental breaking changes since v0.9.0).
- `cargo audit` — no known advisories.
- Published to `crates.io` under the `dgproto` crate name.

**Developer experience:**
- A developer with no prior `dgproto-rs` knowledge can build a working client in
  under 15 minutes using only `docs.rs` and `docs/guides/getting-started.md`.

---

## 2. Analysis — What `dgproto-chat` Reveals

`dgproto-chat` is the real-world integration test for this library. Its source code is
the clearest signal of where the API causes friction. Every problem below maps to a
concrete fix in §3.

---

### P1 · TLV not part of the public API  *(severity: HIGH)*

`EncryptedData.fields` is `Vec<u8>` — raw encoded bytes. The Go reference library
exposes `Fields: []TLV` — a typed slice. Every Rust caller must hand-roll TLV
encode/decode. The chat client has ~25 lines of duplicated, user-space helpers that
should never have been necessary:

```rust
// dgproto-chat/client/src/main.rs — this is library code living in an app
fn encode_tlv(typ: u8, value: &[u8]) -> Vec<u8> { … }
fn decode_first_tlv(fields: &[u8]) -> Option<(u8, Vec<u8>)> { … }
```

The library already owns the TLV codec in `src/tlv.rs` — it is simply `pub(crate)`.
The Go server writes `Fields: []dgproto.TLV{{Type: 1, Value: payload}}` directly.
Our Rust callers cannot.

**Root cause:** `Tlv` struct is `pub(crate)`. `EncryptedData.fields` stores raw bytes.  
**Fix → v0.2.0:** expose `Tlv`, change `fields` to `Vec<Tlv>` (BREAKING), match Go API.

---

### P2 · `ApplicationMessage` not re-exported at crate root  *(severity: MEDIUM)*

```rust
// user must write — internal path leaks into application code:
use dgproto::connection::{ApplicationMessage, MessageHandler};

// should work from crate root:
use dgproto::{ApplicationMessage, MessageHandler};
```

`lib.rs` re-exports `Connection`, `ClientConfig`, `MessageHandler` from `connection`,
but not `ApplicationMessage`. Users who write message handlers are forced to know the
internal module structure.

**Fix → v0.2.0:** add `pub use connection::ApplicationMessage` to `lib.rs`.

---

### P3 · `StaticKey` has no persistence API  *(severity: HIGH)*

The chat client generates a **fresh ephemeral key on every launch**:

```rust
let client_key = StaticKey::generate()?; // new identity on every restart!
```

This defeats Noise XX mutual authentication — the server cannot recognize returning
clients. `StaticKey` has `load(bytes)` but no `to_private_bytes()` accessor. Users
cannot serialize their identity without reaching outside the library.

The immediate consequence in `dgproto-chat`: every client restart is a new anonymous
connection. The server's allowlist is meaningless. Rekey history is lost.

**Fix → v0.3.0:** add `StaticKey::to_private_bytes() -> [u8; 32]` and `public_hex()`.
Add a key-management guide with the persist-and-reload pattern.

---

### P4 · No `Connection::wait_for_close()`  *(severity: MEDIUM)*

There is no way to `await` connection termination. The chat client detects
disconnection only when `conn.send()` returns `Err` on the *next attempted send* —
after the connection is already dead. This makes the reconnect loop reactive and racy:

```rust
// current chat client pattern — detects disconnect only on next send:
match conn.send(msg) {
    Err(_) => {
        tokio::time::sleep(Duration::from_secs(2)).await;
        continue 'reconnect;
    }
    …
}
```

A well-designed client should be able to react to disconnection immediately, not
accidentally on the next message.

**Fix → v0.4.0:** `Connection::wait_for_close() -> impl Future<Output = Option<Error>>`.

---

### P5 · No connection lifecycle callbacks  *(severity: MEDIUM)*

The `MessageHandler` is invoked only for inbound `ApplicationMessage`s. There is no
callback for connect or disconnect events. The chat client cannot show a clean
"disconnected" banner without a polling loop or the racy send-error detection above.

**Fix → v0.4.0:** `on_connect` and `on_disconnect` optional hooks in `ClientConfig`.

---

### P6 · Handler boilerplate — `Box::pin(async move { … })`  *(severity: LOW)*

Every handler requires wrapping in `Box::pin`:

```rust
let handler: MessageHandler = Arc::new(move |_conn, msg| {
    Box::pin(async move { … Ok(()) }) // ← required boilerplate, not obvious
});
```

Idiomatic Rust async, but verbose and not documented with examples. New users copy
this pattern without understanding it.

**Fix → v0.5.0:** `handler_fn` free-function helper; document the pattern clearly.

---

### P7 · `docs/guides/getting-started.md` does not exist  *(severity: MEDIUM)*

`AGENTS.md §2` lists `docs/guides/getting-started.md` as a canonical file in the
repository layout. The Go library has a comprehensive, compile-checked guide. The
Rust library has only the README quick-start snippet, which is insufficient for
real-world onboarding.

**Fix → v0.5.0:** write the guide covering: key lifecycle, connecting, sending,
receiving, reconnect pattern with `wait_for_close()`, graceful shutdown.

---

### P8 · `server_static_hint: None` silently trusts any server (TOFU footgun) *(severity: MEDIUM)*

When `server_static_hint` is `None`, any server that completes a valid Noise XX
handshake is accepted. This is documented inside `connection.rs` but the README
quick-start and the `Default` impl both omit the hint, making TOFU the default.
A developer copying the quick-start will connect insecurely without realising it.

**Fix → v0.5.0 (partial):** add `# Security` warning to `ClientConfig` rustdoc and
`getting-started.md` immediately — do not wait for the builder method.  
**Fix → v0.6.0 (full):** `ClientConfig::with_server_key(key)` builder method that
makes the secure path the ergonomic default.

---

### P9 · `stream_id` and `app_message_type` are underdocumented *(severity: LOW)*

`EncryptedData` exposes two fields that every caller must fill in, but their
semantics are not explained in the rustdoc:

```rust
EncryptedData {
    stream_id:        1,      // ← what is this? why 1 and not 0?
    app_message_type: 0x01,   // ← is this a protocol type or my type?
    fields:           vec![...],
}
```

Both are application-layer values — the library passes them through without
interpretation. A developer copying the quick-start uses `1` and `0x01` without
understanding that these are free-form tags owned entirely by the application
protocol layered on top of DGProto.

**Fix → v0.5.0:** expand rustdoc on `EncryptedData::stream_id` and
`EncryptedData::app_message_type` to make clear they are application-defined,
the library does not interpret them, and callers are free to use any values.
Add a note in `getting-started.md`.

---

### P10 · `ClientConfig` queue fields appear as magic numbers in caller code *(severity: LOW)*

`outbound_queue` and `handler_queue` have sensible defaults (64) but the
getting-started guide and quick-start examples spell them out explicitly:

```rust
let config = ClientConfig {
    outbound_queue: 64,   // ← why 64? is this right for me?
    handler_queue:  64,   // ← same
    ..Default::default()
};
```

Callers copy these numbers without understanding them. The `Default` impl already
sets 64 for both, so spelling them out is redundant and misleading — it implies
the caller must choose a value.

**Fix → v0.5.0:** remove `outbound_queue` and `handler_queue` from the
getting-started example and quick-start snippet (rely on `..Default::default()`).
Expand rustdoc on both fields to explain what the capacity controls and when to
tune it (e.g. high-throughput senders, slow handlers).

---

### P11 · `Connection::send` returning a synchronous `Result` is surprising *(severity: LOW)*

`send` is not `async` — it enqueues into a channel and returns immediately.
This surprises callers who expect all I/O methods to be `async`:

```rust
conn.send(msg)?;          // sync — returns Err if queue full or conn closed
conn.send_and_wait(msg).await?;  // async — waits for write to socket
```

The distinction is correct and useful, but it is easy to miss. A caller who
always uses `send_and_wait` gets unnecessary latency; one who uses `send` without
understanding backpressure may silently drop messages under load.

**Fix → v0.5.0:** add a `# Send semantics` section to `Connection` rustdoc
(mirroring the existing module-level comment) and a short note in
`getting-started.md` explaining when to use each variant.

---

### P12 · `ApplicationMessage::Ack` handling is unexplained *(severity: LOW)*

The getting-started guide shows `ApplicationMessage::Ack(_) => { /* handle or ignore */ }`
without explaining what `Ack` is, when the server sends it, or whether ignoring
it is safe. Most application developers do not need to handle `Ack` directly —
but they do not know that.

**Fix → v0.5.0:** add a rustdoc note to `Ack` and `ApplicationMessage::Ack`
explaining that acknowledgements are protocol-level and most callers can safely
ignore them unless implementing explicit application-level flow control.

---

### P13 · No benchmarks  *(severity: LOW)*

The library makes no performance claims and ships no benchmarks. There is no baseline
for frame encryption throughput, handshake latency, or allocation overhead — making
it impossible to detect regressions or compare against `dgproto-go`.

**Fix → v0.7.0:** add `benches/` with `criterion` benchmarks for all hot paths.

---

## 3. Release Plan

### v0.2.0 — API Ergonomics I: Public TLV & Re-exports

**Goal:** Eliminate hand-rolled TLV helpers in every caller (P1, P2).

**Branch:** `feat/tlv-public-api`

**Status:** Core implementation is complete in `Cargo.toml` v0.2.0. Remaining items
are test, documentation, and release hygiene.

- [x] Expose `Tlv` as a public type:
  ```rust
  pub struct Tlv { pub type_: u8, pub value: Vec<u8> }
  impl Tlv { pub fn new(type_: u8, value: impl Into<Vec<u8>>) -> Self }
  ```
- [x] **BREAKING:** Change `EncryptedData.fields: Vec<u8>` → `Vec<Tlv>`. Updated
      `messages.rs` serialize/deserialize to encode/decode TLVs transparently.
      Matches the Go `Fields []TLV` layout exactly.
- [x] Add `pub use tlv::Tlv` to `lib.rs`.
- [x] Add `pub use connection::ApplicationMessage` to `lib.rs`.
- [ ] Update `tests/wire_vectors.rs` and `tests/integration.rs` to use `Vec<Tlv>` API
      throughout (replace any remaining raw-byte field construction in test helpers).
- [ ] Update `README.md` quick-start example: show `vec![Tlv::new(1, b"hello")]`
      syntax and remove any reference to raw `fields: Vec<u8>`.
- [ ] Verify `testdata/vectors/messages.json` vectors still pass byte-for-byte
      after the `Vec<Tlv>` encode/decode path (`cargo test wire_vectors`).
- [ ] `chore(release): bump version to 0.2.0` commit + git tag `v0.2.0`.

**Semver:** BREAKING (field type change).  
**Touches:** `src/tlv.rs`, `src/messages.rs`, `src/lib.rs`, `tests/`, `README.md`.

**Patch releases under v0.2.x:** If a bug is found in TLV encode/decode (e.g. wrong
4-byte alignment, incorrect type field encoding) after the v0.2.0 tag, a v0.2.1
patch is cut immediately. All other improvements wait for v0.3.0.

---

### v0.3.0 — Key Management: Persistence & Ergonomics

**Goal:** Let applications maintain a stable Noise identity across restarts (P3).
Without key persistence, every client restart is a new anonymous identity — the
server's allowlist is meaningless, and mutual authentication is effectively broken.

**Branch:** `feat/static-key-persistence`

**Status:** Pending. Begins after v0.2.0 is tagged.

#### Implementation checklist

- [ ] Add `StaticKey::to_private_bytes(&self) -> [u8; 32]`
  - Returns the raw 32-byte X25519 private key.
  - **Security-sensitive:** add a prominent `# Safety` doc comment explaining
    that the caller is responsible for zeroing the returned array when done
    (via `zeroize::Zeroize::zeroize` or dropping a `Zeroizing<[u8;32]>` wrapper).
  - Commit: `feat(handshake): add StaticKey::to_private_bytes`

- [ ] Add `StaticKey::public_hex(&self) -> String`
  - Returns the 64-char lowercase hex-encoded public key.
  - No new dependency needed (`hex` is already a dev-dep; for prod code, implement
    the 64-char hex encoding inline using `format!` or a `write!` loop).
  - Useful for server-side registration logs and debug output.
  - Commit: `feat(handshake): add StaticKey::public_hex`

- [ ] Update `AGENTS.md §4` public API table to include both new methods.

- [ ] Unit tests for the new methods:
  - `test_handshake_to_private_bytes_roundtrip` — generate, extract bytes, reload,
    assert `public()` matches original.
  - `test_handshake_public_hex_length_and_charset` — assert 64 chars, all `[0-9a-f]`.
  - Commit: `test(handshake): add StaticKey persistence roundtrip tests`

- [ ] Create `docs/guides/key-management.md` with the following structure:
  ```
  # Key Management Guide

  ## Generating a key (first run)
  ## Persisting to disk (platform-specific paths)
  ## Loading on startup
  ## Security considerations (permissions, never log, never commit)
  ## Registering your public key with the server
  ## Rotating keys
  ```
  Key-management guide content:
  - Generate once: `let key = StaticKey::generate()?;`
  - Persist private bytes to an app-config path with restrictive permissions
    (Unix: `0o600`; Windows: restrict via ACL or OS credential store).
  - Load on startup: `StaticKey::load(&std::fs::read(key_path)?)?`
  - **Never** hardcode, log, or commit private key bytes — not even in tests.
  - Register the public key (`key.public_hex()`) with the server before first connect.
  - Key rotation requires server-side deregistration of the old public key first.
  - Commit: `docs(handshake): add key-management guide`

- [ ] Update `README.md`:
  - Replace the `StaticKey::load(&[0u8; 32])?` placeholder in the quick-start with
    a note linking to `docs/guides/key-management.md`.
  - Commit: `docs(readme): update key management quick-start reference`

- [ ] `chore(release): bump version to 0.3.0` commit + git tag `v0.3.0`.

#### Files touched

| File | Change |
|---|---|
| `src/handshake.rs` | Add `to_private_bytes`, `public_hex` methods |
| `docs/guides/key-management.md` | New file |
| `README.md` | Update key-management section |

**Semver:** Additive (two new methods, no API breaks).

**Patch releases under v0.3.x:** A v0.3.1 patch would be cut if `to_private_bytes`
is found to return incorrect bytes (e.g. wrong key direction from the `snow` state),
or if `public_hex` produces an incorrect encoding. These are security-sensitive
correctness bugs that cannot wait for the next milestone.

---

### v0.4.0 — Connection Lifecycle: `wait_for_close` & Hooks

**Goal:** Clean, non-polling observation of connection state (P4, P5).

**Branch:** `feat/connection-lifecycle`

- [ ] Add `Connection::wait_for_close(&self) -> impl Future<Output = Option<Error>>`  
      Returns when the connection's `CancellationToken` fires. Resolves to `None` on
      clean `SessionClose`, or `Some(err)` on any error termination.  
      Implementation: subscribe to the token, read the stored terminal error.
- [ ] Add `on_disconnect` field to `ClientConfig`:
  ```rust
  pub on_disconnect: Option<Arc<dyn Fn(Option<Error>) + Send + Sync>>,
  ```
  Invoked by the read loop when the connection terminates.
- [ ] Add `on_connect` field to `ClientConfig`:
  ```rust
  pub on_connect: Option<Arc<dyn Fn(Arc<Connection>) + Send + Sync>>,
  ```
  Invoked after the Noise XX handshake completes, before the first message.
- [ ] Add `Default::default()` values (`None`) for both new fields — no breaking change.
- [ ] Add integration tests:
      - `test_integration_wait_for_close_on_abort`
      - `test_integration_wait_for_close_clean_shutdown`
      - `test_integration_on_disconnect_fires_on_error`
- [ ] Document reconnect pattern using `wait_for_close()` in `connection.rs` module doc.

**Semver:** Additive (new fields default to `None`).  
**Touches:** `src/connection.rs`, `tests/integration.rs`.

---

### v0.5.0 — Documentation: Getting Started, Examples & Handler Ergonomics

**Goal:** A developer builds a working client in < 15 minutes without reading Go source (P6, P7).

**Branch:** `docs/getting-started`

- [ ] Create `docs/guides/getting-started.md`:
  ```
  1. Adding the dependency
  2. Key generation and persistence (link → key-management.md)
  3. Connecting with server key verification
  4. Sending EncryptedData with Tlv fields (Vec<Tlv> API)
  5. Receiving messages — the MessageHandler pattern
  6. Graceful shutdown with conn.close()
  7. Reconnect loop using wait_for_close()
  8. Complete compile-checked example
  ```
- [ ] Create `examples/client.rs` — minimal but complete lifecycle demo:
      key load-or-generate, connect, send one message, receive echo, close.
      Add `[[example]]` entry to `Cargo.toml`.
- [ ] Add `handler_fn` free function to `connection.rs` to reduce `Box::pin` boilerplate:
  ```rust
  pub fn handler_fn<F, Fut>(f: F) -> MessageHandler
  where
      F: Fn(Arc<Connection>, ApplicationMessage) -> Fut + Send + Sync + 'static,
      Fut: Future<Output = Result<(), Error>> + Send + 'static,
  ```
- [ ] Re-export `handler_fn` from `lib.rs`.
- [ ] Add `# Examples` doc comments to `ClientConfig`, `Connection::send`,
      `Connection::close`, `Connection::wait_for_close`, `MessageHandler`.
- [ ] Add `# Security` warning to `ClientConfig` rustdoc and `getting-started.md`
      about `server_static_hint: None` (TOFU) — do not wait for the builder in v0.6.0.
      Clearly state: "If `None`, any server completing a valid Noise XX handshake is
      accepted. Always set this in production." (P8 partial fix)
- [ ] Expand rustdoc on `EncryptedData::stream_id` and `EncryptedData::app_message_type`:
      both are application-defined, the library does not interpret them, callers may
      use any values. Add a short note in `getting-started.md`. (P9)
- [ ] Remove `outbound_queue` and `handler_queue` from the getting-started example
      and quick-start snippet — rely on `..Default::default()`. Expand rustdoc on
      both fields to explain what the capacity controls and when to tune it. (P10)
- [ ] Add a `# Send semantics` section to `Connection` rustdoc explaining the
      `send` (sync, fire-and-forget) vs `send_and_wait` (async, socket-confirmed)
      distinction and when to use each. Add a short note in `getting-started.md`. (P11)
- [ ] Add a rustdoc note to `Ack` and `ApplicationMessage::Ack` explaining that
      acknowledgements are protocol-level and most callers can safely ignore them
      unless implementing explicit application-level flow control. (P12)

**Semver:** Additive (new helper, new example).  
**Touches:** `src/connection.rs`, `src/lib.rs`, `docs/guides/`, `examples/`, `Cargo.toml`.

---

### v0.6.0 — Security & Protocol Hardening

**Goal:** Eliminate TOFU footgun, strengthen test coverage of security-critical paths (P8).

**Branch:** `feat/security-hardening`

- [ ] Add `ClientConfig::with_server_key(key: [u8; 32]) -> Self` builder method:
      sets `server_static_hint = Some(key)` and documents security reasoning inline.
      Makes the secure connection path the ergonomic default.
- [ ] Add property-based tests (add `proptest` as dev-dependency):
      - Replay window: arbitrary sequence delivery orders — never panic, never accept
        duplicate, always reject sequence outside window
      - TLV round-trip: `decode_tlvs(encode_tlvs(x)) == x` for arbitrary inputs
      - Frame length invariants: `marshal → unmarshal` is identity for any valid frame
- [ ] Add fuzz target `fuzz/fuzz_targets/fuzz_session.rs`: fuzz
      `Session::decrypt_frame` with arbitrary ciphertext under a known key.
      Register in CI smoke run (30s).
- [ ] Add integration test: `test_integration_wrong_server_key_rejected` —
      set `server_static_hint` to a different key, assert `Error::Handshake`.
- [ ] Audit non-test source for `unwrap()` / `expect()` on untrusted data (must be zero).
      Add `#![forbid(clippy::unwrap_used)]` in `lib.rs` cfg-guarded for non-test builds,
      or document and fix each remaining instance.
- [ ] Update CI: add `cargo +nightly fuzz run fuzz_session -- -max_total_time=30`.

**Semver:** Additive (new method, new dev-deps).  
**Touches:** `src/connection.rs`, `src/lib.rs`, `fuzz/`, `tests/`, `.github/workflows/ci.yml`.

---

### v0.7.0 — Performance: Benchmarks & Hot-Path Review

**Goal:** Establish a repeatable performance baseline; remove obvious allocation waste.

**Branch:** `perf/benchmarks`

- [ ] Add `benches/` with `criterion` benchmarks (add `criterion` as dev-dependency):
  | Benchmark | What it measures |
  |---|---|
  | `bench_frame_encrypt` | `Session::encrypt_frame` throughput (frames/sec, MB/sec) |
  | `bench_frame_decrypt` | `Session::decrypt_frame` throughput |
  | `bench_handshake_loopback` | Full Noise XX loopback latency (µs) |
  | `bench_tlv_encode` | `encode_tlvs` on a 3-field payload |
  | `bench_tlv_decode` | `decode_tlvs` on same payload |
  | `bench_header_roundtrip` | `marshal_binary` + `unmarshal_binary` |
- [ ] Add `[profile.bench]` to `Cargo.toml` (inherits release, debug = 1).
- [ ] Add CI step: `cargo bench --no-run` — compile benchmarks on every PR, catch
      breakage without running the full suite.
- [ ] Profile the write path with `cargo flamegraph` or `perf`. Target: ≤ 1 allocation
      per frame send for typical `EncryptedData` payloads after connection establishment.
- [ ] If allocation target is not met: evaluate `bytes::BytesMut` for inbound frame
      assembly in `transport.rs` to avoid the header-then-body double-read copies.

**Semver:** Additive (no API changes).  
**Touches:** `benches/`, `Cargo.toml`, `.github/workflows/ci.yml`.

---

### v0.8.0 — Pre-1.0 Stabilization: API Audit & Changelog

**Goal:** Final breaking changes window. Everything that ships in v1.0.0 is locked here.

**Branch:** `refactor/pre-1.0-api-audit`

- [ ] Full public API audit against `AGENTS.md §4` contract:
      - Every public type has `Debug`
      - Value types (`Tlv`, `EncryptedData`, `Ack`, etc.) have `Clone`
      - Every public field/method has a doc comment
      - No internal module path appears in public type signatures
- [ ] Decide and lock `Connection::send` signature: keep `impl Into<ApplicationMessage>`
      or switch to typed methods `send_data` / `send_ack`? (Leaning toward keeping the
      current form for ergonomics, but must be decided before 1.0.)
- [ ] Remove any `pub use` of `connection::*` items that are not in the intended stable
      surface. `connection` module stays `pub` but its contents should be re-exported
      deliberately from crate root.
- [ ] Review `Error` variants: fill gaps, remove redundancies. Note: `Error` is
      `#[non_exhaustive]` — new variants can be added in minor versions post-1.0.
- [ ] Bump MSRV to latest stable − 1 at time of release (currently targeting 1.82).
      Update `Cargo.toml`, CI badge, README badge.
- [ ] Run `cargo semver-checks` — no accidental breaking changes relative to v0.7.x.
- [ ] Generate `CHANGELOG.md` from `cliff.toml` and clean it up manually.
      Entry format: `## [0.x.0] - YYYY-MM-DD` with `### Added / Changed / Fixed /
      Breaking` sections.

**Semver:** Potentially BREAKING — last window before 1.0.  
**Touches:** All `src/` files, `Cargo.toml`, `CHANGELOG.md`, `README.md`.

---

### v0.9.0 — Release Candidate: Interop Validation & API Freeze

**Goal:** Prove cross-implementation correctness; freeze API; invite external review.

**Branch:** `chore/v0.9.0-rc`

- [ ] Wire-vector sync: copy latest `dgproto-go/testdata/vectors/*.json` into
      `testdata/vectors/`. Run `cargo test wire_vectors` — must pass byte-for-byte.
- [ ] End-to-end interop matrix against `dgproto-go` server:
      - Full Noise XX handshake
      - EncryptedData round-trip
      - Rekey transition (force trigger at low epoch frame limit)
      - Graceful `SessionClose` from both sides
      - Keepalive ping/pong
- [ ] Publish `v0.9.0-rc.1` to crates.io. Request review from `dgproto-go` maintainers
      and any early adopters.
- [ ] Address all blocking feedback within 2 weeks; publish `rc.2` if needed.
- [ ] `cargo audit` — no known advisories.
- [ ] Verify docs.rs renders all public items correctly (no missing `[]` links,
      no orphaned modules, examples compile).
- [ ] Write final `CHANGELOG.md` entry for v1.0.0.

**Semver:** RC — last chance for breaking changes on critical feedback.  
**Touches:** `testdata/vectors/`, `Cargo.toml`, `CHANGELOG.md`.

---

### v1.0.0 — Stable Release

**Goal:** SemVer guarantees apply. Production use is officially supported.

**Checklist:**
- [ ] All milestones v0.2.0–v0.9.0 complete and merged to `main`.
- [ ] All CI gates green: `cargo test --all-features`, `cargo test --release`,
      `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`,
      fuzz smoke (all four targets), MSRV check.
- [ ] `cargo semver-checks` — no accidental breaking changes since v0.9.0.
- [ ] `docs.rs` — all public items documented; no warnings.
- [ ] `README.md` quick-start uses v1.0.0 API (`Vec<Tlv>`, `handler_fn`, `wait_for_close`).
- [ ] `Cargo.toml` — set `version = "1.0.0"`. Remove any `[patch]` overrides.
- [ ] `CHANGELOG.md` — complete from v0.1.0 to v1.0.0.
- [ ] Tag `v1.0.0` on `main`. Push. Publish to crates.io.
- [ ] Open PR against `dgproto-go` to update the `dgproto-rs` cross-reference links.
- [ ] Update `dgproto-chat` client to v1.0.0 API (remove hand-rolled TLV helpers,
      persist client key, use `wait_for_close` reconnect pattern).

**Post-1.0 stability guarantees:**
- All types and functions in `pub use` at crate root are stable.
- `Error` is `#[non_exhaustive]` — new variants are non-breaking minor changes.
- `ClientConfig` fields may be added with `Default` values in minor versions.
- No public type is removed or renamed without a major version bump.
- Wire format, constants, and security invariants are frozen per spec.

---

## 4. Release Overview

| Version | Theme | Semver impact | Key deliverable |
|---------|-------|---------------|-----------------|
| v0.2.0 | API Ergonomics I | **BREAKING** | `Vec<Tlv>` fields, `ApplicationMessage` at root |
| v0.3.0 | Key Management | Additive | `to_private_bytes()`, key-management guide |
| v0.4.0 | Connection Lifecycle | Additive | `wait_for_close()`, lifecycle hooks |
| v0.5.0 | Documentation & DX | Additive | Getting-started guide, `handler_fn`, examples, TOFU warning, send semantics docs |
| v0.6.0 | Security Hardening | Additive | Property tests, `fuzz_session`, TOFU docs |
| v0.7.0 | Performance | Additive | Criterion benchmarks, allocation audit |
| v0.8.0 | Pre-1.0 Audit | **BREAKING** | Final API locks, CHANGELOG, MSRV bump |
| v0.9.0 | Release Candidate | RC | Interop validation, freeze, community review |
| v1.0.0 | Stable Release | — | SemVer locked, crates.io publish |

---

## 5. Cross-Project Impact on `dgproto-chat`

Every improvement in `dgproto-rs` has a mirror cleanup in `dgproto-chat`:

| When | dgproto-rs change | dgproto-chat fix |
|------|-------------------|------------------|
| v0.2.0 | `fields: Vec<Tlv>` public | Delete `encode_tlv` / `decode_first_tlv` helpers; use `vec![Tlv::new(1, text.as_bytes())]` |
| v0.2.0 | `ApplicationMessage` at crate root | Fix `use dgproto::connection::ApplicationMessage` → `use dgproto::ApplicationMessage` |
| v0.3.0 | `StaticKey::to_private_bytes()` | Persist key to `%APPDATA%\dgproto-chat\key` on Windows; load on startup |
| v0.4.0 | `wait_for_close()` | Replace `'reconnect: loop` + send-error detection with `conn.wait_for_close().await` |
| v0.4.0 | `on_disconnect` hook | Show "· disconnected" banner immediately, not on next send |
| v0.5.0 | `handler_fn` helper | Simplify handler definition with `handler_fn(|conn, msg| async { … })` |

After all updates, `dgproto-chat/client/src/main.rs` should contain **zero** hand-rolled
protocol helpers — all library responsibilities fulfilled by `dgproto`.

---

## 6. What v1.0.0 Deliberately Will NOT Include

Per `AGENTS.md §13` and the MVP scope of the DGProto v1 specification — these require
separate protocol revision first and are explicitly out of scope:

| Item | Reason |
|------|--------|
| QUIC / UDP transport | Post-MVP transport profile |
| WebSocket transport | Post-MVP transport profile |
| Noise IK / Noise XK | Post-MVP handshake pattern |
| 0-RTT / session resumption | Post-MVP; spec §8 historical only |
| Transport obfuscation | Post-MVP; spec §8 historical only |
| Noise XX **responder** (server) role | `dgproto-go` owns the server |
| `ring` crypto backend | Explicitly prohibited (AGENTS.md §5) |
| `serde` for wire encoding | Explicitly prohibited (AGENTS.md §5) |
| `async-std` / `smol` | Explicitly prohibited (AGENTS.md §13) |
| Binary targets (`main.rs`) | Explicitly prohibited (AGENTS.md §13) |
| `anyhow` / `Box<dyn Error>` in library code | Explicitly prohibited (AGENTS.md §6) |
| Public `Frame`, `Header`, `Session`, `Codec` | Explicitly prohibited (AGENTS.md §4) |

---

## 7. Invariants That Must Not Change

The following are correct and must not be altered anywhere in this roadmap:

- Wire format: 40-byte header, magic `DGP1`, version `0x01`, all LE fields, no outer
  length prefix, 65535-byte max frame, 16-byte AEAD tag.
- `Noise_XX_25519_ChaChaPoly_SHA256` — this crate is always the **initiator**.
- Nonce: `[0u8;4] || seq.to_le_bytes()`. Sequences start at 1. Never reuse.
- Rekey labels: `"DGPv1 Rekey Confirm"`, `"DGPv1 Rekey Send Key"` (exact byte strings).
- Replay window: 2048 entries, check-before-authenticate, commit-after-authenticate.
- Three-task concurrency model: read loop, write loop, maintenance loop.
- Separate send/receive `Mutex` guards in `Session` (never held simultaneously).
- `CancellationToken` for coordinated shutdown. First terminal cause retained atomically.
- `#[non_exhaustive]` on `Error`. Apache-2.0 license. `Cargo.lock` always committed.

---

## §v0.3.4 — Patch release checklist

Triggered by security and correctness findings identified during code review.
No public API changes. No wire-format changes. No new features.

| # | Scope | Severity | Description |
|---|-------|----------|-------------|
| 1 | `session` | CRIT | Padding bytes were always zero; replaced with `OsRng::fill_bytes` |
| 2 | `messages` | HIGH | `ErrorMessage::unmarshal_binary` silently truncated wire codes > 255 |
| 3 | `connection` | HIGH | `read_timeout` was incorrectly reusing `write_timeout`; added separate field |
| 4 | `connection` | HIGH | `pong.marshal_binary().unwrap_or_default()` swallowed serialization errors |
| 5 | `replay` | HIGH | `advance()` carry term used `>> (64 - bit_shift)` which panics when `bit_shift == 0` in debug |
| 6 | `session` | MED | `grace_remaining` was not decremented on previous-epoch frames |
| 7 | `session` | MED | Unnecessary `clone()` of replay window before `commit()` |
| 8 | `connection` | LOW | `closing` flag used `Ordering::Relaxed`; upgraded to `Acquire`/`Release` |
| 9 | `messages` | LOW | `expect()` in hot parse paths replaced with fallible `map_err` |

**Regression tests added:** `test_session_padding_is_random`, `test_session_sequence_exhausted`,
`test_messages_error_message_code_out_of_range`, `test_replay_advance_word_aligned_shift`.

---

*Authored from analysis of `dgproto-chat`, `dgproto-rs`, and `dgproto-go` source trees.*  
*Cross-reference: `dgproto-go/docs/protocol/dgproto-v1.md` (normative wire spec).*

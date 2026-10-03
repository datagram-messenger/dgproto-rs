<div align="center">

# dgproto-rs

**Rust client library for the DGProto v1 secure transport protocol.**

[![CI](https://github.com/datagram-messenger/dgproto-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/datagram-messenger/dgproto-rs/actions/workflows/ci.yml?query=branch%3Amain)
[![Crates.io](https://img.shields.io/crates/v/dgproto.svg)](https://crates.io/crates/dgproto)
[![docs.rs](https://docs.rs/dgproto/badge.svg)](https://docs.rs/dgproto)
[![Rust 1.80+](https://img.shields.io/badge/Rust-1.80%2B-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![DGProto v1](https://img.shields.io/badge/protocol-DGProto%20v1-6f42c1)](https://github.com/datagram-messenger/dgproto-go/blob/main/docs/protocol/dgproto-v1.md)

[Install](#install) · [Quick start](#quick-start) · [Key management](#key-management) · [Sending and lifecycle](#sending-and-lifecycle) · [Documentation](#documentation)

</div>

Rust implementation of the draft DGProto v1 wire protocol and secure session runtime. It is a **pure library crate** — no binary, no server, no framework. The canonical reference implementation is [`dgproto-go`](https://github.com/datagram-messenger/dgproto-go).

- **L0:** async TCP transport (Tokio); length derived from the fixed header — no outer length prefix
- **L1:** fixed 40-byte header, strict frame parsing, TLV envelope
- **L2:** `Noise_XX_25519_ChaChaPoly_SHA256` handshake (client/initiator role only), ChaCha20-Poly1305 AEAD
- **L3:** directional epochs, automatic rekeying, 2048-entry replay window, keepalive, connection lifecycle
- **L4:** typed application messages — `EncryptedData`, `Ack`, `ErrorMessage`, `SessionClose`

The [DGProto v1 specification](https://github.com/datagram-messenger/dgproto-go/blob/main/docs/protocol/dgproto-v1.md) is normative for wire behavior. The draft protocol and crate releases are versioned independently.

> [!NOTE]
> **Client only.** This crate implements the Noise XX **initiator** role. The server counterpart is [`dgproto-go`](https://github.com/datagram-messenger/dgproto-go) / [`datagram-server`](https://github.com/datagram-messenger/server).

---

## Install

```toml
[dependencies]
dgproto = "0.1"
tokio   = { version = "1", features = ["full"] }
```

Minimum supported Rust version: **1.80**.

---

## Quick start

```rust
use dgproto::{ClientConfig, Connection, EncryptedData, StaticKey};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), dgproto::Error> {
    // Load a persistent 32-byte X25519 private key (hex-encoded).
    // Generate once with StaticKey::generate(); store the private bytes securely.
    let key = StaticKey::load(&hex::decode("YOUR_64_HEX_CHAR_PRIVATE_KEY").unwrap())?;

    let config = ClientConfig {
        static_key:        key,
        handshake_timeout: Duration::from_secs(10),
        write_timeout:     Duration::from_secs(10),
        outbound_queue:    64,
        ..Default::default()
    };

    // Dial the server and complete the three-flight Noise XX handshake.
    let conn = Connection::connect("127.0.0.1:8090", config).await?;

    // Send an application message (enqueued; returns when accepted by the outbound queue).
    conn.send(EncryptedData {
        stream_id:        1,
        app_message_type: 0x01,
        fields:           b"hello datagram".to_vec(),
    })?;

    // Graceful shutdown: sends SessionClose and waits for the peer's reply.
    conn.close().await?;
    Ok(())
}
```

See [Getting started](docs/guides/getting-started.md) for a complete example with inbound message dispatch, error handling, and signal-driven shutdown.

---

## Key management

The client Noise static private key is your cryptographic identity on the network. Generate it once and reuse it across restarts. The server must register your public key before you can connect.

```rust
// Generate a new key pair (do this once at setup time).
let key = StaticKey::generate()?;
println!("Register this public key on the server:");
println!("{}", hex::encode(key.public()));

// On subsequent runs, load the saved private key bytes.
let key = StaticKey::load(&private_bytes)?;
```

> [!IMPORTANT]
> Never log, commit, or write the static private key to disk in plaintext.
> Use OS keychain APIs or caller-managed secure storage.
> Losing the key requires re-registration with every server you connect to.

---

## Sending and lifecycle

| Method | Semantics |
|---|---|
| `conn.send(msg)` | Enqueues into the bounded outbound channel. Returns immediately. `Err` if the queue is full or the connection is closed. |
| `conn.send_and_wait(msg).await` | Enqueues and awaits confirmation that the frame was written to the TCP socket. Does **not** guarantee peer receipt or application acknowledgement. |
| `conn.send_padded(msg, pad_len)` | Like `send`, with explicit random padding (0–255 bytes). Padding policy is the caller's responsibility. |
| `conn.close().await` | Sends `SessionClose`, waits for the peer's reply, then tears down the connection. |
| `conn.abort()` | Terminates the connection immediately without a close handshake. |

The first observed terminal cause is retained. All subsequent `send` calls return
`Err(Error::ConnectionClosed)`. `Connection` is `Clone` — all clones share the same
underlying session.

---

## Architecture

```
+--------------------------------------------------------------+
| L4  Application Messages                                     |
|     (EncryptedData, Ack, ErrorMessage, SessionClose)         |
+--------------------------------------------------------------+
| L3  DGP Session Layer                                        |
|     (directional epochs, sequence numbers, rekeying,         |
|      2048-entry replay window, keepalive)                    |
+--------------------------------------------------------------+
| L2  DGP Cryptographic Layer                                  |
|     (Noise XX initiator, ChaCha20-Poly1305 AEAD,             |
|      HMAC-SHA256 key ratchet, session ID derivation)         |
+--------------------------------------------------------------+
| L1  DGP Framing Layer                                        |
|     (40-byte fixed header, TLV envelope, optional padding)   |
+--------------------------------------------------------------+
| L0  Transport Layer                                          |
|     (async TCP via Tokio — no outer length prefix)           |
+--------------------------------------------------------------+
```

**Module map:**

| File | Layer | Responsibility |
|---|---|---|
| `src/header.rs` | L1 | 40-byte header encode/decode |
| `src/frame.rs` | L1 | Frame struct, marshal/unmarshal |
| `src/tlv.rs` | L1 | TLV codec, 4-byte alignment |
| `src/messages.rs` | L4 | Typed message structs, parse/serialize |
| `src/codec.rs` | L2 | Stateless ChaCha20-Poly1305 AEAD |
| `src/handshake.rs` | L2 | Noise XX initiator state machine |
| `src/session.rs` | L3 | Directional codec, epoch, sequence, replay |
| `src/replay.rs` | L3 | 2048-bit sliding replay window |
| `src/rekey.rs` | L3 | Rekey epoch transitions, HMAC key ratchet |
| `src/transport.rs` | L0 | `Transport` trait, `TcpTransport` impl |
| `src/connection.rs` | L0–L4 | Connection runtime, loops, lifecycle |
| `src/error.rs` | — | Unified `Error` enum |
| `src/lib.rs` | — | Public API surface |

---

## Wire compatibility

Every parser and serializer is validated against the shared wire test vectors generated by
[`dgproto-go`](https://github.com/datagram-messenger/dgproto-go/tree/main/testdata/vectors):

```sh
cargo test wire_vectors
```

Any divergence from the Go reference is a **bug**, not a design choice. Report it as a
protocol interoperability issue.

---

## Security

DGProto v1 is security-sensitive infrastructure. Key properties of this implementation:

- **Mutual authentication** — Noise XX proves both client and server identity before any
  application data is exchanged. Neither side can be impersonated without the static private key.
- **Authenticated encryption** — ChaCha20-Poly1305 AEAD on every data frame. The full
  40-byte header (including reserved bytes and padding) is authenticated as AAD.
- **Replay protection** — per-direction sequence numbers starting at 1; a 2048-entry
  sliding bitmap window rejects duplicates and reordered frames. Replay check precedes
  decryption; window commits only after authentication succeeds.
- **Automatic rekeying** — after 2³² frames or 10 minutes per epoch (whichever comes
  first), with a 2048-frame / 30-second previous-key grace window for in-flight frames.
  Key derivation uses HMAC-SHA256 with protocol-specific labels.
- **Key material zeroing** — all key arrays implement `ZeroizeOnDrop`.
- **Bounded resources** — outbound queue capacity is configurable; the connection runtime
  enforces handshake and write timeouts.

> [!CAUTION]
> Report vulnerabilities **privately**. Do not open public issues for suspected security bugs.
> See [`SECURITY.md`](https://github.com/datagram-messenger/dgproto-go/blob/main/SECURITY.md)
> in the reference implementation.

---

## Development

```sh
# Run all tests (unit + integration + wire vectors)
cargo test

# Run tests in release mode (CI requirement)
cargo test --release

# Lint — zero warnings policy
cargo clippy --all-targets -- -D warnings

# Format check
cargo fmt --check

# Fuzz a parser (requires cargo-fuzz and nightly toolchain)
cargo +nightly fuzz run fuzz_header  -- -max_total_time=60
cargo +nightly fuzz run fuzz_frame   -- -max_total_time=60
cargo +nightly fuzz run fuzz_tlv     -- -max_total_time=60

# Check MSRV
cargo +1.80 test
```

---

## Documentation

- [Getting started](docs/guides/getting-started.md)
- [Architecture](docs/architecture/overview.md)
- [DGProto v1 specification](https://github.com/datagram-messenger/dgproto-go/blob/main/docs/protocol/dgproto-v1.md)
- [Wire test vectors](testdata/vectors/)
- [dgproto-go — Go reference implementation](https://github.com/datagram-messenger/dgproto-go)
- [datagram-server — Go application server](https://github.com/datagram-messenger/server)
- [API reference (docs.rs)](https://docs.rs/dgproto)

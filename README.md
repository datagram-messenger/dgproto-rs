<div align="center">

# dgproto-rs

**Rust client library for the DGProto v1 secure transport protocol.**

[![CI](https://github.com/datagram-messenger/dgproto-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/datagram-messenger/dgproto-rs/actions/workflows/ci.yml?query=branch%3Amain)
[![Crates.io](https://img.shields.io/crates/v/dgproto.svg)](https://crates.io/crates/dgproto)
[![docs.rs](https://docs.rs/dgproto/badge.svg)](https://docs.rs/dgproto)
[![Rust 1.80+](https://img.shields.io/badge/Rust-1.80%2B-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![DGProto v1](https://img.shields.io/badge/protocol-DGProto%20v1-6f42c1)](https://github.com/datagram-messenger/dgproto-go/blob/main/docs/protocol/dgproto-v1.md)

</div>

---

`dgproto-rs` is a Rust client library for **DGProto v1** — a binary, session-oriented, cryptographically secured transport protocol for low-latency bidirectional communication between native clients and Go backends.

This is a **pure library crate** — no binary, no server, no framework. It handles the full client-side stack: async TCP transport, Noise XX handshake, ChaCha20-Poly1305 encryption, replay protection, and automatic rekeying.

> **Status:** The DGProto v1 specification is a draft. The protocol and crate are versioned independently. Wire compatibility should be claimed only after stabilization.

> [!NOTE]
> **Client (initiator) role only.** The server counterpart is [`dgproto-go`](https://github.com/datagram-messenger/dgproto-go). The canonical wire specification lives there too.

## How it works

| Layer | Role | What it does |
|-------|------|--------------|
| **L4** | Application | Typed messages: `EncryptedData`, `Ack`, `ErrorMessage`, `SessionClose` |
| **L3** | Session | Sequence numbers, directional epochs, rekeying, replay window, keepalive |
| **L2** | Cryptography | Noise XX initiator, ChaCha20-Poly1305 AEAD, HMAC-SHA256 key ratchet |
| **L1** | Framing | 40-byte fixed header, TLV encoding, optional padding |
| **L0** | Transport | Async TCP via Tokio — body length from header, no length prefix |

## Install

```toml
[dependencies]
dgproto = "0.2"
tokio   = { version = "1", features = ["full"] }
```

Minimum supported Rust version: **1.80**.

## Quick start

```rust
use dgproto::{ClientConfig, Connection, EncryptedData, StaticKey, Tlv};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), dgproto::Error> {
    // Load a persistent 32-byte X25519 private key.
    // Generate once with StaticKey::generate(); store the private bytes securely.
    let key = StaticKey::load(&private_bytes)?;

    let config = ClientConfig {
        static_key:        key,
        handshake_timeout: Duration::from_secs(10),
        write_timeout:     Duration::from_secs(10),
        outbound_queue:    64,
        ..Default::default()
    };

    // Dial and complete the three-flight Noise XX handshake.
    let conn = Connection::connect("127.0.0.1:8090", config).await?;

    // Send a typed application message.
    conn.send(EncryptedData {
        stream_id:        1,
        app_message_type: 0x01,
        fields:           vec![Tlv::new(1, b"hello datagram".as_ref())],
    })?;

    // Graceful shutdown: sends SessionClose and waits for the peer's reply.
    conn.close().await
}
```

See [Getting started](docs/guides/getting-started.md) for a full walkthrough including message handling, key setup, and error handling.

## Key management

The static private key is your cryptographic identity. Generate it once and reuse it across restarts — the server must register your public key before you can connect.

```rust
// Generate once at setup time.
let key = StaticKey::generate()?;
println!("Register this public key on the server:");
println!("{}", hex::encode(key.public()));

// On subsequent runs, load from secure storage.
let key = StaticKey::load(&private_bytes)?;
```

> [!IMPORTANT]
> Never log, commit, or write the static private key to disk in plaintext.
> Use OS keychain APIs or caller-managed secure storage.
> Losing the key requires re-registration with every server you connect to.

## Sending and lifecycle

| Method | Semantics |
|--------|-----------|
| `conn.send(msg)` | Enqueues into the bounded outbound channel. Returns immediately; `Err` if the queue is full or the connection is closed. |
| `conn.send_and_wait(msg).await` | Enqueues and awaits confirmation that the frame was written to the socket. Does **not** guarantee peer receipt. |
| `conn.send_padded(msg, pad_len)` | Like `send`, with explicit random padding (0–255 bytes). Padding policy is the caller's responsibility. |
| `conn.close().await` | Sends `SessionClose`, waits for the peer's reply, then tears down the connection. |
| `conn.abort()` | Terminates the connection immediately without a close handshake. |

The first observed terminal cause is always retained. `Connection` is `Clone` — all clones share the same underlying session.

## Security

- **Mutual authentication** — Noise XX proves both sides' identity before any application data is exchanged.
- **Authenticated encryption** — ChaCha20-Poly1305 AEAD on every data frame; the full 40-byte header and padding are authenticated as AAD.
- **Replay protection** — per-direction sequences starting at 1; a 2048-entry sliding bitmap window rejects duplicates. Replay check precedes decryption.
- **Automatic rekeying** — after 2³² frames or 10 minutes per epoch, with a 2048-frame / 30-second grace window for in-flight frames.
- **Key material zeroing** — all key types implement `ZeroizeOnDrop`.

> [!CAUTION]
> Report vulnerabilities **privately** — do not open public issues for suspected security bugs.
> See [SECURITY.md](SECURITY.md).

## Wire compatibility

Parsers and serializers are validated against the shared wire test vectors from [`dgproto-go`](https://github.com/datagram-messenger/dgproto-go/tree/main/testdata/vectors):

```sh
cargo test wire_vectors
```

Any divergence from the Go reference is a **bug**, not a design choice.

## Development

```sh
# Tests
cargo test
cargo test --release          # CI requirement

# Lint and format
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# Fuzz parsers (requires cargo-fuzz + nightly)
cargo +nightly fuzz run fuzz_header -- -max_total_time=60
cargo +nightly fuzz run fuzz_frame  -- -max_total_time=60
cargo +nightly fuzz run fuzz_tlv    -- -max_total_time=60

# Check MSRV
cargo +1.80 test
```

## Documentation

| Document | Description |
|----------|-------------|
| [Getting started](docs/guides/getting-started.md) | Full walkthrough: key setup, connecting, sending, handling messages |
| [Architecture](docs/architecture/overview.md) | Connection data flow, concurrency model, rekeying, shutdown |
| [Protocol specification](https://github.com/datagram-messenger/dgproto-go/blob/main/docs/protocol/dgproto-v1.md) | Normative wire format (lives in `dgproto-go`) |
| [API reference](https://docs.rs/dgproto) | Generated docs on docs.rs |
| [dgproto-go](https://github.com/datagram-messenger/dgproto-go) | Go reference implementation and server library |
| [Contributing](.github/CONTRIBUTING.md) | Contribution workflow and requirements |

## License

Apache 2.0 — see [LICENSE](LICENSE).

<div align="center">

<a href="https://github.com/datagram-messenger">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/datagram-logo-dark.svg" />
    <source media="(prefers-color-scheme: light)" srcset="docs/assets/datagram-logo-light.svg" />
    <img src="docs/assets/datagram-logo-dark.svg" width="96" height="96" alt="Datagram Messenger" />
  </picture>
</a>

# dgproto-rs

**A focused Rust client for the DGProto v1 secure transport protocol.**

[![CI](https://github.com/datagram-messenger/dgproto-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/datagram-messenger/dgproto-rs/actions/workflows/ci.yml?query=branch%3Amain)
[![Crates.io](https://img.shields.io/crates/v/dgproto.svg)](https://crates.io/crates/dgproto)
[![docs.rs](https://docs.rs/dgproto/badge.svg)](https://docs.rs/dgproto/latest/dgproto/)
[![MSRV](https://img.shields.io/badge/MSRV-1.80-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

</div>

`dgproto` is the client-side building block for applications that speak
DGProto v1. It combines the wire format, typed messages, Noise XX handshake,
encrypted sessions, replay protection, rekeying, and connection lifecycle in a
small asynchronous API built on Tokio.

The crate deliberately stops at the transport boundary. Your application keeps
control of identity provisioning, authorization, reconnect policy, and message
semantics.

## Highlights

- **Secure by construction** — Noise XX establishes directional secrets;
  ChaCha20-Poly1305 authenticates encrypted session frames.
- **Protocol-complete client core** — framing, aligned TLVs, typed messages,
  sequencing, replay enforcement, padding, and epoch rekeying.
- **Production-oriented lifecycle** — bounded backpressure, write confirmation,
  keepalive, idle timeout, callbacks, and graceful or immediate shutdown.
- **Interoperability tested** — shared wire vectors and oracle tests track the
  reference Go implementation.
- **Focused API** — one client/initiator library with no server framework or
  application policy hidden behind it.

## Project status

| | |
|---|---|
| Crate | `dgproto` **0.5.0** |
| Protocol | DGProto v1 draft — Implementation Track |
| Role | Client / initiator |
| Transport | Asynchronous TCP on Tokio |
| MSRV | Rust 1.80 |

Crate releases and protocol revisions are versioned independently. DGProto v1
is still a draft, so wire compatibility may change before the specification is
stabilized. The [DGProto v1 specification] and reference server live in
[`dgproto-go`].

## Installation

```toml
[dependencies]
dgproto = "0.5.0"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

The minimum supported Rust version (MSRV) is **1.80**.

## Quick start

This abbreviated workflow loads a persistent client identity, verifies the
provisioned server key, receives messages with `handler_fn`, sends one
application message, and closes the session:

```rust
use dgproto::{handler_fn, ApplicationMessage, ClientConfig, Connection,
              EncryptedData, StaticKey, Tlv};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Provision securely once; this load requires exactly 32 private-key bytes.
    let client_key = StaticKey::load(&std::fs::read("identity.key")?)?;
    let trusted_server_public_key: [u8; 32] = load_server_key()?;
    let handler = handler_fn(|_connection, message| async move {
        if let ApplicationMessage::EncryptedData(data) = message {
            println!("received {} TLVs", data.fields.len());
        }
        Ok(())
    });

    let config = ClientConfig {
        static_key: client_key,
        server_static_hint: Some(trusted_server_public_key),
        handler: Some(handler),
        ..Default::default()
    };

    let connection = Connection::connect("127.0.0.1:8090", config).await?;

    connection
        .send_and_wait(EncryptedData {
            stream_id: 1,
            app_message_type: 0x01,
            fields: vec![Tlv::new(1, b"hello DGProto".as_slice())],
        })
        .await?;

    connection.close().await?;
    Ok(())
}

fn load_server_key() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = std::fs::read("server.pub")?;
    bytes.try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "server.pub must contain exactly 32 bytes",
        )
        .into()
    })
}
```

> [!WARNING]
> Generate the client key once, store it in an OS-backed secret store or a file
> protected by restrictive permissions, and reload it on later runs. The client
> example creates a mode-`0o600` file on Unix; on Windows it requires a protected,
> pre-provisioned 32-byte file and does not verify its ACL. Never log or commit
> private key bytes. Provision the server's 32-byte static public key through a
> trusted channel; `server_static_hint: None` would accept any server completing
> a valid Noise XX handshake.

The server must be running and its admission policy must allow the client's
public key. See [Getting started] and [Key management] for persistence,
registration, inbound handlers, graceful shutdown, and operational setup. See
[Connection lifecycle] for using `wait_for_close()` to drive an application-owned
reconnect loop; the crate does not reconnect automatically.

## Connection lifecycle

| Operation | Semantics |
|---|---|
| `Connection::connect` | Validates the configuration, dials TCP, completes the Noise XX handshake, then starts read, write, and maintenance tasks. `outbound_queue: 0` returns `Error::InvalidOutboundQueueCapacity`. |
| `send` | Non-blocking bounded enqueue; fails if the queue is full or the connection is closing. |
| `send_and_wait` | Waits until the serialized writer reports that the frame was written to the local TCP socket. It is not a peer acknowledgment. |
| `wait_for_close` | Waits for the runtime loops and teardown task, then returns the retained first terminal outcome. |
| `close` | Writes a local `SessionClose`, starts teardown, and normally waits for lifecycle completion. It does not wait for a peer reply. When called from this connection's inbound handler, it returns after the close write so the handler can finish and teardown can complete. |
| `abort` | Cancels immediately without a close handshake; lifecycle completion can be observed with `wait_for_close`. |

Application writes, keepalive/control writes, and rekey write/commit/retry are
serialized in one outbound critical section. `Connection` is a cheap clone backed
by shared state and is `Send + Sync`. Inbound handlers run serially for each
connection, so a slow handler delays later inbound messages. After closing begins,
subsequent sends fail with `Error::ConnectionClosed`. The first clean or error
terminal outcome wins and cannot be overwritten by a later shutdown path.

## Protocol and security model

DGProto v1 uses a fixed 40-byte little-endian frame header and no outer transport
length prefix. Handshake traffic establishes directional session secrets with
`Noise_XX_25519_ChaChaPoly_SHA256`; encrypted frames use ChaCha20-Poly1305. The
received header and cleartext padding are authenticated as associated data.
Directional sequences start at 1, replay state is committed only after successful
authentication, and session keys are rekeyed by epoch.

Noise XX authenticates **possession** of the static keys exchanged during the
handshake. That property does not replace trusted server-key provisioning or
application authorization. Without a trusted `server_static_hint`, a successful
handshake alone does not establish that the peer is the intended server. The
server remains responsible for client admission and authorization, while the
application remains responsible for key distribution, rotation, secret storage,
endpoint security, and padding policy.

The [DGProto v1 specification] is normative for wire behavior. The Rust and Go
implementations plus [shared vectors] provide compatibility evidence for the
covered cases; they are not a promise of stable wire compatibility while the
protocol is a draft.

## Documentation

[ErrorMessage wire migration](docs/guides/error-message-migration.md): paired
rebuild/deploy is required; the public u8 code adapter is not full-u16 interop.

| Resource | Purpose |
|---|---|
| [API reference] | Public Rust API documentation on docs.rs. |
| [Getting started] | Dependency setup, client identity, handlers, sending, and shutdown. |
| [Key management] | Generate, persist, reload, register, and rotate static keys. |
| [Connection lifecycle] | Shutdown, termination, reconnects, keepalive, and timeouts. |
| [Architecture] | Internal layers, task ownership, and data flow. |
| [DGProto v1 specification] | Normative protocol definition. |
| [`dgproto-go`] | Reference server implementation and specification host. |
| [Shared vectors] | Cross-implementation wire fixtures. |

## Testing and quality

CI runs on Linux, Windows, and macOS. The stable jobs execute these commands:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
```

CI also runs release tests on Linux and checks the declared MSRV with Rust 1.80:

```sh
cargo test --release --all-features
cargo check --all-features
```

Parser fuzzing uses nightly Rust and `cargo-fuzz`. CI smoke-tests all four
targets; longer local runs are appropriate for parser changes:

```sh
cargo +nightly fuzz run fuzz_header -- -max_total_time=60
cargo +nightly fuzz run fuzz_frame -- -max_total_time=60
cargo +nightly fuzz run fuzz_tlv -- -max_total_time=60
cargo +nightly fuzz run fuzz_messages -- -max_total_time=60
```

The test suite includes unit tests, loopback integration scenarios, and
cross-implementation header, frame, TLV, and message vectors.

## Platforms and runtime

- **Runtime:** Tokio, using asynchronous TCP and Tokio synchronization/timer
  primitives.
- **CI platforms:** Linux, Windows, and macOS.
- **Rust edition:** 2021.
- **MSRV:** Rust 1.80.

Platform coverage describes the CI matrix, not a guarantee for every target or
network environment.

## Releases

Published crate versions are available on [crates.io]. Release notes and source
tags are available on the [GitHub releases] page. Because crate and protocol
versions are independent, report both when describing interoperability or a
wire-level issue.

## Contributing

Bug fixes, tests, and documentation improvements are welcome. Read the
[contribution guide] before opening a pull request. Protocol-visible changes
must be checked against the normative specification and shared vectors; keep
changes focused and run the applicable CI commands locally.

## Security

Please do not report suspected vulnerabilities in a public issue. Use the
private [GitHub security advisory] form and include the affected crate version,
protocol draft, impact, and reproduction details. See the [security policy] for
key-handling and disclosure guidance.

## License

Licensed under the [Apache License 2.0](LICENSE).

[API reference]: https://docs.rs/dgproto/latest/dgproto/
[Architecture]: docs/architecture/overview.md
[Connection lifecycle]: docs/guides/connection-lifecycle.md
[contribution guide]: .github/CONTRIBUTING.md
[crates.io]: https://crates.io/crates/dgproto
[DGProto v1 specification]: https://github.com/datagram-messenger/dgproto-go/blob/main/docs/protocol/dgproto-v1.md
[`dgproto-go`]: https://github.com/datagram-messenger/dgproto-go
[Getting started]: docs/guides/getting-started.md
[GitHub releases]: https://github.com/datagram-messenger/dgproto-rs/releases
[GitHub security advisory]: https://github.com/datagram-messenger/dgproto-rs/security/advisories/new
[Key management]: docs/guides/key-management.md
[security policy]: SECURITY.md
[Shared vectors]: https://github.com/datagram-messenger/dgproto-go/tree/main/testdata/vectors

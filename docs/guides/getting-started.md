# Getting Started with dgproto

This guide walks you through building a working DGProto v1 client in Rust:
key setup, connecting, sending and receiving messages, and shutting down cleanly.

> **Prerequisite:** a running DGProto v1 server. The reference implementation is
> [`dgproto-go`](https://github.com/datagram-messenger/dgproto-go). The server must
> register your client's public key before you can connect.

---

## 1. Add the dependency

```toml
# Cargo.toml
[dependencies]
dgproto = "0.2"
tokio   = { version = "1", features = ["full"] }
```

Minimum supported Rust version: **1.80**.

---

## 2. Generate your static key

Your Noise static private key is your cryptographic identity on the network.
Generate it **once** and reuse it across every run.

```rust
use dgproto::StaticKey;

// Generate a fresh key pair.
let key = StaticKey::generate()?;

// Print the public key — register this with your server.
println!("public key: {}", hex::encode(key.public()));
```

Register `key.public()` with the server before attempting to connect. How you
do this is server-specific (e.g. a registration HTTP endpoint, a config file,
or an admin CLI command in `dgproto-go`).

> **Key persistence (v0.3.0):** `StaticKey::to_private_bytes()` is coming in
> v0.3.0. Until then, store the raw private bytes via your own mechanism
> (e.g. `StaticKey::generate()` → pass the 32-byte private key bytes directly
> to `StaticKey::load(&bytes)` on reload). See the roadmap in `PLAN.md`.

---

## 3. Connect to the server

```rust
use dgproto::{ClientConfig, Connection};
use std::time::Duration;

let config = ClientConfig {
    static_key:        key,

    // Optional: pin the server's static public key.
    // If None, any server completing a valid Noise XX handshake is accepted.
    // Always set this in production.
    server_static_hint: Some(server_public_key_bytes),

    handshake_timeout: Duration::from_secs(10),
    write_timeout:     Duration::from_secs(10),
    outbound_queue:    64,
    ..Default::default()
};

let conn = Connection::connect("127.0.0.1:8090", config).await?;
println!("connected — session id: {}", hex::encode(conn.session_id()));
```

`Connection::connect` dials TCP, completes the three-flight Noise XX handshake,
derives the session ID and directional keys, then spawns three background tasks
(read loop, write loop, maintenance loop). On success it returns a `Connection`
handle that is cheap to `Clone` — all clones share the same underlying session.

---

## 4. Receive messages

Set up a `MessageHandler` in `ClientConfig` before connecting. The handler is
called serially for every inbound `ApplicationMessage`.

```rust
use dgproto::{ApplicationMessage, ClientConfig, Connection, MessageHandler};
use std::sync::Arc;

let handler: MessageHandler = Arc::new(move |_conn, msg| {
    Box::pin(async move {
        match msg {
            ApplicationMessage::EncryptedData(data) => {
                println!(
                    "stream={} type=0x{:02x} fields={}",
                    data.stream_id,
                    data.app_message_type,
                    data.fields.len()
                );
                for field in &data.fields {
                    println!("  tlv type={} len={}", field.type_, field.value.len());
                }
            }
            ApplicationMessage::SessionClose(close) => {
                println!("server closed: {:?} — {}", close.code, close.reason);
            }
            ApplicationMessage::ErrorMessage(err) => {
                eprintln!("server error 0x{:02x}: {}", err.code, err.reason);
            }
            ApplicationMessage::Ack(ack) => {
                println!("ack: {} sequences", ack.sequences.len());
            }
        }
        Ok(())
    })
});

let config = ClientConfig {
    static_key: key,
    handler_queue: 64,
    ..Default::default()
};
// Pass the handler at connection time:
// (handler is a field of ClientConfig — see docs.rs for the full struct)
```

> **Note:** the handler runs on the read-loop task. A slow or blocking handler
> stalls all subsequent inbound messages for that connection. For heavy work,
> spawn a new task inside the handler.

---

## 5. Send messages

```rust
use dgproto::{EncryptedData, Tlv};

// Non-blocking enqueue. Returns Err if the outbound queue is full or the
// connection is already closed.
conn.send(EncryptedData {
    stream_id:        1,
    app_message_type: 0x01,
    fields:           vec![
        Tlv::new(1, b"hello datagram".as_ref()),
        Tlv::new(2, b"\x00\x01".as_ref()),  // example second field
    ],
})?;

// Blocking enqueue: waits until the frame is written to the TCP socket.
// Does not guarantee peer receipt or application-level acknowledgement.
conn.send_and_wait(EncryptedData {
    stream_id:        1,
    app_message_type: 0x02,
    fields:           vec![Tlv::new(1, b"confirmed send".as_ref())],
}).await?;
```

`Tlv::new(type_, value)` constructs a TLV field. `type_` is a `u8` tag; `value`
is any `Into<Vec<u8>>`. The TLV codec handles 4-byte alignment automatically.
Field semantics (which tag means what) are defined by your application protocol
layered on top of DGProto.

---

## 6. Shut down cleanly

```rust
// Graceful: sends SessionClose, waits for the peer's reply, tears down tasks.
conn.close().await?;

// Immediate: aborts without a close handshake. Use on unrecoverable errors.
conn.abort();
```

After `close()` or `abort()`, all subsequent `send` calls return
`Err(Error::ConnectionClosed)`. The three background tasks exit automatically.

---

## 7. Minimal complete example

```rust
use dgproto::{ApplicationMessage, ClientConfig, Connection, EncryptedData,
              MessageHandler, StaticKey, Tlv};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), dgproto::Error> {
    // --- Key setup (generate once; reload on subsequent runs) ---
    let key = StaticKey::generate()?;
    println!("Register this public key with the server:");
    println!("{}", hex::encode(key.public()));

    // --- Message handler ---
    let handler: MessageHandler = Arc::new(|_conn, msg| {
        Box::pin(async move {
            if let ApplicationMessage::EncryptedData(data) = msg {
                for field in &data.fields {
                    if let Ok(text) = std::str::from_utf8(&field.value) {
                        println!("[recv] tlv={}: {}", field.type_, text);
                    }
                }
            }
            Ok(())
        })
    });

    // --- Connect ---
    let config = ClientConfig {
        static_key:        key,
        handler_queue:     64,
        outbound_queue:    64,
        handshake_timeout: Duration::from_secs(10),
        write_timeout:     Duration::from_secs(10),
        ..Default::default()
    };
    let conn = Connection::connect("127.0.0.1:8090", config).await?;

    // --- Send ---
    conn.send(EncryptedData {
        stream_id:        1,
        app_message_type: 0x01,
        fields:           vec![Tlv::new(1, b"hello".as_ref())],
    })?;

    // --- Close ---
    conn.close().await?;
    Ok(())
}
```

---

## 8. Common errors

| Error | Cause | Fix |
|---|---|---|
| `Error::Handshake` | Noise XX failed — wrong server key, server rejected public key, or network error. | Verify `server_static_hint` and that your public key is registered with the server. |
| `Error::OutboundQueueFull` | The write loop is behind — `outbound_queue` capacity exceeded. | Increase `outbound_queue` in `ClientConfig`, or use `send_and_wait` for flow control. |
| `Error::ConnectionClosed` | The connection has already terminated. | Check for terminal errors; reconnect if needed. |
| `Error::Authentication` | AEAD decryption failed — frame was tampered with or keys are mismatched. | This is a security event; log and close immediately. |
| `Error::Transport(e)` | Underlying TCP error (disconnected, timeout, etc.). | Reconnect after a backoff delay. |

---

## Next steps

- [Architecture overview](../architecture/overview.md) — module structure and data flow diagrams
- [API reference (docs.rs)](https://docs.rs/dgproto) — full Rustdoc for all public types
- [DGProto v1 specification](https://github.com/datagram-messenger/dgproto-go/blob/main/docs/protocol/dgproto-v1.md) — normative wire spec
- [dgproto-go](https://github.com/datagram-messenger/dgproto-go) — Go reference server

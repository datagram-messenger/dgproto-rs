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
dgproto = "0.4"
tokio   = { version = "1", features = ["full"] }
```

Minimum supported Rust version: **1.80**.

---

## 2. Set up your static key

Your Noise static private key is your cryptographic identity on the network.
Generate it **once**, persist it to disk, and reload it on every subsequent run.

```rust
use dgproto::StaticKey;
use std::path::Path;

fn load_or_generate(path: &Path) -> Result<StaticKey, Box<dyn std::error::Error>> {
    if path.exists() {
        let bytes = std::fs::read(path)?;
        Ok(StaticKey::load(&bytes)?)
    } else {
        let key = StaticKey::generate()?;
        std::fs::write(path, key.to_private_bytes().as_ref())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(key)
    }
}
```

Register the public key with the server before the first connection:

```rust
let key = load_or_generate(Path::new("identity.key"))?;
println!("Register this public key: {}", key.public_hex());
```

> [!IMPORTANT]
> Never log, commit, or store the private key without restrictive file
> permissions (Unix: `0o600`). See the [Key Management Guide](key-management.md)
> for the full persist-and-reload pattern, platform paths, and rotation.

---

## 3. Connect and handle inbound messages

Define the message handler **before** building `ClientConfig` — the handler is
a field of `ClientConfig` and is passed directly to `Connection::connect`.

```rust
use dgproto::{ApplicationMessage, ClientConfig, Connection, MessageHandler};
use std::sync::Arc;
use std::time::Duration;

// Step 1 — define what to do with incoming messages.
// The handler is called serially for each ApplicationMessage in arrival order.
let handler: MessageHandler = Arc::new(|_conn, msg| {
    Box::pin(async move {
        match msg {
            ApplicationMessage::EncryptedData(data) => {
                println!(
                    "[recv] stream={} type=0x{:02x} fields={}",
                    data.stream_id,
                    data.app_message_type,
                    data.fields.len()
                );
                for field in &data.fields {
                    println!("  tlv type={} len={}", field.type_, field.value.len());
                }
            }
            ApplicationMessage::SessionClose(close) => {
                println!("[close] {:?}: {}", close.code, close.reason);
            }
            ApplicationMessage::ErrorMessage(err) => {
                eprintln!("[error] 0x{:02x}: {}", err.code, err.reason);
            }
            ApplicationMessage::Ack(_) => { /* handle or ignore */ }
        }
        Ok(())
    })
});

// Step 2 — build the config, passing the handler and all other options.
let config = ClientConfig {
    static_key: key,
    handler:    Some(handler),  // ← required to receive messages

    // Pin the server's static public key (strongly recommended in production).
    // If None, any server completing a valid Noise XX handshake is accepted.
    server_static_hint: Some(server_public_key_bytes),

    handshake_timeout: Duration::from_secs(10),
    write_timeout:     Duration::from_secs(10),
    // Must be greater than zero; zero returns
    // Error::InvalidOutboundQueueCapacity before dialing.
    outbound_queue:    64,
    handler_queue:     64,
    ..Default::default()
};

// Step 3 — connect.
// Dials TCP, runs the three-flight Noise XX handshake, spawns three
// background tasks (read loop, write loop, maintenance loop).
let conn = Connection::connect("127.0.0.1:8090", config).await?;
println!("connected — session: {}", hex::encode(conn.session_id()));
```

`Connection` is `Clone` — all clones share the same underlying session.

> **Note:** the handler runs on the read-loop task. A slow or blocking handler
> delays subsequent inbound messages on the same connection. For CPU-heavy or
> I/O-heavy work, spawn a `tokio::task` inside the handler.

---

## 4. Send messages

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

## 5. Shut down cleanly

```rust
// Graceful: writes SessionClose locally and waits for teardown.
// It does not wait for a peer reply.
conn.close().await?;

// Immediate: aborts without a close handshake. Use on unrecoverable errors.
conn.abort();
```

After `close()` or `abort()`, all subsequent `send` calls return
`Err(Error::ConnectionClosed)`. The three background tasks exit automatically.

---

## 6. Wait for termination and reconnect

`wait_for_close()` blocks until all background tasks have exited and returns
the terminal cause — `None` for a clean `SessionClose`, `Some(err)` for any
error termination. Use it to drive a reconnect loop without polling:

```rust
loop {
    match Connection::connect("127.0.0.1:8090", config.clone()).await {
        Err(e) => eprintln!("connect failed: {e}"),
        Ok(conn) => {
            // ... send messages, set up handlers ...

            if let Some(err) = conn.wait_for_close().await {
                eprintln!("disconnected: {err}");
            }
            // clean shutdown — reconnect immediately or after a delay
        }
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
}
```

> [!NOTE]
> `wait_for_close()` returns immediately if the connection is already closed
> when you call it — there is no race between subscribing and the terminal
> event firing.

---

## 7. Lifecycle callbacks

`ClientConfig` provides two optional callbacks for connection events:

```rust
use std::sync::Arc;

let config = ClientConfig {
    static_key: key,

    // Called once after the Noise XX handshake completes, before the first
    // inbound message is dispatched. Receives an Arc<Connection> so you can
    // store or use the connection immediately. Keep it non-blocking.
    on_connect: Some(Arc::new(|conn: Arc<Connection>| {
        println!("connected — session {}", hex::encode(conn.session_id()));
    })),

    // Called when the connection terminates for any reason.
    // None  = clean SessionClose from either side.
    // Some(err) = error termination (I/O, auth failure, timeout, etc.).
    // Keep it non-blocking.
    on_disconnect: Some(Arc::new(|cause: Option<dgproto::Error>| {
        match cause {
            None      => println!("disconnected cleanly"),
            Some(err) => eprintln!("disconnected with error: {err}"),
        }
    })),

    ..Default::default()
};
```

---

## 8. Minimal complete example

```rust,no_run
use dgproto::{ApplicationMessage, ClientConfig, Connection, EncryptedData,
              MessageHandler, StaticKey, Tlv};
use std::{path::Path, sync::Arc, time::Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- Key setup ---
    let key = if Path::new("identity.key").exists() {
        StaticKey::load(&std::fs::read("identity.key")?)?
    } else {
        let k = StaticKey::generate()?;
        std::fs::write("identity.key", k.to_private_bytes().as_ref())?;
        println!("Register this public key: {}", k.public_hex());
        k
    };

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
        handler:           Some(handler),
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

    // --- Graceful close ---
    conn.close().await?;
    Ok(())
}
```

---

## 9. Common errors

| Error | Cause | Fix |
|---|---|---|
| `Error::Handshake` | Noise XX failed — wrong server key, server rejected public key, or network error. | Verify `server_static_hint` and that your public key is registered with the server. |
| `Error::OutboundQueueFull` | The write loop is behind — `outbound_queue` capacity exceeded. | Increase `outbound_queue` in `ClientConfig`, or use `send_and_wait` for flow control. |
| `Error::ConnectionClosed` | The connection has already terminated. | Check for terminal errors with `wait_for_close()`; reconnect if needed. |
| `Error::Authentication` | AEAD decryption failed — frame was tampered with or keys are mismatched. | This is a security event; log and close immediately. |
| `Error::TransportClosed` | The TCP transport was closed by the peer (clean close at the OS level). | Reconnect after a backoff delay. |
| `Error::Io(e)` | Raw OS-level I/O error (timeout, connection reset, broken pipe, etc.). | Inspect `e.kind()` to decide whether to retry; reconnect after backoff. |

---

## Next steps

- [Connection lifecycle](connection-lifecycle.md) — reconnect patterns, keepalive, idle timeout, callbacks
- [Key Management Guide](key-management.md) — persist, load, and rotate your static key
- [Architecture overview](../architecture/overview.md) — module structure and data flow diagrams
- [API reference (docs.rs)](https://docs.rs/dgproto) — full Rustdoc for all public types
- [DGProto v1 specification](https://github.com/datagram-messenger/dgproto-go/blob/main/docs/protocol/dgproto-v1.md) — normative wire spec
- [dgproto-go](https://github.com/datagram-messenger/dgproto-go) — Go reference server

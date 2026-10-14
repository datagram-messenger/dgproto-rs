# Connection Lifecycle

This guide covers everything that happens after `Connection::connect` returns:
how to shut down cleanly, how to detect and react to disconnections, how to
build a reconnect loop, and how to configure keepalive and idle timeouts.

---

## Table of contents

- [Shutdown: close vs abort](#shutdown-close-vs-abort)
- [Waiting for termination](#waiting-for-termination)
- [Reconnect loop](#reconnect-loop)
- [Lifecycle callbacks](#lifecycle-callbacks)
- [Keepalive](#keepalive)
- [Idle timeout](#idle-timeout)
- [Terminal error reference](#terminal-error-reference)

---

## Shutdown: close vs abort

There are two ways to end a connection:

| Method | What it does | When to use |
|--------|-------------|-------------|
| `conn.close().await` | Sends `SessionClose`, waits for the peer's reply, then tears down all tasks. Returns `Ok(())` on clean exchange, `Err(e)` if the write failed. | Normal application shutdown. |
| `conn.abort()` | Cancels all tasks immediately without a close handshake. Fire-and-forget — returns before tasks have fully exited. | Unrecoverable errors, timeouts, or when you cannot wait for the peer. |

```rust,no_run
// Graceful — preferred when the connection is healthy.
conn.close().await?;

// Immediate — use when you need to stop now.
conn.abort();
// Optionally wait for all tasks to finish:
conn.wait_for_close().await;
```

After either call, all subsequent `send` calls return `Err(Error::ConnectionClosed)`.

> [!NOTE]
> `close()` internally calls `abort()` after the `SessionClose` exchange
> completes, so you do not need to call both.

---

## Waiting for termination

`wait_for_close()` blocks until all three background tasks (read loop, write
loop, maintenance loop) have exited. It returns the **terminal cause**:

- `None` — clean shutdown: `SessionClose` was exchanged by either side, or
  `close()` completed normally.
- `Some(err)` — error termination: I/O error, authentication failure,
  keepalive timeout, idle timeout, handler error, etc.

```rust,no_run
let cause = conn.wait_for_close().await;
match cause {
    None      => println!("disconnected cleanly"),
    Some(err) => eprintln!("disconnected with error: {err}"),
}
```

`wait_for_close()` is safe to call at any time — it returns immediately if the
connection is already closed when you call it. There is no race between
subscribing and the terminal event firing.

`Connection` is `Clone` (cheap `Arc` clone). You can hold one clone for
sending and another for waiting:

```rust,no_run
let sender = conn.clone();
let waiter = conn;

tokio::spawn(async move {
    // send messages using `sender` ...
});

if let Some(err) = waiter.wait_for_close().await {
    eprintln!("connection failed: {err}");
}
```

---

## Reconnect loop

The idiomatic reconnect pattern uses `wait_for_close()` to block until the
connection ends, then reconnects after a delay:

```rust,no_run
use dgproto::{ClientConfig, Connection};
use std::time::Duration;

async fn run_with_reconnect(config: ClientConfig) {
    let mut backoff = Duration::from_secs(1);

    loop {
        match Connection::connect("127.0.0.1:8090", config.clone()).await {
            Err(e) => {
                eprintln!("connect failed: {e} — retrying in {backoff:?}");
            }
            Ok(conn) => {
                backoff = Duration::from_secs(1); // reset on success

                // ... register conn, start sending ...

                match conn.wait_for_close().await {
                    None      => println!("clean disconnect — reconnecting"),
                    Some(err) => eprintln!("error: {err} — reconnecting"),
                }
            }
        }

        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30)); // exponential cap
    }
}
```

> [!NOTE]
> `ClientConfig` is `Clone`. Build it once before the loop and clone it on
> each iteration. The `static_key` field is also `Clone` — it does not
> regenerate the key.

---

## Lifecycle callbacks

`ClientConfig` provides two optional callbacks that fire at connection
boundaries. Both are called from a background task — keep them non-blocking.

### `on_connect`

Called once after the Noise XX handshake completes, before the first inbound
message is dispatched. Receives an `Arc<Connection>` so you can store or use
the connection immediately.

```rust,no_run
use dgproto::{ClientConfig, Connection};
use std::sync::Arc;

let config = ClientConfig {
    on_connect: Some(Arc::new(|conn: Arc<Connection>| {
        println!("connected — session {}", hex::encode(conn.session_id()));
        // Store conn in shared state, notify other tasks, etc.
    })),
    ..Default::default()
};
```

### `on_disconnect`

Called when the connection terminates for any reason, after all background
tasks have exited. Receives the same terminal cause as `wait_for_close()`.

```rust,no_run
use dgproto::{ClientConfig, Error};
use std::sync::Arc;

let config = ClientConfig {
    on_disconnect: Some(Arc::new(|cause: Option<Error>| {
        match cause {
            None      => println!("disconnected cleanly"),
            Some(err) => eprintln!("disconnected: {err}"),
        }
        // Update UI state, trigger reconnect logic, etc.
    })),
    ..Default::default()
};
```

> [!IMPORTANT]
> `on_disconnect` fires **before** `wait_for_close()` resolves. If you use
> both, the callback always runs first.

---

## Keepalive

Keepalive sends periodic `Ping` frames and closes the connection if the peer
does not reply within a deadline. Configure it in `ClientConfig`:

```rust,no_run
use dgproto::ClientConfig;
use std::time::Duration;

let config = ClientConfig {
    // Send a Ping every 30 seconds.
    keepalive_interval: Duration::from_secs(30),

    // Close with Error::KeepaliveTimeout if no Pong arrives within 10 seconds.
    // Default (Duration::ZERO) uses 2 * keepalive_interval.
    keepalive_timeout: Duration::from_secs(10),

    ..Default::default()
};
```

Keepalive is **disabled by default** (`keepalive_interval: Duration::ZERO`).
Enable it when you need to detect silent peer failures or NAT timeouts on
long-lived connections.

The first Ping is sent after the first full `keepalive_interval` has elapsed
from the moment the connection is established — not immediately on connect.

---

## Idle timeout

The idle timeout closes the connection if no inbound frame arrives within a
given duration. It resets on every received frame (including Pings and Pongs).

```rust,no_run
use dgproto::ClientConfig;
use std::time::Duration;

let config = ClientConfig {
    // Close with Error::IdleTimeout if no inbound frame arrives for 60 seconds.
    idle_timeout: Duration::from_secs(60),

    ..Default::default()
};
```

Idle timeout is **disabled by default** (`idle_timeout: Duration::ZERO`).

The timer starts after the first full `idle_timeout` period from connect — a
freshly connected client is never immediately timed out.

**Idle timeout vs keepalive:** use keepalive when you want to actively probe
the peer; use idle timeout when you want to close a connection that has gone
silent from the server side.

---

## Terminal error reference

| Error | Cause | Typical action |
|-------|-------|----------------|
| `None` (clean) | `SessionClose` exchanged by either side. | Reconnect or exit normally. |
| `Error::KeepaliveTimeout` | No Pong received within `keepalive_timeout`. | Reconnect after backoff. |
| `Error::IdleTimeout` | No inbound frame within `idle_timeout`. | Reconnect after backoff. |
| `Error::TransportClosed` | Peer closed the TCP connection. | Reconnect after backoff. |
| `Error::Io(e)` | OS-level I/O error (reset, broken pipe, timeout). | Inspect `e.kind()`; reconnect after backoff. |
| `Error::Authentication` | AEAD decryption failed — tampered frame or key mismatch. | Log as a security event; do not reconnect automatically. |
| `Error::ReplayDuplicate` | Duplicate sequence number received. | Log; reconnect. |
| `Error::ConnectionClosed` | `abort()` was called explicitly. | Reconnect if appropriate. |
| `Error::SequenceExhausted` | Send sequence counter reached `u64::MAX`. | Should not occur in practice; reconnect. |

---

## See also

- [Getting started](getting-started.md) — connect, send, and receive basics
- [Key Management Guide](key-management.md) — persist and reload your static key
- [Architecture overview](../architecture/overview.md) — shutdown and maintenance loop internals
- [API reference (docs.rs)](https://docs.rs/dgproto) — full Rustdoc

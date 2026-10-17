# Key Management Guide

This guide explains how to generate, persist, and rotate a `StaticKey` — the
long-term X25519 Noise identity used by every DGProto v1 client.

---

## Why key persistence matters

`StaticKey` is the client's cryptographic identity in the Noise XX handshake.
The server uses the client's public key for allowlisting and mutual
authentication. If you generate a fresh key on every startup (the default when
you call `StaticKey::generate()` without saving the result), the server sees a
new, unknown client on every restart — its allowlist is meaningless and rekey
history is lost.

**Persist the key once. Load it on every subsequent startup.**

---

## Generating a key (first run)

```rust
use dgproto::StaticKey;

let key = StaticKey::generate()?;
```

`generate()` uses the OS CSPRNG via the `snow` crate. It is infallible on any
supported platform.

---

## Persisting to disk

Exporting produces the raw 32-byte private key in a `Zeroizing<[u8; 32]>`
wrapper, which zeroes that copy when dropped. Persistence must apply restrictive
protection at creation time: use `create_new` with mode `0o600` on Unix. On
Windows, use an OS credential store or provision a file with a restrictive DACL
through an appropriate Windows API; writing into a user-profile directory alone
does not verify or guarantee a restrictive ACL.

The runnable client example deliberately does not add a Windows API dependency.
It therefore creates a new key file only on Unix. On Windows, a missing file is
an error and the user must provide a protected, exactly 32-byte key file (or
adapt the application to load from an OS credential store). Existing Windows
files are loaded, but the example does not inspect their ACLs.

---

## Loading on startup

```rust
use std::fs;
use dgproto::StaticKey;

fn load_provisioned(path: &std::path::Path) -> Result<StaticKey, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    Ok(StaticKey::load(&bytes)?) // rejects any length other than 32 bytes
}
```

---

## Registering your public key with the server

Before the first connection, register the client's public key with the server
so it can be added to the allowlist. Use `public_hex()` to get a printable
representation:

```rust
let key = load_provisioned(&key_path)?;
println!("Client public key: {}", key.public_hex());
// → "a3f1c2...64 lowercase hex chars"
```

Pass this string to the server administrator or to the server's registration
API. The server stores it and uses it to verify the Noise XX handshake.

---

## Security considerations

- **Never log, print, or commit private key bytes.** The `to_private_bytes()`
  return value is wrapped in `Zeroizing` — drop it as soon as you have written
  it to its destination.
- **Never hardcode a private key** in source code or configuration files that
  are committed to version control.
- **File permissions are critical.** A world-readable key file allows any local
  user to impersonate this client. Always set `0o600` on Unix.
- **Backup securely.** If the key file is lost, the client loses its identity.
  Back up to an encrypted store (e.g. a password manager or OS keychain), not
  to a plain-text file.
- **The public key is not secret.** `public_hex()` output may be logged,
  displayed, and shared with the server administrator.

---

## Rotating keys

Key rotation requires coordination with the server:

1. Generate a new key: `let new_key = StaticKey::generate()?;`
2. Register the new public key (`new_key.public_hex()`) with the server.
3. Wait for the server to confirm the new key is active.
4. Replace the key file on disk with the new private bytes.
5. Restart the client — it will now connect with the new identity.
6. Ask the server administrator to deregister the old public key.

**Do not replace the key file before the server has registered the new key.**
The client will be unable to connect during the window between file replacement
and server registration.

---

## See also

- [Getting started](getting-started.md) — connect, send, and receive basics
- [Connection lifecycle](connection-lifecycle.md) — reconnect patterns, keepalive, and idle timeout
- [Architecture overview](../architecture/overview.md) — module structure and data flow diagrams
- [API reference (docs.rs)](https://docs.rs/dgproto) — full Rustdoc for `StaticKey`

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

Export the raw 32-byte private key and write it to a file with restrictive
permissions. The returned `Zeroizing<[u8; 32]>` wrapper automatically zeroes
the stack copy when it is dropped.

```rust
use std::fs;
use dgproto::StaticKey;

fn save_key(key: &StaticKey, path: &std::path::Path) -> std::io::Result<()> {
    let private_bytes = key.to_private_bytes(); // Zeroizing<[u8; 32]>

    // Write the raw bytes.
    fs::write(path, private_bytes.as_ref())?;

    // Restrict permissions so only the owner can read the file.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }

    // On Windows, use ACLs or the OS credential store (DPAPI) for equivalent
    // protection. The simplest approach is to store the file inside a
    // user-profile directory that is not world-readable by default.

    Ok(())
}
```

**Platform-specific paths** (recommended locations):

| Platform | Suggested path |
|---|---|
| Linux / macOS | `~/.config/<app>/identity.key` |
| Windows | `%APPDATA%\<app>\identity.key` |

Use the [`dirs`](https://crates.io/crates/dirs) crate to resolve these paths
portably at runtime.

---

## Loading on startup

```rust
use std::fs;
use dgproto::StaticKey;

fn load_or_generate(path: &std::path::Path) -> Result<StaticKey, Box<dyn std::error::Error>> {
    if path.exists() {
        // Load the existing key.
        let bytes = fs::read(path)?;
        let key = StaticKey::load(&bytes)?;
        Ok(key)
    } else {
        // First run: generate and persist.
        let key = StaticKey::generate()?;
        let private_bytes = key.to_private_bytes();
        fs::write(path, private_bytes.as_ref())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(key)
    }
}
```

---

## Registering your public key with the server

Before the first connection, register the client's public key with the server
so it can be added to the allowlist. Use `public_hex()` to get a printable
representation:

```rust
let key = load_or_generate(&key_path)?;
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

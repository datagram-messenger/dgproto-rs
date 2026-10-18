//! Debug session-key export for Wireshark traffic analysis.
//!
//! This module writes session key material to a file when the `DGPROTO_KEYLOG`
//! environment variable is set. It is intended exclusively for local Wireshark
//! debugging and must never be enabled in production environments.
//!
//! # Activation
//!
//! Set `DGPROTO_KEYLOG` to an absolute file path before starting the process:
//!
//! ```text
//! set DGPROTO_KEYLOG=C:\Users\you\dgproto_keylog.txt
//! ```
//!
//! # Output format
//!
//! Two lines are appended per session, immediately after the Noise XX handshake
//! completes:
//!
//! ```text
//! DGPROTO_SESSION_KEY <session_id_hex> send 1 <send_key_hex>
//! DGPROTO_SESSION_KEY <session_id_hex> recv 1 <recv_key_hex>
//! ```
//!
//! The Wireshark Lua dissector (`wireshark/dgproto.lua`) reads this file to
//! decrypt `EncryptedData` frames in captured traffic.

use std::{
    env,
    fs::{File, OpenOptions},
    io::Write,
    sync::OnceLock,
};

// ── Internal writer state ─────────────────────────────────────────────────────

struct KeylogWriter {
    file: File,
}

static WRITER: OnceLock<Option<KeylogWriter>> = OnceLock::new();

fn writer() -> Option<&'static KeylogWriter> {
    WRITER
        .get_or_init(|| {
            let path = env::var("DGPROTO_KEYLOG").ok()?;
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .ok()?;
            Some(KeylogWriter { file })
        })
        .as_ref()
}

// ── Public(crate) API ─────────────────────────────────────────────────────────

/// Append session key material to the keylog file.
///
/// This is a no-op when `DGPROTO_KEYLOG` is unset or the file cannot be
/// opened. The file is opened once on the first call and never closed.
///
/// # Safety
///
/// Key material is written in plaintext. Only call this in debug builds or
/// controlled local environments. Never set `DGPROTO_KEYLOG` in production.
pub(crate) fn write(
    session_id: &[u8; 16],
    send_key: &[u8; crate::KEY_SIZE],
    recv_key: &[u8; crate::KEY_SIZE],
) {
    let Some(w) = writer() else { return };

    let sid = hex(session_id);
    let sk = hex(send_key);
    let rk = hex(recv_key);

    // A single write call keeps both lines together in the file.
    let line =
        format!("DGPROTO_SESSION_KEY {sid} send 1 {sk}\nDGPROTO_SESSION_KEY {sid} recv 1 {rk}\n");

    // Ignore write errors — keylog is best-effort debug output.
    let mut f: &File = &w.file;
    let _ = f.write_all(line.as_bytes());
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        })
}

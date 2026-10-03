# Architecture

This document describes the Rust client implementation. The
[protocol specification](https://github.com/datagram-messenger/dgproto-go/blob/main/docs/protocol/dgproto-v1.md)
is normative for wire behavior. The Go reference implementation is
[`dgproto-go`](https://github.com/datagram-messenger/dgproto-go).

---

## Module map

| Module | Layer | Owns |
|---|---|---|
| `header.rs` | L1 | 40-byte header encode/decode, `MessageType`, `Flags` |
| `frame.rs` | L1 | `Frame` struct, `marshal_binary`, `unmarshal_binary` |
| `tlv.rs` | L1 | TLV codec, 4-byte alignment, `encode_tlvs`/`decode_tlvs` |
| `messages.rs` | L4 | Typed message structs, parse/serialize per spec §5 |
| `codec.rs` | L2 | Stateless `Codec` (ChaCha20-Poly1305 encrypt/decrypt) |
| `handshake.rs` | L2 | `StaticKey`, `HandshakeState` (Noise XX initiator), `HandshakeSecrets` |
| `replay.rs` | L3 | `ReplayWindow` (2048-bit bitmap), `ReplayToken` |
| `rekey.rs` | L3 | `RekeyState`, key derivation, grace window constants |
| `session.rs` | L3 | `Session` (directional codec pair, epoch, sequence, replay, rekey) |
| `transport.rs` | L0 | `Transport` trait, `TcpTransport` (async TCP framing) |
| `connection.rs` | L0–L4 | `Connection`, `ClientConfig`, `MessageHandler`, runtime loops |
| `error.rs` | — | `Error` enum (all variants, Go equivalents) |
| `lib.rs` | — | Public API surface, crate-level constants |

---

## Data flow: connect

```
caller
  │
  ▼
Connection::connect(addr, config)
  │
  ├─ TcpStream::connect(addr)          [tokio]
  │
  ├─ TcpTransport::new(stream)         [transport.rs]
  │
  ├─ HandshakeState::new(static_key)   [handshake.rs]
  │    │
  │    ├─ write_init()  ──────────────────────────────► server
  │    │    Frame { type=0x01, session_id=0, seq=0 }
  │    │    payload: [0u8;4] || ephemeral_public (36 B)
  │    │
  │    ├─ read_response() ◄──────────────────────────── server
  │    │    Frame { type=0x02, session_id=0, seq=0 }
  │    │    payload: server_ephemeral (32 B) || noise_msg2 (64 B)
  │    │
  │    └─ write_finish() ─────────────────────────────► server
  │         Frame { type=0x03, session_id=0, seq=0 }
  │         payload: noise_msg3 (64 B)
  │         → HandshakeSecrets { session_id, send_key, receive_key }
  │
  ├─ Session::new(secrets)             [session.rs]
  │    send:    Codec(send_key),    epoch=1, seq=1
  │    receive: Codec(receive_key), epoch=1, ReplayWindow::new()
  │
  └─ spawn tasks:
       read_loop        [connection.rs]
       write_loop       [connection.rs]
       maintenance_loop [connection.rs]
```

---

## Data flow: send (outbound)

```
caller
  │  conn.send(EncryptedData { ... })
  ▼
Connection::send
  │  enqueue into mpsc::Sender<OutboundItem>
  │  (non-blocking; Err::OutboundQueueFull if full)
  ▼
write_loop (tokio task)
  │  recv from mpsc::Receiver<OutboundItem>
  │
  ├─ Session::encrypt_frame(msg_type, plaintext, pad_len)   [session.rs]
  │    ├─ acquire send_mutex
  │    ├─ check rekey trigger (frame count OR elapsed time)
  │    │    if triggered → return NeedsRekey
  │    │    (write_loop emits RekeyInit first, then retries)
  │    ├─ allocate sequence (seq += 1; check exhaustion)
  │    ├─ Codec::encrypt(header, plaintext, padding)        [codec.rs]
  │    │    nonce = [0u8;4] || seq.to_le_bytes()
  │    │    aad   = marshal_binary(header) || padding_bytes
  │    │    ciphertext = ChaCha20Poly1305::encrypt(nonce, plaintext, aad)
  │    └─ release send_mutex → Frame
  │
  └─ TcpTransport::write_frame(frame)                       [transport.rs]
       write all bytes to TcpStream (with write_timeout)
```

---

## Data flow: receive (inbound)

```
TcpTransport::read_frame()                                  [transport.rs]
  │  read 40-byte header → derive body length → read body
  ▼
read_loop (tokio task)
  │
  ├─ Session::decrypt_frame(frame)                          [session.rs]
  │    ├─ acquire receive_mutex
  │    ├─ select codec: current epoch OR previous (grace window)
  │    ├─ ReplayWindow::check(sequence)                     [replay.rs]
  │    │    (check precedes authentication)
  │    ├─ Codec::decrypt(frame)                             [codec.rs]
  │    │    aad = marshal_binary(header) || padding_bytes
  │    │    plaintext = ChaCha20Poly1305::decrypt(nonce, ciphertext, aad)
  │    │    Err::Authentication on failure (no detail leaked)
  │    ├─ ReplayWindow::commit(token)   (only on auth success)
  │    └─ release receive_mutex → plaintext bytes
  │
  ├─ parse typed message from plaintext                     [messages.rs]
  │
  ├─ handle control messages internally:
  │    Ping       → enqueue Pong
  │    RekeyInit  → Session::accept_rekey()
  │    SessionClose → initiate shutdown
  │
  └─ dispatch ApplicationMessage to MessageHandler (serial)
```

---

## Data flow: rekey (send side)

```
write_loop detects NeedsRekey from Session::encrypt_frame
  │
  ├─ Session::begin_rekey()                                 [session.rs]
  │    ├─ acquire send_mutex
  │    ├─ RekeyState::compute_key_confirm(K, epoch+1)       [rekey.rs]
  │    │    HMAC-SHA256(K, b"DGPv1 Rekey Confirm" || LE32(epoch+1))
  │    ├─ RekeyState::derive_next_key(K)
  │    │    HMAC-SHA256(K, b"DGPv1 Rekey Send Key")
  │    ├─ encrypt RekeyInit as LAST frame of epoch E-1
  │    ├─ install K_next, set epoch = E, reset seq = 1
  │    └─ release send_mutex
  │
  └─ continue sending new-epoch frames
```

---

## Data flow: rekey (receive side)

```
read_loop receives RekeyInit frame
  │
  └─ Session::accept_rekey(payload)                         [session.rs]
       ├─ acquire receive_mutex
       ├─ verify epoch == current_receive_epoch + 1
       ├─ verify KeyConfirm in constant time (subtle::ConstantTimeEq)
       │    on failure: return Err::KeyConfirmFailed, change NO state
       ├─ derive K_next = HMAC-SHA256(K, b"DGPv1 Rekey Send Key")
       ├─ install K_next as new receive Codec
       ├─ retain old Codec as previous (grace window)
       ├─ reset new-epoch ReplayWindow
       ├─ set grace_frames = 2048, grace_deadline = now + 30s
       └─ release receive_mutex
```

---

## Concurrency model

```
Connection (Arc<ConnectionInner>)
  │
  ├─ send_mutex  ──── protects: send Codec, send epoch, send seq, RekeyState
  │                   (never held simultaneously with receive_mutex)
  │
  ├─ receive_mutex ── protects: receive Codec, receive epoch, ReplayWindow,
  │                   previous Codec, grace state
  │
  ├─ outbound: mpsc::channel<OutboundItem>(capacity)
  │
  ├─ cancel: CancellationToken   ← abort() / close() / terminal error
  │
  ├─ Task: read_loop
  │    reads frames → decrypts → dispatches handler (serial)
  │    on error → cancel.cancel(), store terminal cause
  │
  ├─ Task: write_loop
  │    drains outbound channel → encrypts → writes TCP
  │    on error → cancel.cancel(), store terminal cause
  │
  └─ Task: maintenance_loop
       fires keepalive pings (interval timer)
       fires rekey check (interval timer)
       observes cancel token → exits
```

---

## Implementation order

Implement modules in this order. Each step depends only on previously
completed modules.

```
Step 1:  error.rs          ✅ done — Error enum, all variants
Step 2:  header.rs         ⬜ Header, Flags, MessageType, marshal/unmarshal
Step 3:  frame.rs          ⬜ Frame, marshal_binary, unmarshal_binary
Step 4:  tlv.rs            ⬜ Tlv, encode_tlvs, decode_tlvs
Step 5:  messages.rs       ⬜ all typed message structs, parse/serialize
Step 6:  codec.rs          ⬜ Codec, encrypt, decrypt
Step 7:  replay.rs         ⬜ ReplayWindow, check, commit
Step 8:  rekey.rs          ⬜ RekeyState, compute_key_confirm, derive_next_key
Step 9:  handshake.rs      ⬜ StaticKey, HandshakeState, HandshakeSecrets
Step 10: session.rs        ⬜ Session, encrypt_frame, decrypt_frame, begin/accept_rekey
Step 11: transport.rs      ⬜ Transport trait, TcpTransport
Step 12: connection.rs     ⬜ Connection, ClientConfig, connect, send, close, loops
Step 13: tests/wire_vectors.rs  ⬜ cross-validate all parsers against testdata/vectors/
Step 14: tests/integration.rs   ⬜ loopback handshake, send, rekey, close
Step 15: fuzz targets      ⬜ fuzz_header, fuzz_frame, fuzz_tlv, fuzz_messages
```

After each step: `cargo check`, `cargo clippy -- -D warnings`, unit tests pass.
After step 13: `cargo test wire_vectors` must pass before any further work.

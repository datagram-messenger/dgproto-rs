//! DGProto v1 transport abstraction and async TCP implementation.
//!
//! # Transport trait
//!
//! `Transport` is the interface between the connection runtime and the
//! underlying byte stream. It exposes three operations:
//! - `read_frame`  — read one complete frame (blocks until available)
//! - `write_frame` — write one complete frame (blocks until all bytes written)
//! - `close`       — close the underlying connection
//!
//! # TcpTransport
//!
//! `TcpTransport` wraps a `tokio::net::TcpStream`. Frame length is derived
//! from the 40-byte fixed header — there is no outer length prefix.
//!
//! Read and write are independently mutex-guarded so one read and one write
//! may proceed concurrently (mirroring Go's `TCPTransport`).
//!
//! Context cancellation sets the socket deadline then clears it after the
//! operation completes, matching the Go `watchContext` pattern.
//!
//! See `docs/protocol/dgproto-v1.md` §3 for the normative specification.

// TODO: implement Transport trait and TcpTransport struct.
// Reference: dgproto-go/transport.go, tcp.go

//! High-level DGProto v1 connection runtime.
//!
//! `Connection` is the primary consumer-facing type. It manages the full
//! lifecycle of a single DGProto v1 client session:
//!
//! 1. TCP dial + Noise XX handshake (via [`Connection::connect`])
//! 2. Three concurrent Tokio tasks:
//!    - **Read loop** — reads frames, decrypts, dispatches to `MessageHandler`
//!    - **Write loop** — drains the outbound channel, encrypts, writes to TCP
//!    - **Maintenance loop** — fires keepalive pings and rekey timers
//! 3. Graceful shutdown via [`Connection::close`] or immediate via [`Connection::abort`]
//!
//! # Send semantics
//!
//! - [`send`](Connection::send) — enqueues into the bounded outbound channel.
//!   Returns immediately. `Err(Error::OutboundQueueFull)` if the channel is full.
//! - [`send_and_wait`](Connection::send_and_wait) — enqueues and awaits a
//!   oneshot confirmation from the write loop. Success means the frame was
//!   written to the TCP socket, not acknowledged by the peer.
//! - [`send_padded`](Connection::send_padded) — like `send`, with explicit
//!   random padding (0–255 bytes). Padding policy is the caller's responsibility.
//!
//! # Lifecycle
//!
//! The first observed terminal cause is retained. All subsequent `send` calls
//! return `Err(Error::ConnectionClosed)`. `Connection` is `Clone` (cheap
//! `Arc` clone) and `Send + Sync`.
//!
//! # Inbound dispatch
//!
//! Inbound messages are dispatched **serially** per connection (one handler at
//! a time). A slow handler delays subsequent messages on the same connection.
//!
//! See `docs/architecture/overview.md` for the data-flow diagram.

use std::sync::Arc;
use std::time::Duration;

use crate::{Ack, EncryptedData, Error, ErrorMessage, SessionClose, StaticKey};

// ── Public types ──────────────────────────────────────────────────────────────

/// Configuration for a client connection.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Client Noise static identity key.
    pub static_key: StaticKey,

    /// Optional server static public key for pre-authentication verification.
    /// If `None`, any server that completes a valid Noise handshake is accepted.
    pub server_static_hint: Option<[u8; 32]>,

    /// Maximum time allowed for the Noise XX handshake to complete.
    /// Default: 10 seconds.
    pub handshake_timeout: Duration,

    /// Maximum time allowed for a single frame write to complete.
    /// Default: 10 seconds.
    pub write_timeout: Duration,

    /// Idle timeout: close the connection if no inbound activity is observed
    /// for this duration. Default: disabled (0 = no timeout).
    pub idle_timeout: Duration,

    /// Keepalive ping interval. Default: disabled (0 = no keepalive).
    pub keepalive_interval: Duration,

    /// Keepalive timeout: close if a ping is not acknowledged within this
    /// duration. Default: `2 * keepalive_interval`.
    pub keepalive_timeout: Duration,

    /// Outbound channel capacity (number of queued messages).
    /// Default: 64.
    pub outbound_queue: usize,

    /// Handler queue capacity (number of inbound messages buffered before
    /// the handler is invoked). Default: 64.
    pub handler_queue: usize,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            static_key: StaticKey::generate().expect("StaticKey::generate"),
            server_static_hint: None,
            handshake_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(10),
            idle_timeout: Duration::ZERO,
            keepalive_interval: Duration::ZERO,
            keepalive_timeout: Duration::ZERO,
            outbound_queue: 64,
            handler_queue: 64,
        }
    }
}

/// An application-visible inbound message.
#[derive(Debug, Clone)]
pub enum ApplicationMessage {
    EncryptedData(EncryptedData),
    Ack(Ack),
    ErrorMessage(ErrorMessage),
    SessionClose(SessionClose),
}

/// Handler for inbound application messages.
///
/// Called serially per connection. Returning `Err` closes the connection.
pub type MessageHandler = Arc<
    dyn Fn(
            Arc<Connection>,
            ApplicationMessage,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Error>> + Send>>
        + Send
        + Sync,
>;

/// A DGProto v1 client connection.
///
/// `Clone` is cheap (Arc clone). All methods take `&self`. `Send + Sync`.
#[derive(Clone, Debug)]
pub struct Connection {
    // TODO: inner: Arc<ConnectionInner>
    _private: (),
}

impl Connection {
    /// Dial `addr`, perform the Noise XX handshake, and start the connection
    /// runtime. Returns when the handshake completes successfully.
    pub async fn connect(
        _addr: impl tokio::net::ToSocketAddrs,
        _config: ClientConfig,
    ) -> Result<Self, Error> {
        // TODO: implement
        // 1. tokio::net::TcpStream::connect(addr)
        // 2. TcpTransport::new(stream)
        // 3. HandshakeState::new(config.static_key)
        // 4. write_init -> read_response -> write_finish -> HandshakeSecrets
        // 5. Session::new(secrets)
        // 6. Spawn read_loop, write_loop, maintenance_loop
        // 7. Return Connection { inner: Arc::new(...) }
        todo!("Connection::connect")
    }

    /// Enqueue `msg` into the bounded outbound channel.
    ///
    /// Returns immediately. Does not wait for the frame to be written.
    /// Returns `Err(Error::OutboundQueueFull)` if the channel is full.
    pub fn send(&self, _msg: impl Into<ApplicationMessage>) -> Result<(), Error> {
        // TODO: implement
        todo!("Connection::send")
    }

    /// Enqueue `msg` and await confirmation that the frame was written to TCP.
    ///
    /// Success means the frame was written locally — not acknowledged by the
    /// peer or processed by the application.
    pub async fn send_and_wait(&self, _msg: impl Into<ApplicationMessage>) -> Result<(), Error> {
        // TODO: implement
        todo!("Connection::send_and_wait")
    }

    /// Like [`send`](Self::send), with explicit random padding (0–255 bytes).
    pub fn send_padded(
        &self,
        _msg: impl Into<ApplicationMessage>,
        _pad_len: u8,
    ) -> Result<(), Error> {
        // TODO: implement
        todo!("Connection::send_padded")
    }

    /// Initiate a graceful `SessionClose` exchange and wait for completion.
    pub async fn close(&self) -> Result<(), Error> {
        // TODO: implement
        todo!("Connection::close")
    }

    /// Terminate the connection immediately without a close handshake.
    pub fn abort(&self) {
        // TODO: implement — cancel the CancellationToken
        todo!("Connection::abort")
    }

    /// Return the 16-byte session identifier established during the handshake.
    pub fn session_id(&self) -> [u8; 16] {
        // TODO: implement
        todo!("Connection::session_id")
    }

    /// Return the server's 32-byte Noise static public key.
    pub fn peer_static(&self) -> [u8; 32] {
        // TODO: implement
        todo!("Connection::peer_static")
    }
}

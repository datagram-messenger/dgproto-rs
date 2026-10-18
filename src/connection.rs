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
//! - [`send_and_wait_padded`](Connection::send_and_wait_padded) — like
//!   `send_and_wait`, with explicit random padding.
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
//! # Reconnect pattern
//!
//! Use [`Connection::wait_for_close`] to drive a reconnect loop without polling
//! or relying on send-error detection:
//!
//! ```rust,no_run
//! # use dgproto::{ClientConfig, Connection};
//! # async fn example(config: ClientConfig) {
//! loop {
//!     match Connection::connect("127.0.0.1:8090", config.clone()).await {
//!         Err(e) => eprintln!("connect failed: {e}"),
//!         Ok(conn) => {
//!             if let Some(err) = conn.wait_for_close().await {
//!                 eprintln!("disconnected: {err}");
//!             }
//!             // clean shutdown — reconnect immediately or after a delay
//!         }
//!     }
//!     tokio::time::sleep(std::time::Duration::from_secs(2)).await;
//! }
//! # }
//! ```
//!
//! See `docs/architecture/overview.md` for the data-flow diagram.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};
use tokio_util::sync::CancellationToken;

use crate::{
    frame::Frame,
    handshake::InitiatorHandshake,
    header::{Header, MessageType},
    messages::{Ack, EncryptedData, ErrorMessage, PingPong, SessionClose},
    session::{EncryptResult, Session},
    transport::{TcpTransport, Transport},
    Error, StaticKey,
};

// ── Public types ──────────────────────────────────────────────────────────────

/// Configuration for a client connection.
///
/// Start with [`Default`] so queue and timeout defaults evolve safely, then set
/// the persistent client identity and the known server key.
///
/// # Security
///
/// `server_static_hint: None` accepts any server that completes a valid Noise XX
/// handshake. Production clients should set it to a previously provisioned,
/// known server static public key.
///
/// # Examples
///
/// ```rust
/// use dgproto::{ClientConfig, StaticKey};
///
/// # fn config(client_private: &[u8; 32], known_server_key: [u8; 32]) -> Result<ClientConfig, dgproto::Error> {
/// let config = ClientConfig {
///     static_key: StaticKey::load(client_private)?,
///     server_static_hint: Some(known_server_key),
///     ..Default::default()
/// };
/// # Ok(config)
/// # }
/// ```
#[derive(Clone)]
pub struct ClientConfig {
    /// Client Noise static identity key.
    pub static_key: StaticKey,

    /// Optional server static public key for handshake identity verification.
    ///
    /// `None` accepts any server that completes a valid Noise XX handshake.
    /// Production clients should provide a known server static public key.
    pub server_static_hint: Option<[u8; 32]>,

    /// Maximum time allowed for the Noise XX handshake to complete.
    /// Default: 10 seconds.
    pub handshake_timeout: Duration,

    /// Maximum time allowed for a single frame write to complete.
    /// Default: 10 seconds.
    pub write_timeout: Duration,

    /// Maximum time allowed for a single frame read to complete.
    /// A value of `Duration::ZERO` means no read timeout (reads block until
    /// data arrives or the connection is cancelled).
    /// Default: 0 (no read timeout; idle_timeout governs inactivity instead).
    pub read_timeout: Duration,

    /// Idle timeout: close the connection if no inbound activity is observed
    /// for this duration. Default: disabled (0 = no timeout).
    pub idle_timeout: Duration,

    /// Keepalive ping interval. Default: disabled (0 = no keepalive).
    pub keepalive_interval: Duration,

    /// Keepalive timeout: close if a ping is not acknowledged within this
    /// duration. Default: `2 * keepalive_interval`.
    pub keepalive_timeout: Duration,

    /// Outbound channel capacity (number of queued messages). Default: 64.
    ///
    /// Keep the default unless application load and backpressure measurements
    /// justify tuning it. A full queue makes [`Connection::send`] fail with
    /// [`Error::OutboundQueueFull`].
    pub outbound_queue: usize,

    /// Reserved handler-dispatch setting. Default: 64.
    ///
    /// This is not currently a parallel queue: the handler runs serially in the
    /// read loop, so changing this value has no effect in this release.
    pub handler_queue: usize,

    /// Optional inbound message handler. If `None`, inbound application
    /// messages are silently discarded.
    pub handler: Option<MessageHandler>,

    /// Optional callback invoked after the Noise XX handshake completes,
    /// before the first inbound message is dispatched.
    ///
    /// Receives an `Arc<Connection>` so the callback can store or use the
    /// connection immediately. Called synchronously in the connect path —
    /// keep it non-blocking.
    ///
    /// Default: `None`.
    pub on_connect: Option<Arc<dyn Fn(Arc<Connection>) + Send + Sync>>,

    /// Optional callback invoked when the connection terminates for any reason.
    ///
    /// - `None` — clean `SessionClose` from either side.
    /// - `Some(err)` — error termination (I/O error, authentication failure,
    ///   keepalive timeout, idle timeout, handler error, etc.).
    ///
    /// Called from the last task loop to exit. Keep it non-blocking.
    ///
    /// Default: `None`.
    pub on_disconnect: Option<Arc<dyn Fn(Option<Error>) + Send + Sync>>,
}

/// Creates a `ClientConfig` with safe defaults.
///
/// **The default `static_key` is a placeholder** (derived from an all-zero
/// private key). You MUST replace it with a real key generated by
/// [`StaticKey::generate`] or loaded via [`StaticKey::load`] before calling
/// [`Connection::connect`].
impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            static_key: StaticKey::load(&[0u8; 32]).expect("all-zero key is a valid 32-byte slice"),
            server_static_hint: None,
            handshake_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(10),
            read_timeout: Duration::ZERO,
            idle_timeout: Duration::ZERO,
            keepalive_interval: Duration::ZERO,
            keepalive_timeout: Duration::ZERO,
            outbound_queue: 64,
            handler_queue: 64,
            handler: None,
            on_connect: None,
            on_disconnect: None,
        }
    }
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("static_key", &self.static_key)
            .field("server_static_hint", &self.server_static_hint)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("write_timeout", &self.write_timeout)
            .field("read_timeout", &self.read_timeout)
            .field("idle_timeout", &self.idle_timeout)
            .field("keepalive_interval", &self.keepalive_interval)
            .field("keepalive_timeout", &self.keepalive_timeout)
            .field("outbound_queue", &self.outbound_queue)
            .field("handler_queue", &self.handler_queue)
            .field(
                "handler",
                &self.handler.as_ref().map(|_| "<MessageHandler>"),
            )
            .field("on_connect", &self.on_connect.as_ref().map(|_| "<Fn>"))
            .field(
                "on_disconnect",
                &self.on_disconnect.as_ref().map(|_| "<Fn>"),
            )
            .finish()
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

impl From<EncryptedData> for ApplicationMessage {
    fn from(message: EncryptedData) -> Self {
        Self::EncryptedData(message)
    }
}

impl From<Ack> for ApplicationMessage {
    fn from(message: Ack) -> Self {
        Self::Ack(message)
    }
}

impl From<ErrorMessage> for ApplicationMessage {
    fn from(message: ErrorMessage) -> Self {
        Self::ErrorMessage(message)
    }
}

impl From<SessionClose> for ApplicationMessage {
    fn from(message: SessionClose) -> Self {
        Self::SessionClose(message)
    }
}

/// Handler for inbound application messages.
///
/// Called serially per connection. Returning `Err` closes the connection.
/// [`handler_fn`] is the ergonomic way to create one from an async closure.
///
/// # Examples
///
/// ```rust
/// use dgproto::{handler_fn, ApplicationMessage, MessageHandler};
///
/// let handler: MessageHandler = handler_fn(|_connection, message| async move {
///     if let ApplicationMessage::EncryptedData(data) = message {
///         println!("received {} TLVs", data.fields.len());
///     }
///     Ok(())
/// });
/// ```
pub type MessageHandler = Arc<
    dyn Fn(
            Arc<Connection>,
            ApplicationMessage,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Error>> + Send>>
        + Send
        + Sync,
>;

/// Adapts an async closure into a [`MessageHandler`].
pub fn handler_fn<F, Fut>(handler: F) -> MessageHandler
where
    F: Fn(Arc<Connection>, ApplicationMessage) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<(), Error>> + Send + 'static,
{
    Arc::new(move |connection, message| Box::pin(handler(connection, message)))
}

// ── Internal types ────────────────────────────────────────────────────────────

/// A message queued for the write loop.
struct QueuedMessage {
    msg: ApplicationMessage,
    pad_len: u8,
    /// If set, the write loop sends the write result here.
    completion: Option<oneshot::Sender<Result<(), Error>>>,
}

/// A graceful-close request sent to the write loop.
struct CloseRequest {
    message: SessionClose,
    result: oneshot::Sender<Result<(), Error>>,
}

#[derive(Debug)]
enum TerminalState {
    Unset,
    Clean,
    Error(Error),
}

impl TerminalState {
    fn set_once(&mut self, cause: Option<Error>) {
        if matches!(self, Self::Unset) {
            *self = match cause {
                Some(error) => Self::Error(error),
                None => Self::Clean,
            };
        }
    }

    fn cause(&self) -> Option<Error> {
        match self {
            Self::Error(error) => Some(error.clone()),
            Self::Unset | Self::Clean => None,
        }
    }
}

// Marks an inline read-loop handler so Connection::close can avoid waiting
// for that same loop to exit.
tokio::task_local! {
    static HANDLER_CONNECTION: usize;
}

struct LoopExitGuard {
    conn: Connection,
}

impl LoopExitGuard {
    fn new(conn: Connection) -> Self {
        Self { conn }
    }
}

impl Drop for LoopExitGuard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.conn.shutdown(Some(Error::ConnectionClosed));
        }
        self.conn.note_loop_exit();
    }
}

/// Shared connection state, owned by an `Arc`.
struct ConnectionInner {
    transport: Arc<TcpTransport>,
    session: Arc<Session>,
    config: ClientConfig,
    peer_static: [u8; 32],
    outbound: mpsc::Sender<QueuedMessage>,
    close_tx: mpsc::Sender<CloseRequest>,
    /// Capacity-1 channel; write loop signals activity to maintenance loop.
    activity_tx: mpsc::Sender<()>,
    /// Capacity-1 channel; read loop forwards pong nonces to maintenance loop.
    pong_tx: mpsc::Sender<u64>,
    /// Becomes `true` when all three task loops have exited.
    done: tokio::sync::watch::Sender<bool>,
    cancel: CancellationToken,
    /// Serializes sequence allocation, transport write, and rekey commit/retry.
    writer: AsyncMutex<()>,
    /// First terminal outcome (set once, never cleared).
    terminal: Mutex<TerminalState>,
    ping_nonce: AtomicU64,
    closing: AtomicBool,
    /// Number of lifecycle tasks still running (three loops plus teardown).
    loops_remaining: AtomicU8,
    /// Ensures session/transport teardown is spawned exactly once.
    teardown_started: AtomicBool,
}

// ── Connection ────────────────────────────────────────────────────────────────

/// A DGProto v1 client connection.
///
/// `Clone` is cheap (Arc clone). All methods take `&self`. `Send + Sync`.
#[derive(Clone)]
pub struct Connection {
    inner: Arc<ConnectionInner>,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("session_id", &self.inner.session.session_id())
            .finish_non_exhaustive()
    }
}

impl Connection {
    /// Dial `addr`, perform the Noise XX handshake, and start the connection
    /// runtime. Returns when the handshake completes successfully.
    pub async fn connect(
        addr: impl tokio::net::ToSocketAddrs,
        config: ClientConfig,
    ) -> Result<Self, Error> {
        validate_config(&config)?;
        let handshake_timeout = config.handshake_timeout;
        let conn = tokio::time::timeout(handshake_timeout, Self::do_connect(addr, config))
            .await
            .map_err(|_| {
                Error::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "handshake timed out",
                ))
            })??;
        Ok(conn)
    }

    async fn do_connect(
        addr: impl tokio::net::ToSocketAddrs,
        config: ClientConfig,
    ) -> Result<Self, Error> {
        // 1. TCP connect.
        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(Error::Io)?;
        let transport = Arc::new(TcpTransport::new(stream));

        // 2. Noise XX handshake (initiator).
        let mut hs =
            InitiatorHandshake::new(&config.static_key, config.server_static_hint.as_ref())?;

        // Flight 1: send HandshakeInit.
        let init_payload = hs.write_init()?;
        let init_frame = Frame {
            header: Header::new(
                MessageType::HandshakeInit,
                [0u8; 16],
                0,
                init_payload.len() as u32,
                0,
            ),
            payload: init_payload,
            tag: [0u8; crate::AEAD_TAG_SIZE],
            padding: vec![],
        };
        transport.write_frame(&init_frame, Duration::ZERO).await?;

        // Flight 2: receive HandshakeResponse.
        let resp_frame = transport.read_frame(Duration::ZERO).await?;
        validate_handshake_response_envelope(&resp_frame)?;
        hs.read_response(&resp_frame.payload)?;

        // Flight 3: send HandshakeFinish.
        let (finish_payload, secrets) = hs.write_finish()?;
        let finish_frame = Frame {
            header: Header::new(
                MessageType::HandshakeResponse,
                [0u8; 16],
                0,
                finish_payload.len() as u32,
                0,
            ),
            payload: finish_payload,
            tag: [0u8; crate::AEAD_TAG_SIZE],
            padding: vec![],
        };
        transport.write_frame(&finish_frame, Duration::ZERO).await?;

        // The handshake already verified the peer static key if a hint was provided.
        let peer_static = secrets.peer_static;

        // 3. Open session.
        let session = Arc::new(Session::new(secrets)?);

        // 4. Build channels and inner state.
        let (outbound_tx, outbound_rx) = mpsc::channel::<QueuedMessage>(config.outbound_queue);
        let (close_tx, close_rx) = mpsc::channel::<CloseRequest>(1);
        let (activity_tx, activity_rx) = mpsc::channel::<()>(1);
        let (pong_tx, pong_rx) = mpsc::channel::<u64>(1);
        let (done, _done_rx) = tokio::sync::watch::channel(false);
        let cancel = CancellationToken::new();

        let inner = Arc::new(ConnectionInner {
            transport: transport.clone(),
            session: session.clone(),
            config,
            peer_static,
            outbound: outbound_tx,
            close_tx,
            activity_tx,
            pong_tx,
            done,
            cancel: cancel.clone(),
            writer: AsyncMutex::new(()),
            terminal: Mutex::new(TerminalState::Unset),
            ping_nonce: AtomicU64::new(0),
            closing: AtomicBool::new(false),
            loops_remaining: AtomicU8::new(4),
            teardown_started: AtomicBool::new(false),
        });

        let conn = Connection {
            inner: inner.clone(),
        };

        // Spawn read loop.
        {
            let c = conn.clone();
            tokio::spawn(async move { c.run_read_loop().await });
        }
        // Spawn write loop.
        {
            let c = conn.clone();
            tokio::spawn(async move { c.run_write_loop(outbound_rx, close_rx).await });
        }
        // Spawn maintenance loop.
        {
            let c = conn.clone();
            tokio::spawn(async move { c.run_maintenance_loop(activity_rx, pong_rx).await });
        }

        // Fire on_connect after all loops are running, preserving the documented
        // ordering. A callback panic rolls the fully-started runtime back before
        // resuming the panic to the caller.
        if let Some(ref cb) = conn.inner.config.on_connect {
            if let Err(panic) = catch_unwind(AssertUnwindSafe(|| cb(Arc::new(conn.clone())))) {
                conn.shutdown(Some(Error::ConnectionClosed));
                let _ = tokio::time::timeout(
                    conn.inner.config.handshake_timeout,
                    conn.wait_for_close(),
                )
                .await;
                std::panic::resume_unwind(panic);
            }
        }

        Ok(conn)
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Enqueue `msg` into the bounded outbound channel without blocking.
    ///
    /// Success only means the message was queued locally. It does not wait for a
    /// TCP write, peer receipt, an [`Ack`], or application processing. Returns
    /// [`Error::OutboundQueueFull`] if the bounded queue is full.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dgproto::{Connection, EncryptedData, Tlv};
    ///
    /// # fn send_one(connection: &Connection) -> Result<(), dgproto::Error> {
    /// connection.send(EncryptedData {
    ///     stream_id: 1,
    ///     app_message_type: 1,
    ///     fields: vec![Tlv::new(1, b"hello")],
    /// })?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn send(&self, msg: impl Into<ApplicationMessage>) -> Result<(), Error> {
        self.send_padded(msg, 0)
    }

    /// Like [`send`](Self::send), with explicit random padding (0–255 bytes).
    pub fn send_padded(
        &self,
        msg: impl Into<ApplicationMessage>,
        pad_len: u8,
    ) -> Result<(), Error> {
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(Error::ConnectionClosed);
        }
        self.inner
            .outbound
            .try_send(QueuedMessage {
                msg: msg.into(),
                pad_len,
                completion: None,
            })
            .map_err(|e| match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => Error::OutboundQueueFull,
                tokio::sync::mpsc::error::TrySendError::Closed(_) => Error::ConnectionClosed,
            })
    }

    /// Enqueue `msg` and await confirmation that the frame was written to TCP.
    ///
    /// Success means the frame was written locally — not acknowledged by the
    /// peer or processed by the application.
    pub async fn send_and_wait(&self, msg: impl Into<ApplicationMessage>) -> Result<(), Error> {
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(Error::ConnectionClosed);
        }
        let (tx, rx) = oneshot::channel();
        self.inner
            .outbound
            .send(QueuedMessage {
                msg: msg.into(),
                pad_len: 0,
                completion: Some(tx),
            })
            .await
            .map_err(|_| Error::ConnectionClosed)?;
        rx.await.map_err(|_| Error::ConnectionClosed)?
    }

    /// Like [`send_and_wait`](Self::send_and_wait), with explicit random padding
    /// (0–255 bytes).
    ///
    /// Enqueues the message with `pad_len` bytes of random padding and awaits a
    /// oneshot confirmation from the write loop. Success means the frame was
    /// written to the TCP socket, not acknowledged by the peer.
    ///
    /// A `pad_len` of `0` is equivalent to calling [`send_and_wait`](Self::send_and_wait).
    /// Padding policy is the caller's responsibility.
    pub async fn send_and_wait_padded(
        &self,
        msg: impl Into<ApplicationMessage>,
        pad_len: u8,
    ) -> Result<(), Error> {
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(Error::ConnectionClosed);
        }
        let (tx, rx) = oneshot::channel();
        self.inner
            .outbound
            .send(QueuedMessage {
                msg: msg.into(),
                pad_len,
                completion: Some(tx),
            })
            .await
            .map_err(|_| Error::ConnectionClosed)?;
        rx.await.map_err(|_| Error::ConnectionClosed)?
    }

    /// Initiate a graceful `SessionClose` exchange and wait for local teardown.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dgproto::Connection;
    ///
    /// # async fn shutdown(connection: &Connection) -> Result<(), dgproto::Error> {
    /// connection.close().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn close(&self) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        let req = CloseRequest {
            message: SessionClose {
                code: crate::messages::CloseCode::Normal,
                reason: String::new(),
            },
            result: tx,
        };
        self.inner.closing.store(true, Ordering::Release);
        self.inner
            .close_tx
            .send(req)
            .await
            .map_err(|_| Error::ConnectionClosed)?;
        // Wait for the write loop to process the close. A dropped completion
        // sender means the write loop exited before handling this request.
        let result = rx.await.map_err(|_| Error::ConnectionClosed)?;
        // A handler runs inline in the read loop. Waiting for global completion
        // from that same task would deadlock, so return after the write loop has
        // completed the close handshake; teardown continues in the background.
        let in_own_handler = HANDLER_CONNECTION
            .try_with(|id| *id == Arc::as_ptr(&self.inner) as usize)
            .unwrap_or(false);
        if !in_own_handler {
            let mut done = self.inner.done.subscribe();
            if !*done.borrow() {
                done.changed().await.map_err(|_| Error::ConnectionClosed)?;
            }
        }
        result
    }

    /// Wait until the connection terminates and return the terminal cause.
    ///
    /// Resolves to:
    /// - `None` — clean shutdown: `SessionClose` was exchanged by either side,
    ///   or [`close`](Self::close) completed normally.
    /// - `Some(err)` — error termination: I/O error, authentication failure,
    ///   keepalive timeout, idle timeout, handler error, etc.
    ///
    /// Returns immediately if the connection is already closed.
    ///
    /// # Reconnect pattern
    ///
    /// ```rust,no_run
    /// # use dgproto::{ClientConfig, Connection};
    /// # async fn example(config: ClientConfig) {
    /// loop {
    ///     match Connection::connect("127.0.0.1:8090", config.clone()).await {
    ///         Err(e) => { eprintln!("connect failed: {e}"); }
    ///         Ok(conn) => {
    ///             if let Some(err) = conn.wait_for_close().await {
    ///                 eprintln!("disconnected: {err}");
    ///             }
    ///         }
    ///     }
    ///     tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    /// }
    /// # }
    /// ```
    pub async fn wait_for_close(&self) -> Option<Error> {
        // Subscribe before checking the flag to avoid a race where done fires
        // between the is_closed check and the subscribe call.
        let mut done_rx = self.inner.done.subscribe();
        if !*done_rx.borrow() {
            // Ignore the error: the sender is dropped only after send_replace(true),
            // so a RecvError here means the channel is already done.
            let _ = done_rx.changed().await;
        }
        // Return a clone of the first terminal cause, if any.
        self.inner.terminal.lock().expect("terminal mutex").cause()
    }

    /// Terminate the connection immediately without a close handshake.
    ///
    /// Cancels all I/O and session tasks. Fire-and-forget — returns before
    /// the loops have fully exited. To wait for teardown, call
    /// [`wait_for_close`](Self::wait_for_close) afterwards.
    ///
    /// Subsequent [`send`](Self::send) calls return [`Error::ConnectionClosed`].
    pub fn abort(&self) {
        self.shutdown(Some(Error::ConnectionClosed));
    }

    /// Return the 16-byte session identifier established during the handshake.
    pub fn session_id(&self) -> [u8; 16] {
        self.inner.session.session_id()
    }

    /// Return the server's 32-byte Noise static public key.
    pub fn peer_static(&self) -> [u8; 32] {
        self.inner.peer_static
    }

    /// Return `true` if the connection has been closed or aborted.
    ///
    /// Once this returns `true` all subsequent [`send`](Self::send) calls will
    /// return [`Error::ConnectionClosed`].
    pub fn is_closed(&self) -> bool {
        self.inner.closing.load(Ordering::Acquire)
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Initiate connection shutdown.
    ///
    /// `cause` is `None` for a clean `SessionClose` (both sides exchanged
    /// close frames), or `Some(err)` for any error termination.
    /// The first cause wins; subsequent calls are no-ops.
    fn shutdown(&self, cause: Option<Error>) {
        self.inner
            .terminal
            .lock()
            .expect("terminal mutex")
            .set_once(cause);
        self.inner.closing.store(true, Ordering::Release);
        self.inner.cancel.cancel();
        if !self.inner.teardown_started.swap(true, Ordering::AcqRel) {
            let conn = self.clone();
            tokio::spawn(async move {
                conn.inner.session.close().await;
                let _ = conn.inner.transport.close().await;
                conn.note_loop_exit();
            });
        }
    }

    fn note_activity(&self) {
        let _ = self.inner.activity_tx.try_send(());
    }

    fn note_loop_exit(&self) {
        let prev = self.inner.loops_remaining.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            // All loops and teardown have exited. Keep the documented callback
            // ordering, but never let user panic suppress completion publication.
            if let Some(ref cb) = self.inner.config.on_disconnect {
                let cause = self.inner.terminal.lock().expect("terminal mutex").cause();
                let _ = catch_unwind(AssertUnwindSafe(|| cb(cause)));
            }
            self.inner.done.send_replace(true);
        }
    }

    // ── Task loops ────────────────────────────────────────────────────────────

    async fn run_read_loop(&self) {
        let _exit = LoopExitGuard::new(self.clone());
        loop {
            let read_timeout = self.inner.config.read_timeout;
            let frame = tokio::select! {
                result = self.inner.transport.read_frame(read_timeout) => {
                    match result {
                        Ok(f) => f,
                        Err(e) => { self.shutdown(Some(e)); return; }
                    }
                }
                _ = self.inner.cancel.cancelled() => { return; },
            };

            let plaintext = match self.inner.session.decrypt_frame(&frame).await {
                Ok(p) => p,
                Err(e) => {
                    self.shutdown(Some(e));
                    return;
                }
            };

            self.note_activity();

            match frame.header.msg_type {
                MessageType::PingPong => {
                    match PingPong::unmarshal_binary(&plaintext) {
                        Ok(ping) => {
                            if ping.is_response {
                                let _ = self.inner.pong_tx.try_send(ping.nonce);
                            } else {
                                // Echo back as pong.
                                let pong = PingPong {
                                    is_response: true,
                                    nonce: ping.nonce,
                                };
                                match pong.marshal_binary() {
                                    Ok(payload) => {
                                        if let Err(e) = self
                                            .send_internal(MessageType::PingPong, &payload, 0)
                                            .await
                                        {
                                            self.shutdown(Some(e));
                                            return;
                                        }
                                    }
                                    Err(e) => {
                                        self.shutdown(Some(e));
                                        return;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            self.shutdown(Some(e));
                            return;
                        }
                    }
                }
                MessageType::SessionClose => {
                    if let Err(e) = validate_session_close_payload(&plaintext) {
                        self.shutdown(Some(e));
                        return;
                    }
                    self.shutdown(None);
                    return;
                }
                MessageType::RekeyInit => {
                    // Already handled by session.decrypt_frame — no dispatch needed.
                }
                _ => {
                    // Dispatch to handler if set.
                    if let Some(handler) = &self.inner.config.handler {
                        let app_msg = match parse_inbound(&frame, &plaintext) {
                            Ok(m) => m,
                            Err(e) => {
                                self.shutdown(Some(e));
                                return;
                            }
                        };
                        let conn = Connection {
                            inner: self.inner.clone(),
                        };
                        let handler_result = HANDLER_CONNECTION
                            .scope(
                                Arc::as_ptr(&self.inner) as usize,
                                (handler)(Arc::new(conn), app_msg),
                            )
                            .await;
                        if let Err(e) = handler_result {
                            self.shutdown(Some(e));
                            return;
                        }
                    }
                }
            }
        }
    }

    async fn run_write_loop(
        &self,
        mut outbound_rx: mpsc::Receiver<QueuedMessage>,
        mut close_rx: mpsc::Receiver<CloseRequest>,
    ) {
        let _exit = LoopExitGuard::new(self.clone());
        loop {
            tokio::select! {
                // Prioritize close requests.
                Some(req) = close_rx.recv() => {
                    let payload = match req.message.marshal_binary() {
                        Ok(p) => p,
                        Err(e) => {
                            let _ = req.result.send(Err(e.clone()));
                            self.shutdown(Some(e));
                            return;
                        }
                    };
                    let result = self.send_internal(MessageType::SessionClose, &payload, 0).await;
                    match result {
                        Ok(()) => {
                            let _ = req.result.send(Ok(()));
                            self.shutdown(None);
                        }
                        Err(e) => {
                            let _ = req.result.send(Err(e.clone()));
                            self.shutdown(Some(e));
                        }
                    }
                    return;
                }
                Some(item) = outbound_rx.recv() => {
                    let (msg_type, payload) = match app_msg_to_wire(&item.msg) {
                        Ok(v) => v,
                        Err(e) => {
                            if let Some(tx) = item.completion { let _ = tx.send(Err(Error::ConnectionClosed)); }
                            self.shutdown(Some(e));
                            return;
                        }
                    };
                    let result = self.send_internal(msg_type, &payload, item.pad_len).await;
                    match result {
                        Ok(()) => {
                            if let Some(tx) = item.completion { let _ = tx.send(Ok(())); }
                        }
                        Err(e) => {
                            if let Some(tx) = item.completion { let _ = tx.send(Err(Error::ConnectionClosed)); }
                            self.shutdown(Some(e));
                            return;
                        }
                    }
                }
                _ = self.inner.cancel.cancelled() => { return; },
            }
        }
    }

    async fn run_maintenance_loop(
        &self,
        mut activity_rx: mpsc::Receiver<()>,
        mut pong_rx: mpsc::Receiver<u64>,
    ) {
        let _exit = LoopExitGuard::new(self.clone());
        let mut idle_interval = if self.inner.config.idle_timeout.is_zero() {
            None
        } else {
            let d = self.inner.config.idle_timeout;
            Some(tokio::time::interval_at(tokio::time::Instant::now() + d, d))
        };
        let mut keepalive_interval = if self.inner.config.keepalive_interval.is_zero() {
            None
        } else {
            let d = self.inner.config.keepalive_interval;
            Some(tokio::time::interval_at(tokio::time::Instant::now() + d, d))
        };
        let mut pong_deadline: Option<tokio::time::Instant> = None;
        let mut outstanding_nonce: u64 = 0;

        loop {
            let idle_tick = async {
                if let Some(ref mut t) = idle_interval {
                    t.tick().await;
                    true
                } else {
                    std::future::pending::<bool>().await
                }
            };
            let keepalive_tick = async {
                if let Some(ref mut t) = keepalive_interval {
                    t.tick().await;
                    true
                } else {
                    std::future::pending::<bool>().await
                }
            };
            let pong_expired = async {
                if let Some(deadline) = pong_deadline {
                    tokio::time::sleep_until(deadline).await;
                    true
                } else {
                    std::future::pending::<bool>().await
                }
            };

            tokio::select! {
                _ = self.inner.cancel.cancelled() => { return; },
                _ = activity_rx.recv() => {
                    // Reset idle timer.
                    if let Some(ref mut t) = idle_interval {
                        t.reset();
                    }
                }
                Some(nonce) = pong_rx.recv() => {
                    if outstanding_nonce != 0 && nonce == outstanding_nonce {
                        outstanding_nonce = 0;
                        pong_deadline = None;
                        // Reset keepalive timer.
                        if let Some(ref mut t) = keepalive_interval {
                            t.reset();
                        }
                    }
                }
                true = keepalive_tick => {
                    if outstanding_nonce == 0 {
                        let nonce = self.inner.ping_nonce.fetch_add(1, Ordering::Relaxed) + 1;
                        outstanding_nonce = nonce;
                        let ping = PingPong { is_response: false, nonce };
                        let payload = match ping.marshal_binary() {
                            Ok(payload) => payload,
                            Err(e) => {
                                self.shutdown(Some(e));
                                return;
                            }
                        };
                        if let Err(e) = self.send_internal(MessageType::PingPong, &payload, 0).await {
                            self.shutdown(Some(e));
                            return;
                        }
                        let timeout = if self.inner.config.keepalive_timeout.is_zero() {
                            self.inner.config.keepalive_interval * 2
                        } else {
                            self.inner.config.keepalive_timeout
                        };
                        pong_deadline = Some(tokio::time::Instant::now() + timeout);
                    }
                }
                true = pong_expired => {
                    self.shutdown(Some(Error::KeepaliveTimeout));
                    return;
                }
                true = idle_tick => {
                    self.shutdown(Some(Error::IdleTimeout));
                    return;
                }
            }
        }
    }

    /// Encrypt and write a single frame, handling the rekey protocol.
    async fn send_internal(
        &self,
        msg_type: MessageType,
        plaintext: &[u8],
        pad_len: u8,
    ) -> Result<(), Error> {
        let _writer = self.inner.writer.lock().await;
        loop {
            match self
                .inner
                .session
                .encrypt_frame(msg_type, plaintext, pad_len)
                .await?
            {
                EncryptResult::Frame(frame) => {
                    return self
                        .inner
                        .transport
                        .write_frame(&frame, self.inner.config.write_timeout)
                        .await;
                }
                EncryptResult::NeedsRekey(rekey_frame) => {
                    self.inner
                        .transport
                        .write_frame(&rekey_frame, self.inner.config.write_timeout)
                        .await?;
                    self.inner.session.mark_rekey_sent(&rekey_frame).await?;
                    // Retry the original message.
                }
            }
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn validate_config(config: &ClientConfig) -> Result<(), Error> {
    if config.outbound_queue == 0 {
        return Err(Error::InvalidOutboundQueueCapacity);
    }
    if config.handler_queue == 0 {
        return Err(Error::InvalidHandlerQueueCapacity);
    }
    Ok(())
}

fn validate_handshake_response_envelope(frame: &Frame) -> Result<(), Error> {
    if frame.header.msg_type != MessageType::HandshakeResponse
        || frame.header.session_id != [0u8; 16]
        || frame.header.sequence != 0
        || frame.header.pad_length != 0
    {
        return Err(Error::Handshake);
    }
    Ok(())
}

fn app_msg_to_wire(msg: &ApplicationMessage) -> Result<(MessageType, Vec<u8>), Error> {
    match msg {
        ApplicationMessage::EncryptedData(m) => {
            Ok((MessageType::EncryptedData, m.marshal_binary()?))
        }
        ApplicationMessage::Ack(m) => Ok((MessageType::Ack, m.marshal_binary()?)),
        ApplicationMessage::ErrorMessage(m) => Ok((MessageType::Error, m.marshal_binary()?)),
        ApplicationMessage::SessionClose(m) => Ok((MessageType::SessionClose, m.marshal_binary()?)),
    }
}

fn validate_session_close_payload(plaintext: &[u8]) -> Result<(), Error> {
    SessionClose::unmarshal_binary(plaintext).map(|_| ())
}

fn parse_inbound(frame: &Frame, plaintext: &[u8]) -> Result<ApplicationMessage, Error> {
    match frame.header.msg_type {
        MessageType::EncryptedData => Ok(ApplicationMessage::EncryptedData(
            EncryptedData::unmarshal_binary(plaintext)?,
        )),
        MessageType::Ack => Ok(ApplicationMessage::Ack(Ack::unmarshal_binary(plaintext)?)),
        MessageType::Error => Ok(ApplicationMessage::ErrorMessage(
            ErrorMessage::unmarshal_binary(plaintext)?,
        )),
        MessageType::SessionClose => Ok(ApplicationMessage::SessionClose(
            SessionClose::unmarshal_binary(plaintext)?,
        )),
        _ => Err(Error::MessageType),
    }
}

#[cfg(test)]
mod handshake_envelope_tests {
    use super::*;

    fn response_frame() -> Frame {
        Frame {
            header: Header::new(MessageType::HandshakeResponse, [0u8; 16], 0, 96, 0),
            payload: vec![0u8; 96],
            tag: [0u8; crate::AEAD_TAG_SIZE],
            padding: vec![],
        }
    }

    #[test]
    fn rejects_zero_handler_queue_capacity() {
        let config = ClientConfig {
            handler_queue: 0,
            ..ClientConfig::default()
        };

        assert_eq!(
            validate_config(&config),
            Err(Error::InvalidHandlerQueueCapacity)
        );
    }

    #[test]
    fn malformed_session_close_payload_is_rejected() {
        assert!(matches!(
            validate_session_close_payload(&[]),
            Err(Error::MessageTooShort)
        ));
        assert!(matches!(
            validate_session_close_payload(&[0xff, 0xff]),
            Err(Error::InvalidCloseCode)
        ));
    }

    #[test]
    fn terminal_state_is_first_wins_for_clean_and_error() {
        let mut clean_first = TerminalState::Unset;
        clean_first.set_once(None);
        clean_first.set_once(Some(Error::IdleTimeout));
        assert!(matches!(clean_first, TerminalState::Clean));
        assert_eq!(clean_first.cause(), None);

        let mut error_first = TerminalState::Unset;
        error_first.set_once(Some(Error::KeepaliveTimeout));
        error_first.set_once(None);
        assert_eq!(error_first.cause(), Some(Error::KeepaliveTimeout));
    }

    #[test]
    fn rejects_zero_outbound_queue_capacity() {
        let config = ClientConfig {
            outbound_queue: 0,
            ..ClientConfig::default()
        };
        assert_eq!(
            validate_config(&config),
            Err(Error::InvalidOutboundQueueCapacity)
        );

        let config = ClientConfig {
            outbound_queue: 1,
            ..ClientConfig::default()
        };
        assert_eq!(validate_config(&config), Ok(()));
    }

    #[test]
    fn accepts_canonical_response_and_ignored_receive_fields() {
        let mut frame = response_frame();
        frame.header.flags = 0x80;
        frame.header.reserved = [1, 2, 3, 4];
        assert!(validate_handshake_response_envelope(&frame).is_ok());
    }

    #[test]
    fn rejects_malformed_response_envelope() {
        let mut wrong_type = response_frame();
        wrong_type.header.msg_type = MessageType::EncryptedData;
        assert!(matches!(
            validate_handshake_response_envelope(&wrong_type),
            Err(Error::Handshake)
        ));

        let mut session = response_frame();
        session.header.session_id[0] = 1;
        assert!(matches!(
            validate_handshake_response_envelope(&session),
            Err(Error::Handshake)
        ));

        let mut sequence = response_frame();
        sequence.header.sequence = 1;
        assert!(matches!(
            validate_handshake_response_envelope(&sequence),
            Err(Error::Handshake)
        ));

        let mut padded = response_frame();
        padded.header.flags = crate::header::Flags::PADDING;
        padded.header.pad_length = 1;
        padded.padding.push(0);
        assert!(matches!(
            validate_handshake_response_envelope(&padded),
            Err(Error::Handshake)
        ));
    }
}

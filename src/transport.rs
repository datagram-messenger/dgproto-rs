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
//! Context cancellation is handled via `tokio::time::timeout` wrapping each
//! operation, matching the Go `watchContext` pattern.
//!
//! See `docs/protocol/dgproto-v1.md` §3 for the normative specification.

use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

use crate::{frame::Frame, Error, HEADER_SIZE, MAX_FRAME_SIZE};

// ── Transport trait ───────────────────────────────────────────────────────────

/// The interface between the connection runtime and the underlying byte stream.
///
/// Implementations must be `Send + Sync` so they can be shared across the
/// three connection task loops.
///
/// `async fn` in traits requires Rust 1.75+. MSRV for this crate is 1.80.
pub(crate) trait Transport: Send + Sync {
    /// Read one complete DGProto v1 frame from the stream.
    ///
    /// Blocks until the frame is available or an error occurs.
    /// A `timeout` of `Duration::ZERO` means no timeout.
    fn read_frame(
        &self,
        timeout: Duration,
    ) -> impl std::future::Future<Output = Result<Frame, Error>> + Send + '_;

    /// Write one complete DGProto v1 frame to the stream.
    ///
    /// Blocks until all bytes are written or an error occurs.
    /// A `timeout` of `Duration::ZERO` means no timeout.
    fn write_frame<'a>(
        &'a self,
        frame: &'a Frame,
        timeout: Duration,
    ) -> impl std::future::Future<Output = Result<(), Error>> + Send + 'a;

    /// Close the underlying connection.
    fn close(&self) -> impl std::future::Future<Output = Result<(), Error>> + Send + '_;
}

// ── TcpTransport ─────────────────────────────────────────────────────────────

/// Carries canonical DGProto v1 frames directly over a TCP stream.
///
/// Frames have no transport length prefix. One read and one write may proceed
/// concurrently; reads are serialized with reads and writes with writes.
pub(crate) struct TcpTransport {
    /// Read half — guarded so reads are serialized.
    read: Mutex<tokio::net::tcp::OwnedReadHalf>,
    /// Write half — guarded so writes are serialized.
    write: Mutex<tokio::net::tcp::OwnedWriteHalf>,
}

impl TcpTransport {
    /// Wrap a `TcpStream`. The stream is split into independent read/write halves.
    pub(crate) fn new(stream: TcpStream) -> Self {
        let (read, write) = stream.into_split();
        Self {
            read: Mutex::new(read),
            write: Mutex::new(write),
        }
    }
}

impl Transport for TcpTransport {
    async fn read_frame(&self, timeout: Duration) -> Result<Frame, Error> {
        let fut = async {
            let mut read = self.read.lock().await;

            // Read the fixed 40-byte header.
            let mut header_wire = [0u8; HEADER_SIZE];
            read.read_exact(&mut header_wire)
                .await
                .map_err(map_io_err)?;

            // Parse the header to determine body length.
            let header = crate::header::Header::unmarshal_binary(&header_wire)?;
            let frame_size_u64 = header.frame_size();

            if frame_size_u64 < HEADER_SIZE as u64 {
                return Err(Error::TransportFrameTooShort);
            }
            if frame_size_u64 > MAX_FRAME_SIZE as u64 {
                return Err(Error::TransportFrameTooLarge);
            }
            let frame_size = frame_size_u64 as usize;

            // Read the body (payload + tag + padding).
            let body_len = frame_size - HEADER_SIZE;
            let mut wire = vec![0u8; frame_size];
            wire[..HEADER_SIZE].copy_from_slice(&header_wire);
            if body_len > 0 {
                read.read_exact(&mut wire[HEADER_SIZE..])
                    .await
                    .map_err(map_io_err)?;
            }

            Frame::unmarshal_binary(&wire)
        };

        if timeout.is_zero() {
            fut.await
        } else {
            tokio::time::timeout(timeout, fut).await.map_err(|_| {
                Error::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "read_frame timed out",
                ))
            })?
        }
    }

    async fn write_frame<'a>(&'a self, frame: &'a Frame, timeout: Duration) -> Result<(), Error> {
        let wire = frame.marshal_binary()?;

        if wire.len() < HEADER_SIZE {
            return Err(Error::TransportFrameTooShort);
        }
        if wire.len() > MAX_FRAME_SIZE {
            return Err(Error::TransportFrameTooLarge);
        }

        let fut = async {
            let mut write = self.write.lock().await;
            write.write_all(&wire).await.map_err(map_io_err)
        };

        if timeout.is_zero() {
            fut.await
        } else {
            tokio::time::timeout(timeout, fut).await.map_err(|_| {
                Error::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "write_frame timed out",
                ))
            })?
        }
    }

    async fn close(&self) -> Result<(), Error> {
        let mut write = self.write.lock().await;
        write.shutdown().await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotConnected
                || e.kind() == std::io::ErrorKind::BrokenPipe
            {
                Error::TransportClosed
            } else {
                Error::Io(e)
            }
        })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn map_io_err(e: std::io::Error) -> Error {
    match e.kind() {
        std::io::ErrorKind::UnexpectedEof
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::BrokenPipe => Error::TransportClosed,
        _ => Error::Io(e),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        frame::Frame,
        header::{Header, MessageType},
    };
    use tokio::net::TcpListener;

    /// Build a minimal handshake frame (no AEAD tag) for transport tests.
    fn make_handshake_frame() -> Frame {
        let header = Header::new(MessageType::HandshakeInit, [0u8; 16], 0, 36, 0);
        Frame {
            header,
            payload: vec![0u8; 36],
            tag: [0u8; 16],
            padding: vec![],
        }
    }

    #[tokio::test]
    async fn test_transport_write_read_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let frame_to_send = make_handshake_frame();
        let frame_clone = frame_to_send.clone();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let transport = TcpTransport::new(stream);
            transport
                .read_frame(Duration::ZERO)
                .await
                .expect("server read_frame")
        });

        let client_stream = TcpStream::connect(addr).await.expect("connect");
        let client = TcpTransport::new(client_stream);
        client
            .write_frame(&frame_clone, Duration::ZERO)
            .await
            .expect("write_frame");

        let received = server.await.expect("server task");
        assert_eq!(received.header.msg_type, frame_to_send.header.msg_type);
        assert_eq!(received.payload, frame_to_send.payload);
    }

    #[tokio::test]
    async fn test_transport_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let transport = TcpTransport::new(stream);
            // Close immediately — client should get TransportClosed on read.
            transport.close().await.expect("close");
        });

        let client_stream = TcpStream::connect(addr).await.expect("connect");
        let client = TcpTransport::new(client_stream);
        server.await.expect("server task");

        // After server closes, reading should fail.
        let err = client
            .read_frame(Duration::ZERO)
            .await
            .expect_err("should fail");
        assert!(
            matches!(err, Error::TransportClosed | Error::Io(_)),
            "unexpected error: {err:?}"
        );
    }
}

//! Complete DGProto client lifecycle example.
//!
//! Usage:
//! `cargo run --example client -- <addr> <identity-key-file> <server-static-key-hex>`
//!
//! The identity file contains the client's raw 32-byte Noise private key. On the
//! first run this example creates it; protect it with an OS credential store or
//! restrictive filesystem permissions. The server key must be provisioned over
//! a trusted channel and is always verified during the Noise XX handshake.

use std::{
    env, fs, io,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use dgproto::{
    handler_fn, ApplicationMessage, ClientConfig, Connection, EncryptedData, StaticKey, Tlv,
};
use tokio::sync::oneshot;

const OPERATION_TIMEOUT: Duration = Duration::from_secs(10);
const ECHO_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let addr = args.next().ok_or_else(|| usage("missing server address"))?;
    let key_path = args
        .next()
        .ok_or_else(|| usage("missing identity key file"))?;
    let server_key_hex = args
        .next()
        .ok_or_else(|| usage("missing server static public key"))?;
    if args.next().is_some() {
        return Err(usage("too many arguments").into());
    }

    let static_key = load_or_generate_key(Path::new(&key_path))?;
    let server_static_hint = decode_key(&server_key_hex)?;
    let (echo_tx, echo_rx) = oneshot::channel();
    let echo_tx = Arc::new(Mutex::new(Some(echo_tx)));

    let handler = handler_fn(move |_connection, message| {
        let echo_tx = Arc::clone(&echo_tx);
        async move {
            if let ApplicationMessage::EncryptedData(data) = message {
                if let Some(tx) = echo_tx.lock().expect("echo sender mutex").take() {
                    let _ = tx.send(data);
                }
            }
            Ok(())
        }
    });

    let config = ClientConfig {
        static_key,
        server_static_hint: Some(server_static_hint),
        handler: Some(handler),
        ..Default::default()
    };

    let connection = tokio::time::timeout(OPERATION_TIMEOUT, Connection::connect(&addr, config))
        .await
        .map_err(|_| timed_out("connect"))??;

    let message = EncryptedData {
        stream_id: 1,
        app_message_type: 1,
        fields: vec![Tlv::new(1, b"hello DGProto")],
    };
    tokio::time::timeout(OPERATION_TIMEOUT, connection.send_and_wait(message))
        .await
        .map_err(|_| timed_out("send"))??;

    let echo = tokio::time::timeout(ECHO_TIMEOUT, echo_rx)
        .await
        .map_err(|_| timed_out("echo"))?
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed before echo"))?;
    println!(
        "received echo: stream={} type={} fields={}",
        echo.stream_id,
        echo.app_message_type,
        echo.fields.len()
    );

    match tokio::time::timeout(OPERATION_TIMEOUT, connection.close()).await {
        Ok(result) => result?,
        Err(_) => {
            connection.abort();
            let _ = tokio::time::timeout(OPERATION_TIMEOUT, connection.wait_for_close()).await;
            return Err(timed_out("graceful close").into());
        }
    }

    Ok(())
}

fn load_or_generate_key(path: &Path) -> Result<StaticKey, Box<dyn std::error::Error>> {
    match fs::read(path) {
        Ok(bytes) => Ok(StaticKey::load(&bytes)?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let key = StaticKey::generate()?;
            let private = key.to_private_bytes();
            write_new_private_key(path, private.as_ref())?;
            eprintln!(
                "created client identity; register public key {}",
                key.public_hex()
            );
            Ok(key)
        }
        Err(error) => Err(error.into()),
    }
}

fn write_new_private_key(path: &Path, private: &[u8]) -> io::Result<()> {
    use std::io::Write;

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(private)?;
    file.sync_all()
}

fn decode_key(hex: &str) -> Result<[u8; 32], io::Error> {
    if hex.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "server static key must be 64 hexadecimal characters",
        ));
    }
    let mut key = [0u8; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&hex[offset..offset + 2], 16).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "server static key contains non-hexadecimal characters",
            )
        })?;
    }
    Ok(key)
}

fn timed_out(operation: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("timed out during {operation}"),
    )
}

fn usage(reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{reason}; usage: client <addr> <identity-key-file> <server-static-key-hex>"),
    )
}

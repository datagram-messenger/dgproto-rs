//! Complete DGProto client lifecycle example.
//!
//! Usage:
//! `cargo run --example client -- <addr> <identity-key-file> <server-static-key-hex>`
//!
//! The identity file contains the client's raw 32-byte Noise private key. On Unix,
//! the first run creates it with mode `0o600`. On Windows, automatic creation is
//! disabled: provision a protected, exactly 32-byte file or use an OS credential
//! store. Existing files are loaded but their ACLs are not checked. The server key
//! must be provisioned over a trusted channel and is always verified during the
//! Noise XX handshake.

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
        #[cfg(windows)]
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "identity key file not found; on Windows, provision a protected exactly 32-byte key file or use an OS credential store",
        )
        .into()),
        #[cfg(unix)]
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let key = StaticKey::generate()?;
            let private = key.to_private_bytes();
            write_new_private_key(path, private.as_ref())?;
            eprintln!(
                "created client identity with mode 0600; register public key {}",
                key.public_hex()
            );
            Ok(key)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn write_new_private_key(path: &Path, private: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
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
        format!(
            "{reason}; usage: client <addr> <identity-key-file> <server-static-key-hex> (Windows requires a pre-provisioned protected 32-byte identity file)"
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn test_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_nanos();
        env::temp_dir().join(format!(
            "dgproto-client-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn existing_key_must_be_exactly_32_bytes() {
        let path = test_path("invalid-key");
        fs::write(&path, [0u8; 31]).expect("write test key");

        let result = load_or_generate_key(&path);

        fs::remove_file(path).expect("remove test key");
        assert!(result.is_err());
    }

    #[test]
    fn existing_32_byte_key_is_loaded() {
        let path = test_path("existing-key");
        let expected = [7u8; 32];
        fs::write(&path, expected).expect("write test key");

        let key = load_or_generate_key(&path).expect("load existing key");

        fs::remove_file(path).expect("remove test key");
        assert_eq!(key.to_private_bytes().as_ref(), &expected);
    }

    #[cfg(windows)]
    #[test]
    fn missing_key_is_not_persisted_on_windows() {
        let path = test_path("missing-key");

        let error = load_or_generate_key(&path).expect_err("missing key must fail");

        assert!(error
            .to_string()
            .contains("provision a protected exactly 32-byte key file"));
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn missing_key_is_created_once_with_owner_only_mode_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let path = test_path("new-key");
        let generated = load_or_generate_key(&path).expect("generate key");
        let metadata = fs::metadata(&path).expect("read key metadata");
        let loaded = load_or_generate_key(&path).expect("reload key");

        fs::remove_file(path).expect("remove test key");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(loaded.to_private_bytes(), generated.to_private_bytes());
    }
}

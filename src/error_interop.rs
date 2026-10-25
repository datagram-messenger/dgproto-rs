//! Opt-in real Go/Rust encrypted Session loopback with synthetic secrets.
//! This checks session/frame/message interoperability, not Noise establishment.
use std::time::Duration;

use crate::{
    handshake::HandshakeSecrets,
    header::MessageType,
    messages::{CloseCode, ErrorMessage, PingPong, SessionClose},
    session::{EncryptResult, Session},
    transport::{TcpTransport, Transport},
};

#[tokio::test]
#[ignore = "set DGPROTO_ERROR_INTEROP_ADDR to the running Go test peer"]
async fn go_rust_error_session_interop() {
    let addr = std::env::var("DGPROTO_ERROR_INTEROP_ADDR").expect("Go peer address");
    assert!(addr.starts_with("127.0.0.1:"), "loopback only");
    tokio::time::timeout(Duration::from_secs(15), async {
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let transport = TcpTransport::new(stream);
        let session = Session::new(HandshakeSecrets {
            session_id: [1; 16],
            send_key: [3; 32],
            receive_key: [2; 32],
            peer_static: [0; 32],
        })
        .unwrap();
        let wait = Duration::from_secs(5);
        for (code, text) in [(3, "hi"), (255, "Ошибка")] {
            let frame = transport.read_frame(wait).await.unwrap();
            assert_eq!(frame.header.msg_type, MessageType::Error);
            let payload = session.decrypt_frame(&frame).await.unwrap();
            let value = ErrorMessage::unmarshal_binary(&payload).unwrap();
            assert_eq!(value.code, code);
            assert_eq!(value.reason, text);
            let wire = ErrorMessage {
                code,
                reason: text.into(),
            }
            .marshal_binary()
            .unwrap();
            match session
                .encrypt_frame(MessageType::Error, &wire, 5)
                .await
                .unwrap()
            {
                EncryptResult::Frame(reply) => transport.write_frame(&reply, wait).await.unwrap(),
                EncryptResult::NeedsRekey(_) => panic!("unexpected early rekey"),
            }
        }
        let frame = transport.read_frame(wait).await.unwrap();
        let payload = session.decrypt_frame(&frame).await.unwrap();
        let ping = PingPong::unmarshal_binary(&payload).unwrap();
        assert_eq!(ping.nonce, 42);
        assert!(!ping.is_response);
        let wire = PingPong {
            is_response: true,
            nonce: 42,
        }
        .marshal_binary()
        .unwrap();
        if let EncryptResult::Frame(reply) = session
            .encrypt_frame(MessageType::PingPong, &wire, 0)
            .await
            .unwrap()
        {
            transport.write_frame(&reply, wait).await.unwrap();
        } else {
            panic!("unexpected early rekey");
        }
        let frame = transport.read_frame(wait).await.unwrap();
        let payload = session.decrypt_frame(&frame).await.unwrap();
        assert_eq!(payload, b"\x03\x00\x01\x02\x00hi\x00\x00\x00");
        let close = SessionClose::unmarshal_binary(&payload).unwrap();
        assert_eq!(close.code, CloseCode::ResourceLimit);
        assert_eq!(close.reason, "hi");
        if let EncryptResult::Frame(reply) = session
            .encrypt_frame(
                MessageType::SessionClose,
                &close.marshal_binary().unwrap(),
                0,
            )
            .await
            .unwrap()
        {
            transport.write_frame(&reply, wait).await.unwrap();
        } else {
            panic!("unexpected early rekey");
        }
        session.close().await;
    })
    .await
    .expect("bounded Go/Rust session interop");
}

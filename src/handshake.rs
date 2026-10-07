//! Three-flight Noise XX **initiator** handshake state machine.
//!
//! This module implements only the client (initiator) role. The server
//! (responder) role is not implemented and must not be added.
//!
//! # Noise suite
//!
//! `Noise_XX_25519_ChaChaPoly_SHA256`
//!
//! # Prologue
//!
//! `b"DGPv1"` (5 bytes). Both sides must use the same prologue.
//!
//! # Flight order (client perspective)
//!
//! 1. **Send** `HandshakeInit` (type 0x01):
//!    4-byte reserved prefix + 32-byte ephemeral public key = 36 bytes.
//!    Noise message 1.
//!
//! 2. **Receive** `HandshakeResponse` (type 0x02):
//!    32-byte server ephemeral prefix + 64 Noise bytes = 96 bytes.
//!    Noise message 2.
//!
//! 3. **Send** `HandshakeFinish` (type 0x03, zero session ID):
//!    64-byte Noise message 3.
//!
//! # Session ID derivation
//!
//! After `HandshakeFinish`:
//! ```text
//! session_id = SHA-256(b"DGPv1 SessionID" || handshake_hash)[:16]
//! ```
//! where `handshake_hash` is the 32-byte Noise channel binding from
//! `snow`'s `get_handshake_hash()`.
//!
//! # Directional keys
//!
//! Keys are extracted from `HandshakeState::get_ciphers()` BEFORE calling
//! `into_transport_mode()`:
//! - Initiator send key    = first  cipher output
//! - Initiator receive key = second cipher output
//!
//! See `docs/protocol/dgproto-v1.md` §4.2 for the normative specification.

use sha2::{Digest, Sha256};
use snow::Builder;
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

use crate::{
    messages::{HandshakeFinish, HandshakeInit, HandshakeResponse},
    Error, KEY_SIZE,
};

/// Noise XX pattern string for `snow`.
const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

/// Prologue bytes — both sides must use the same value.
const PROLOGUE: &[u8] = b"DGPv1";

/// Session ID derivation label.
const SESSION_ID_LABEL: &[u8] = b"DGPv1 SessionID";

// ── StaticKey ─────────────────────────────────────────────────────────────────

/// An X25519 Noise static identity key pair.
///
/// The private key is zeroed on drop.
#[derive(ZeroizeOnDrop, Clone)]
pub struct StaticKey {
    private: [u8; 32],
    public: [u8; 32],
}

impl StaticKey {
    /// Generate a new random X25519 static key pair.
    pub fn generate() -> Result<Self, Error> {
        let builder = Builder::new(NOISE_PARAMS.parse().map_err(|_| Error::Handshake)?)
            .prologue(PROLOGUE)
            .generate_keypair()
            .map_err(|_| Error::Handshake)
            .and_then(Self::from_snow_keypair)?;
        Ok(builder)
    }

    /// Load a static key from 32 raw private key bytes and derive the public key.
    ///
    /// Returns `Err(Error::Handshake)` if `private_bytes` is not exactly 32 bytes.
    pub fn load(private_bytes: &[u8]) -> Result<Self, Error> {
        if private_bytes.len() != 32 {
            return Err(Error::Handshake);
        }
        // Derive the X25519 public key from the private key bytes.
        // snow's generate_keypair() generates a random key, not from our private bytes.
        // We use snow's Builder with local_private_key to build an initiator,
        // then use generate_keypair on a fresh builder to get the public key.
        // Actually the correct approach: snow stores the static keypair when
        // local_private_key is set. We can retrieve it via generate_keypair
        // on a builder that has local_private_key set — but snow's generate_keypair
        // ignores the local_private_key and generates a fresh random keypair.
        //
        // The real solution: use snow's Builder::local_private_key, build the
        // initiator, then call generate_keypair on a SEPARATE builder to get
        // the public key from the private key. But snow doesn't expose this.
        //
        // Correct approach: use the Keypair struct with manually computed public key.
        // X25519 public key derivation: multiply the base point by the clamped scalar.
        // We do this using the curve25519-dalek crate (already a transitive dep via snow).
        let public_bytes = derive_x25519_public(private_bytes);
        let kp = snow::Keypair {
            private: private_bytes.to_vec(),
            public: public_bytes,
        };
        Self::from_snow_keypair(kp)
    }

    fn from_snow_keypair(kp: snow::Keypair) -> Result<Self, Error> {
        if kp.private.len() != 32 || kp.public.len() != 32 {
            return Err(Error::Handshake);
        }
        let mut private = [0u8; 32];
        let mut public = [0u8; 32];
        private.copy_from_slice(&kp.private);
        public.copy_from_slice(&kp.public);
        Ok(Self { private, public })
    }

    /// Return the 32-byte X25519 public key.
    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }

    /// Return the private key bytes (used internally by `InitiatorHandshake`).
    ///
    /// Intentionally module-private: the private key must never leave this module.
    fn private(&self) -> &[u8; 32] {
        &self.private
    }
}

impl std::fmt::Debug for StaticKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut hex_buf = [0u8; 64];
        const HEX: &[u8] = b"0123456789abcdef";
        for (i, &b) in self.public.iter().enumerate() {
            hex_buf[i * 2] = HEX[(b >> 4) as usize];
            hex_buf[i * 2 + 1] = HEX[(b & 0xf) as usize];
        }
        let hex_str = std::str::from_utf8(&hex_buf).unwrap_or("?");
        f.debug_struct("StaticKey")
            .field("public", &hex_str)
            .finish_non_exhaustive()
    }
}

// ── HandshakeSecrets ──────────────────────────────────────────────────────────

/// Secrets produced by a completed Noise XX handshake.
///
/// Zeroed on drop.
#[derive(ZeroizeOnDrop)]
pub(crate) struct HandshakeSecrets {
    pub session_id: [u8; 16],
    pub send_key: [u8; KEY_SIZE],
    pub receive_key: [u8; KEY_SIZE],
    pub peer_static: [u8; 32],
}

// ── InitiatorHandshake ────────────────────────────────────────────────────────

/// Initiator-only three-flight Noise XX state machine.
///
/// Drive in order: `write_init` → `read_response` → `write_finish`.
/// Any out-of-order call returns `Err(Error::Handshake)`.
pub(crate) struct InitiatorHandshake {
    inner: Option<snow::HandshakeState>,
    step: HandshakeStep,
    expected_peer: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakeStep {
    WriteInit,
    ReadResponse,
    WriteFinish,
    Complete,
    Failed,
}

impl InitiatorHandshake {
    /// Create a new initiator handshake state.
    ///
    /// `expected_peer_static` is an optional 32-byte server static public key.
    /// If provided, the handshake will fail if the server presents a different key.
    pub(crate) fn new(
        static_key: &StaticKey,
        expected_peer_static: Option<&[u8; 32]>,
    ) -> Result<Self, Error> {
        let mut builder = Builder::new(NOISE_PARAMS.parse().map_err(|_| Error::Handshake)?)
            .prologue(PROLOGUE)
            .local_private_key(static_key.private());

        if let Some(peer) = expected_peer_static {
            builder = builder.remote_public_key(peer.as_slice());
        }

        let inner = builder.build_initiator().map_err(|_| Error::Handshake)?;

        Ok(Self {
            inner: Some(inner),
            step: HandshakeStep::WriteInit,
            expected_peer: expected_peer_static.copied(),
        })
    }

    /// **Flight 1**: produce the `HandshakeInit` frame payload bytes.
    ///
    /// Returns the 36-byte wire payload for a `HandshakeInit` frame.
    pub(crate) fn write_init(&mut self) -> Result<Vec<u8>, Error> {
        if self.step != HandshakeStep::WriteInit {
            return Err(self.fail());
        }
        let inner = self.inner.as_mut().ok_or(Error::Handshake)?;

        let mut noise_msg = vec![0u8; 64]; // Noise message 1 is 32 bytes (ephemeral)
        let n = match inner.write_message(&[], &mut noise_msg) {
            Ok(n) => n,
            Err(_) => {
                self.step = HandshakeStep::Failed;
                self.inner = None;
                return Err(Error::Handshake);
            }
        };
        let noise_msg = &noise_msg[..n];

        if noise_msg.len() != 32 {
            return Err(self.fail());
        }

        let mut ephemeral = [0u8; 32];
        ephemeral.copy_from_slice(noise_msg);

        let init = HandshakeInit {
            client_ephemeral: ephemeral,
            noise_payload: vec![],
        };
        let wire = match init.marshal_binary() {
            Ok(w) => w,
            Err(_) => {
                self.step = HandshakeStep::Failed;
                self.inner = None;
                return Err(Error::Handshake);
            }
        };

        self.step = HandshakeStep::ReadResponse;
        Ok(wire)
    }

    /// **Flight 2**: consume the `HandshakeResponse` frame payload bytes.
    pub(crate) fn read_response(&mut self, payload: &[u8]) -> Result<(), Error> {
        if self.step != HandshakeStep::ReadResponse {
            return Err(self.fail());
        }
        let inner = self.inner.as_mut().ok_or(Error::Handshake)?;

        let resp = match HandshakeResponse::unmarshal_binary(payload) {
            Ok(r) => r,
            Err(_) => {
                self.step = HandshakeStep::Failed;
                self.inner = None;
                return Err(Error::Handshake);
            }
        };
        if resp.noise_payload.len() != 64 {
            return Err(self.fail());
        }

        // Reconstruct the 96-byte Noise message 2: server_ephemeral || noise_payload
        let mut noise_msg = Vec::with_capacity(96);
        noise_msg.extend_from_slice(&resp.server_ephemeral);
        noise_msg.extend_from_slice(&resp.noise_payload);

        let mut buf = vec![0u8; 128];
        match inner.read_message(&noise_msg, &mut buf) {
            Ok(_) => {}
            Err(_) => {
                self.step = HandshakeStep::Failed;
                self.inner = None;
                return Err(Error::Handshake);
            }
        }

        self.step = HandshakeStep::WriteFinish;
        Ok(())
    }

    /// **Flight 3**: produce the `HandshakeFinish` frame payload bytes and
    /// return the completed `HandshakeSecrets`.
    pub(crate) fn write_finish(&mut self) -> Result<(Vec<u8>, HandshakeSecrets), Error> {
        if self.step != HandshakeStep::WriteFinish {
            return Err(self.fail());
        }
        let inner = self.inner.as_mut().ok_or(Error::Handshake)?;

        let mut noise_msg = vec![0u8; 128]; // Noise message 3 is 64 bytes
        let n = match inner.write_message(&[], &mut noise_msg) {
            Ok(n) => n,
            Err(_) => {
                self.step = HandshakeStep::Failed;
                self.inner = None;
                return Err(Error::Handshake);
            }
        };
        let noise_msg = &noise_msg[..n];

        if noise_msg.len() != 64 {
            return Err(self.fail());
        }

        let finish = HandshakeFinish {
            noise_payload: noise_msg.to_vec(),
        };
        let wire = match finish.marshal_binary() {
            Ok(w) => w,
            Err(_) => {
                self.step = HandshakeStep::Failed;
                self.inner = None;
                return Err(Error::Handshake);
            }
        };

        // Extract channel binding (handshake hash) before extracting keys.
        let channel_binding = inner.get_handshake_hash().to_vec();

        // Verify peer static key if expected.
        let peer_static_slice = match inner.get_remote_static() {
            Some(s) => s,
            None => {
                self.step = HandshakeStep::Failed;
                self.inner = None;
                return Err(Error::Handshake);
            }
        };
        if peer_static_slice.len() != 32 {
            return Err(self.fail());
        }
        let mut peer_static = [0u8; 32];
        peer_static.copy_from_slice(peer_static_slice);

        if let Some(expected) = &self.expected_peer {
            if expected.ct_eq(&peer_static).unwrap_u8() != 1 {
                return Err(self.fail());
            }
        }

        // Extract keys from HandshakeState BEFORE into_transport_mode().
        // dangerously_get_raw_split() returns (send_key, recv_key) for initiator.
        let (send_key_arr, recv_key_arr) = inner.dangerously_get_raw_split();

        let mut send_key = [0u8; KEY_SIZE];
        let mut receive_key = [0u8; KEY_SIZE];
        send_key.copy_from_slice(&send_key_arr);
        receive_key.copy_from_slice(&recv_key_arr);

        let session_id = derive_session_id(&channel_binding);

        self.step = HandshakeStep::Complete;
        self.inner = None;

        Ok((
            wire,
            HandshakeSecrets {
                session_id,
                send_key,
                receive_key,
                peer_static,
            },
        ))
    }

    fn fail(&mut self) -> Error {
        self.step = HandshakeStep::Failed;
        self.inner = None;
        Error::Handshake
    }
}

/// Derive the X25519 public key from a 32-byte private key.
///
/// Uses the same clamping and scalar multiplication as the X25519 function.
/// curve25519-dalek is a transitive dependency via snow's default-resolver.
fn derive_x25519_public(private_bytes: &[u8]) -> Vec<u8> {
    use curve25519_dalek::montgomery::MontgomeryPoint;
    use curve25519_dalek::scalar::Scalar;
    let mut clamped = [0u8; 32];
    clamped.copy_from_slice(private_bytes);
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    let scalar = Scalar::from_bytes_mod_order(clamped);
    let public = MontgomeryPoint::mul_base(&scalar);
    public.to_bytes().to_vec()
}

/// Derive the 16-byte session ID from the Noise channel binding.
///
/// `session_id = SHA-256(b"DGPv1 SessionID" || channel_binding)[:16]`
fn derive_session_id(channel_binding: &[u8]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_ID_LABEL);
    hasher.update(channel_binding);
    let hash = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&hash[..16]);
    id
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_static_key_generate() {
        let key = StaticKey::generate().expect("generate");
        // Public key must be non-zero.
        assert_ne!(key.public(), &[0u8; 32]);
        // Private key must be non-zero.
        assert_ne!(key.private(), &[0u8; 32]);
    }

    #[test]
    fn test_handshake_static_key_load_roundtrip() {
        let key = StaticKey::generate().expect("generate");
        let loaded = StaticKey::load(key.private()).expect("load");
        assert_eq!(key.public(), loaded.public());
    }

    #[test]
    fn test_handshake_static_key_load_wrong_length() {
        assert!(matches!(StaticKey::load(&[0u8; 16]), Err(Error::Handshake)));
    }

    #[test]
    fn test_handshake_state_new() {
        let key = StaticKey::generate().expect("generate");
        let hs = InitiatorHandshake::new(&key, None);
        assert!(hs.is_ok());
    }

    #[test]
    fn test_handshake_write_init_produces_36_bytes() {
        let key = StaticKey::generate().expect("generate");
        let mut hs = InitiatorHandshake::new(&key, None).expect("new");
        let wire = hs.write_init().expect("write_init");
        assert_eq!(wire.len(), 36);
    }

    #[test]
    fn test_handshake_out_of_order_read_response_before_write_init() {
        let key = StaticKey::generate().expect("generate");
        let mut hs = InitiatorHandshake::new(&key, None).expect("new");
        // Skip write_init — read_response should fail.
        assert!(matches!(
            hs.read_response(&[0u8; 96]),
            Err(Error::Handshake)
        ));
    }

    #[test]
    fn test_handshake_full_xx_loopback() {
        // Build initiator and responder using snow directly.
        let init_key = StaticKey::generate().expect("init key");
        let resp_key = StaticKey::generate().expect("resp key");

        let mut initiator = InitiatorHandshake::new(&init_key, None).expect("initiator");

        // Build a snow responder for the loopback.
        let mut resp_inner = snow::Builder::new(NOISE_PARAMS.parse().expect("params"))
            .prologue(PROLOGUE)
            .local_private_key(resp_key.private())
            .build_responder()
            .expect("responder");

        // Flight 1: initiator → responder
        let init_wire = initiator.write_init().expect("write_init");
        let init_msg = HandshakeInit::unmarshal_binary(&init_wire).expect("parse init");
        let mut buf = vec![0u8; 128];
        let n = resp_inner
            .read_message(&init_msg.client_ephemeral, &mut buf)
            .expect("resp read 1");
        let _ = &buf[..n];

        // Flight 2: responder → initiator
        let mut resp_msg = vec![0u8; 128];
        let n = resp_inner
            .write_message(&[], &mut resp_msg)
            .expect("resp write 2");
        let resp_noise = &resp_msg[..n]; // 96 bytes
        assert_eq!(resp_noise.len(), 96);
        let mut server_ephemeral = [0u8; 32];
        server_ephemeral.copy_from_slice(&resp_noise[..32]);
        let resp_payload = HandshakeResponse {
            server_ephemeral,
            noise_payload: resp_noise[32..].to_vec(),
        };
        let resp_wire = resp_payload.marshal_binary().expect("marshal resp");
        initiator.read_response(&resp_wire).expect("read_response");

        // Flight 3: initiator → responder
        let (finish_wire, secrets) = initiator.write_finish().expect("write_finish");
        let finish_msg = HandshakeFinish::unmarshal_binary(&finish_wire).expect("parse finish");
        let mut buf2 = vec![0u8; 128];
        resp_inner
            .read_message(&finish_msg.noise_payload, &mut buf2)
            .expect("resp read 3");

        // Session ID must be non-zero.
        assert_ne!(secrets.session_id, [0u8; 16]);
        // Keys must be non-zero.
        assert_ne!(secrets.send_key, [0u8; KEY_SIZE]);
        assert_ne!(secrets.receive_key, [0u8; KEY_SIZE]);
        // Peer static must match the responder's public key.
        assert_eq!(&secrets.peer_static, resp_key.public());
    }

    #[test]
    fn test_derive_session_id_deterministic() {
        let binding = [0xABu8; 32];
        let id1 = derive_session_id(&binding);
        let id2 = derive_session_id(&binding);
        assert_eq!(id1, id2);
        assert_ne!(id1, [0u8; 16]);
    }
}

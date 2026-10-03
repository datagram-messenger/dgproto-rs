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
//! After `into_transport_mode()`:
//! - Initiator send key    = first  Split output
//! - Initiator receive key = second Split output
//!
//! See `docs/protocol/dgproto-v1.md` §4.2 for the normative specification.

use zeroize::ZeroizeOnDrop;

/// An X25519 Noise static identity key pair.
///
/// The private key is zeroed on drop.
#[derive(ZeroizeOnDrop)]
pub struct StaticKey {
    private: [u8; 32],
    public:  [u8; 32],
}

impl StaticKey {
    /// Generate a new random X25519 static key pair.
    pub fn generate() -> Result<Self, crate::Error> {
        // TODO: implement using snow's DH25519.generate_keypair(rand::thread_rng())
        todo!("StaticKey::generate")
    }

    /// Load a static key from 32 raw private key bytes and derive the public key.
    pub fn load(private_bytes: &[u8]) -> Result<Self, crate::Error> {
        // TODO: implement using snow's DH25519.generate_keypair(fixed_reader)
        // Reject if len != 32.
        todo!("StaticKey::load")
    }

    /// Return the 32-byte X25519 public key.
    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }
}

impl std::fmt::Debug for StaticKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticKey")
            .field("public", &hex::encode(self.public))
            .finish_non_exhaustive()
    }
}

/// Secrets produced by a completed Noise XX handshake.
///
/// Zeroed on drop.
#[derive(ZeroizeOnDrop)]
pub(crate) struct HandshakeSecrets {
    pub session_id:  [u8; 16],
    pub send_key:    [u8; 32],
    pub receive_key: [u8; 32],
}

// TODO: implement HandshakeState (initiator state machine):
//   - new(static_key) -> HandshakeState
//   - write_init()    -> Frame  (flight 1)
//   - read_response(frame) -> Result<()>  (flight 2)
//   - write_finish()  -> Result<(Frame, HandshakeSecrets)>  (flight 3)
// Reference: dgproto-go/handshake.go

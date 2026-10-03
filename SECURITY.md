# Security policy

## Reporting a vulnerability

Do not open a public issue. Report suspected vulnerabilities through the private
[GitHub security advisory form](https://github.com/datagram-messenger/dgproto-rs/security/advisories/new),
including affected versions, impact, and reproduction details.

Security fixes target supported tagged releases and the current default branch.
Identify both the crate release and protocol draft version when reporting
wire-level behavior.

## Authentication and authorization

A successful Noise XX handshake authenticates possession of a static key; it
does not grant application permissions. The server counterpart
([`dgproto-go`](https://github.com/datagram-messenger/dgproto-go)) is
responsible for admission control and authorization policy via
`ServerConfig.AllowedClients` and `ServerConfig.Admission`.

Applications remain responsible for key provisioning and rotation, secret
storage, dependency updates, endpoint hardening, and padding policy.
DGProto v1 permits ChaCha20-Poly1305 only; AES-GCM is not protocol compliant.

## Key material

Never log, commit, or share static private keys. Use `StaticKey::generate()`
to produce ephemeral keys for tests. Store production private key bytes in a
secure secret store outside the repository.

The `zeroize` crate is used throughout to zero key material on drop. Do not
remove `#[zeroize(drop)]` annotations or bypass `ZeroizeOnDrop` derives.

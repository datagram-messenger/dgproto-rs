# DGProto test vectors

The JSON files in this directory are immutable interoperability fixtures containing deterministic wire inputs and expected outputs.

## Validation levels

Frame-level validation checks bytes, lengths, flags, type, epoch/sequence, payload, padding, tag, and parser rejection. Semantic validation additionally checks protocol state: handshake order, transcript/key agreement, epoch transition, replay acceptance, and message meaning.

A frame that parses is not automatically a semantically valid handshake. Handshake tests must apply the Noise state machine and transcript rules in addition to registry/parser checks.

## Post-MVP coverage

The registry/parser may recognize post-MVP or reserved identifiers so implementations can reject or route them deterministically. Recognition does not mean that the strict v1 MVP runtime implements those semantics. Each vector records its intended coverage; normative MVP behavior remains defined by [the protocol specification](../../docs/protocol/dgproto-v1.md).

When adding vectors, identify the validation level, keep inputs deterministic, and update corresponding tests. Do not regenerate unrelated fixtures.

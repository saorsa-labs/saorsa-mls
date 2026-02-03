# Saorsa MLS

[![Crates.io](https://img.shields.io/crates/v/saorsa-mls.svg)](https://crates.io/crates/saorsa-mls)
[![Documentation](https://docs.rs/saorsa-mls/badge.svg)](https://docs.rs/saorsa-mls)
[![Tests](https://github.com/dirvine/saorsa-mls/actions/workflows/test.yml/badge.svg)](https://github.com/dirvine/saorsa-mls/actions/workflows/test.yml)

Experimental implementation of the Message Layer Security (MLS) Protocol ([RFC 9420](https://datatracker.ietf.org/doc/rfc9420/)) with post-quantum cryptography enhancements for P2P secure group communication.

## Status and scope

This crate implements core concepts from [RFC 9420 (The Messaging Layer Security Protocol)](https://datatracker.ietf.org/doc/rfc9420/) while replacing classical cryptographic primitives with post-quantum alternatives. It provides RFC 9420-compatible protocol flow and semantics, but uses quantum-resistant algorithms (ML-KEM and ML-DSA) instead of traditional elliptic curve cryptography.

Do not use this crate to protect sensitive data in production systems.

## Features

- **RFC 9420 Protocol Flow**: Implements MLS protocol semantics and message flow
- **Post-Quantum Cryptography**: Uses NIST-standardized ML-KEM (Kyber) and ML-DSA (Dilithium) algorithms
- **Group Management**: Create, join, and manage secure group communication per RFC 9420
- **Forward Secrecy**: Cryptographic forward secrecy through epoch-based key rotation
- **Post-Compromise Security**: Automatic recovery from member key compromise
- **TreeKEM**: RFC 9420-compliant tree-based group key agreement with PQC
- **Asynchronous Architecture**: Built on Tokio for high-performance async operations
- **Memory Safe**: Written in Rust with secure zeroization of sensitive data

## Architecture (high-level)

The MLS implementation provides secure group messaging with the following components:

### Core Components (RFC 9420 with PQC)

- **Group Management**: RFC 9420-compliant group creation and membership operations
- **Key Derivation**: HKDF-based key schedule as specified in RFC 9420 Section 8
- **Message Encryption**: ChaCha20-Poly1305 AEAD encryption (RFC 9420 Section 5.2)
- **Signature Verification**: ML-DSA (Dilithium) signatures for quantum-resistant authentication
- **Key Agreement**: ML-KEM (Kyber) for post-quantum key encapsulation
- **TreeKEM**: RFC 9420 Section 7 tree-based group key agreement with PQC adaptations

### Security Properties (RFC 9420 Section 1.1)

- **Forward Secrecy**: Epoch-based key rotation ensures past messages remain secure (RFC 9420 Section 1.1.1)
- **Post-Compromise Security**: Automatic recovery from member key compromise through TreeKEM updates
- **Authentication**: Quantum-resistant ML-DSA signatures authenticate all group operations
- **Integrity**: AEAD encryption provides message integrity and confidentiality
- **Quantum Resistance**: ML-KEM and ML-DSA provide security against quantum computer attacks

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
saorsa-mls = "0.1.0"
```

### Basic example

```rust
use saorsa_mls::{MlsGroup, MemberIdentity, GroupConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create a new group
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate();
    let mut group = MlsGroup::new(config, creator).await?;

    // Add members to the group
    let member1 = MemberIdentity::generate();
    let member2 = MemberIdentity::generate();

    group.add_member(&member1).await?;
    group.add_member(&member2).await?;

    // Send a message to the group
    let plaintext = b"Hello, experimental MLS!";
    let encrypted = group.encrypt_message(plaintext).await?;

    // Decrypt the message
    let decrypted = group.decrypt_message(&encrypted).await?;
    assert_eq!(plaintext, &decrypted[..]);

    Ok(())
}
```

### Advanced notes

- The only available ciphersuite today is `CipherSuite::Ed25519ChaCha20Poly1305Blake3`.
- Epoch changes can be triggered with `group.update_epoch().await?;`.
- The wire format uses `postcard` serialization and is not stable across versions.

## Protocol Details (RFC 9420 with PQC)

### Cipher Suites

Post-quantum cipher suites replacing RFC 9420 Section 16.1:
- **MlKem768MlDsa65**: ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly1305 + BLAKE3 (NIST Level 3)
- **MlKem1024MlDsa87**: ML-KEM-1024 + ML-DSA-87 + ChaCha20-Poly1305 + BLAKE3 (NIST Level 5)

### Key Schedule (RFC 9420 Section 8)

- **HKDF-SHA256**: Key derivation function for epoch secrets
- **ML-KEM**: Post-quantum key encapsulation replacing ECDH
- **ML-DSA**: Post-quantum signatures replacing EdDSA
- **Labels**: RFC 9420-compliant KDF labels for all derived secrets

### Message Formats (RFC 9420 Section 6)

All messages follow RFC 9420 wire format with PQC adaptations:
- **MLSMessage**: Top-level message container (Section 6)
- **ApplicationMessage**: AEAD-encrypted group content (Section 6.3)
- **HandshakeMessage**: Group operations (Add, Remove, Update, Commit) (Section 12)
- **Welcome**: New member onboarding with encrypted group secrets (Section 12.4.3)
- **KeyPackage**: Member credentials and public keys (Section 10)

## Performance

The implementation is optimized for:
- **Low Latency**: Minimal cryptographic overhead
- **High Throughput**: Efficient batch operations
- **Memory Efficiency**: Zero-copy operations where possible
- **Async Operations**: Non-blocking I/O for network operations

## Security considerations

This crate is not yet production-ready. Important limitations include:
- Key agreement and TreeKEM are simplified; TreeKEM path secrets are placeholder logic.
- Signatures and credential handling are simplified in places; some signatures are placeholders in tests/examples.
- Nonce uniqueness previously relied on randomness; now derived from (epoch, sequence) but still lacks full MLS transcript binding.
- Secrets are now zeroized where feasible, but not all paths are audited.
- Serialization uses `postcard`; no versioning yet.

Until these are addressed, treat this crate as a prototype for experimentation only.

## Testing

Run the test suite:

```bash
cargo test
```

Run benchmarks (optional):

```bash
cargo bench
```

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to our GitHub repository.

## License

This project is dual-licensed under:
- GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
- Commercial License

For AGPL-3.0 license details, see [LICENSE-AGPL-3.0](LICENSE-AGPL-3.0).
For commercial licensing, contact: saorsalabs@gmail.com

## Security

For security issues, please contact: saorsalabs@gmail.com

Do not report security vulnerabilities through public GitHub issues.
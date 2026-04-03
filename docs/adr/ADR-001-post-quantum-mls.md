# ADR-001: Post-Quantum MLS from Day One

## Status

Accepted (2024-11)

## Context

The Messaging Layer Security protocol (RFC 9420) is designed with explicit algorithm agility — cipher suites are negotiated per group and can be swapped without protocol changes. Most existing MLS implementations default to classical cryptography (P-256/X25519 for key exchange, Ed25519 for signatures).

However, the "harvest now, decrypt later" threat is real. State-level adversaries collect encrypted traffic today expecting future quantum computers will break classical key exchange. Group messaging traffic is a high-value target because a single compromised group key reveals the entire conversation.

Saorsa Labs is building long-lived decentralised infrastructure. Messages stored in distributed systems may persist for years. Retrofitting post-quantum cryptography later requires coordinated migration of every group member to a new cipher suite.

NIST finalised its first post-quantum standards in 2024:
- **FIPS 203 — ML-KEM** (Module-Lattice Key Encapsulation, from CRYSTALS-Kyber)
- **FIPS 204 — ML-DSA** (Module-Lattice Digital Signatures, from CRYSTALS-Dilithium)

## Decision

`saorsa-mls` implements MLS using post-quantum cryptography exclusively. No classical fallback, no hybrid mode. The single supported cipher suite uses:

| Function | Algorithm | Standard | Security Level |
|----------|-----------|----------|----------------|
| Digital signatures | ML-DSA-65 | FIPS 204 | NIST Level 3 |
| Key encapsulation | ML-KEM-768 | FIPS 203 | NIST Level 3 |
| AEAD | ChaCha20-Poly1305 | RFC 8439 | 256-bit key |
| KDF | HKDF-SHA-256 | RFC 5869 | 256-bit |

ChaCha20-Poly1305 was chosen over AES-GCM because it has no timing side-channels without hardware AES support and consistent performance across platforms.

## Consequences

### Benefits
- No harvest-now-decrypt-later risk from the first message
- No migration burden — groups never need cipher suite transitions
- Simpler codebase — one cipher suite, no negotiation logic, no downgrade attacks
- Future-proof for the post-quantum era

### Trade-offs
- Larger keys and signatures (ML-DSA-65 sigs ~3,309 bytes vs Ed25519 64 bytes)
- No interoperability with classical MLS implementations (acceptable within Saorsa/x0x network)
- Dependency on relatively new NIST standards (2024), though extensively reviewed
- No hybrid classical+PQC hedge (assessed as unnecessary given NIST Level 3 maturity)

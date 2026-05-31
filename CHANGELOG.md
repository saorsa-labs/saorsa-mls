# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [0.3.7] - 2026-05-31
### Added — persistent / derivable TreeKEM identity (x0x upstream ask)
- `MemberIdentity::from_seed(id, suite, &[u8; 32])`: deterministic identity
  derivation (same seed ⇒ same keys), backed by a real
  `KeyPair::generate_from_seed` (ML-DSA + ML-KEM seeded keygen). Lets a group's
  owning identity be reconstructed across restarts and bound to externally-held
  key material. ML-DSA suites only (no seeded SLH-DSA keygen upstream).
- `MemberIdentity::to_secret_bytes()` / `from_secret_bytes()`: opaque,
  encrypt-at-rest serialization that includes the secret keys (the derived
  `Serialize` impl still drops them).
### Changed
- `RatchetTree::find_leaf` and `TreeKemGroup::from_snapshot` match the owner leaf
  on the stable public keys (`verifying_key` + `agreement_key`) rather than full
  key-package equality, so a re-derived / restored identity reattaches to its
  leaf (ML-DSA signing is randomized, so the key-package signature is not
  reproducible). Key-package integrity is still verified on tree import.

## [0.3.6] - 2026-05-30
### Added — real post-quantum TreeKEM (ADR-002)
- `treekem`: RFC 9420-subset ratchet tree (perfect-tree math, per-node ML-KEM
  keypairs via deterministic `DeriveKeyPair`, tree hash, RFC 9420 §7.9 parent
  hashes), and UpdatePath generation/processing — the forward-secrecy /
  post-compromise-security mechanism.
- `key_schedule`: hash-aware MLS key schedule with epoch chaining
  (`init_secret` + `commit_secret` → `joiner_secret` → `epoch_secret`), giving
  FS (init chaining) and PCS (fresh commit secret per epoch).
- `treekem_group::TreeKemGroup`: a usable group with **real FS/PCS** —
  `create`/`add_member`/`from_welcome`/`update`/`remove_member`/`process_commit`,
  authenticated commits and Welcomes (committer signature), per-message
  signatures, per-sender replay protection, and an encrypt-at-rest serde
  snapshot. Two independent instances converge on the same epoch secrets via
  Welcome + UpdatePath; a removed member cannot derive the next epoch.
### Changed
- Documented that the legacy `MlsGroup` is a per-epoch group-shared-secret (GSS)
  plane **without** FS/PCS; use `TreeKemGroup` for real FS/PCS. ADR-001 amended;
  ADR-002 records the design and acceptance criteria.
- Signature-variant accessors (`CipherSuite::ml_dsa_variant`/`slh_dsa_variant`,
  `KeyPair::verifying_key`) now return `Result` instead of panicking; production
  code is panic/unwrap/expect-free.
### Fixed
- `MlsGroup::add_member` no longer double-advances the epoch.

### Notes
- The new `TreeKemGroup` API is **additive**; the legacy `MlsGroup` is unchanged.
- Out of scope (tracked): IETF wire interop (incl. RFC 9420 §7.9 unmerged-leaf
  filtering of the sibling tree hash), PSK injection, external commits, reinit,
  and migrating consumers off `MlsGroup`.

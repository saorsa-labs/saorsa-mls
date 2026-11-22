# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [0.3.10] - 2026-11-22
### Changed
Release-only: fixes the manifest warning that blocked the 0.3.9 release workflow.
0.3.9 was tagged but never published; 0.3.10 carries the same code (multi-remove
TreeKEM commit). The `homepage` field in Cargo.toml was removed because it was
redundant with `repository`, causing `cargo::redundant_homepage` to fire on every
`cargo` invocation and failing the doc-validation step of the release workflow.

## [0.3.9] - 2026-11-22
### Added — remove several members in one TreeKEM commit
- `TreeKemGroup::remove_members(&[u32])`: one signed commit that blanks every
  listed leaf (and its direct path) before the committer's fresh UpdatePath is
  generated. Path secrets are sealed only to the remaining tree, so no removed
  leaf receives key material from the commit and none can derive the new epoch.
  (Repeated `remove_member` calls seal each intermediate commit to the leaves
  removed later.) The commit lists the removed leaves in ascending order.
- Typed errors: `RemovalError` (`Empty`, `Duplicate`, `OutOfRange`,
  `BlankLeaf`, `CommitterLeaf`) and `RemoveMembersError` (`Invalid`, `Mls`),
  with `From<RemoveMembersError> for MlsError`.
- `TreeKemGroup::check_commit_removals(&TreeKemCommit)`: the receiver-side
  check of a commit's removal list, returning the typed `RemovalError`.
### Changed
- `TreeKemGroup::process_commit` checks the removal list (duplicates, range,
  blank leaves) before the signature check and any state change, and returns
  `MlsError::InvalidMessage` on failure. Before, a duplicate, out-of-range or
  blank removed leaf in a validly signed commit failed later with
  `MlsError::TreeKemError`. Commits from `remove_member`, `update` and
  `add_member` are not affected.
### Wire compatibility
- No wire or snapshot format change. `TreeKemCommit` already carried a list of
  removed leaves and receivers already applied every entry; saorsa-mls 0.3.8
  receivers apply a multi-remove commit and reach the same epoch secret
  (cross-version tests in `tests/multi_remove_wire_compat.rs`).

## [0.3.7] - 2026-05-31
### Added — persistent / derivable TreeKEM identity (x0x upstream ask)
- `MemberIdentity::from_seed(id, suite, &[u8; 32])`: deterministic identity
  derivation (same seed ⇒ same keys), backed by a real
  `KeyPair::generate_from_seed` (ML-DSA + ML-KEM seeded keygen). Lets a group's
  owning identity be reconstructed across restarts and bound to externally-held
  key material. ML-DSA suites only (no seeded SLH-DSA keygen upstream).
- `MemberIdentity::to_secret_bytes()` / `from_secret_bytes()`: opaque,
  encrypt-at-rest serialization that includes the secret keys (the derived
  `Serialize` impl still drops them). `from_secret_bytes` **validates** that the
  reconstructed secrets match the key package's public keys (sign-then-verify for
  the signing key; encapsulate/decapsulate for the KEM key) and that the key
  package / credential signatures are self-consistent, rejecting tampered or
  mismatched snapshots instead of producing an unusable identity.
### Changed
- `RatchetTree::find_leaf` and `TreeKemGroup::from_snapshot` match the owner leaf
  on the stable public keys (`verifying_key` + `agreement_key`) rather than full
  key-package equality, so a re-derived / restored identity reattaches to its
  leaf (ML-DSA signing is randomized, so the key-package signature is not
  reproducible). Key-package integrity is still verified on tree import.
- `from_seed` binds `id` + `suite` into the HKDF derivation (same raw seed under a
  different id/suite now yields different keys), and `to_secret_bytes` zeroizes its
  intermediate plaintext secret buffers.
### Determinism contract (narrower than the upstream ask)
- `from_seed` guarantees **same `(id, suite, seed)` ⇒ same signing/KEM key pairs**
  (stable `verifying_key`/`agreement_key`), **not** a byte-identical `KeyPackage`:
  ML-DSA signing is randomized upstream with no deterministic-signing API, so the
  key-package/credential signature differs on each derivation. Leaf matching keys
  off the stable public keys to accommodate this. If a byte-stable `KeyPackage` is
  required, persist it via `to_secret_bytes` rather than re-deriving.

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

# Upstream ask: persistable / derivable `MemberIdentity` for TreeKEM

- Requested by: x0x (ADR-0012, TreeKEM default secure groups)
- Date: 2026-05-31
- Against: saorsa-mls 0.3.6

## Status: RESOLVED in saorsa-mls 0.3.7

Both requested options shipped (additive, no breaking changes):

- **Option B (preferred):** `MemberIdentity::from_seed(id, suite, &[u8; 32])` —
  deterministic identity derivation. Backed by a real
  `KeyPair::generate_from_seed` (ML-DSA `generate_keypair_from_seed` + ML-KEM
  `generate_keypair_from_seed`, HKDF-expanded sub-seeds). x0x derives the seed
  from the agent's long-term key material, giving restart-persistence **and**
  binding the leaf to the agent's identity. (ML-DSA suites only — `saorsa-pqc`
  has no seeded SLH-DSA keygen, so SLH-DSA suites return an error.)
- **Option A:** `MemberIdentity::to_secret_bytes()` / `from_secret_bytes()` —
  opaque, encrypt-at-rest serialization including the secret keys.

Important caveat surfaced during implementation: ML-DSA signing in `saorsa-pqc`
0.5.1 is **randomized** (`try_sign_with_rng(OsRng)`), so a re-derived identity
reproduces the same **keys** but a different `KeyPackage`/credential
*signature*. Leaf lookup (`RatchetTree::find_leaf`) and the snapshot owner-leaf
check therefore match on the **stable public keys** (`verifying_key` +
`agreement_key`), not full key-package equality; key-package integrity is still
verified separately on tree import. This makes `from_seed`-restored and
`from_secret_bytes`-restored identities reattach to their leaf after a restart.

End-to-end restart (create → snapshot → drop → re-derive identity → restore →
encrypt/decrypt with peer) is covered by tests for both options.

---
*Original request below.*

## Problem

x0x is integrating `treekem_group::TreeKemGroup` as the default secure-group
plane (real FS/PCS). Two things x0x needs cannot be done with the current API:

1. **Persist a group across daemon restarts.** `TreeKemGroup::from_snapshot*`
   re-supplies the member identity, which is correct — but x0x has no way to
   reload that identity with its secret keys. `MemberIdentity`
   (`src/member.rs:51`) derives `Serialize`/`Deserialize`, but both secret
   fields are dropped:

   ```rust
   #[serde(skip)]
   signing_key: Option<Arc<SecretSignatureKey>>,
   #[serde(skip)]
   kem_secret: Option<Arc<MlKemSecretKey>>,
   ```

   So a round-tripped `MemberIdentity` has `signing_key == None` and
   `kem_secret == None` — it cannot sign commits or open Welcomes/joiner
   secrets. There is no `from_*`/`with_keys` constructor that takes secret key
   material back in, only `generate*` (which mints fresh keys). Net: a created
   or joined group's owning identity cannot survive a restart, so TreeKEM groups
   are forced to be session-scoped.

2. **Bind the group leaf to the agent's real long-term identity.**
   `MemberIdentity::generate*` mints a fresh ML-DSA signing key internally.
   x0x agents already have a long-term ML-DSA `AgentKeypair` (and a persisted
   ML-KEM `AgentKemKeypair`). Today the TreeKEM leaf is signed by a saorsa-
   generated key unrelated to the agent's real identity, so group membership is
   not cryptographically tied to the agent.

## Requested API (either option solves #1; option B also solves #2)

### Option A — secret-key (de)serialization

A way to export and re-import a `MemberIdentity` *including* its secret keys, as
opaque encrypted-at-rest-by-caller bytes. For example:

```rust
impl MemberIdentity {
    /// Serialize including secret keys. Caller MUST encrypt at rest.
    pub fn to_secret_bytes(&self) -> Result<Vec<u8>>;
    /// Reconstruct an identity (with secret keys) from `to_secret_bytes`.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self>;
}
```

Mirror the `TreeKemGroupSnapshot` convention (raw secrets, caller encrypts).

### Option B — deterministic identity from a seed (preferred)

Derive the whole identity deterministically from caller-supplied seed material,
so there is no new secret to store at all and the leaf can be bound to the
agent's existing key material:

```rust
impl MemberIdentity {
    /// Deterministically derive an identity (ML-DSA signing + ML-KEM agreement
    /// keypairs) from a 32-byte seed. Same seed -> same identity/keypackage.
    pub fn from_seed(id: MemberId, suite: CipherSuite, seed: &[u8; 32]) -> Result<Self>;
}
```

saorsa-pqc 0.5.1 already exposes deterministic keygen
(`MlKem::generate_keypair_from_seed`, `MlDsa::generate_keypair_from_seed` — see
saorsa-mls ADR-002's feasibility note), so this is mechanically available; it
just needs to be surfaced on `MemberIdentity`. x0x would derive the seed from
the agent's existing key material (HKDF of the agent secret + a group/context
label), giving restart-persistence *and* binding the leaf to real identity in
one step.

## Impact if not provided

x0x ships TreeKEM groups **session-scoped only** (secure while members are
online together, but lost on daemon restart) and keeps the GSS plane for any
group that needs to survive a restart. ADR-0012 Phase 4 (encrypted-at-rest
snapshots) and the AgentCard-KeyPackage prerequisite both block on this.

## Preference

Option B (`from_seed`), because it also resolves the long-standing "bind the
TreeKEM leaf to the agent's real AgentKeypair" goal and avoids storing a second
long-lived secret. Option A is an acceptable fallback if deterministic derivation
is more than expected.

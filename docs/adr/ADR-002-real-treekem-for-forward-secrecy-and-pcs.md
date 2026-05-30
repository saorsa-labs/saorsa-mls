# ADR-002: Implement Real TreeKEM for Forward Secrecy and Post-Compromise Security

## Status

Accepted — staged implementation in progress (each phase gated behind tests + review)

- Date: 2026-05-30
- Accepted: 2026-05-30
- Supersedes the implicit FS/PCS claim in ADR-001.

### Implementation feasibility note (verified 2026-05-30)

The standard RFC 9420 TreeKEM `DeriveKeyPair` step requires **deterministic**
generation of a node's KEM keypair from that node's path secret, so that any
member who learns a path secret derives the *same* keypair the committer used.
`saorsa-pqc 0.5.1` exposes `MlKem::generate_keypair_from_seed(d_seed, z_seed)`
(FIPS-203 deterministic keygen) and `MlDsa::generate_keypair_from_seed(xi)`.
The stale comment at `src/crypto.rs` claiming seeded keygen is "pending
upstream" is incorrect for 0.5.1. TreeKEM is therefore implementable on the
existing primitives without new cryptographic dependencies.

## Context

ADR-001 states that this crate provides "group key management with forward
secrecy and post-compromise security." A source audit of `saorsa-mls 0.3.5`
shows that claim is **not yet met**: the current group construction is a
per-epoch **group shared secret (GSS)**, not TreeKEM. The cryptographic
properties advertised in the crate's docstrings ("real TreeKEM key
management", `forward-secrecy` keyword) do not match the implementation.

### What the code actually does (verified)

- **Tree-node secrets are local randomness, never distributed.**
  `TreeKemState::add_leaf` sets each leaf `secret: random_bytes(32)`
  (`src/group.rs:918`); parent secrets are `hash(left.secret || right.secret)`
  (`src/group.rs:1006`); the root secret falls out of that
  (`src/group.rs:1019`). Because every node secret is locally random, two
  separate group instances can never converge on the same root secret.

- **The only key that crosses the wire is the epoch application secret.**
  `add_member` reads `secrets["application"]`, ML-KEM-768-encapsulates it to
  the joiner, and ships it in the Welcome (`src/group.rs:219-256`). This is a
  shared epoch secret, not a per-member path secret.

- **Per-member keys are HKDF of the shared secret.**
  `get_sender_application_key_and_nonce` derives
  `derive_key(epoch, application_secret, "mls application key" || sender_id)`
  (`src/group.rs:506`). Anyone holding `application_secret` can derive every
  member's keys.

- **No Commit / UpdatePath distribution.** Membership change calls
  `advance_epoch` locally and re-derives from the same local tree root
  (`src/group.rs:535`, `:578`). There is no mechanism to deliver a new epoch's
  secret to *existing* members over the wire.

This is the same construction as the GSS plane that x0x ships for its named
groups (x0x `docs/adr/0010-gss-before-mls-treekem-for-v1-secure-groups.md`).
x0x's authors reached this conclusion independently and deliberately refused
to call their plane "TreeKEM".

### Security consequence

The current scheme provides **neither forward secrecy nor post-compromise
security (PCS)**:

- All members in an epoch share one secret, so compromise of any single
  member's local state exposes all current-epoch content.
- Re-keying only changes the secret going forward and only excludes *removed*
  members; it does not heal a compromise of a member who remains in the group.

For consumers carrying sensitive long-lived payloads (e.g. x0x/Fae personal
memory in groups), the absence of PCS is the dominant risk.

### Why "just add `from_welcome` + serde" is insufficient

A prior external framing suggested the only gap was a `MlsGroup::from_welcome`
constructor plus `Serialize`/`Deserialize` on the group. That is incorrect:

- Serializing today's `MlsGroup` would only persist a **shared secret** — it
  does not add FS/PCS.
- A `from_welcome` over today's scheme would reconstruct the **shared-secret**
  model — still GSS, still no FS/PCS.

`from_welcome` and serde are *outputs* of a real TreeKEM implementation, not
the implementation itself.

## Decision

Implement real MLS TreeKEM (a pragmatic RFC 9420 subset) in `saorsa-mls`,
using the existing post-quantum primitives (ML-KEM-768/1024, ML-DSA-65/87,
ChaCha20-Poly1305). The work is **net-new cryptography**, staged across
phases, each gated behind tests and review. No phase ships without test
vectors and an adversarial review pass.

### Target construction (subset of RFC 9420)

1. **Ratchet tree with per-node KEM keypairs.** Each node holds an
   ML-KEM-768 (or suite-appropriate) keypair, not a random byte blob. Leaf
   nodes bind to a member's `KeyPackage`. Define parent-hash and tree-hash
   over public state.

2. **UpdatePath generation / processing (the FS+PCS mechanism).** A committer
   samples a fresh leaf path secret, derives the secret for each node on the
   direct path to the root, and encrypts each new node secret to the
   **copath resolution** (the public KEM keys of the sibling subtrees) via
   ML-KEM. Existing members process the UpdatePath to learn the new path
   secrets they are entitled to, and thereby the new root/commit secret.

3. **Key-schedule chaining.** Replace the local-root derivation with the MLS
   chain: `init_secret[n]` + `commit_secret` → `joiner_secret` →
   `epoch_secret[n+1]`, then derive the standard labelled secrets
   (sender_data, handshake, application, exporter, confirmation, membership,
   resumption, init). Chaining `init_secret` across epochs is what delivers
   forward secrecy; deriving the new epoch from a fresh `commit_secret` an
   attacker does not hold is what delivers PCS.

4. **Welcome carrying ratchet tree + GroupSecrets.** The Welcome must convey
   the public ratchet tree (or a `ratchet_tree` extension) plus a
   per-joiner `GroupSecrets { joiner_secret/path_secret, ... }` KEM-sealed to
   the joiner's KeyPackage, so the joiner reconstructs **real shared tree
   state**, not a copy of a flat shared secret.

5. **`MlsGroup::from_welcome(welcome, identity)`** falls out of (4): validate
   the GroupInfo signature, install the ratchet tree, decrypt the joiner's
   path/joiner secret, run the key schedule to the stated epoch, and return a
   fully-functional group able to call `encrypt_message`/`decrypt_message`.

6. **Serialization.** `MlsGroup` (and the private `TreeKemState`,
   `KeySchedule` state, per-sender ratchet/replay state) gain a serializable
   snapshot so a group survives process restart. Secret material is handled
   per "Secret-material handling" below — never serialized in the clear by
   default.

### Explicitly out of scope for v1 of this work

To bound the surface, the first TreeKEM release deliberately omits: external
commits / external joins, pre-shared-key (PSK) injection, resumption,
reinitialization, and classical (non-PQ) ciphersuite interop. These are
tracked as follow-ups, not hidden assumptions.

### Secret-material handling

- Snapshots that include private key material must be encrypted at rest by the
  caller (x0x already has a sealed-storage path); the crate exposes the
  snapshot as opaque bytes and documents the at-rest-encryption requirement,
  mirroring how `MemberIdentity` already uses `#[serde(skip)]` for secret keys
  (`src/member.rs:51`).
- `zeroize` on drop for path secrets and the key-schedule secrets.

### Resolved open question: ciphersuite registry alignment

x0x ADR-0010 names `draft-ietf-mls-pq-ciphersuites-04` as the migration trigger,
but this crate uses its own private-use "SPEC-2" suite IDs (`0x0B01`–`0x0B03`),
not that draft's codepoints.

**Decision: document the divergence and retain the SPEC-2 `0x0B**` IDs.** We do
**not** adopt the draft-04 codepoints for this release. Rationale:

1. `draft-ietf-mls-pq-ciphersuites-04` is a non-final IETF draft; its codepoints
   are not IANA-registered and may still change.
2. x0x already consumes `0x0B01` on the wire; changing the suite IDs is a
   breaking wire change that delivers no FS/PCS benefit.
3. Classical / IETF cross-stack interop is explicitly out of scope for this work
   (see "out of scope" above), so registry alignment buys nothing functional
   here.
4. The FS/PCS properties are delivered by the TreeKEM construction and key
   schedule, which are independent of the suite-ID registry value.

For future interop, the equivalent draft-04 entries are recorded for reference:

| SPEC-2 ID | Suite | Nearest draft-04 analogue |
|-----------|-------|---------------------------|
| `0x0B01` | ML-KEM-768 + ChaCha20Poly1305 + SHA-256 + ML-DSA-65 | `MLS_256_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65` (PQ-only) |
| `0x0B02` | ML-KEM-1024 + ChaCha20Poly1305 + SHA-512 + ML-DSA-87 | `MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87` (PQ-only) |
| `0x0B03` | ML-KEM-1024 + ChaCha20Poly1305 + SHA-384 + SLH-DSA-192 | no direct analogue (SLH-DSA) |

**Revisit trigger (tracked, out of scope here):** adopt the IETF codepoints only
if/when (a) the draft reaches RFC with stable IANA codepoints, **and**
(b) x0x or another consumer requires interop with a non-saorsa MLS stack. At that
point a suite-ID alias/negotiation layer (not a hard cutover) is preferred so
existing `0x0B**` groups keep working.

## Consequences

### Positive

- Real forward secrecy and post-compromise security for group payloads.
- Persistent groups (survive restart) and genuine cross-daemon join via
  `from_welcome` — unblocking x0x's `/mls/groups` as a persistent,
  cross-machine secure plane and giving x0x/Fae a path off GSS for
  personal-memory groups.
- The crate's advertised properties finally match its implementation.

### Negative / cost

- Weeks of security-critical implementation; must not be rushed.
- Wire format and on-disk snapshot format change → a migration is required for
  any existing GSS groups (see x0x ADR-0010, which already anticipates this).
- Larger attack surface than GSS; requires KATs/test vectors and external
  review before any production use.

### Migration

- The migration trigger in x0x ADR-0010 still governs x0x's adoption: migrate
  named groups to TreeKEM only once this work lands **and** named-groups v1 has
  been prod-stable for ≥1 release cycle. Define in-place upgrade vs.
  bridged-transition vs. recreate at that time.

## Required Follow-up Work

1. Correct the misleading docstrings now (`src/group.rs:1` "real TreeKEM key
   management"; the `forward-secrecy` keyword in `Cargo.toml`; ADR-001's
   blanket FS/PCS claim) so they describe the *current* GSS behavior until
   TreeKEM lands. (Deferred per maintainer instruction 2026-05-30; tracked
   here so it is not lost.)
2. Investigate the apparent double `advance_epoch` in `add_member`
   (`src/group.rs:204` and `:215`) — likely an unintended double epoch bump,
   independent of this ADR.
3. Stage implementation as: (P2) ratchet tree + KEM keypairs + hashes;
   (P3) UpdatePath gen/process + KATs; (P4) key-schedule chaining;
   (P5) Welcome ratchet-tree + GroupSecrets + `from_welcome` + serde;
   (P6) x0x integration + named-group migration. Each phase gated behind
   tests and review.

## Acceptance Criteria

This ADR's *implementation* is satisfied only when:

- two independently-constructed `MlsGroup` instances (separate processes)
  reach the same epoch secret via Welcome + UpdatePath — proven by a
  cross-instance encrypt→decrypt test (today's `tests/join_processing.rs`
  hand-derives keys and never builds a second `MlsGroup`; that gap is the
  baseline this work must close);
- a removed member provably cannot derive the next epoch's secrets, and a
  compromise of one member's epoch-N state provably does not yield epoch-N+1
  secrets after a Commit (FS + PCS regression tests);
- `from_welcome` produces a group that round-trips `encrypt_message` /
  `decrypt_message` against the committer;
- a serialized group restores to a functionally identical group;
- KATs / test vectors cover the key schedule and UpdatePath;
- docstrings and ADR-001 no longer over-state properties beyond what is
  implemented at that point.

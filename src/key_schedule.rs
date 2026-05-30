// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
//! MLS key schedule with epoch chaining (RFC 9420 §8 subset, post-quantum).
//!
//! This is phase P4 of [ADR-002](../../docs/adr/ADR-002-real-treekem-for-forward-secrecy-and-pcs.md):
//! it turns the `commit_secret` produced by an UpdatePath (phase P3,
//! [`crate::treekem::RatchetTree::generate_update_path`]) into a full set of
//! epoch secrets, **chaining `init_secret` across epochs**:
//!
//! ```text
//! init_secret[n-1]  +  commit_secret
//!         \             /
//!          v           v
//!        joiner_secret = Extract(init_secret[n-1], commit_secret)
//!                |
//!                v
//!        epoch_secret  = ExpandWithLabel(joiner_secret, "epoch", group_context)
//!                |
//!     +----------+----------+----  DeriveSecret(epoch_secret, label) ----+
//!     v          v          v                                            v
//! sender_data  encryption  exporter ...                          init_secret[n]
//! ```
//!
//! - **Forward secrecy** comes from `init_secret[n] = DeriveSecret(epoch_secret[n], "init")`:
//!   each epoch's init secret is a one-way function of the previous epoch, so
//!   deleting `init_secret[n-1]` makes earlier epochs unrecoverable.
//! - **Post-compromise security** comes from folding a fresh `commit_secret`
//!   (which an attacker who could not decrypt the UpdatePath does not hold) into
//!   every epoch via the `Extract` step.
//!
//! Unlike the legacy [`crate::crypto::KeySchedule`] (which hard-wires
//! HKDF-SHA3-256), this schedule is **hash-aware**: suites in the SHA-256 /
//! SHA3-256 / BLAKE3 family use HMAC-SHA3-256 (32-byte secrets) and suites in
//! the SHA-384 / SHA-512 / SHA3-512 family use HMAC-SHA3-512 (64-byte secrets),
//! matching the suite's advertised security level. Labels use the RFC 9420
//! `"MLS 1.0 "` prefix.
//!
//! PSK injection, resumption, and external init are out of scope (ADR-002); the
//! `psk_secret` is implicitly zero.

use crate::{
    crypto::{CipherSuite, Hash, MlsHash},
    MlsError, Result,
};
use zeroize::Zeroizing;

/// Which HMAC/HKDF the schedule uses for a suite, and its output size `Nh`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KdfFamily {
    /// HMAC-SHA3-256, `Nh = 32`.
    Sha3_256,
    /// HMAC-SHA3-512, `Nh = 64`.
    Sha3_512,
}

impl KdfFamily {
    fn for_suite(suite: CipherSuite) -> Self {
        match suite.hash() {
            MlsHash::Sha256 | MlsHash::Sha3_256 | MlsHash::Blake3 => KdfFamily::Sha3_256,
            MlsHash::Sha384 | MlsHash::Sha512 | MlsHash::Sha3_512 => KdfFamily::Sha3_512,
        }
    }

    /// Output size `Nh` in bytes.
    fn nh(self) -> usize {
        match self {
            KdfFamily::Sha3_256 => 32,
            KdfFamily::Sha3_512 => 64,
        }
    }
}

/// HMAC over the suite's hash. `key` is the MAC key (HKDF salt / PRK).
fn hmac(suite: CipherSuite, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use saorsa_pqc::api::hmac::{HmacSha3_256, HmacSha3_512};
    use saorsa_pqc::api::traits::Mac;
    match KdfFamily::for_suite(suite) {
        KdfFamily::Sha3_256 => {
            let mut mac = HmacSha3_256::new(key)
                .map_err(|e| MlsError::CryptoError(format!("HMAC key error: {e:?}")))?;
            mac.update(data);
            Ok(mac.finalize().as_ref().to_vec())
        }
        KdfFamily::Sha3_512 => {
            let mut mac = HmacSha3_512::new(key)
                .map_err(|e| MlsError::CryptoError(format!("HMAC key error: {e:?}")))?;
            mac.update(data);
            Ok(mac.finalize().as_ref().to_vec())
        }
    }
}

/// HKDF-Extract: `PRK = HMAC(salt, ikm)`.
fn extract(suite: CipherSuite, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>> {
    hmac(suite, salt, ikm)
}

/// HKDF-Expand (RFC 5869 §2.3): `T(i) = HMAC(prk, T(i-1) ‖ info ‖ i)`,
/// concatenated and truncated to `len` (max `255 * Nh`). Every key-schedule
/// secret is exactly `Nh` (a single block); the exporter may request more. All
/// intermediate buffers are zeroized.
fn expand(suite: CipherSuite, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let nh = KdfFamily::for_suite(suite).nh();
    let n_blocks = len.div_ceil(nh);
    if n_blocks > 255 {
        return Err(MlsError::CryptoError(format!(
            "expand length {len} exceeds 255*Nh"
        )));
    }
    // okm is held in a Zeroizing buffer of the full block-aligned size and is
    // never truncated, so its entire backing (including the discarded tail
    // beyond `len`) is wiped on drop.
    let mut okm: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(n_blocks * nh));
    let mut prev: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    for i in 1..=n_blocks {
        let mut data: Zeroizing<Vec<u8>> =
            Zeroizing::new(Vec::with_capacity(prev.len() + info.len() + 1));
        data.extend_from_slice(&prev);
        data.extend_from_slice(info);
        data.push(i as u8);
        prev = Zeroizing::new(hmac(suite, prk, &data)?);
        okm.extend_from_slice(&prev);
    }
    Ok(okm[..len].to_vec())
}

/// RFC 9420 `ExpandWithLabel(secret, label, context, length)`.
///
/// The `KDFLabel` is encoded deterministically as
/// `u16(length) ‖ vec16("MLS 1.0 " + label) ‖ vec16(context)`, where `vec16` is
/// a `u16` big-endian length prefix followed by the bytes. (Interop with the
/// IETF wire format is out of scope per ADR-002; this encoding only needs to be
/// unambiguous and stable.)
fn expand_with_label(
    suite: CipherSuite,
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    let mut full_label = Vec::with_capacity(8 + label.len());
    full_label.extend_from_slice(b"MLS 1.0 ");
    full_label.extend_from_slice(label.as_bytes());

    let len_u16 = u16::try_from(length)
        .map_err(|_| MlsError::CryptoError("label length too large".into()))?;
    let label_len = u16::try_from(full_label.len())
        .map_err(|_| MlsError::CryptoError("label too long".into()))?;
    let ctx_len = u16::try_from(context.len())
        .map_err(|_| MlsError::CryptoError("context too long".into()))?;

    let mut info = Vec::new();
    info.extend_from_slice(&len_u16.to_be_bytes());
    info.extend_from_slice(&label_len.to_be_bytes());
    info.extend_from_slice(&full_label);
    info.extend_from_slice(&ctx_len.to_be_bytes());
    info.extend_from_slice(context);
    expand(suite, secret, &info, length)
}

/// RFC 9420 `DeriveSecret(secret, label) = ExpandWithLabel(secret, label, "", Nh)`.
fn derive_secret(suite: CipherSuite, secret: &[u8], label: &str) -> Result<Zeroizing<Vec<u8>>> {
    let nh = KdfFamily::for_suite(suite).nh();
    Ok(Zeroizing::new(expand_with_label(
        suite,
        secret,
        label,
        &[],
        nh,
    )?))
}

/// The set of secrets for one epoch, plus the `init_secret` that chains to the
/// next epoch. All fields are zeroized on drop.
#[derive(Clone)]
pub struct EpochSecrets {
    suite: CipherSuite,
    /// `init_secret[n]` — feeds the next epoch's `Extract`. Keep private; it is
    /// the FS-critical chaining value.
    init_secret: Zeroizing<Vec<u8>>,
    /// Per-epoch secrets (RFC 9420 §8).
    sender_data_secret: Zeroizing<Vec<u8>>,
    encryption_secret: Zeroizing<Vec<u8>>,
    exporter_secret: Zeroizing<Vec<u8>>,
    external_secret: Zeroizing<Vec<u8>>,
    confirmation_key: Zeroizing<Vec<u8>>,
    membership_key: Zeroizing<Vec<u8>>,
    resumption_psk: Zeroizing<Vec<u8>>,
    epoch_authenticator: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for EpochSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochSecrets")
            .field("suite", &self.suite)
            .field("secrets", &"<redacted>")
            .finish()
    }
}

impl EpochSecrets {
    /// The `Nh` (secret length in bytes) for `suite`.
    #[must_use]
    pub fn secret_len(suite: CipherSuite) -> usize {
        KdfFamily::for_suite(suite).nh()
    }

    /// Derive the secrets for an epoch from the previous epoch's `init_secret`,
    /// the `commit_secret` from this epoch's Commit/UpdatePath, and the group
    /// context (group id ‖ epoch ‖ tree hash ‖ … — the caller's binding).
    ///
    /// For the very first epoch, pass a freshly sampled random `init_secret` of
    /// length [`EpochSecrets::secret_len`] and the initial tree's `commit_secret`.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] if any HKDF/HMAC step fails.
    pub fn derive(
        suite: CipherSuite,
        prev_init_secret: &[u8],
        commit_secret: &[u8],
        group_context: &[u8],
    ) -> Result<Self> {
        let joiner = Self::joiner_secret(suite, prev_init_secret, commit_secret)?;
        Self::from_joiner(suite, &joiner, group_context)
    }

    /// `joiner_secret = Extract(init_secret[n-1], commit_secret)`.
    ///
    /// This is the value a Welcome message seals to a newly added member so the
    /// joiner can reconstruct the epoch without learning prior epochs' secrets.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] on HMAC failure.
    pub fn joiner_secret(
        suite: CipherSuite,
        prev_init_secret: &[u8],
        commit_secret: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(extract(
            suite,
            prev_init_secret,
            commit_secret,
        )?))
    }

    /// Derive the epoch secrets from a `joiner_secret` and the group context.
    /// Both the committer (after computing the joiner from init+commit) and a
    /// newly added member (who receives the joiner via Welcome) call this and
    /// arrive at the identical epoch.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] if any HKDF step fails.
    pub fn from_joiner(
        suite: CipherSuite,
        joiner_secret: &[u8],
        group_context: &[u8],
    ) -> Result<Self> {
        // epoch_secret = ExpandWithLabel(joiner_secret, "epoch", group_context, Nh)
        // (psk_secret is implicitly zero — PSK is out of scope)
        let nh = KdfFamily::for_suite(suite).nh();
        let epoch_secret = Zeroizing::new(expand_with_label(
            suite,
            joiner_secret,
            "epoch",
            group_context,
            nh,
        )?);

        Ok(Self {
            suite,
            sender_data_secret: derive_secret(suite, &epoch_secret, "sender data")?,
            encryption_secret: derive_secret(suite, &epoch_secret, "encryption")?,
            exporter_secret: derive_secret(suite, &epoch_secret, "exporter")?,
            external_secret: derive_secret(suite, &epoch_secret, "external")?,
            confirmation_key: derive_secret(suite, &epoch_secret, "confirm")?,
            membership_key: derive_secret(suite, &epoch_secret, "membership")?,
            resumption_psk: derive_secret(suite, &epoch_secret, "resumption")?,
            epoch_authenticator: derive_secret(suite, &epoch_secret, "authentication")?,
            init_secret: derive_secret(suite, &epoch_secret, "init")?,
        })
    }

    /// Advance to the next epoch: `EpochSecrets::derive(suite, self.init_secret,
    /// commit_secret, group_context)`. Consumes the old init secret implicitly
    /// (the caller should drop the previous `EpochSecrets`, zeroizing it).
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] on HKDF/HMAC failure.
    pub fn next(&self, commit_secret: &[u8], group_context: &[u8]) -> Result<Self> {
        Self::derive(self.suite, &self.init_secret, commit_secret, group_context)
    }

    /// The secret that chains to the next epoch (`init_secret[n]`). Exposed for
    /// persistence (P5) — treat as sensitive, encrypt at rest.
    #[must_use]
    pub fn init_secret(&self) -> &[u8] {
        &self.init_secret
    }

    /// Application/encryption secret for this epoch (root of the message-key
    /// ratchet wired up in P5).
    #[must_use]
    pub fn encryption_secret(&self) -> &[u8] {
        &self.encryption_secret
    }

    /// Sender-data secret (protects message metadata).
    #[must_use]
    pub fn sender_data_secret(&self) -> &[u8] {
        &self.sender_data_secret
    }

    /// Membership key (authenticates membership of handshake messages).
    #[must_use]
    pub fn membership_key(&self) -> &[u8] {
        &self.membership_key
    }

    /// Confirmation key (for the Commit's confirmation tag).
    #[must_use]
    pub fn confirmation_key(&self) -> &[u8] {
        &self.confirmation_key
    }

    /// External secret (external-init public key derivation).
    #[must_use]
    pub fn external_secret(&self) -> &[u8] {
        &self.external_secret
    }

    /// Resumption PSK for this epoch.
    #[must_use]
    pub fn resumption_psk(&self) -> &[u8] {
        &self.resumption_psk
    }

    /// Epoch authenticator (binds external observers to the epoch).
    #[must_use]
    pub fn epoch_authenticator(&self) -> &[u8] {
        &self.epoch_authenticator
    }

    /// MLS exporter (RFC 9420 §8.5):
    /// `ExpandWithLabel(DeriveSecret(exporter_secret, label), "exported", Hash(context), length)`.
    /// `length` may be up to `255 * Nh`.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] on HKDF failure or if `length` exceeds `255 * Nh`.
    pub fn export(&self, label: &str, context: &[u8], length: usize) -> Result<Vec<u8>> {
        let derived = derive_secret(self.suite, &self.exporter_secret, label)?;
        let context_hash = Hash::new(self.suite).hash(context);
        expand_with_label(self.suite, &derived, "exported", &context_hash, length)
    }

    /// Derive the per-sender AEAD key and base nonce for an application message
    /// from this epoch's `encryption_secret`, bound to the sender's leaf index
    /// and a per-sender `generation` counter.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] on HKDF failure.
    pub fn application_key_and_nonce(
        &self,
        sender_leaf: u32,
        generation: u32,
    ) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
        let mut context = Vec::with_capacity(8);
        context.extend_from_slice(&sender_leaf.to_be_bytes());
        context.extend_from_slice(&generation.to_be_bytes());
        let key = Zeroizing::new(expand_with_label(
            self.suite,
            &self.encryption_secret,
            "key",
            &context,
            self.suite.key_size(),
        )?);
        let nonce = expand_with_label(
            self.suite,
            &self.encryption_secret,
            "nonce",
            &context,
            self.suite.nonce_size(),
        )?;
        Ok((key, nonce))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CipherSuiteId;

    fn suite_256() -> CipherSuite {
        CipherSuite::default() // 0x0B01, SHA-256 family
    }

    fn suite_512() -> CipherSuite {
        CipherSuite::from_id(CipherSuiteId::SPEC2_MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87)
            .unwrap()
    }

    #[test]
    fn test_hash_agility_secret_sizes() {
        assert_eq!(EpochSecrets::secret_len(suite_256()), 32);
        assert_eq!(EpochSecrets::secret_len(suite_512()), 64);

        let es256 = EpochSecrets::derive(suite_256(), &[1u8; 32], &[2u8; 32], b"ctx").unwrap();
        assert_eq!(es256.encryption_secret().len(), 32);
        let es512 = EpochSecrets::derive(suite_512(), &[1u8; 64], &[2u8; 64], b"ctx").unwrap();
        assert_eq!(
            es512.encryption_secret().len(),
            64,
            "SHA-512 suite must derive 64-byte secrets, not the legacy 32"
        );
    }

    #[test]
    fn test_derive_is_deterministic() {
        let a = EpochSecrets::derive(suite_256(), &[7u8; 32], &[9u8; 32], b"group-ctx").unwrap();
        let b = EpochSecrets::derive(suite_256(), &[7u8; 32], &[9u8; 32], b"group-ctx").unwrap();
        assert_eq!(a.encryption_secret(), b.encryption_secret());
        assert_eq!(a.init_secret(), b.init_secret());
        assert_eq!(a.epoch_authenticator(), b.epoch_authenticator());
    }

    #[test]
    fn test_distinct_labels_distinct_secrets() {
        let es = EpochSecrets::derive(suite_256(), &[1u8; 32], &[2u8; 32], b"ctx").unwrap();
        // all labelled secrets must differ from each other
        let all = [
            es.encryption_secret(),
            es.sender_data_secret(),
            es.exporter_secret.as_slice(),
            es.external_secret(),
            es.confirmation_key(),
            es.membership_key(),
            es.resumption_psk(),
            es.epoch_authenticator(),
            es.init_secret(),
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "labelled secrets {i} and {j} collide");
            }
        }
    }

    #[test]
    fn test_pcs_epoch_depends_on_commit_secret() {
        // An attacker who holds init_secret[n] but NOT the fresh commit_secret
        // cannot derive epoch n+1: changing only the commit_secret changes every
        // epoch secret.
        let init = [3u8; 32];
        let e1 = EpochSecrets::derive(suite_256(), &init, &[10u8; 32], b"ctx").unwrap();
        let e2 = EpochSecrets::derive(suite_256(), &init, &[11u8; 32], b"ctx").unwrap();
        assert_ne!(e1.encryption_secret(), e2.encryption_secret());
        assert_ne!(e1.init_secret(), e2.init_secret());
    }

    #[test]
    fn test_fs_init_chaining_one_way() {
        // init_secret[n] is derived from epoch_secret[n]; it must differ from the
        // previous init_secret and from the commit_secret, and chaining forward
        // must keep advancing.
        let prev_init = [4u8; 32];
        let commit = [5u8; 32];
        let e_n = EpochSecrets::derive(suite_256(), &prev_init, &commit, b"ctx").unwrap();
        assert_ne!(e_n.init_secret(), &prev_init[..], "init must advance");
        assert_ne!(e_n.init_secret(), &commit[..]);

        // next epoch chains from init_secret[n] + a new commit
        let e_n1 = e_n.next(&[6u8; 32], b"ctx").unwrap();
        assert_ne!(e_n1.init_secret(), e_n.init_secret());
        assert_ne!(e_n1.encryption_secret(), e_n.encryption_secret());
    }

    #[test]
    fn test_group_context_binding() {
        let a = EpochSecrets::derive(suite_256(), &[1u8; 32], &[2u8; 32], b"group-A").unwrap();
        let b = EpochSecrets::derive(suite_256(), &[1u8; 32], &[2u8; 32], b"group-B").unwrap();
        assert_ne!(
            a.encryption_secret(),
            b.encryption_secret(),
            "epoch secrets must be bound to the group context"
        );
    }

    #[test]
    fn test_exporter_label_and_context_separation() {
        let es = EpochSecrets::derive(suite_256(), &[1u8; 32], &[2u8; 32], b"ctx").unwrap();
        let a = es.export("label-a", b"ctx", 32).unwrap();
        let b = es.export("label-b", b"ctx", 32).unwrap();
        let c = es.export("label-a", b"ctx2", 32).unwrap();
        assert_ne!(a, b, "different labels must separate");
        assert_ne!(a, c, "different contexts must separate");
        assert_eq!(a.len(), 32);
        // deterministic
        assert_eq!(a, es.export("label-a", b"ctx", 32).unwrap());
    }

    #[test]
    fn test_expand_multi_block_lengths() {
        // multi-block HKDF-Expand produces exact lengths beyond a single block,
        // and rejects > 255*Nh.
        let out = expand_with_label(suite_256(), &[0u8; 32], "x", b"", 100).unwrap();
        assert_eq!(out.len(), 100); // > Nh=32 → 4 blocks
        let out512 = expand_with_label(suite_512(), &[0u8; 64], "x", b"", 200).unwrap();
        assert_eq!(out512.len(), 200);
        // raw expand (fixed info) is prefix-stable across lengths per RFC 5869
        let long = expand(suite_256(), &[1u8; 32], b"info", 100).unwrap();
        let short = expand(suite_256(), &[1u8; 32], b"info", 32).unwrap();
        assert_eq!(&long[..32], &short[..], "HKDF-Expand must be prefix-stable");
        // 255*Nh+1 must error
        assert!(expand_with_label(suite_256(), &[0u8; 32], "x", b"", 255 * 32 + 1).is_err());
    }

    #[test]
    fn test_sha512_family_determinism() {
        // the HMAC-SHA3-512 path must also be deterministic across the full
        // secret set (MiniMax review: 512 family only had a size test).
        let a = EpochSecrets::derive(suite_512(), &[7u8; 64], &[9u8; 64], b"ctx").unwrap();
        let b = EpochSecrets::derive(suite_512(), &[7u8; 64], &[9u8; 64], b"ctx").unwrap();
        assert_eq!(a.encryption_secret(), b.encryption_secret());
        assert_eq!(a.init_secret(), b.init_secret());
        assert_eq!(a.epoch_authenticator(), b.epoch_authenticator());
        assert_eq!(
            a.export("x", b"ctx", 100).unwrap(),
            b.export("x", b"ctx", 100).unwrap()
        );
    }

    /// End-to-end P3→P4: a real UpdatePath commit_secret, fed through the key
    /// schedule on two independent instances, yields identical epoch secrets —
    /// the cross-instance epoch-secret convergence at the heart of ADR-002.
    #[test]
    fn test_commit_secret_drives_converged_epoch_secrets() {
        use crate::member::{MemberId, MemberIdentity};
        use crate::treekem::RatchetTree;

        let suite = suite_256();
        let alice = MemberIdentity::generate(MemberId::generate()).unwrap();
        let bob = MemberIdentity::generate(MemberId::generate()).unwrap();

        let mut tree_a = RatchetTree::new(alice.key_package.clone(), suite).unwrap();
        tree_a
            .attach_owner(0, alice.kem_secret().unwrap().clone())
            .unwrap();
        let bob_leaf = tree_a.add_leaf(bob.key_package.clone()).unwrap();

        // Bob's independent view of the shared public tree.
        let mut tree_b = tree_a.clone();
        tree_b
            .attach_owner(bob_leaf, bob.kem_secret().unwrap().clone())
            .unwrap();

        let group_context = b"group-id|epoch=1";
        let (update_path, cs_alice) = tree_a.generate_update_path(group_context, None).unwrap();
        let cs_bob = tree_b
            .process_update_path(&update_path, group_context)
            .unwrap();
        assert_eq!(&*cs_alice, &*cs_bob, "tree-level commit secrets must match");

        // Both members run the key schedule from the same prior init secret.
        let prev_init = vec![0u8; EpochSecrets::secret_len(suite)];
        let epoch_a = EpochSecrets::derive(suite, &prev_init, &cs_alice, group_context).unwrap();
        let epoch_b = EpochSecrets::derive(suite, &prev_init, &cs_bob, group_context).unwrap();

        assert_eq!(
            epoch_a.encryption_secret(),
            epoch_b.encryption_secret(),
            "both members must reach the same epoch encryption secret"
        );
        assert_eq!(epoch_a.init_secret(), epoch_b.init_secret());
        assert_eq!(epoch_a.epoch_authenticator(), epoch_b.epoch_authenticator());
        // and the exporter agrees across instances
        assert_eq!(
            epoch_a.export("app", b"ctx", 32).unwrap(),
            epoch_b.export("app", b"ctx", 32).unwrap()
        );
    }
}

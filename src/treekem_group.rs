// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
//! Real `TreeKEM` group (phase P5 of
//! [ADR-002](../../docs/adr/ADR-002-real-treekem-for-forward-secrecy-and-pcs.md)).
//!
//! [`TreeKemGroup`] wires the reviewed ratchet tree
//! ([`crate::treekem::RatchetTree`]) and key schedule
//! ([`crate::key_schedule::EpochSecrets`]) into a usable group with real forward
//! secrecy and post-compromise security:
//!
//! - [`TreeKemGroup::create`] starts a one-member group.
//! - [`TreeKemGroup::add_member`] adds a member and returns a [`TreeKemWelcome`]
//!   that conveys the public ratchet tree plus the `joiner_secret` sealed to the
//!   new member's key package.
//! - [`TreeKemGroup::from_welcome`] reconstructs the group on the joiner's side
//!   and lands on the *same* epoch secrets as the committer.
//! - [`TreeKemGroup::update`] / [`TreeKemGroup::process_commit`] run an
//!   UpdatePath commit so members heal (PCS) and advance epochs (FS).
//! - [`TreeKemGroup::encrypt_message`] / [`TreeKemGroup::decrypt_message`]
//!   protect application messages with per-sender/per-generation keys derived
//!   from the epoch's `encryption_secret`, signed with the sender's identity.
//!
//! This is the type intended to replace the legacy GSS [`crate::group::MlsGroup`]
//! (ADR-002 P5/P6). It deliberately uses the post-quantum primitives only.
//!
//! Scope of this first cut: member **add** (via Welcome) and member **update**
//! (UpdatePath commit). Member **remove**, full on-disk serde snapshotting,
//! and committer-signature / parent-hash verification of commits are tracked
//! follow-ups (see ADR-002 and the P3/P4 review notes) — message-level
//! authentication (per-message signatures) IS enforced here.

use crate::{
    crypto::{AeadCipher, CipherSuite, Signature},
    key_schedule::EpochSecrets,
    member::{KeyPackage, MemberIdentity},
    treekem::{self, RatchetTree, UpdatePath},
    EpochNumber, MlsError, Result,
};
use saorsa_pqc::api::{MlDsaSignature, SlhDsaSignature};
use serde::{Deserialize, Serialize};

/// A real `TreeKEM` group as seen by one member.
pub struct TreeKemGroup {
    suite: CipherSuite,
    group_id: Vec<u8>,
    epoch: EpochNumber,
    identity: MemberIdentity,
    tree: RatchetTree,
    epoch_secrets: EpochSecrets,
    /// Monotonic per-epoch send counter (reset each epoch).
    send_generation: u32,
}

impl std::fmt::Debug for TreeKemGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TreeKemGroup")
            .field("suite", &self.suite)
            .field("group_id", &hex::encode(&self.group_id))
            .field("epoch", &self.epoch)
            .field("own_leaf", &self.tree.own_leaf())
            .field("members", &self.tree.active_leaf_count())
            .finish_non_exhaustive()
    }
}

/// A Welcome message: the public ratchet tree plus the `joiner_secret` sealed to
/// the new member's KEM key. Wire-serializable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeKemWelcome {
    /// Group identifier.
    pub group_id: Vec<u8>,
    /// Epoch the joiner lands in.
    pub epoch: EpochNumber,
    /// Cipher suite.
    pub cipher_suite: CipherSuite,
    /// The committer's post-commit public ratchet tree.
    pub public_nodes: Vec<Option<treekem::Node>>,
    /// `joiner_secret` sealed to the new member's key package KEM key.
    pub encrypted_joiner: treekem::HpkeCiphertext,
}

/// A commit carrying an UpdatePath (member update / rekey). Wire-serializable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeKemCommit {
    /// Epoch this commit produces.
    pub epoch: EpochNumber,
    /// The UpdatePath rotating the committer's direct path.
    pub update_path: UpdatePath,
}

/// An encrypted application message. Wire-serializable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplicationCiphertext {
    /// Epoch the message was sent in.
    pub epoch: EpochNumber,
    /// Sender's leaf index.
    pub sender_leaf: u32,
    /// Per-sender generation counter.
    pub generation: u32,
    /// `nonce ‖ AEAD ciphertext`.
    pub ciphertext: Vec<u8>,
    /// Signature over `ciphertext` by the sender's identity key.
    pub signature: Vec<u8>,
}

impl TreeKemGroup {
    /// Start a new one-member group. The creator owns leaf 0.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] if `creator` lacks its private keys or on crypto
    /// failure.
    pub fn create(group_id: Vec<u8>, creator: MemberIdentity) -> Result<Self> {
        let suite = creator.cipher_suite();
        let creator_kem = creator
            .kem_secret()
            .ok_or_else(|| MlsError::InvalidGroupState("creator missing KEM secret".into()))?
            .clone();
        let mut tree = RatchetTree::new(creator.key_package.clone(), suite)?;
        tree.attach_owner(0, creator_kem)?;

        // Epoch 0 secrets: a fresh init secret + a fresh commit secret. (No
        // member joins at epoch 0, so reproducibility by a joiner is not needed
        // until the first add.)
        let nh = EpochSecrets::secret_len(suite);
        let init0 = crate::crypto::random_bytes(nh);
        let commit0 = crate::crypto::random_bytes(nh);
        let ctx = Self::group_context(&group_id, 0, &tree.tree_hash()?);
        let epoch_secrets = EpochSecrets::derive(suite, &init0, &commit0, &ctx)?;

        Ok(Self {
            suite,
            group_id,
            epoch: 0,
            identity: creator,
            tree,
            epoch_secrets,
            send_generation: 0,
        })
    }

    /// Add a new member, returning a [`TreeKemWelcome`] for them. The caller
    /// (committer) advances to the next epoch; existing members other than the
    /// joiner would process the embedded UpdatePath via a separate Commit (the
    /// joiner uses the sealed `joiner_secret` and does not process the path).
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] on crypto/tree failure or if the new member's suite
    /// mismatches.
    pub fn add_member(&mut self, new_member: &KeyPackage) -> Result<TreeKemWelcome> {
        if new_member.cipher_suite != self.suite {
            return Err(MlsError::InvalidGroupState(
                "new member cipher suite mismatch".into(),
            ));
        }
        self.tree.add_leaf(new_member.clone())?;

        // UpdatePath rooted at the committer; bound to the current (pre-commit)
        // group + epoch as AAD so existing members decrypt under a shared context.
        let path_aad = Self::path_context(&self.group_id, self.epoch);
        let (update_path, commit_secret) = self.tree.generate_update_path(&path_aad, None)?;
        let _ = update_path; // existing members consume this via process_commit; the
                             // joiner below reconstructs the epoch from joiner_secret.

        let new_epoch = self.epoch + 1;
        let new_tree_hash = self.tree.tree_hash()?;
        let new_ctx = Self::group_context(&self.group_id, new_epoch, &new_tree_hash);

        let joiner = EpochSecrets::joiner_secret(
            self.suite,
            self.epoch_secrets.init_secret(),
            &commit_secret,
        )?;
        let new_epoch_secrets = EpochSecrets::from_joiner(self.suite, &joiner, &new_ctx)?;

        // Seal joiner_secret to the new member's KEM key, bound to the new epoch.
        let seal_aad = Self::path_context(&self.group_id, new_epoch);
        let encrypted_joiner =
            treekem::seal_to(self.suite, &new_member.agreement_key, &joiner, &seal_aad)?;

        let welcome = TreeKemWelcome {
            group_id: self.group_id.clone(),
            epoch: new_epoch,
            cipher_suite: self.suite,
            public_nodes: self.tree.export_public_nodes(),
            encrypted_joiner,
        };

        self.epoch_secrets = new_epoch_secrets;
        self.epoch = new_epoch;
        self.send_generation = 0;
        Ok(welcome)
    }

    /// Join a group from a [`TreeKemWelcome`], landing on the same epoch secrets
    /// as the committer.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] if the suite mismatches, the joiner's leaf is not in
    /// the tree, the sealed joiner secret cannot be opened, or on crypto failure.
    pub fn from_welcome(welcome: &TreeKemWelcome, identity: MemberIdentity) -> Result<Self> {
        let suite = welcome.cipher_suite;
        if identity.cipher_suite() != suite {
            return Err(MlsError::InvalidGroupState(
                "identity cipher suite does not match welcome".into(),
            ));
        }
        let mut tree = RatchetTree::from_public_nodes(suite, welcome.public_nodes.clone());
        let my_leaf = tree.find_leaf(&identity.key_package).ok_or_else(|| {
            MlsError::InvalidGroupState("own key package not found in welcome tree".into())
        })?;
        let kem_secret = identity
            .kem_secret()
            .ok_or_else(|| MlsError::InvalidGroupState("joiner missing KEM secret".into()))?
            .clone();
        tree.attach_owner(my_leaf, kem_secret.clone())?;

        let joiner = treekem::open_from(
            suite,
            &kem_secret,
            &welcome.encrypted_joiner,
            &Self::path_context(&welcome.group_id, welcome.epoch),
        )?;

        let tree_hash = tree.tree_hash()?;
        let ctx = Self::group_context(&welcome.group_id, welcome.epoch, &tree_hash);
        let epoch_secrets = EpochSecrets::from_joiner(suite, &joiner, &ctx)?;

        Ok(Self {
            suite,
            group_id: welcome.group_id.clone(),
            epoch: welcome.epoch,
            identity,
            tree,
            epoch_secrets,
            send_generation: 0,
        })
    }

    /// Commit a self-update (rekey): rotate this member's direct path and
    /// advance the epoch. Returns the [`TreeKemCommit`] other members process.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] on crypto/tree failure.
    pub fn update(&mut self) -> Result<TreeKemCommit> {
        let path_aad = Self::path_context(&self.group_id, self.epoch);
        let (update_path, commit_secret) = self.tree.generate_update_path(&path_aad, None)?;

        let new_epoch = self.epoch + 1;
        let new_ctx = Self::group_context(&self.group_id, new_epoch, &self.tree.tree_hash()?);
        self.epoch_secrets = self.epoch_secrets.next(&commit_secret, &new_ctx)?;
        self.epoch = new_epoch;
        self.send_generation = 0;
        Ok(TreeKemCommit {
            epoch: new_epoch,
            update_path,
        })
    }

    /// Process another member's [`TreeKemCommit`], advancing to the same epoch
    /// secrets as the committer.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] if the commit's epoch is unexpected or on
    /// crypto/tree failure.
    pub fn process_commit(&mut self, commit: &TreeKemCommit) -> Result<()> {
        let new_epoch = self.epoch + 1;
        if commit.epoch != new_epoch {
            return Err(MlsError::InvalidEpoch {
                expected: new_epoch,
                actual: commit.epoch,
            });
        }
        let path_aad = Self::path_context(&self.group_id, self.epoch);
        let commit_secret = self
            .tree
            .process_update_path(&commit.update_path, &path_aad)?;

        let new_ctx = Self::group_context(&self.group_id, new_epoch, &self.tree.tree_hash()?);
        self.epoch_secrets = self.epoch_secrets.next(&commit_secret, &new_ctx)?;
        self.epoch = new_epoch;
        self.send_generation = 0;
        Ok(())
    }

    /// Encrypt and sign an application message for the group.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] on key derivation, AEAD, or signing failure.
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<ApplicationCiphertext> {
        let sender_leaf = self
            .tree
            .own_leaf()
            .ok_or_else(|| MlsError::InvalidGroupState("group instance owns no leaf".into()))?;
        let generation = self.send_generation;
        self.send_generation = self.send_generation.saturating_add(1);

        let (key, nonce) = self
            .epoch_secrets
            .application_key_and_nonce(sender_leaf, generation)?;
        let cipher = AeadCipher::new(key.to_vec(), self.suite)?;
        let aad = self.message_aad(sender_leaf, generation);
        let ciphertext = cipher.encrypt(&nonce, plaintext, &aad)?;
        let signature = self.identity.sign(&ciphertext)?.to_bytes();

        Ok(ApplicationCiphertext {
            epoch: self.epoch,
            sender_leaf,
            generation,
            ciphertext,
            signature,
        })
    }

    /// Verify and decrypt an application message from another member.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] on epoch mismatch, unknown sender, invalid
    /// signature, or AEAD failure.
    pub fn decrypt_message(&self, message: &ApplicationCiphertext) -> Result<Vec<u8>> {
        if message.epoch != self.epoch {
            return Err(MlsError::InvalidEpoch {
                expected: self.epoch,
                actual: message.epoch,
            });
        }
        let leaf = self.tree.leaf(message.sender_leaf).ok_or_else(|| {
            MlsError::InvalidMessage(format!("unknown sender leaf {}", message.sender_leaf))
        })?;

        // verify the sender's signature over the ciphertext
        let signature = self.reconstruct_signature(&message.signature)?;
        if !leaf
            .key_package
            .verify_signature(&message.ciphertext, &signature)?
        {
            return Err(MlsError::InvalidMessage("invalid message signature".into()));
        }

        let (key, nonce) = self
            .epoch_secrets
            .application_key_and_nonce(message.sender_leaf, message.generation)?;
        let cipher = AeadCipher::new(key.to_vec(), self.suite)?;
        let aad = self.message_aad(message.sender_leaf, message.generation);
        cipher.decrypt(&nonce, &message.ciphertext, &aad)
    }

    /// MLS exporter for this epoch (RFC 9420 §8.5).
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] on HKDF failure.
    pub fn export_secret(&self, label: &str, context: &[u8], length: usize) -> Result<Vec<u8>> {
        self.epoch_secrets.export(label, context, length)
    }

    /// Current epoch.
    #[must_use]
    pub fn epoch(&self) -> EpochNumber {
        self.epoch
    }

    /// Group identifier bytes.
    #[must_use]
    pub fn group_id(&self) -> &[u8] {
        &self.group_id
    }

    /// This member's leaf index.
    #[must_use]
    pub fn own_leaf(&self) -> Option<u32> {
        self.tree.own_leaf()
    }

    /// Number of active members.
    #[must_use]
    pub fn member_count(&self) -> u32 {
        self.tree.active_leaf_count()
    }

    fn reconstruct_signature(&self, bytes: &[u8]) -> Result<Signature> {
        if self.suite.uses_slh_dsa() {
            let sig = SlhDsaSignature::from_bytes(self.suite.slh_dsa_variant(), bytes)
                .map_err(|e| MlsError::CryptoError(format!("invalid SLH-DSA signature: {e:?}")))?;
            Ok(Signature::SlhDsa(sig))
        } else {
            let sig = MlDsaSignature::from_bytes(self.suite.ml_dsa_variant(), bytes)
                .map_err(|e| MlsError::CryptoError(format!("invalid ML-DSA signature: {e:?}")))?;
            Ok(Signature::MlDsa(sig))
        }
    }

    /// Group context for the key schedule: `group_id ‖ epoch ‖ tree_hash`.
    fn group_context(group_id: &[u8], epoch: EpochNumber, tree_hash: &[u8]) -> Vec<u8> {
        let mut ctx = Vec::with_capacity(group_id.len() + 8 + tree_hash.len());
        ctx.extend_from_slice(group_id);
        ctx.extend_from_slice(&epoch.to_be_bytes());
        ctx.extend_from_slice(tree_hash);
        ctx
    }

    /// AAD for UpdatePath / Welcome seals: `group_id ‖ epoch` (no tree hash, to
    /// avoid an ordering dependency on the in-flight rotation).
    fn path_context(group_id: &[u8], epoch: EpochNumber) -> Vec<u8> {
        let mut ctx = Vec::with_capacity(group_id.len() + 8);
        ctx.extend_from_slice(group_id);
        ctx.extend_from_slice(&epoch.to_be_bytes());
        ctx
    }

    fn message_aad(&self, sender_leaf: u32, generation: u32) -> Vec<u8> {
        let mut aad = Vec::with_capacity(self.group_id.len() + 16);
        aad.extend_from_slice(&self.group_id);
        aad.extend_from_slice(&self.epoch.to_be_bytes());
        aad.extend_from_slice(&sender_leaf.to_be_bytes());
        aad.extend_from_slice(&generation.to_be_bytes());
        aad
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::member::MemberId;

    fn identity(suite: CipherSuite) -> MemberIdentity {
        MemberIdentity::generate_with_suite(MemberId::generate(), suite).unwrap()
    }

    #[test]
    fn test_create_and_solo_encrypt_roundtrip() {
        let suite = CipherSuite::default();
        let mut group = TreeKemGroup::create(b"group-1".to_vec(), identity(suite)).unwrap();
        assert_eq!(group.epoch(), 0);
        assert_eq!(group.member_count(), 1);
        let ct = group.encrypt_message(b"hello self").unwrap();
        let pt = group.decrypt_message(&ct).unwrap();
        assert_eq!(pt, b"hello self");
    }

    #[test]
    fn test_welcome_cross_instance_encrypt_decrypt() {
        // The headline acceptance criterion: two independent TreeKemGroup
        // instances reach the same epoch via Welcome and encrypt/decrypt across
        // instances in BOTH directions.
        let suite = CipherSuite::default();
        let alice = identity(suite);
        let bob = identity(suite);

        let mut alice_group = TreeKemGroup::create(b"room".to_vec(), alice).unwrap();
        let welcome = alice_group.add_member(&bob.key_package).unwrap();
        let mut bob_group = TreeKemGroup::from_welcome(&welcome, bob).unwrap();

        assert_eq!(alice_group.epoch(), bob_group.epoch());
        assert_eq!(alice_group.epoch(), 1);

        // Alice -> Bob
        let ct = alice_group.encrypt_message(b"hi bob").unwrap();
        assert_eq!(bob_group.decrypt_message(&ct).unwrap(), b"hi bob");
        // Bob -> Alice
        let ct = bob_group.encrypt_message(b"hi alice").unwrap();
        assert_eq!(alice_group.decrypt_message(&ct).unwrap(), b"hi alice");

        // exporters agree across instances (same epoch secrets)
        assert_eq!(
            alice_group.export_secret("app", b"ctx", 32).unwrap(),
            bob_group.export_secret("app", b"ctx", 32).unwrap()
        );
    }

    #[test]
    fn test_update_commit_advances_both_in_sync() {
        // After joining, a commit (UpdatePath) by one member is processed by the
        // other; both advance to the same new epoch and keep communicating (FS:
        // new epoch; PCS: fresh commit secret).
        let suite = CipherSuite::default();
        let alice = identity(suite);
        let bob = identity(suite);
        let mut alice_group = TreeKemGroup::create(b"room".to_vec(), alice).unwrap();
        let welcome = alice_group.add_member(&bob.key_package).unwrap();
        let mut bob_group = TreeKemGroup::from_welcome(&welcome, bob).unwrap();

        let epoch1_export = alice_group.export_secret("x", b"", 32).unwrap();

        // Bob commits an update; Alice processes it.
        let commit = bob_group.update().unwrap();
        alice_group.process_commit(&commit).unwrap();

        assert_eq!(alice_group.epoch(), 2);
        assert_eq!(bob_group.epoch(), 2);

        // New epoch secrets differ from the old (FS/PCS healing).
        let epoch2_export = alice_group.export_secret("x", b"", 32).unwrap();
        assert_ne!(epoch1_export, epoch2_export);
        assert_eq!(
            epoch2_export,
            bob_group.export_secret("x", b"", 32).unwrap(),
            "both members must share the post-commit epoch secret"
        );

        // and they still encrypt/decrypt at the new epoch
        let ct = alice_group.encrypt_message(b"post-commit").unwrap();
        assert_eq!(bob_group.decrypt_message(&ct).unwrap(), b"post-commit");
    }

    #[test]
    fn test_wrong_epoch_message_rejected() {
        let suite = CipherSuite::default();
        let alice = identity(suite);
        let bob = identity(suite);
        let mut alice_group = TreeKemGroup::create(b"room".to_vec(), alice).unwrap();
        let welcome = alice_group.add_member(&bob.key_package).unwrap();
        let mut bob_group = TreeKemGroup::from_welcome(&welcome, bob).unwrap();

        let ct = alice_group.encrypt_message(b"x").unwrap();
        // Bob advances epoch via his own update; the old-epoch message is rejected.
        let _ = bob_group.update().unwrap();
        assert!(matches!(
            bob_group.decrypt_message(&ct),
            Err(MlsError::InvalidEpoch { .. })
        ));
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let suite = CipherSuite::default();
        let alice = identity(suite);
        let bob = identity(suite);
        let mut alice_group = TreeKemGroup::create(b"room".to_vec(), alice).unwrap();
        let welcome = alice_group.add_member(&bob.key_package).unwrap();
        let bob_group = TreeKemGroup::from_welcome(&welcome, bob).unwrap();

        let mut ct = alice_group.encrypt_message(b"secret").unwrap();
        // Flip a ciphertext byte (after the 12-byte nonce): signature must fail.
        let idx = ct.ciphertext.len() - 1;
        ct.ciphertext[idx] ^= 0xFF;
        assert!(bob_group.decrypt_message(&ct).is_err());
    }
}

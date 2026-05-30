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
//! - [`TreeKemGroup::add_member`] adds a member, returning a signed
//!   [`TreeKemCommit`] for existing members and a [`TreeKemWelcome`] (public
//!   ratchet tree + `joiner_secret` sealed to the new member's key package) for
//!   the joiner.
//! - [`TreeKemGroup::from_welcome`] reconstructs the group on the joiner's side
//!   (after verifying the committer's signature) and lands on the *same* epoch
//!   secrets as the committer.
//! - [`TreeKemGroup::update`] / [`TreeKemGroup::remove_member`] /
//!   [`TreeKemGroup::process_commit`] run signed UpdatePath commits so members
//!   heal (PCS) and advance epochs (FS); a removed member cannot derive the new
//!   epoch.
//! - [`TreeKemGroup::encrypt_message`] / [`TreeKemGroup::decrypt_message`]
//!   protect application messages with per-sender/per-generation keys derived
//!   from the epoch's `encryption_secret`, signed with the sender's identity.
//! - [`TreeKemGroup::to_snapshot_bytes`] / [`TreeKemGroup::from_snapshot_bytes`]
//!   persist and restore a group across process restart (secret material is
//!   opaque and must be encrypted at rest; the long-term identity is re-supplied).
//!
//! This is the type intended to replace the legacy GSS [`crate::group::MlsGroup`]
//! (ADR-002 P5/P6). It deliberately uses the post-quantum primitives only.
//!
//! Commits and Welcomes are authenticated by the committer's signature, and
//! application messages by the sender's signature. Tree integrity is bound
//! three ways: RFC 9420 §7.9 parent hashes are computed along the committer's
//! direct path and folded into the tree hash
//! ([`crate::treekem::RatchetTree::set_parent_hashes`]); the committer signs the
//! resulting tree hash in each commit (receivers recompute and must match it);
//! and `process_update_path` independently verifies every derived node public
//! key. PSK injection, external commits, and reinit remain out of scope per
//! ADR-002.

use crate::{
    crypto::{AeadCipher, CipherSuite, Signature},
    key_schedule::{EpochSecrets, EpochSecretsSnapshot},
    member::{KeyPackage, MemberIdentity},
    treekem::{self, RatchetTree, UpdatePath},
    EpochNumber, MlsError, Result,
};
use saorsa_pqc::api::{MlDsaSignature, SlhDsaSignature};
use serde::{Deserialize, Serialize};

/// Sliding replay window over per-sender message generations (64-slot).
#[derive(Clone, Debug, Default)]
struct ReplayWindow {
    max_seen: u64,
    window: u64,
}

impl ReplayWindow {
    /// Accept `seq` if new within the window and mark it seen; reject replays.
    fn allow_and_update(&mut self, seq: u64) -> bool {
        if seq > self.max_seen {
            let shift = seq - self.max_seen;
            if shift >= 64 {
                self.window = 0;
            } else {
                self.window <<= shift;
            }
            self.window |= 1;
            self.max_seen = seq;
            true
        } else {
            let offset = self.max_seen - seq;
            if offset >= 64 {
                false
            } else {
                let mask = 1u64 << offset;
                if self.window & mask != 0 {
                    false
                } else {
                    self.window |= mask;
                    true
                }
            }
        }
    }
}

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
    /// Per-sender (leaf) received-generation replay windows for the current
    /// epoch; cleared on every epoch change.
    recv_windows: std::collections::HashMap<u32, ReplayWindow>,
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
/// the new member's KEM key, authenticated by the committer's signature.
/// Wire-serializable.
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
    /// Leaf index of the committer who produced this Welcome.
    pub committer_leaf: u32,
    /// Committer's signature over the Welcome contents (see `welcome_tbs`).
    pub signature: Vec<u8>,
}

/// A commit carrying an UpdatePath (member update / rekey / removal),
/// authenticated by the committer's signature. Wire-serializable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeKemCommit {
    /// Epoch this commit produces.
    pub epoch: EpochNumber,
    /// Leaf index of the committer.
    pub committer_leaf: u32,
    /// Members added by this commit, as `(leaf index, key package)`. Existing
    /// members install these leaves (at the stated indices) before processing
    /// the path; the added members themselves receive a separate Welcome.
    pub added: Vec<(u32, KeyPackage)>,
    /// Leaves removed by this commit (blanked before the committer's path is
    /// processed), if any.
    pub removed_leaves: Vec<u32>,
    /// The UpdatePath rotating the committer's direct path.
    pub update_path: UpdatePath,
    /// Tree hash of the committer's tree after applying this commit (including
    /// parent hashes). Receivers recompute and must match it, binding the
    /// committer's signature to the exact resulting tree.
    pub tree_hash_after: Vec<u8>,
    /// Committer's signature over the commit contents (see `commit_tbs`).
    pub signature: Vec<u8>,
}

/// A full persistence snapshot of a [`TreeKemGroup`] (minus the long-term member
/// identity, which the caller re-supplies on restore).
///
/// **Contains raw secret key material** (leaf KEM secret, path secrets, epoch
/// secrets). The caller MUST encrypt this at rest — mirroring how
/// [`crate::member::MemberIdentity`] keeps secret keys `#[serde(skip)]`.
#[derive(Clone, Serialize, Deserialize)]
pub struct TreeKemGroupSnapshot {
    suite: CipherSuite,
    group_id: Vec<u8>,
    epoch: EpochNumber,
    public_nodes: Vec<Option<treekem::Node>>,
    own_leaf: Option<u32>,
    own_leaf_secret: Option<Vec<u8>>,
    path_secrets: Vec<(u32, Vec<u8>)>,
    epoch_secrets: EpochSecretsSnapshot,
    send_generation: u32,
    /// Per-sender replay windows as `(leaf, max_seen, window)`.
    recv_windows: Vec<(u32, u64, u64)>,
}

impl std::fmt::Debug for TreeKemGroupSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact secret material (own_leaf_secret, path_secrets, epoch_secrets).
        f.debug_struct("TreeKemGroupSnapshot")
            .field("suite", &self.suite)
            .field("group_id", &hex::encode(&self.group_id))
            .field("epoch", &self.epoch)
            .field("own_leaf", &self.own_leaf)
            .field("secrets", &"<redacted>")
            .finish_non_exhaustive()
    }
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
            recv_windows: std::collections::HashMap::new(),
        })
    }

    /// Add a new member. Returns a signed [`TreeKemCommit`] that existing
    /// members process (they install the new leaf, then the committer's
    /// UpdatePath) and a [`TreeKemWelcome`] for the new member (who reconstructs
    /// the epoch from the sealed `joiner_secret`). The committer advances to the
    /// next epoch.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] on crypto/tree failure or if the new member's suite
    /// mismatches.
    pub fn add_member(
        &mut self,
        new_member: &KeyPackage,
    ) -> Result<(TreeKemCommit, TreeKemWelcome)> {
        if new_member.cipher_suite != self.suite {
            return Err(MlsError::InvalidGroupState(
                "new member cipher suite mismatch".into(),
            ));
        }
        // Admission control: the new member's key package must be self-consistent
        // (credential ↔ verifying key ↔ agreement key binding).
        if !new_member.verify()? {
            return Err(MlsError::InvalidGroupState(
                "new member key package self-signature is invalid".into(),
            ));
        }
        // Work on a clone; the live group is only mutated once every fallible
        // step below (rotation, signing, sealing, key schedule) has succeeded.
        let mut tree = self.tree.clone();
        let new_leaf = tree.add_leaf(new_member.clone())?;
        let committer_leaf = tree
            .own_leaf()
            .ok_or_else(|| MlsError::InvalidGroupState("committer owns no leaf".into()))?;

        // UpdatePath rooted at the committer; bound to the current (pre-commit)
        // group + epoch as AAD so existing members decrypt under a shared context.
        let path_aad = Self::path_context(&self.group_id, self.epoch);
        let (update_path, commit_secret) = tree.generate_update_path(&path_aad, None)?;

        let new_epoch = self.epoch + 1;
        let added = vec![(new_leaf, new_member.clone())];
        // Tree hash after the rotation (includes parent hashes) — bound into
        // both the commit signature and the key-schedule group context.
        let new_tree_hash = tree.tree_hash()?;

        // Commit for existing members (they add the leaf, then process the path).
        let commit_tbs = Self::commit_tbs(
            &self.group_id,
            new_epoch,
            committer_leaf,
            &added,
            &[],
            &update_path,
            &new_tree_hash,
        )?;
        let commit_signature = self.identity.sign(&commit_tbs)?.to_bytes();
        let commit = TreeKemCommit {
            epoch: new_epoch,
            committer_leaf,
            added,
            removed_leaves: Vec::new(),
            update_path,
            tree_hash_after: new_tree_hash.clone(),
            signature: commit_signature,
        };

        // Welcome for the new member (reconstructs the epoch from joiner_secret).
        let new_ctx = Self::group_context(&self.group_id, new_epoch, &new_tree_hash);
        let joiner = EpochSecrets::joiner_secret(
            self.suite,
            self.epoch_secrets.init_secret(),
            &commit_secret,
        )?;
        let new_epoch_secrets = EpochSecrets::from_joiner(self.suite, &joiner, &new_ctx)?;

        let seal_aad = Self::path_context(&self.group_id, new_epoch);
        let encrypted_joiner =
            treekem::seal_to(self.suite, &new_member.agreement_key, &joiner, &seal_aad)?;
        let public_nodes = tree.export_public_nodes();
        let welcome_tbs = Self::welcome_tbs(
            &self.group_id,
            new_epoch,
            self.suite,
            committer_leaf,
            &public_nodes,
            &encrypted_joiner,
        )?;
        let welcome_signature = self.identity.sign(&welcome_tbs)?.to_bytes();
        let welcome = TreeKemWelcome {
            group_id: self.group_id.clone(),
            epoch: new_epoch,
            cipher_suite: self.suite,
            public_nodes,
            encrypted_joiner,
            committer_leaf,
            signature: welcome_signature,
        };

        // All fallible work succeeded — commit the new state atomically.
        self.tree = tree;
        self.epoch_secrets = new_epoch_secrets;
        self.epoch = new_epoch;
        self.send_generation = 0;
        self.recv_windows.clear();
        Ok((commit, welcome))
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
        // Validate the untrusted public tree (suite/index/key-package checks)
        // before any use; bound the committer leaf before indexing.
        let tree = RatchetTree::from_public_nodes(suite, welcome.public_nodes.clone())?;
        if welcome.committer_leaf >= tree.leaf_capacity() {
            return Err(MlsError::InvalidMessage(
                "welcome committer leaf out of range".into(),
            ));
        }

        // Authenticate the Welcome: the committer (a tree member) must have
        // signed it (including the sealed joiner secret and suite). Verify
        // before trusting any of the conveyed tree state.
        let committer_kp = tree
            .leaf(welcome.committer_leaf)
            .map(|l| &l.key_package)
            .ok_or_else(|| MlsError::InvalidMessage("welcome committer leaf is blank".into()))?;
        let tbs = Self::welcome_tbs(
            &welcome.group_id,
            welcome.epoch,
            suite,
            welcome.committer_leaf,
            &welcome.public_nodes,
            &welcome.encrypted_joiner,
        )?;
        let sig = Self::reconstruct_signature_for(suite, &welcome.signature)?;
        if !committer_kp.verify_signature(&tbs, &sig)? {
            return Err(MlsError::InvalidMessage(
                "invalid welcome committer signature".into(),
            ));
        }

        let mut tree = tree;
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
            recv_windows: std::collections::HashMap::new(),
        })
    }

    /// Commit a self-update (rekey): rotate this member's direct path and
    /// advance the epoch. Returns the signed [`TreeKemCommit`] other members
    /// process.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] on crypto/tree failure.
    pub fn update(&mut self) -> Result<TreeKemCommit> {
        self.make_commit(Vec::new())
    }

    /// Remove the member at `leaf`: blank their leaf and direct path, then
    /// commit a fresh UpdatePath so the removed member cannot derive the new
    /// epoch (forward secrecy on removal). Returns the signed [`TreeKemCommit`].
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] if `leaf` is this member, is blank/out of range, or
    /// on crypto/tree failure.
    pub fn remove_member(&mut self, leaf: u32) -> Result<TreeKemCommit> {
        if self.tree.own_leaf() == Some(leaf) {
            return Err(MlsError::InvalidGroupState(
                "cannot remove self via remove_member".into(),
            ));
        }
        if self.tree.leaf(leaf).is_none() {
            return Err(MlsError::MemberNotFound(crate::member::MemberId::generate()));
        }
        self.make_commit(vec![leaf])
    }

    /// Build, apply, and sign a commit that optionally removes `removed_leaves`
    /// and rotates the committer's direct path.
    fn make_commit(&mut self, removed_leaves: Vec<u32>) -> Result<TreeKemCommit> {
        // Work on a clone; only swap into the live group after all fallible work
        // (blanking, rotation, signing, key schedule) has succeeded.
        let mut tree = self.tree.clone();
        for &leaf in &removed_leaves {
            tree.blank_leaf(leaf)?;
        }
        let committer_leaf = tree
            .own_leaf()
            .ok_or_else(|| MlsError::InvalidGroupState("committer owns no leaf".into()))?;
        let path_aad = Self::path_context(&self.group_id, self.epoch);
        let (update_path, commit_secret) = tree.generate_update_path(&path_aad, None)?;

        let new_epoch = self.epoch + 1;
        let new_tree_hash = tree.tree_hash()?;
        let tbs = Self::commit_tbs(
            &self.group_id,
            new_epoch,
            committer_leaf,
            &[],
            &removed_leaves,
            &update_path,
            &new_tree_hash,
        )?;
        let signature = self.identity.sign(&tbs)?.to_bytes();

        let new_ctx = Self::group_context(&self.group_id, new_epoch, &new_tree_hash);
        let new_epoch_secrets = self.epoch_secrets.next(&commit_secret, &new_ctx)?;

        // All fallible work succeeded — commit the new state atomically.
        self.tree = tree;
        self.epoch_secrets = new_epoch_secrets;
        self.epoch = new_epoch;
        self.send_generation = 0;
        self.recv_windows.clear();
        Ok(TreeKemCommit {
            epoch: new_epoch,
            committer_leaf,
            added: Vec::new(),
            removed_leaves,
            update_path,
            tree_hash_after: new_tree_hash,
            signature,
        })
    }

    /// Process another member's [`TreeKemCommit`], advancing to the same epoch
    /// secrets as the committer. The committer's signature is verified before
    /// any tree state is mutated.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] if the commit's epoch is unexpected, the committer
    /// signature is invalid, this member was the one removed, or on crypto/tree
    /// failure.
    pub fn process_commit(&mut self, commit: &TreeKemCommit) -> Result<()> {
        let new_epoch = self.epoch + 1;
        if commit.epoch != new_epoch {
            return Err(MlsError::InvalidEpoch {
                expected: new_epoch,
                actual: commit.epoch,
            });
        }
        // Bound the attacker-supplied committer leaf before any indexing.
        if commit.committer_leaf >= self.tree.leaf_capacity() {
            return Err(MlsError::InvalidMessage(
                "commit committer leaf out of range".into(),
            ));
        }
        // The UpdatePath must rotate the SAME leaf that signed the commit; a
        // mismatch would let a member (signing as itself) rotate another
        // member's leaf/path. The signature only authenticates `committer_leaf`.
        if commit.update_path.leaf_index != commit.committer_leaf {
            return Err(MlsError::InvalidMessage(
                "commit update_path leaf does not match committer leaf".into(),
            ));
        }
        if commit.removed_leaves.contains(&commit.committer_leaf) {
            return Err(MlsError::InvalidMessage(
                "commit cannot remove its own committer".into(),
            ));
        }

        // Authenticate the committer before touching any state.
        let tbs = Self::commit_tbs(
            &self.group_id,
            new_epoch,
            commit.committer_leaf,
            &commit.added,
            &commit.removed_leaves,
            &commit.update_path,
            &commit.tree_hash_after,
        )?;
        let sig = Self::reconstruct_signature_for(self.suite, &commit.signature)?;
        {
            let committer_kp = self
                .tree
                .leaf(commit.committer_leaf)
                .map(|l| &l.key_package)
                .ok_or_else(|| MlsError::InvalidMessage("commit committer leaf is blank".into()))?;
            if !committer_kp.verify_signature(&tbs, &sig)? {
                return Err(MlsError::InvalidMessage(
                    "invalid commit committer signature".into(),
                ));
            }
        }
        let my_leaf = self
            .tree
            .own_leaf()
            .ok_or_else(|| MlsError::InvalidGroupState("instance owns no leaf".into()))?;
        if commit.removed_leaves.contains(&my_leaf) {
            return Err(MlsError::InvalidGroupState(
                "this member was removed by the commit".into(),
            ));
        }

        // Verify-then-apply: perform all mutations on a working clone and only
        // swap it in if every step succeeds, so a malformed commit can never
        // leave the live tree partially mutated / desynchronized.
        let mut tree = self.tree.clone();
        for (leaf, key_package) in &commit.added {
            if key_package.cipher_suite != self.suite || !key_package.verify()? {
                return Err(MlsError::InvalidMessage(
                    "commit adds an invalid key package".into(),
                ));
            }
            let assigned = tree.add_leaf(key_package.clone())?;
            if assigned != *leaf {
                return Err(MlsError::InvalidGroupState(format!(
                    "added member landed at leaf {assigned}, commit expected {leaf} (tree desync)"
                )));
            }
        }
        for &leaf in &commit.removed_leaves {
            tree.blank_leaf(leaf)?;
        }
        let path_aad = Self::path_context(&self.group_id, self.epoch);
        let commit_secret = tree.process_update_path(&commit.update_path, &path_aad)?;
        // Explicit tree-integrity check: our recomputed tree hash (incl. parent
        // hashes) must equal the committer-signed value.
        let new_tree_hash = tree.tree_hash()?;
        if new_tree_hash != commit.tree_hash_after {
            return Err(MlsError::InvalidMessage(
                "commit tree hash does not match committer signature".into(),
            ));
        }
        let new_ctx = Self::group_context(&self.group_id, new_epoch, &new_tree_hash);
        let new_epoch_secrets = self.epoch_secrets.next(&commit_secret, &new_ctx)?;

        // All checks passed — commit the new state atomically.
        self.tree = tree;
        self.epoch_secrets = new_epoch_secrets;
        self.epoch = new_epoch;
        self.send_generation = 0;
        self.recv_windows.clear();
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
        // A reused (sender_leaf, generation) within an epoch would reuse the AEAD
        // key+nonce — refuse rather than saturate. Callers must rekey (commit a
        // new epoch) before this limit.
        self.send_generation = self.send_generation.checked_add(1).ok_or_else(|| {
            MlsError::ProtocolError("epoch send-generation exhausted; rekey required".into())
        })?;

        let (key, nonce) = self
            .epoch_secrets
            .application_key_and_nonce(sender_leaf, generation)?;
        let cipher = AeadCipher::new(key.to_vec(), self.suite)?;
        let aad = self.message_aad(sender_leaf, generation);
        let ciphertext = cipher.encrypt(&nonce, plaintext, &aad)?;
        // Sign the full envelope (epoch ‖ sender ‖ generation ‖ group_id ‖ ct),
        // not just the ciphertext, so the signature commits to the metadata too.
        let signature = self
            .identity
            .sign(&Self::message_tbs(
                &self.group_id,
                self.epoch,
                sender_leaf,
                generation,
                &ciphertext,
            ))?
            .to_bytes();

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
    /// Takes `&mut self` to record the sender's message generation for replay
    /// protection: a generation already seen from that sender in the current
    /// epoch is rejected. Replay state is per-epoch (cleared on epoch change)
    /// and is captured in [`Self::to_snapshot`].
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] on epoch mismatch, unknown sender, invalid
    /// signature, AEAD failure, or a replayed generation.
    pub fn decrypt_message(&mut self, message: &ApplicationCiphertext) -> Result<Vec<u8>> {
        if message.epoch != self.epoch {
            return Err(MlsError::InvalidEpoch {
                expected: self.epoch,
                actual: message.epoch,
            });
        }
        let leaf = self.tree.leaf(message.sender_leaf).ok_or_else(|| {
            MlsError::InvalidMessage(format!("unknown sender leaf {}", message.sender_leaf))
        })?;

        // verify the sender's signature over the full envelope
        let signature = Self::reconstruct_signature_for(self.suite, &message.signature)?;
        let tbs = Self::message_tbs(
            &self.group_id,
            message.epoch,
            message.sender_leaf,
            message.generation,
            &message.ciphertext,
        );
        if !leaf.key_package.verify_signature(&tbs, &signature)? {
            return Err(MlsError::InvalidMessage("invalid message signature".into()));
        }

        let (key, nonce) = self
            .epoch_secrets
            .application_key_and_nonce(message.sender_leaf, message.generation)?;
        let cipher = AeadCipher::new(key.to_vec(), self.suite)?;
        let aad = self.message_aad(message.sender_leaf, message.generation);
        let plaintext = cipher.decrypt(&nonce, &message.ciphertext, &aad)?;

        // Replay protection: reject a generation already accepted from this
        // sender in this epoch. Done only after authentication succeeds.
        if !self
            .recv_windows
            .entry(message.sender_leaf)
            .or_default()
            .allow_and_update(u64::from(message.generation))
        {
            return Err(MlsError::ProtocolError(
                "replayed message generation".into(),
            ));
        }

        Ok(plaintext)
    }

    /// MLS exporter for this epoch (RFC 9420 §8.5).
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] on HKDF failure.
    pub fn export_secret(&self, label: &str, context: &[u8], length: usize) -> Result<Vec<u8>> {
        self.epoch_secrets.export(label, context, length)
    }

    /// Capture a full persistence [`TreeKemGroupSnapshot`] (survives process
    /// restart). **Contains secret material — encrypt at rest.**
    #[must_use]
    pub fn to_snapshot(&self) -> TreeKemGroupSnapshot {
        let (own_leaf, own_leaf_secret, path_secrets) = self.tree.secret_state();
        TreeKemGroupSnapshot {
            suite: self.suite,
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            public_nodes: self.tree.export_public_nodes(),
            own_leaf,
            own_leaf_secret,
            path_secrets,
            epoch_secrets: self.epoch_secrets.snapshot(),
            send_generation: self.send_generation,
            recv_windows: self
                .recv_windows
                .iter()
                .map(|(&leaf, w)| (leaf, w.max_seen, w.window))
                .collect(),
        }
    }

    /// Serialize a snapshot to opaque bytes. **Encrypt at rest.**
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] on serialization failure.
    pub fn to_snapshot_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_stdvec(&self.to_snapshot())
            .map_err(|e| MlsError::SerializationError(e.to_string()))
    }

    /// Restore a group from a snapshot, re-supplying the member's long-term
    /// identity (kept in the caller's keystore, not in the snapshot).
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] if the suite mismatches, the snapshot's owner leaf
    /// does not match `identity`, or the leaf KEM secret is invalid.
    pub fn from_snapshot(snapshot: TreeKemGroupSnapshot, identity: MemberIdentity) -> Result<Self> {
        let suite = snapshot.suite;
        if identity.cipher_suite() != suite {
            return Err(MlsError::InvalidGroupState(
                "identity cipher suite does not match snapshot".into(),
            ));
        }
        let mut tree = RatchetTree::from_public_nodes(suite, snapshot.public_nodes)?;
        tree.restore_secret_state(
            snapshot.own_leaf,
            snapshot.own_leaf_secret,
            snapshot.path_secrets,
        )?;
        // The restored owner leaf must carry this identity's key package.
        let owner_ok = snapshot.own_leaf.is_some_and(|leaf| {
            tree.leaf(leaf)
                .is_some_and(|l| l.key_package == identity.key_package)
        });
        if !owner_ok {
            return Err(MlsError::InvalidGroupState(
                "identity does not match the snapshot's owner leaf".into(),
            ));
        }
        let epoch_secrets = EpochSecrets::from_snapshot(snapshot.epoch_secrets);
        Ok(Self {
            suite,
            group_id: snapshot.group_id,
            epoch: snapshot.epoch,
            identity,
            tree,
            epoch_secrets,
            send_generation: snapshot.send_generation,
            recv_windows: snapshot
                .recv_windows
                .into_iter()
                .map(|(leaf, max_seen, window)| (leaf, ReplayWindow { max_seen, window }))
                .collect(),
        })
    }

    /// Restore a group from snapshot bytes produced by [`Self::to_snapshot_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] on deserialization failure or snapshot/identity
    /// mismatch.
    pub fn from_snapshot_bytes(bytes: &[u8], identity: MemberIdentity) -> Result<Self> {
        let snapshot: TreeKemGroupSnapshot = postcard::from_bytes(bytes)
            .map_err(|e| MlsError::DeserializationError(e.to_string()))?;
        Self::from_snapshot(snapshot, identity)
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

    fn reconstruct_signature_for(suite: CipherSuite, bytes: &[u8]) -> Result<Signature> {
        if suite.uses_slh_dsa() {
            let sig = SlhDsaSignature::from_bytes(suite.slh_dsa_variant()?, bytes)
                .map_err(|e| MlsError::CryptoError(format!("invalid SLH-DSA signature: {e:?}")))?;
            Ok(Signature::SlhDsa(sig))
        } else {
            let sig = MlDsaSignature::from_bytes(suite.ml_dsa_variant()?, bytes)
                .map_err(|e| MlsError::CryptoError(format!("invalid ML-DSA signature: {e:?}")))?;
            Ok(Signature::MlDsa(sig))
        }
    }

    /// Bytes signed by the committer for a [`TreeKemCommit`]: a domain-separated,
    /// length-prefixed encoding of group id, new epoch, committer leaf, removed
    /// leaves, and the full UpdatePath (which determines the resulting tree).
    #[allow(clippy::too_many_arguments)]
    fn commit_tbs(
        group_id: &[u8],
        new_epoch: EpochNumber,
        committer_leaf: u32,
        added: &[(u32, KeyPackage)],
        removed_leaves: &[u32],
        update_path: &UpdatePath,
        tree_hash_after: &[u8],
    ) -> Result<Vec<u8>> {
        let mut tbs = Vec::new();
        tbs.extend_from_slice(b"saorsa-mls TreeKemCommit v1");
        push_field(&mut tbs, group_id)?;
        tbs.extend_from_slice(&new_epoch.to_be_bytes());
        tbs.extend_from_slice(&committer_leaf.to_be_bytes());
        let added_bytes = postcard::to_stdvec(&added.to_vec())
            .map_err(|e| MlsError::SerializationError(e.to_string()))?;
        push_field(&mut tbs, &added_bytes)?;
        let removed_bytes: Vec<u8> = removed_leaves
            .iter()
            .flat_map(|l| l.to_be_bytes())
            .collect();
        push_field(&mut tbs, &removed_bytes)?;
        let path_bytes = postcard::to_stdvec(update_path)
            .map_err(|e| MlsError::SerializationError(e.to_string()))?;
        push_field(&mut tbs, &path_bytes)?;
        push_field(&mut tbs, tree_hash_after)?;
        Ok(tbs)
    }

    /// Bytes signed by the committer for a [`TreeKemWelcome`]: group id, epoch,
    /// committer leaf, and the public ratchet tree.
    fn welcome_tbs(
        group_id: &[u8],
        epoch: EpochNumber,
        suite: CipherSuite,
        committer_leaf: u32,
        public_nodes: &[Option<treekem::Node>],
        encrypted_joiner: &treekem::HpkeCiphertext,
    ) -> Result<Vec<u8>> {
        let mut tbs = Vec::new();
        tbs.extend_from_slice(b"saorsa-mls TreeKemWelcome v1");
        push_field(&mut tbs, group_id)?;
        tbs.extend_from_slice(&epoch.to_be_bytes());
        tbs.extend_from_slice(&suite.id().as_u16().to_be_bytes());
        tbs.extend_from_slice(&committer_leaf.to_be_bytes());
        let nodes_bytes = postcard::to_stdvec(public_nodes)
            .map_err(|e| MlsError::SerializationError(e.to_string()))?;
        push_field(&mut tbs, &nodes_bytes)?;
        let joiner_bytes = postcard::to_stdvec(encrypted_joiner)
            .map_err(|e| MlsError::SerializationError(e.to_string()))?;
        push_field(&mut tbs, &joiner_bytes)?;
        Ok(tbs)
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

    /// Bytes signed by the sender of an application message: a domain-separated
    /// encoding binding the group, epoch, sender leaf, generation, and the
    /// ciphertext (placed last, so no inner length prefix is needed).
    fn message_tbs(
        group_id: &[u8],
        epoch: EpochNumber,
        sender_leaf: u32,
        generation: u32,
        ciphertext: &[u8],
    ) -> Vec<u8> {
        let mut tbs = Vec::with_capacity(group_id.len() + ciphertext.len() + 48);
        tbs.extend_from_slice(b"saorsa-mls AppMessage v1");
        tbs.extend_from_slice(&(group_id.len() as u64).to_be_bytes());
        tbs.extend_from_slice(group_id);
        tbs.extend_from_slice(&epoch.to_be_bytes());
        tbs.extend_from_slice(&sender_leaf.to_be_bytes());
        tbs.extend_from_slice(&generation.to_be_bytes());
        tbs.extend_from_slice(ciphertext);
        tbs
    }
}

/// Append `data` to `buf` with a 4-byte big-endian length prefix, so the
/// signed-content encoding is unambiguous. Errors (rather than silently
/// truncating) if `data` exceeds `u32::MAX` bytes, which would desynchronize the
/// signer and verifier.
fn push_field(buf: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    let len = u32::try_from(data.len())
        .map_err(|_| MlsError::SerializationError("signed field exceeds u32::MAX".into()))?;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
    Ok(())
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
        let (_commit, welcome) = alice_group.add_member(&bob.key_package).unwrap();
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
        let (_commit, welcome) = alice_group.add_member(&bob.key_package).unwrap();
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
        let (_commit, welcome) = alice_group.add_member(&bob.key_package).unwrap();
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
        let (_commit, welcome) = alice_group.add_member(&bob.key_package).unwrap();
        let mut bob_group = TreeKemGroup::from_welcome(&welcome, bob).unwrap();

        let mut ct = alice_group.encrypt_message(b"secret").unwrap();
        // Flip a ciphertext byte (after the 12-byte nonce): signature must fail.
        let idx = ct.ciphertext.len() - 1;
        ct.ciphertext[idx] ^= 0xFF;
        assert!(bob_group.decrypt_message(&ct).is_err());
    }

    #[test]
    fn test_three_members_converge_via_commit() {
        // Alice adds Bob, then adds Carol; existing member Bob processes the
        // second commit while Carol joins via Welcome. All three land on the
        // same epoch and exchange messages.
        let suite = CipherSuite::default();
        let alice = identity(suite);
        let bob = identity(suite);
        let carol = identity(suite);

        let mut alice_group = TreeKemGroup::create(b"room".to_vec(), alice).unwrap();
        let (_c1, w1) = alice_group.add_member(&bob.key_package).unwrap();
        let mut bob_group = TreeKemGroup::from_welcome(&w1, bob).unwrap();

        let (c2, w2) = alice_group.add_member(&carol.key_package).unwrap();
        bob_group.process_commit(&c2).unwrap();
        let mut carol_group = TreeKemGroup::from_welcome(&w2, carol).unwrap();

        assert_eq!(alice_group.epoch(), 2);
        assert_eq!(bob_group.epoch(), 2);
        assert_eq!(carol_group.epoch(), 2);
        assert_eq!(alice_group.member_count(), 3);

        // Carol -> {Alice, Bob}
        let ct = carol_group.encrypt_message(b"hello all").unwrap();
        assert_eq!(alice_group.decrypt_message(&ct).unwrap(), b"hello all");
        assert_eq!(bob_group.decrypt_message(&ct).unwrap(), b"hello all");

        // exporters agree across all three
        let ea = alice_group.export_secret("x", b"", 32).unwrap();
        assert_eq!(ea, bob_group.export_secret("x", b"", 32).unwrap());
        assert_eq!(ea, carol_group.export_secret("x", b"", 32).unwrap());
    }

    #[test]
    fn test_forged_welcome_signature_rejected() {
        let suite = CipherSuite::default();
        let alice = identity(suite);
        let bob = identity(suite);
        let mut alice_group = TreeKemGroup::create(b"room".to_vec(), alice).unwrap();
        let (_c, mut welcome) = alice_group.add_member(&bob.key_package).unwrap();
        welcome.signature[0] ^= 0xFF;
        assert!(TreeKemGroup::from_welcome(&welcome, bob).is_err());
    }

    #[test]
    fn test_forged_commit_signature_rejected() {
        let suite = CipherSuite::default();
        let alice = identity(suite);
        let bob = identity(suite);
        let mut alice_group = TreeKemGroup::create(b"room".to_vec(), alice).unwrap();
        let (_c, w) = alice_group.add_member(&bob.key_package).unwrap();
        let mut bob_group = TreeKemGroup::from_welcome(&w, bob).unwrap();

        let mut commit = alice_group.update().unwrap();
        commit.signature[0] ^= 0xFF;
        assert!(bob_group.process_commit(&commit).is_err());
        // bob's epoch must be unchanged after a rejected commit
        assert_eq!(bob_group.epoch(), 1);
    }

    #[test]
    fn test_remove_member_forward_secrecy() {
        let suite = CipherSuite::default();
        let alice = identity(suite);
        let bob = identity(suite);
        let mut alice_group = TreeKemGroup::create(b"room".to_vec(), alice).unwrap();
        let (_c, w) = alice_group.add_member(&bob.key_package).unwrap();
        let mut bob_group = TreeKemGroup::from_welcome(&w, bob).unwrap();
        let bob_leaf = bob_group.own_leaf().unwrap();

        // Alice removes Bob and commits a fresh path.
        let commit = alice_group.remove_member(bob_leaf).unwrap();
        assert_eq!(alice_group.epoch(), 2);
        assert_eq!(alice_group.member_count(), 1);

        // Bob cannot process a commit that removed him.
        assert!(bob_group.process_commit(&commit).is_err());
        assert_eq!(
            bob_group.epoch(),
            1,
            "removed member stays at the old epoch"
        );

        // Alice (solo) still operates at the new epoch; Bob's stale epoch-1 keys
        // cannot decrypt it.
        let ct = alice_group.encrypt_message(b"after removal").unwrap();
        assert!(matches!(
            bob_group.decrypt_message(&ct),
            Err(MlsError::InvalidEpoch { .. })
        ));
    }

    #[test]
    fn test_snapshot_restore_roundtrip() {
        // A serialized group restores to a functionally identical group (the
        // member re-supplies their long-term identity).
        let suite = CipherSuite::default();
        let alice = identity(suite);
        let bob = identity(suite);
        let mut alice_group = TreeKemGroup::create(b"room".to_vec(), alice).unwrap();
        let (_c, w) = alice_group.add_member(&bob.key_package).unwrap();
        let bob_group = TreeKemGroup::from_welcome(&w, bob.clone()).unwrap();

        // Snapshot Bob, then restore from the opaque bytes.
        let snapshot = bob_group.to_snapshot_bytes().unwrap();
        let mut restored = TreeKemGroup::from_snapshot_bytes(&snapshot, bob).unwrap();
        assert_eq!(restored.epoch(), bob_group.epoch());
        assert_eq!(restored.own_leaf(), bob_group.own_leaf());

        // The restored group still decrypts Alice's messages...
        let ct = alice_group.encrypt_message(b"to restored bob").unwrap();
        assert_eq!(restored.decrypt_message(&ct).unwrap(), b"to restored bob");
        // ...and Alice decrypts the restored group's messages.
        let ct = restored.encrypt_message(b"from restored bob").unwrap();
        assert_eq!(
            alice_group.decrypt_message(&ct).unwrap(),
            b"from restored bob"
        );
        // exporter agreement confirms identical epoch secrets
        assert_eq!(
            restored.export_secret("x", b"", 32).unwrap(),
            alice_group.export_secret("x", b"", 32).unwrap()
        );
    }

    #[test]
    fn test_snapshot_rejects_wrong_identity() {
        let suite = CipherSuite::default();
        let alice = identity(suite);
        let bob = identity(suite);
        let eve = identity(suite);
        let mut alice_group = TreeKemGroup::create(b"room".to_vec(), alice).unwrap();
        let (_c, w) = alice_group.add_member(&bob.key_package).unwrap();
        let bob_group = TreeKemGroup::from_welcome(&w, bob).unwrap();
        let snapshot = bob_group.to_snapshot_bytes().unwrap();
        // Eve cannot adopt Bob's snapshot.
        assert!(TreeKemGroup::from_snapshot_bytes(&snapshot, eve).is_err());
    }

    #[test]
    fn test_wire_serialized_welcome_and_message() {
        // Cross-"process": everything crosses the wire as postcard bytes. Bob
        // joins from serialized Welcome bytes and decrypts a serialized message.
        let suite = CipherSuite::default();
        let alice = identity(suite);
        let bob = identity(suite);
        let mut alice_group = TreeKemGroup::create(b"room".to_vec(), alice).unwrap();
        let (_commit, welcome) = alice_group.add_member(&bob.key_package).unwrap();

        let welcome_bytes = postcard::to_stdvec(&welcome).unwrap();
        let welcome_wire: TreeKemWelcome = postcard::from_bytes(&welcome_bytes).unwrap();
        let mut bob_group = TreeKemGroup::from_welcome(&welcome_wire, bob).unwrap();

        let ct = alice_group.encrypt_message(b"over the wire").unwrap();
        let ct_bytes = postcard::to_stdvec(&ct).unwrap();
        let ct_wire: ApplicationCiphertext = postcard::from_bytes(&ct_bytes).unwrap();
        assert_eq!(
            bob_group.decrypt_message(&ct_wire).unwrap(),
            b"over the wire"
        );
    }

    // ---- adversarial / authentication tests (P5 review hardening) ----

    fn two_member_group() -> (TreeKemGroup, TreeKemGroup, MemberIdentity) {
        let suite = CipherSuite::default();
        let alice = identity(suite);
        let bob = identity(suite);
        let mut alice_group = TreeKemGroup::create(b"room".to_vec(), alice).unwrap();
        let (_c, w) = alice_group.add_member(&bob.key_package).unwrap();
        let bob_group = TreeKemGroup::from_welcome(&w, bob.clone()).unwrap();
        (alice_group, bob_group, bob)
    }

    #[test]
    fn test_committer_leaf_spoofing_rejected() {
        // 3-member group; Bob crafts a commit claiming to be Alice (committer
        // leaf 0) but signs with his own key. Carol must reject it.
        let suite = CipherSuite::default();
        let alice = identity(suite);
        let bob = identity(suite);
        let carol = identity(suite);
        let mut alice_group = TreeKemGroup::create(b"room".to_vec(), alice).unwrap();
        let (_c1, w1) = alice_group.add_member(&bob.key_package).unwrap();
        let mut bob_group = TreeKemGroup::from_welcome(&w1, bob).unwrap();
        let (c2, w2) = alice_group.add_member(&carol.key_package).unwrap();
        bob_group.process_commit(&c2).unwrap();
        let mut carol_group = TreeKemGroup::from_welcome(&w2, carol).unwrap();

        let mut spoofed = bob_group.update().unwrap();
        spoofed.committer_leaf = 0; // claim to be Alice
        assert!(
            carol_group.process_commit(&spoofed).is_err(),
            "a commit signed by Bob but claiming Alice's leaf must be rejected"
        );
    }

    #[test]
    fn test_cross_group_commit_rejected() {
        // A commit from one group must not apply in another (group_id is in the
        // signed TBS).
        let suite = CipherSuite::default();
        let alice1 = identity(suite);
        let bob1 = identity(suite);
        let mut g1 = TreeKemGroup::create(b"group-1".to_vec(), alice1).unwrap();
        let (_c, w1) = g1.add_member(&bob1.key_package).unwrap();
        let mut bob_g1 = TreeKemGroup::from_welcome(&w1, bob1).unwrap();

        let alice2 = identity(suite);
        let bob2 = identity(suite);
        let mut g2 = TreeKemGroup::create(b"group-2".to_vec(), alice2).unwrap();
        let (_c2, _w2) = g2.add_member(&bob2.key_package).unwrap();

        let commit_g2 = g2.update().unwrap();
        // bob_g1 (a different group) must reject g2's commit.
        assert!(bob_g1.process_commit(&commit_g2).is_err());
    }

    #[test]
    fn test_cross_group_message_rejected() {
        // The same identity in two groups: a message from group A must not
        // decrypt in group B (group_id binds the signature TBS and the AEAD AAD).
        let suite = CipherSuite::default();
        let alice = identity(suite);
        let bob = identity(suite);
        let mut a1 = TreeKemGroup::create(b"group-A".to_vec(), alice.clone()).unwrap();
        let (_c1, w1) = a1.add_member(&bob.key_package).unwrap();
        let _b1 = TreeKemGroup::from_welcome(&w1, bob.clone()).unwrap();

        let mut a2 = TreeKemGroup::create(b"group-B".to_vec(), alice).unwrap();
        let (_c2, w2) = a2.add_member(&bob.key_package).unwrap();
        let mut b2 = TreeKemGroup::from_welcome(&w2, bob).unwrap();

        let msg_from_a1 = a1.encrypt_message(b"group A secret").unwrap();
        // Deliver a group-A message into the group-B instance.
        assert!(b2.decrypt_message(&msg_from_a1).is_err());
    }

    #[test]
    fn test_commit_replay_rejected() {
        let (mut alice_group, mut bob_group, _bob) = two_member_group();
        let commit = alice_group.update().unwrap();
        bob_group.process_commit(&commit).unwrap();
        assert_eq!(bob_group.epoch(), 2);
        // Replaying the same commit must be rejected (epoch already advanced).
        assert!(matches!(
            bob_group.process_commit(&commit),
            Err(MlsError::InvalidEpoch { .. })
        ));
    }

    #[test]
    fn test_sender_leaf_spoofing_rejected() {
        let (mut alice_group, mut bob_group, _bob) = two_member_group();
        let mut msg = alice_group.encrypt_message(b"from alice").unwrap();
        // Claim the message came from Bob's leaf (1) instead of Alice's (0).
        msg.sender_leaf = 1;
        assert!(
            bob_group.decrypt_message(&msg).is_err(),
            "a message signed by Alice but claiming Bob's leaf must be rejected"
        );
    }

    #[test]
    fn test_tampered_encrypted_joiner_rejected() {
        // The committer signs the sealed joiner secret; tampering it must fail
        // the Welcome signature (closes the MITM joiner-swap gap).
        let suite = CipherSuite::default();
        let alice = identity(suite);
        let bob = identity(suite);
        let mut alice_group = TreeKemGroup::create(b"room".to_vec(), alice).unwrap();
        let (_c, mut welcome) = alice_group.add_member(&bob.key_package).unwrap();
        welcome.encrypted_joiner.aead_ct[0] ^= 0xFF;
        assert!(TreeKemGroup::from_welcome(&welcome, bob).is_err());
    }

    #[test]
    fn test_tampered_commit_tree_hash_rejected() {
        // tree_hash_after is in the committer-signed TBS; tampering it must fail
        // the signature (and would also fail the explicit tree-hash check).
        let (mut alice_group, mut bob_group, _bob) = two_member_group();
        let mut commit = alice_group.update().unwrap();
        commit.tree_hash_after[0] ^= 0xFF;
        assert!(bob_group.process_commit(&commit).is_err());
        assert_eq!(
            bob_group.epoch(),
            1,
            "rejected commit must not advance epoch"
        );
    }

    #[test]
    fn test_hostile_sender_leaf_does_not_panic() {
        // A message claiming sender_leaf = u32::MAX must be rejected cleanly,
        // not panic/wrap (review: unchecked leaf * 2).
        let (mut alice_group, mut bob_group, _bob) = two_member_group();
        let mut msg = alice_group.encrypt_message(b"x").unwrap();
        msg.sender_leaf = u32::MAX;
        assert!(bob_group.decrypt_message(&msg).is_err());
    }

    #[test]
    fn test_remove_member_hostile_index_does_not_panic() {
        let (mut alice_group, _bob_group, _bob) = two_member_group();
        assert!(alice_group.remove_member(u32::MAX).is_err());
        assert_eq!(
            alice_group.epoch(),
            1,
            "failed remove must not advance epoch"
        );
    }

    #[test]
    fn test_commit_path_leaf_must_match_committer() {
        // A commit signed as one member but whose UpdatePath rotates a different
        // leaf must be rejected (review finding #1).
        let (mut alice_group, mut bob_group, _bob) = two_member_group();
        let mut commit = alice_group.update().unwrap();
        // Point the UpdatePath at a different leaf than the (signed) committer.
        commit.update_path.leaf_index = 1;
        assert!(bob_group.process_commit(&commit).is_err());
        assert_eq!(
            bob_group.epoch(),
            1,
            "rejected commit must not advance epoch"
        );
    }

    #[test]
    fn test_application_message_replay_rejected() {
        // The same ciphertext must not be accepted twice within an epoch.
        let (mut alice_group, mut bob_group, _bob) = two_member_group();
        let ct = alice_group.encrypt_message(b"once").unwrap();
        assert_eq!(bob_group.decrypt_message(&ct).unwrap(), b"once");
        assert!(
            matches!(
                bob_group.decrypt_message(&ct),
                Err(MlsError::ProtocolError(_))
            ),
            "replaying a message generation must be rejected"
        );
        // A fresh message (new generation) is still accepted.
        let ct2 = alice_group.encrypt_message(b"twice").unwrap();
        assert_eq!(bob_group.decrypt_message(&ct2).unwrap(), b"twice");
    }

    #[test]
    fn test_replay_window_survives_snapshot() {
        // Replay state is captured in the snapshot, so a restored group still
        // rejects a replay of a pre-snapshot message.
        let suite = CipherSuite::default();
        let alice = identity(suite);
        let bob = identity(suite);
        let mut alice_group = TreeKemGroup::create(b"room".to_vec(), alice).unwrap();
        let (_c, w) = alice_group.add_member(&bob.key_package).unwrap();
        let mut bob_group = TreeKemGroup::from_welcome(&w, bob.clone()).unwrap();

        let ct = alice_group.encrypt_message(b"msg").unwrap();
        bob_group.decrypt_message(&ct).unwrap();
        let snapshot = bob_group.to_snapshot_bytes().unwrap();
        let mut restored = TreeKemGroup::from_snapshot_bytes(&snapshot, bob).unwrap();
        assert!(
            restored.decrypt_message(&ct).is_err(),
            "restored group must still reject a replayed message"
        );
    }

    #[test]
    fn test_out_of_range_committer_leaf_rejected() {
        let (_alice_group, mut bob_group, _bob) = two_member_group();
        let suite = CipherSuite::default();
        let mut alice2 = TreeKemGroup::create(b"room".to_vec(), identity(suite)).unwrap();
        let (_c, _w) = alice2.add_member(&identity(suite).key_package).unwrap();
        let mut commit = alice2.update().unwrap();
        commit.committer_leaf = u32::MAX; // hostile index must not panic
        assert!(bob_group.process_commit(&commit).is_err());
    }
}

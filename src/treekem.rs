// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
//! Real `TreeKEM` ratchet tree (RFC 9420 subset, post-quantum).
//!
//! This module implements the public ratchet-tree structure and the
//! cryptographic primitives that make real forward secrecy (FS) and
//! post-compromise security (PCS) possible, per
//! [ADR-002](../../docs/adr/ADR-002-real-treekem-for-forward-secrecy-and-pcs.md).
//!
//! Scope of this module (phases P2–P3):
//!
//! - [`treemath`]: RFC 9420 Appendix C array-based tree math. The tree is kept
//!   as a **perfect** binary tree (its leaf count is always rounded up to a
//!   power of two, with trailing blank leaves), which is what makes the simple
//!   `parent`/`left`/`right`/`sibling` index formulas correct — see the note
//!   on that module.
//! - [`Node`]/[`RatchetTree`]: the tree state — the public nodes (each carrying
//!   a KEM public key, leaves bound to a member [`KeyPackage`]) plus this
//!   member's private path secrets and owned-leaf secret key.
//! - [`derive_key_pair`]: deterministic `DeriveKeyPair` — turns a node secret
//!   into the *same* ML-KEM keypair for every member who learns that secret.
//! - [`RatchetTree::tree_hash`]: a deterministic hash over the public tree state.
//! - [`RatchetTree::generate_update_path`] / [`RatchetTree::process_update_path`]
//!   (P3): the UpdatePath mechanism that delivers forward secrecy and
//!   post-compromise security — a committer rotates its direct path and seals a
//!   fresh path secret to each copath subtree, and every other member derives
//!   the same `commit_secret`.
//!
//! The key-schedule chaining that consumes `commit_secret` into epoch secrets is
//! phase P4; Welcome / `from_welcome` / serde are phase P5.

use crate::{
    crypto::{AeadCipher, CipherSuite, Hash, KeySchedule},
    member::KeyPackage,
    MlsError, Result,
};
use saorsa_pqc::api::{MlKem, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Upper bound on the number of leaves (members) a ratchet tree may hold.
///
/// Bounding the leaf count keeps every node/leaf index and the array width well
/// within `u32` (the backing array has at most `2 * MAX_LEAVES - 1` nodes), so
/// the `u32` index arithmetic in this module cannot overflow or truncate in
/// practice. Matches the crate-wide [`crate::MAX_GROUP_SIZE`].
pub const MAX_LEAVES: u32 = 1 << 16;

/// A member's exported private tree state: `(own_leaf, own_leaf_secret_bytes,
/// path_secret_bytes_by_node)`. **Secret material — encrypt at rest.** Returned
/// by [`RatchetTree::secret_state`] and consumed by
/// [`RatchetTree::restore_secret_state`].
pub type SecretState = (Option<u32>, Option<Vec<u8>>, Vec<(u32, Vec<u8>)>);

/// RFC 9420 Appendix C array-based tree math.
///
/// The tree is represented as a flat array of nodes for a **perfect** binary
/// tree: a tree with `L` leaves where `L` is a power of two has `2*L - 1`
/// nodes. Leaves sit at the even indices `0, 2, 4, …` and parents at the odd
/// indices. The "width" passed to these functions is that node count
/// (`2*L - 1`); because the tree is perfect, the bare `parent_step` formula and
/// the `left`/`right` formulas are exact for every in-range node (no
/// incomplete-tree special-casing is needed — that is the whole reason the tree
/// is padded to a power of two).
pub mod treemath {
    use crate::{MlsError, Result};

    /// `floor(log2(x))`; defined as `0` for `x == 0` to match RFC 9420.
    #[must_use]
    pub fn log2(x: u32) -> u32 {
        if x == 0 {
            0
        } else {
            31 - x.leading_zeros()
        }
    }

    /// Level of a node: leaves are level 0, their parents level 1, etc.
    /// Equal to the number of trailing one-bits of the index.
    #[must_use]
    pub fn level(x: u32) -> u32 {
        x.trailing_ones()
    }

    /// True if `x` is a leaf (even index).
    #[must_use]
    pub fn is_leaf(x: u32) -> bool {
        x & 1 == 0
    }

    /// Node index of leaf number `leaf`.
    ///
    /// Uses saturating multiplication so a hostile/oversized `leaf` can never
    /// wrap and alias a valid node index; an out-of-range leaf maps to an
    /// out-of-range (or odd) node index that downstream lookups treat as blank.
    #[must_use]
    pub fn leaf_to_node(leaf: u32) -> u32 {
        leaf.saturating_mul(2)
    }

    /// Leaf number of leaf node `x`.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::TreeKemError`] if `x` is not a leaf node.
    pub fn node_to_leaf(x: u32) -> Result<u32> {
        if is_leaf(x) {
            Ok(x / 2)
        } else {
            Err(MlsError::TreeKemError(format!(
                "node {x} is not a leaf node"
            )))
        }
    }

    /// Node count of a perfect tree holding at least `leaves` leaves
    /// (`2 * next_pow2(leaves) - 1`). `leaves == 0` is treated as one leaf.
    #[must_use]
    pub fn width_for_leaves(leaves: u32) -> u32 {
        let l = leaves.max(1).next_power_of_two();
        2 * l - 1
    }

    /// Index of the root node of a tree whose array `width` is the node count.
    #[must_use]
    pub fn root(width: u32) -> u32 {
        (1 << log2(width)) - 1
    }

    /// Left child of intermediate node `x`.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::TreeKemError`] if `x` is a leaf (has no children).
    pub fn left(x: u32) -> Result<u32> {
        let k = level(x);
        if k == 0 {
            return Err(MlsError::TreeKemError(format!(
                "leaf node {x} has no children"
            )));
        }
        Ok(x ^ (1 << (k - 1)))
    }

    /// Right child of intermediate node `x`.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::TreeKemError`] if `x` is a leaf (has no children).
    pub fn right(x: u32) -> Result<u32> {
        let k = level(x);
        if k == 0 {
            return Err(MlsError::TreeKemError(format!(
                "leaf node {x} has no children"
            )));
        }
        Ok(x ^ (3 << (k - 1)))
    }

    /// Parent of node `x` in a perfect tree of node count `width`.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::TreeKemError`] if `x` is the root (has no parent).
    pub fn parent(x: u32, width: u32) -> Result<u32> {
        if x == root(width) {
            return Err(MlsError::TreeKemError(format!(
                "root node {x} has no parent"
            )));
        }
        let k = level(x);
        let b = (x >> (k + 1)) & 1;
        Ok((x | (1 << k)) ^ (b << (k + 1)))
    }

    /// Sibling of node `x` (the other child of its parent).
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::TreeKemError`] if `x` is the root.
    pub fn sibling(x: u32, width: u32) -> Result<u32> {
        let p = parent(x, width)?;
        if x < p {
            right(p)
        } else {
            left(p)
        }
    }

    /// Direct path of `x`: the parents from `x` up to and including the root,
    /// ordered leaf → root. Empty if `x` is the root.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::TreeKemError`] on internal tree-math inconsistency.
    pub fn direct_path(x: u32, width: u32) -> Result<Vec<u32>> {
        let r = root(width);
        let mut path = Vec::new();
        let mut cur = x;
        while cur != r {
            cur = parent(cur, width)?;
            path.push(cur);
        }
        Ok(path)
    }

    /// Copath of `x`: the siblings of `x` and of each node on its direct path
    /// (excluding the root), ordered to align with `[x] ++ direct_path` minus
    /// the root. Empty if `x` is the root.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::TreeKemError`] on internal tree-math inconsistency.
    pub fn copath(x: u32, width: u32) -> Result<Vec<u32>> {
        if x == root(width) {
            return Ok(Vec::new());
        }
        let mut nodes = vec![x];
        nodes.extend(direct_path(x, width)?);
        nodes.pop(); // drop the root; it has no sibling
        nodes.into_iter().map(|y| sibling(y, width)).collect()
    }
}

/// A node in the ratchet tree. Holds only **public** material, so it is safe to
/// serialize and ship in a Welcome / ratchet-tree extension.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Node {
    /// A leaf node bound to a member's key package.
    Leaf(LeafNodeData),
    /// An intermediate (parent) node holding a derived KEM public key.
    Parent(ParentNodeData),
}

/// Public data carried by a leaf node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeafNodeData {
    /// ML-KEM public key bytes for this leaf (equals
    /// `key_package.agreement_key`).
    pub encryption_key: Vec<u8>,
    /// The member's key package bound to this leaf.
    pub key_package: KeyPackage,
}

/// Public data carried by an intermediate (parent) node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParentNodeData {
    /// ML-KEM public key bytes for this node (derived during an UpdatePath).
    pub encryption_key: Vec<u8>,
    /// Parent hash binding this node to its position (RFC 9420 §7.9).
    pub parent_hash: Vec<u8>,
    /// Leaves added since this node's key was last set, not yet merged into it.
    pub unmerged_leaves: Vec<u32>,
}

/// The ratchet-tree state held by one member of a group.
///
/// The `nodes` array is the **public** tree (KEM public keys and key packages),
/// identical across all members. The remaining fields are this member's
/// **private** view: the leaf it owns and the path secrets / leaf secret key it
/// is entitled to. Private material is redacted from the [`Debug`] impl and the
/// path secrets are zeroized on drop.
#[derive(Clone)]
pub struct RatchetTree {
    suite: CipherSuite,
    /// Perfect-tree array of `2*L - 1` slots (`L` a power of two). `None` marks
    /// a blank node.
    nodes: Vec<Option<Node>>,
    /// The leaf index owned by this member, if this instance is a participant
    /// (as opposed to a public-tree-only view).
    own_leaf: Option<u32>,
    /// Secret key for this member's own leaf (rotates when the member commits an
    /// UpdatePath). Derived from the member's `KeyPackage` initially.
    own_leaf_secret: Option<MlKemSecretKey>,
    /// Path secrets this member knows, keyed by node index. The member can
    /// re-derive each node's KEM keypair from its path secret via
    /// [`derive_key_pair`].
    path_secrets: std::collections::BTreeMap<u32, zeroize::Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for RatchetTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RatchetTree")
            .field("suite", &self.suite)
            .field("width", &self.width())
            .field("active_leaves", &self.active_leaf_count())
            .field("own_leaf", &self.own_leaf)
            .field("path_secrets", &"<redacted>")
            .field("own_leaf_secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl RatchetTree {
    /// Build a new single-member tree for `creator`.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] if the key package cipher suite does not match
    /// `suite`.
    pub fn new(creator: KeyPackage, suite: CipherSuite) -> Result<Self> {
        if creator.cipher_suite != suite {
            return Err(MlsError::TreeKemError(
                "creator key package cipher suite does not match tree suite".to_string(),
            ));
        }
        let mut tree = Self {
            suite,
            nodes: vec![None],
            own_leaf: None,
            own_leaf_secret: None,
            path_secrets: std::collections::BTreeMap::new(),
        };
        tree.set_leaf_node(0, creator);
        Ok(tree)
    }

    /// Mark `leaf` as owned by this member and attach the leaf's KEM secret key
    /// (from the member's `KeyPackage`), enabling UpdatePath processing.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] if `leaf` is blank/out of range.
    pub fn attach_owner(&mut self, leaf: u32, leaf_kem_secret: MlKemSecretKey) -> Result<()> {
        if self.leaf(leaf).is_none() {
            return Err(MlsError::TreeKemError(format!(
                "cannot own blank/out-of-range leaf {leaf}"
            )));
        }
        self.own_leaf = Some(leaf);
        self.own_leaf_secret = Some(leaf_kem_secret);
        Ok(())
    }

    /// The leaf index owned by this member, if any.
    #[must_use]
    pub fn own_leaf(&self) -> Option<u32> {
        self.own_leaf
    }

    /// Export the public node array (no private material) for shipping in a
    /// Welcome or ratchet-tree extension.
    #[must_use]
    pub fn export_public_nodes(&self) -> Vec<Option<Node>> {
        self.nodes.clone()
    }

    /// Reconstruct a public-only tree (no owner, no secrets) from an exported
    /// node array — the joiner's starting point before [`Self::attach_owner`].
    ///
    /// Validates the untrusted node array: the length must be a valid
    /// perfect-tree width (`2^k - 1`); every leaf node's key package must match
    /// `suite`, be self-consistent (`KeyPackage::verify`), and sit at an even
    /// index; every parent node must sit at an odd index with in-range
    /// `unmerged_leaves`. This is the admission/sanity gate that keeps later
    /// tree math and signature checks panic-free on hostile input.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] if the node array is malformed or any leaf key
    /// package is invalid for `suite`.
    pub fn from_public_nodes(suite: CipherSuite, nodes: Vec<Option<Node>>) -> Result<Self> {
        let width = nodes.len() as u64;
        // width must be 2^(k+1) - 1 (a perfect-tree node count), and fit u32.
        if width == 0 || width > u64::from(u32::MAX) || (width + 1).count_ones() != 1 {
            return Err(MlsError::TreeKemError(format!(
                "invalid ratchet-tree node count {width}"
            )));
        }
        let leaf_capacity = width.div_ceil(2) as u32;
        for (idx, node) in nodes.iter().enumerate() {
            let idx = idx as u32;
            match node {
                Some(Node::Leaf(data)) => {
                    if idx & 1 != 0 {
                        return Err(MlsError::TreeKemError(format!(
                            "leaf node at odd index {idx}"
                        )));
                    }
                    if data.key_package.cipher_suite != suite {
                        return Err(MlsError::TreeKemError(
                            "leaf key package cipher suite does not match tree".to_string(),
                        ));
                    }
                    // NOTE: `encryption_key` legitimately diverges from
                    // `key_package.agreement_key` once a member's leaf has been
                    // rotated by an UpdatePath, so we do NOT require equality.
                    if !data.key_package.verify().unwrap_or(false) {
                        return Err(MlsError::TreeKemError(
                            "leaf key package self-signature is invalid".to_string(),
                        ));
                    }
                }
                Some(Node::Parent(data)) => {
                    if idx & 1 == 0 {
                        return Err(MlsError::TreeKemError(format!(
                            "parent node at even index {idx}"
                        )));
                    }
                    if data.unmerged_leaves.iter().any(|&l| l >= leaf_capacity) {
                        return Err(MlsError::TreeKemError(
                            "parent unmerged_leaves index out of range".to_string(),
                        ));
                    }
                }
                None => {}
            }
        }
        Ok(Self {
            suite,
            nodes,
            own_leaf: None,
            own_leaf_secret: None,
            path_secrets: std::collections::BTreeMap::new(),
        })
    }

    /// Find the leaf index owned by `key_package`, matching on the **stable
    /// public keys** (`verifying_key` + `agreement_key`) rather than full
    /// key-package equality.
    ///
    /// This is deliberate: ML-DSA signing is randomized, so a re-derived or
    /// restored identity ([`crate::member::MemberIdentity::from_seed`] /
    /// `from_secret_bytes`) yields the same public keys but a different
    /// key-package signature. The signed key package's own integrity is checked
    /// separately in [`Self::from_public_nodes`]; the pair
    /// `(verifying_key, agreement_key)` uniquely identifies a member's leaf.
    #[must_use]
    pub fn find_leaf(&self, key_package: &KeyPackage) -> Option<u32> {
        (0..self.leaf_capacity()).find(|&leaf| {
            self.leaf(leaf).is_some_and(|data| {
                data.key_package.verifying_key == key_package.verifying_key
                    && data.key_package.agreement_key == key_package.agreement_key
            })
        })
    }

    /// The signature verifying key bytes for the member at `leaf`, if present.
    #[must_use]
    pub fn leaf_verifying_key(&self, leaf: u32) -> Option<&[u8]> {
        self.leaf(leaf)
            .map(|data| data.key_package.verifying_key.as_slice())
    }

    /// Export this member's **private** state (owned leaf, leaf KEM secret bytes,
    /// and per-node path secret bytes) for persistence.
    ///
    /// **Returns raw secret key material** — the caller MUST encrypt it at rest.
    #[must_use]
    pub fn secret_state(&self) -> SecretState {
        let leaf_secret = self.own_leaf_secret.as_ref().map(|k| k.to_bytes().to_vec());
        let path = self
            .path_secrets
            .iter()
            .map(|(idx, secret)| (*idx, secret.to_vec()))
            .collect();
        (self.own_leaf, leaf_secret, path)
    }

    /// Restore this member's private state captured by [`Self::secret_state`].
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] if the leaf KEM secret bytes are invalid for the
    /// tree's cipher suite.
    pub fn restore_secret_state(
        &mut self,
        own_leaf: Option<u32>,
        own_leaf_secret: Option<Vec<u8>>,
        path_secrets: Vec<(u32, Vec<u8>)>,
    ) -> Result<()> {
        let width = self.width();
        if let Some(leaf) = own_leaf {
            if leaf >= self.leaf_capacity() || self.leaf(leaf).is_none() {
                return Err(MlsError::TreeKemError(format!(
                    "snapshot owner leaf {leaf} is out of range or blank"
                )));
            }
        }
        // Path secrets are keyed by parent (odd) node indices within the tree.
        for (idx, _) in &path_secrets {
            if *idx >= width || idx & 1 == 0 {
                return Err(MlsError::TreeKemError(format!(
                    "snapshot path secret has invalid node index {idx}"
                )));
            }
        }
        self.own_leaf = own_leaf;
        self.own_leaf_secret = match own_leaf_secret {
            Some(bytes) => Some(
                MlKemSecretKey::from_bytes(self.suite.ml_kem_variant(), &bytes).map_err(|e| {
                    MlsError::CryptoError(format!("invalid leaf KEM secret: {e:?}"))
                })?,
            ),
            None => None,
        };
        self.path_secrets = path_secrets
            .into_iter()
            .map(|(idx, secret)| (idx, zeroize::Zeroizing::new(secret)))
            .collect();
        Ok(())
    }

    /// Cipher suite this tree is pinned to.
    #[must_use]
    pub fn cipher_suite(&self) -> CipherSuite {
        self.suite
    }

    /// Node count of the backing perfect-tree array (`2*L - 1`).
    #[must_use]
    pub fn width(&self) -> u32 {
        self.nodes.len() as u32
    }

    /// Number of leaf slots in the tree (`L`, a power of two; includes blanks).
    #[must_use]
    pub fn leaf_capacity(&self) -> u32 {
        // width = 2*L - 1  =>  L = (width + 1) / 2 = ceil(width / 2)
        self.width().div_ceil(2)
    }

    /// Number of non-blank leaves (active members).
    #[must_use]
    pub fn active_leaf_count(&self) -> u32 {
        (0..self.leaf_capacity())
            .filter(|&leaf| matches!(self.node(treemath::leaf_to_node(leaf)), Some(Node::Leaf(_))))
            .count() as u32
    }

    /// Borrow the node at array index `idx`, if present and non-blank.
    #[must_use]
    pub fn node(&self, idx: u32) -> Option<&Node> {
        self.nodes.get(idx as usize).and_then(Option::as_ref)
    }

    /// Borrow the leaf node for `leaf`, if present and non-blank.
    ///
    /// Returns `None` for any out-of-range `leaf` (including hostile values)
    /// before any index arithmetic.
    #[must_use]
    pub fn leaf(&self, leaf: u32) -> Option<&LeafNodeData> {
        if leaf >= self.leaf_capacity() {
            return None;
        }
        match self.node(treemath::leaf_to_node(leaf)) {
            Some(Node::Leaf(data)) => Some(data),
            _ => None,
        }
    }

    /// Add a member at the leftmost blank leaf (or extend the tree), returning
    /// the assigned leaf index.
    ///
    /// Per RFC 9420, the new leaf is added to the `unmerged_leaves` of every
    /// non-blank node on its direct path; those parents' KEM keys are only
    /// refreshed by a subsequent UpdatePath/Commit (phase P3).
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] if the key package cipher suite does not match the
    /// tree, or if the group would exceed [`MAX_LEAVES`], or on internal
    /// tree-math inconsistency.
    pub fn add_leaf(&mut self, key_package: KeyPackage) -> Result<u32> {
        if key_package.cipher_suite != self.suite {
            return Err(MlsError::TreeKemError(
                "key package cipher suite does not match tree suite".to_string(),
            ));
        }

        let leaf_index = self
            .first_blank_leaf()
            .unwrap_or_else(|| self.leaf_capacity());
        if leaf_index >= MAX_LEAVES {
            return Err(MlsError::TreeKemError(format!(
                "group would exceed MAX_LEAVES ({MAX_LEAVES})"
            )));
        }
        // `set_leaf_node` grows the backing array to fit `leaf_index`.
        self.set_leaf_node(leaf_index, key_package);

        // Register the new leaf as unmerged in each non-blank ancestor, keeping
        // the list sorted so the tree hash is independent of insertion order.
        let width = self.width();
        for ancestor in treemath::direct_path(treemath::leaf_to_node(leaf_index), width)? {
            if let Some(Node::Parent(parent)) = self.nodes[ancestor as usize].as_mut() {
                if let Err(pos) = parent.unmerged_leaves.binary_search(&leaf_index) {
                    parent.unmerged_leaves.insert(pos, leaf_index);
                }
            }
        }

        Ok(leaf_index)
    }

    /// Blank the leaf `leaf` and its entire direct path (used on member
    /// removal — the path's KEM keys are re-established by the removing
    /// member's Commit in phase P3).
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] if `leaf` is out of range or blank, or on internal
    /// tree-math inconsistency.
    pub fn blank_leaf(&mut self, leaf: u32) -> Result<()> {
        // Range-check before `leaf_to_node` (leaf * 2) so a huge index cannot
        // wrap and alias a valid occupied node.
        if leaf >= self.leaf_capacity() {
            return Err(MlsError::TreeKemError(format!(
                "leaf {leaf} is out of range"
            )));
        }
        let leaf_node = treemath::leaf_to_node(leaf);
        if self.node(leaf_node).is_none() {
            return Err(MlsError::TreeKemError(format!(
                "leaf {leaf} is already blank or out of range"
            )));
        }
        let width = self.width();
        self.nodes[leaf_node as usize] = None;
        for ancestor in treemath::direct_path(leaf_node, width)? {
            self.nodes[ancestor as usize] = None;
        }
        Ok(())
    }

    /// Deterministic hash over the public tree state (RFC 9420 §7.8 shape).
    ///
    /// Two instances with the same public tree produce the same hash; any
    /// change to a node's public key, a leaf's key package, or the tree shape
    /// changes the hash.
    ///
    /// Note: like the rest of this crate, the hash is computed with BLAKE3
    /// (via [`struct@Hash`]) regardless of the cipher suite's advertised hash field —
    /// see the crate-level note on hash agility. This is self-consistent for
    /// all in-stack members (every member hashes identically), but it means the
    /// suite's hash field is not honoured here; cross-stack interop is out of
    /// scope per ADR-002 and a per-suite hash is tracked for the P4 key-schedule
    /// rework.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] on serialization or internal tree-math failure.
    pub fn tree_hash(&self) -> Result<Vec<u8>> {
        self.tree_hash_node(treemath::root(self.width()))
    }

    fn tree_hash_node(&self, idx: u32) -> Result<Vec<u8>> {
        let hasher = Hash::new(self.suite);
        let mut input = Vec::new();
        if treemath::is_leaf(idx) {
            input.push(0x01); // leaf marker
            match self.node(idx) {
                Some(Node::Leaf(data)) => {
                    input.push(0x01); // present
                                      // bind the (rotating) leaf KEM key as well as the stable
                                      // key package, so an UpdatePath leaf rotation changes the hash
                    push_len_prefixed(&mut input, &data.encryption_key);
                    let kp = postcard::to_stdvec(&data.key_package)
                        .map_err(|e| MlsError::SerializationError(e.to_string()))?;
                    push_len_prefixed(&mut input, &kp);
                }
                _ => input.push(0x00), // blank
            }
        } else {
            input.push(0x02); // parent marker
            match self.node(idx) {
                Some(Node::Parent(data)) => {
                    input.push(0x01); // present
                    push_len_prefixed(&mut input, &data.encryption_key);
                    push_len_prefixed(&mut input, &data.parent_hash);
                    let mut unmerged = Vec::new();
                    for leaf in &data.unmerged_leaves {
                        unmerged.extend_from_slice(&leaf.to_be_bytes());
                    }
                    push_len_prefixed(&mut input, &unmerged);
                }
                _ => input.push(0x00), // blank
            }
            let left_hash = self.tree_hash_node(treemath::left(idx)?)?;
            let right_hash = self.tree_hash_node(treemath::right(idx)?)?;
            push_len_prefixed(&mut input, &left_hash);
            push_len_prefixed(&mut input, &right_hash);
        }
        Ok(hasher.hash(&input))
    }

    fn first_blank_leaf(&self) -> Option<u32> {
        (0..self.leaf_capacity()).find(|&leaf| self.node(treemath::leaf_to_node(leaf)).is_none())
    }

    /// Recompute RFC 9420 §7.9 parent hashes along `leaf`'s direct path after
    /// its node keys have been (re)installed by an UpdatePath.
    ///
    /// Each path node's `parent_hash` binds it to (a) its parent's encryption
    /// key, (b) its parent's own parent hash, and (c) the tree hash of its
    /// sibling subtree — the standard chain that prevents tree-grafting /
    /// node-relocation attacks. The root's parent hash is empty. The values are
    /// a deterministic function of public state, so committer and members agree
    /// and the result is folded into [`Self::tree_hash`].
    ///
    /// Conformance note: RFC 9420 §7.9 uses the *original* sibling tree hash (the
    /// sibling subtree with the committer's `unmerged_leaves` filtered out); this
    /// implementation uses the current sibling tree hash. It is fully
    /// deterministic and identical across all in-stack members (convergence and
    /// the signed `tree_hash_after` binding hold), and is a deliberate
    /// simplification since IETF wire interop is out of scope (ADR-002). The
    /// filtering rule would be required before any cross-stack interop claim.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] on internal tree-math/serialization failure.
    pub fn set_parent_hashes(&mut self, leaf: u32) -> Result<()> {
        let width = self.width();
        let leaf_node = treemath::leaf_to_node(leaf);
        let direct = treemath::direct_path(leaf_node, width)?;
        let copath = treemath::copath(leaf_node, width)?;
        let Some(&root_idx) = direct.last() else {
            return Ok(()); // single-leaf tree: no parent nodes
        };
        if let Some(Node::Parent(p)) = self.nodes[root_idx as usize].as_mut() {
            p.parent_hash = Vec::new(); // root has no parent
        }
        // Walk from just-below-root down to the leaf's parent, so each node's
        // parent (one step closer to the root) already has its parent hash set.
        for i in (0..direct.len().saturating_sub(1)).rev() {
            let parent_idx = direct[i + 1];
            let sibling_idx = copath[i + 1];
            let (parent_enc, parent_ph) = match self.node(parent_idx) {
                Some(Node::Parent(p)) => (p.encryption_key.clone(), p.parent_hash.clone()),
                _ => {
                    return Err(MlsError::TreeKemError(format!(
                        "parent-hash: node {parent_idx} is not a populated parent"
                    )))
                }
            };
            let sibling_hash = self.tree_hash_node(sibling_idx)?;
            let parent_hash = self.parent_hash_input(&parent_enc, &parent_ph, &sibling_hash);
            if let Some(Node::Parent(p)) = self.nodes[direct[i] as usize].as_mut() {
                p.parent_hash = parent_hash;
            }
        }
        Ok(())
    }

    /// `Hash(ParentHashInput{ encryption_key, parent_hash, original_sibling_tree_hash })`
    /// (RFC 9420 §7.9), length-prefixed for unambiguous encoding.
    fn parent_hash_input(
        &self,
        encryption_key: &[u8],
        parent_hash: &[u8],
        sibling_tree_hash: &[u8],
    ) -> Vec<u8> {
        let hasher = Hash::new(self.suite);
        let mut input = Vec::new();
        push_len_prefixed(&mut input, encryption_key);
        push_len_prefixed(&mut input, parent_hash);
        push_len_prefixed(&mut input, sibling_tree_hash);
        hasher.hash(&input)
    }

    /// Grow the backing array so the perfect tree can hold `leaf_index`.
    fn grow_to_fit(&mut self, leaf_index: u32) {
        let required = treemath::width_for_leaves(leaf_index + 1) as usize;
        if self.nodes.len() < required {
            self.nodes.resize(required, None);
        }
    }

    fn set_leaf_node(&mut self, leaf: u32, key_package: KeyPackage) {
        self.grow_to_fit(leaf);
        let idx = treemath::leaf_to_node(leaf) as usize;
        self.nodes[idx] = Some(Node::Leaf(LeafNodeData {
            encryption_key: key_package.agreement_key.clone(),
            key_package,
        }));
    }

    fn set_leaf_encryption_key(&mut self, leaf: u32, key: Vec<u8>) -> Result<()> {
        let idx = treemath::leaf_to_node(leaf) as usize;
        match self.nodes.get_mut(idx).and_then(Option::as_mut) {
            Some(Node::Leaf(data)) => {
                data.encryption_key = key;
                Ok(())
            }
            _ => Err(MlsError::TreeKemError(format!(
                "leaf {leaf} is blank; cannot set encryption key"
            ))),
        }
    }

    /// The current KEM public key for node `idx` (leaf or parent).
    fn node_public_key(&self, idx: u32) -> Result<Vec<u8>> {
        match self.node(idx) {
            Some(Node::Leaf(d)) => Ok(d.encryption_key.clone()),
            Some(Node::Parent(d)) => Ok(d.encryption_key.clone()),
            None => Err(MlsError::TreeKemError(format!("node {idx} is blank"))),
        }
    }

    /// Resolution of `node` per RFC 9420 §7.6: the ordered list of non-blank
    /// node indices that cover the subtree rooted at `node` for encryption. A
    /// non-blank node resolves to itself (plus its unmerged leaves); a blank
    /// parent resolves to the concatenation of its children's resolutions; a
    /// blank leaf resolves to nothing.
    fn resolution(&self, node: u32) -> Result<Vec<u32>> {
        match self.node(node) {
            Some(Node::Leaf(_)) => Ok(vec![node]),
            Some(Node::Parent(p)) => {
                let mut out = vec![node];
                for &leaf in &p.unmerged_leaves {
                    out.push(treemath::leaf_to_node(leaf));
                }
                Ok(out)
            }
            None => {
                if treemath::is_leaf(node) {
                    Ok(Vec::new())
                } else {
                    let mut out = self.resolution(treemath::left(node)?)?;
                    out.extend(self.resolution(treemath::right(node)?)?);
                    Ok(out)
                }
            }
        }
    }

    /// `DeriveSecret(secret, label)` — fixed-length HKDF-Expand used to chain
    /// path secrets and to derive the commit secret.
    fn derive_secret(&self, secret: &[u8], label: &str) -> Result<Vec<u8>> {
        KeySchedule::new(self.suite).derive_secret(secret, label, &[])
    }

    /// Is `node` an ancestor of `descendant` (or equal to it)?
    fn is_ancestor_or_self(&self, node: u32, descendant: u32, width: u32) -> Result<bool> {
        if node == descendant {
            return Ok(true);
        }
        Ok(treemath::direct_path(descendant, width)?.contains(&node))
    }

    /// The KEM secret key this member holds for `node`, if any: its own leaf
    /// secret, or a key derived from a known path secret.
    fn secret_for_node(&self, node: u32) -> Result<Option<MlKemSecretKey>> {
        if Some(node) == self.own_leaf.map(treemath::leaf_to_node) {
            return Ok(self.own_leaf_secret.clone());
        }
        if let Some(ps) = self.path_secrets.get(&node) {
            let (_pub, sk) = derive_key_pair(self.suite, ps)?;
            return Ok(Some(sk));
        }
        Ok(None)
    }

    /// Generate an UpdatePath rooted at this member's leaf (an MLS Commit's path
    /// component): sample a fresh leaf secret, rotate the leaf and every node on
    /// the direct path to the root with freshly derived KEM keypairs, and seal
    /// each path secret to the resolution of the corresponding copath node.
    ///
    /// Returns the [`UpdatePath`] to broadcast and the resulting `commit_secret`
    /// (the input to the next epoch's key schedule — phase P4). This is the
    /// mechanism that delivers post-compromise security: an attacker who lacks
    /// the fresh leaf secret cannot derive the new `commit_secret`.
    ///
    /// `group_context` is bound as AEAD associated data on every sealed path
    /// secret; callers (the group layer, P4/P5) pass the group id and epoch so a
    /// sealed secret cannot be replayed into another group or epoch. Receivers
    /// must pass the identical context to [`Self::process_update_path`].
    ///
    /// `leaf_secret_seed` is normally `None` (fresh randomness); tests may pass a
    /// fixed seed for determinism.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] if this instance owns no leaf, or on crypto/tree
    /// failure.
    pub fn generate_update_path(
        &mut self,
        group_context: &[u8],
        leaf_secret_seed: Option<&[u8]>,
    ) -> Result<(UpdatePath, zeroize::Zeroizing<Vec<u8>>)> {
        let leaf = self
            .own_leaf
            .ok_or_else(|| MlsError::TreeKemError("instance owns no leaf".to_string()))?;
        let width = self.width();
        let leaf_node = treemath::leaf_to_node(leaf);
        let direct = treemath::direct_path(leaf_node, width)?;
        let copath = treemath::copath(leaf_node, width)?;

        // fresh leaf secret + rotated leaf keypair
        let leaf_secret = zeroize::Zeroizing::new(
            leaf_secret_seed
                .map(<[u8]>::to_vec)
                .unwrap_or_else(|| crate::crypto::random_bytes(self.suite.hash_size())),
        );
        let (leaf_pub, leaf_sk) = derive_key_pair(self.suite, &leaf_secret)?;

        // Chain a path secret + keypair for each direct-path node into local
        // buffers first; the tree is only mutated once everything below succeeds
        // (so a mid-way crypto failure cannot leave a half-rotated tree).
        let mut prev = leaf_secret;
        let mut new_parents: Vec<(u32, Vec<u8>, zeroize::Zeroizing<Vec<u8>>)> = Vec::new();
        for &dn in &direct {
            let ps = zeroize::Zeroizing::new(self.derive_secret(&prev, "path")?);
            let (pub_i, _sk_i) = derive_key_pair(self.suite, &ps)?;
            new_parents.push((dn, pub_i, ps.clone()));
            prev = ps;
        }
        let commit_secret = zeroize::Zeroizing::new(self.derive_secret(&prev, "path")?);

        // Seal each path secret to the resolution of the matching copath node.
        // Resolutions are computed against the pre-rotation tree (copath nodes
        // are untouched by this commit), so the order matches the receiver's.
        let mut up_nodes = Vec::with_capacity(direct.len());
        for ((_, pub_i, ps_i), &cn) in new_parents.iter().zip(copath.iter()) {
            let recipients = self.resolution(cn)?;
            let mut cts = Vec::with_capacity(recipients.len());
            for r in recipients {
                let rpub = self.node_public_key(r)?;
                cts.push(seal_to(self.suite, &rpub, ps_i, group_context)?);
            }
            up_nodes.push(UpdatePathNode {
                encryption_key: pub_i.clone(),
                encrypted_path_secret: cts,
            });
        }

        // Everything succeeded — commit the rotation to the tree and our secrets.
        self.set_leaf_encryption_key(leaf, leaf_pub.clone())?;
        self.own_leaf_secret = Some(leaf_sk);
        self.path_secrets.clear();
        for (dn, pub_i, ps) in new_parents {
            self.nodes[dn as usize] = Some(Node::Parent(ParentNodeData {
                encryption_key: pub_i,
                parent_hash: Vec::new(),
                unmerged_leaves: Vec::new(),
            }));
            self.path_secrets.insert(dn, ps);
        }
        // Bind the rotated path with RFC 9420 parent hashes (folded into tree_hash).
        self.set_parent_hashes(leaf)?;

        Ok((
            UpdatePath {
                leaf_index: leaf,
                leaf_encryption_key: leaf_pub,
                nodes: up_nodes,
            },
            commit_secret,
        ))
    }

    /// Process an [`UpdatePath`] produced by another member's
    /// [`Self::generate_update_path`], installing the new public keys and deriving the
    /// same `commit_secret` the committer computed.
    ///
    /// This is the forward-secrecy / post-compromise-security mechanism on the
    /// receiving side: only a member entitled to a copath subtree can decrypt
    /// the path secret sealed to it, and from it derive the new epoch's secret.
    ///
    /// `group_context` must match the value the committer passed to
    /// [`Self::generate_update_path`] (it is verified as AEAD associated data).
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] if this instance owns no leaf, if `update_path`
    /// references an out-of-range committer leaf, if no path secret is
    /// decryptable by this member, if a derived public key does not match the
    /// committer's, or on crypto/tree failure. On error the tree is left
    /// unmodified (verify-then-apply).
    pub fn process_update_path(
        &mut self,
        update_path: &UpdatePath,
        group_context: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let my_leaf = self
            .own_leaf
            .ok_or_else(|| MlsError::TreeKemError("instance owns no leaf".to_string()))?;
        if update_path.leaf_index == my_leaf {
            return Err(MlsError::TreeKemError(
                "cannot process own UpdatePath; use the commit_secret from generate".to_string(),
            ));
        }
        // Bound the attacker-supplied committer leaf index BEFORE any tree math:
        // an out-of-range value would otherwise drive `direct_path` past the
        // array (out-of-bounds) or, for huge values, into a non-terminating
        // parent walk. Must be an existing (non-blank) leaf.
        if update_path.leaf_index >= self.leaf_capacity()
            || self.leaf(update_path.leaf_index).is_none()
        {
            return Err(MlsError::TreeKemError(format!(
                "UpdatePath references invalid committer leaf {}",
                update_path.leaf_index
            )));
        }
        let width = self.width();
        let my_node = treemath::leaf_to_node(my_leaf);
        let committer_node = treemath::leaf_to_node(update_path.leaf_index);
        let direct = treemath::direct_path(committer_node, width)?;
        let copath = treemath::copath(committer_node, width)?;
        if update_path.nodes.len() != direct.len() {
            return Err(MlsError::TreeKemError(
                "UpdatePath length does not match direct path".to_string(),
            ));
        }

        // Find the overlap copath node whose subtree contains my leaf, and
        // decrypt the path secret sealed to it. Read-only against the current
        // tree (copath nodes are not on the committer's direct path).
        let mut decrypted: Option<(usize, zeroize::Zeroizing<Vec<u8>>)> = None;
        for (i, &cn) in copath.iter().enumerate() {
            if !self.is_ancestor_or_self(cn, my_node, width)? {
                continue;
            }
            let recipients = self.resolution(cn)?;
            for (j, &r) in recipients.iter().enumerate() {
                if let Some(sk) = self.secret_for_node(r)? {
                    let ct = update_path.nodes[i]
                        .encrypted_path_secret
                        .get(j)
                        .ok_or_else(|| {
                            MlsError::TreeKemError(
                                "missing ciphertext for resolution slot".to_string(),
                            )
                        })?;
                    let ps = open_from(self.suite, &sk, ct, group_context)?;
                    decrypted = Some((i, zeroize::Zeroizing::new(ps)));
                    break;
                }
            }
            if decrypted.is_some() {
                break;
            }
        }
        let (start, ps_start) = decrypted.ok_or_else(|| {
            MlsError::TreeKemError("no decryptable path secret for this member".to_string())
        })?;

        // Re-derive path secrets from the overlap up to the root, verifying each
        // derived public key matches the committer's, into a local buffer. The
        // tree is only mutated after every check passes (verify-then-apply).
        let mut prev = ps_start;
        let mut derived: Vec<(u32, zeroize::Zeroizing<Vec<u8>>)> = Vec::new();
        for (i, (&dn, node)) in direct
            .iter()
            .zip(update_path.nodes.iter())
            .enumerate()
            .skip(start)
        {
            let ps = if i == start {
                prev.clone()
            } else {
                zeroize::Zeroizing::new(self.derive_secret(&prev, "path")?)
            };
            let (pub_i, _sk) = derive_key_pair(self.suite, &ps)?;
            if pub_i != node.encryption_key {
                return Err(MlsError::TreeKemError(format!(
                    "derived public key for node {dn} does not match UpdatePath"
                )));
            }
            derived.push((dn, ps.clone()));
            prev = ps;
        }
        let commit_secret = zeroize::Zeroizing::new(self.derive_secret(&prev, "path")?);

        // All checks passed — apply the committer's new public keys and our
        // freshly derived path secrets.
        self.set_leaf_encryption_key(
            update_path.leaf_index,
            update_path.leaf_encryption_key.clone(),
        )?;
        for (&dn, node) in direct.iter().zip(update_path.nodes.iter()) {
            self.nodes[dn as usize] = Some(Node::Parent(ParentNodeData {
                encryption_key: node.encryption_key.clone(),
                parent_hash: Vec::new(),
                unmerged_leaves: Vec::new(),
            }));
        }
        for (dn, ps) in derived {
            self.path_secrets.insert(dn, ps);
        }
        // Recompute parent hashes the same way the committer did; they feed
        // tree_hash, so any divergence is fail-closed at the key schedule.
        self.set_parent_hashes(update_path.leaf_index)?;
        Ok(commit_secret)
    }
}

/// Length-prefix `data` (4-byte big-endian length) and append to `buf`, so the
/// concatenation of fields is unambiguous.
///
/// Inputs are bounded (key packages, 32–64 byte hashes, and `unmerged_leaves`
/// lists capped by [`MAX_LEAVES`]), so the length always fits in `u32`; the
/// saturating conversion is a defensive guard that can never trigger in
/// practice.
fn push_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
}

/// An UpdatePath: the path component of an MLS Commit. Rotates the committer's
/// leaf and every node on its direct path, sealing each new path secret to the
/// members entitled to it. See [`RatchetTree::generate_update_path`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdatePath {
    /// Leaf index of the committer.
    pub leaf_index: u32,
    /// The committer's new leaf KEM public key.
    pub leaf_encryption_key: Vec<u8>,
    /// One entry per node on the committer's direct path, ordered leaf → root.
    pub nodes: Vec<UpdatePathNode>,
}

/// One node of an [`UpdatePath`]: the node's new public key plus the path secret
/// sealed to each member in the corresponding copath node's resolution (in
/// resolution order).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdatePathNode {
    /// The node's freshly derived KEM public key.
    pub encryption_key: Vec<u8>,
    /// Sealed path secret, one ciphertext per resolved recipient node.
    pub encrypted_path_secret: Vec<HpkeCiphertext>,
}

/// An ML-KEM-encapsulated, AEAD-sealed secret addressed to a single recipient.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HpkeCiphertext {
    /// ML-KEM ciphertext (encapsulation to the recipient's KEM public key).
    pub kem_ct: Vec<u8>,
    /// AEAD ciphertext (`nonce ‖ ct`) of the sealed secret under the KEM-derived key.
    pub aead_ct: Vec<u8>,
}

/// Derive the AEAD cipher and base nonce for a path-secret seal from an ML-KEM
/// shared secret. Shared by [`seal_to`] and [`open_from`] so the two cannot
/// drift on labels or sizes.
fn path_aead(suite: CipherSuite, shared_secret: &[u8]) -> Result<(AeadCipher, Vec<u8>)> {
    let ks = KeySchedule::new(suite);
    let key = ks.derive_key(
        &[],
        shared_secret,
        b"saorsa treekem path key",
        suite.key_size(),
    )?;
    let nonce = ks.derive_key(
        &[],
        shared_secret,
        b"saorsa treekem path nonce",
        suite.nonce_size(),
    )?;
    Ok((AeadCipher::new(key, suite)?, nonce))
}

/// Seal `plaintext` to a recipient's KEM public key: ML-KEM encapsulate, then
/// HKDF the shared secret into a key/nonce and AEAD-seal. `aad` binds the
/// ciphertext to a group context (the caller passes group id + epoch so a sealed
/// path secret cannot be replayed into another group or epoch).
pub(crate) fn seal_to(
    suite: CipherSuite,
    recipient_pub: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<HpkeCiphertext> {
    let pk = MlKemPublicKey::from_bytes(suite.ml_kem_variant(), recipient_pub)
        .map_err(|e| MlsError::CryptoError(format!("invalid recipient KEM key: {e:?}")))?;
    let kem = MlKem::new(suite.ml_kem_variant());
    let (shared, ct) = kem
        .encapsulate(&pk)
        .map_err(|e| MlsError::CryptoError(format!("encapsulation failed: {e:?}")))?;
    let (aead, nonce) = path_aead(suite, &shared.to_bytes())?;
    let aead_ct = aead.encrypt(&nonce, plaintext, aad)?;
    Ok(HpkeCiphertext {
        kem_ct: ct.to_bytes(),
        aead_ct,
    })
}

/// Inverse of [`seal_to`]: decapsulate with `my_sk` and AEAD-open under `aad`.
pub(crate) fn open_from(
    suite: CipherSuite,
    my_sk: &MlKemSecretKey,
    hc: &HpkeCiphertext,
    aad: &[u8],
) -> Result<Vec<u8>> {
    let ct = MlKemCiphertext::from_bytes(suite.ml_kem_variant(), &hc.kem_ct)
        .map_err(|e| MlsError::CryptoError(format!("invalid KEM ciphertext: {e:?}")))?;
    let kem = MlKem::new(suite.ml_kem_variant());
    let shared = kem
        .decapsulate(my_sk, &ct)
        .map_err(|e| MlsError::CryptoError(format!("decapsulation failed: {e:?}")))?;
    let (aead, nonce) = path_aead(suite, &shared.to_bytes())?;
    aead.decrypt(&nonce, &hc.aead_ct, aad)
}

/// Deterministically derive a node's ML-KEM keypair from a node secret
/// (`DeriveKeyPair`).
///
/// Any member who learns `node_secret` derives the identical keypair. This is
/// the cornerstone of UpdatePath processing: the committer encrypts a path
/// secret to the copath, and each recipient re-derives the same node keypair
/// from it.
///
/// Returns the KEM public key bytes and the secret key.
///
/// # Errors
///
/// Returns [`MlsError`] if the HKDF expansion fails.
pub fn derive_key_pair(
    suite: CipherSuite,
    node_secret: &[u8],
) -> Result<(Vec<u8>, MlKemSecretKey)> {
    let ks = KeySchedule::new(suite);
    // FIPS 203 keygen needs a 64-byte seed (d ‖ z).
    let mut seed = ks.derive_key(&[], node_secret, b"MLS 1.0 DeriveKeyPair", 64)?;
    if seed.len() != 64 {
        seed.zeroize();
        return Err(MlsError::CryptoError(format!(
            "DeriveKeyPair expected 64 seed bytes, got {}",
            seed.len()
        )));
    }
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    d.copy_from_slice(&seed[..32]);
    z.copy_from_slice(&seed[32..]);
    seed.zeroize();

    let kem = MlKem::new(suite.ml_kem_variant());
    let (public, secret) = kem.generate_keypair_from_seed(&d, &z);
    d.zeroize();
    z.zeroize();
    Ok((public.to_bytes().to_vec(), secret))
}

#[cfg(test)]
mod tests {
    use super::treemath::*;
    use super::*;
    use crate::crypto::KeyPair;
    use crate::member::{Credential, KeyPackage, MemberId, MemberIdentity};

    // ---- tree math KATs (hand-verified against RFC 9420 Appendix C,
    //      perfect-tree array model as used by OpenMLS) ----

    #[test]
    fn test_log2_level() {
        assert_eq!(log2(0), 0);
        assert_eq!(log2(1), 0);
        assert_eq!(log2(2), 1);
        assert_eq!(log2(3), 1);
        assert_eq!(log2(4), 2);
        assert_eq!(log2(7), 2);
        assert_eq!(log2(8), 3);

        assert_eq!(level(0), 0); // leaf
        assert_eq!(level(2), 0); // leaf
        assert_eq!(level(1), 1);
        assert_eq!(level(3), 2);
        assert_eq!(level(7), 3);
        assert_eq!(level(5), 1);
    }

    #[test]
    fn test_width_and_root() {
        assert_eq!(width_for_leaves(1), 1);
        assert_eq!(width_for_leaves(2), 3);
        assert_eq!(width_for_leaves(3), 7); // padded to 4 leaves
        assert_eq!(width_for_leaves(4), 7);
        assert_eq!(width_for_leaves(5), 15); // padded to 8 leaves

        assert_eq!(root(1), 0);
        assert_eq!(root(3), 1);
        assert_eq!(root(7), 3);
        assert_eq!(root(15), 7);
    }

    #[test]
    fn test_children() {
        // node 1 (root of 2-leaf tree): children 0 and 2
        assert_eq!(left(1).unwrap(), 0);
        assert_eq!(right(1).unwrap(), 2);
        // node 3 (root of 4-leaf tree): children 1 and 5
        assert_eq!(left(3).unwrap(), 1);
        assert_eq!(right(3).unwrap(), 5);
        // node 5: children 4 and 6
        assert_eq!(left(5).unwrap(), 4);
        assert_eq!(right(5).unwrap(), 6);
        // node 7 (root of 8-leaf tree): children 3 and 11
        assert_eq!(left(7).unwrap(), 3);
        assert_eq!(right(7).unwrap(), 11);
        // leaves have no children
        assert!(left(0).is_err());
        assert!(right(2).is_err());
    }

    #[test]
    fn test_parent_kats() {
        // width 3 (2 leaves)
        assert_eq!(parent(0, 3).unwrap(), 1);
        assert_eq!(parent(2, 3).unwrap(), 1);
        assert!(parent(1, 3).is_err()); // root

        // width 7 (4 leaves, perfect)
        assert_eq!(parent(0, 7).unwrap(), 1);
        assert_eq!(parent(2, 7).unwrap(), 1);
        assert_eq!(parent(1, 7).unwrap(), 3);
        assert_eq!(parent(4, 7).unwrap(), 5);
        assert_eq!(parent(6, 7).unwrap(), 5);
        assert_eq!(parent(5, 7).unwrap(), 3);
        assert!(parent(3, 7).is_err()); // root
    }

    #[test]
    fn test_sibling() {
        assert_eq!(sibling(0, 3).unwrap(), 2);
        assert_eq!(sibling(2, 3).unwrap(), 0);
        assert_eq!(sibling(0, 7).unwrap(), 2);
        assert_eq!(sibling(1, 7).unwrap(), 5);
        assert_eq!(sibling(5, 7).unwrap(), 1);
        assert_eq!(sibling(4, 7).unwrap(), 6);
    }

    #[test]
    fn test_direct_path_and_copath() {
        assert_eq!(direct_path(0, 1).unwrap(), Vec::<u32>::new());
        assert_eq!(copath(0, 1).unwrap(), Vec::<u32>::new());

        assert_eq!(direct_path(0, 3).unwrap(), vec![1]);
        assert_eq!(copath(0, 3).unwrap(), vec![2]);

        assert_eq!(direct_path(0, 7).unwrap(), vec![1, 3]);
        assert_eq!(copath(0, 7).unwrap(), vec![2, 5]);

        assert_eq!(direct_path(4, 7).unwrap(), vec![5, 3]);
        assert_eq!(copath(4, 7).unwrap(), vec![6, 1]);
    }

    /// Structural invariants over every node of every valid perfect-tree width
    /// — catches tree-math regressions without external KATs.
    #[test]
    fn test_tree_math_invariants() {
        for &width in &[1u32, 3, 7, 15, 31, 63, 127] {
            let r = root(width);
            for x in 0..width {
                if x != r {
                    // every non-root node has a parent within range
                    let p = parent(x, width).unwrap();
                    assert!(p < width, "parent {p} of {x} out of range, width={width}");
                    // x is a child of its parent (holds because tree is perfect)
                    let (l, rr) = (left(p).unwrap(), right(p).unwrap());
                    assert!(x == l || x == rr, "width={width}: {x} not a child of {p}");
                    // sibling is the other child, in range, and not x
                    let s = sibling(x, width).unwrap();
                    assert!(s == l || s == rr);
                    assert!(s < width, "sibling {s} of {x} out of range, width={width}");
                    assert_ne!(s, x);
                }
                // direct path ends at the root; copath aligns 1:1 with it
                let dp = direct_path(x, width).unwrap();
                if let Some(&last) = dp.last() {
                    assert_eq!(
                        last, r,
                        "width={width}: direct path of {x} must end at root"
                    );
                }
                let cp = copath(x, width).unwrap();
                assert_eq!(
                    cp.len(),
                    dp.len(),
                    "width={width}: copath/direct_path length"
                );
                for &c in &cp {
                    assert!(
                        c < width,
                        "copath node {c} of {x} out of range, width={width}"
                    );
                }
            }
        }
    }

    // ---- ratchet tree + DeriveKeyPair ----

    fn make_key_package() -> KeyPackage {
        let suite = CipherSuite::default();
        let keypair = KeyPair::generate(suite);
        let cred = Credential::new_basic(MemberId::generate(), None, &keypair, suite).unwrap();
        KeyPackage::new(keypair, cred).unwrap()
    }

    #[test]
    fn test_derive_key_pair_is_deterministic() {
        let suite = CipherSuite::default();
        let secret = vec![7u8; 32];
        let (pk1, sk1) = derive_key_pair(suite, &secret).unwrap();
        let (pk2, sk2) = derive_key_pair(suite, &secret).unwrap();
        assert_eq!(pk1, pk2, "same secret must yield same public key");
        assert_eq!(
            sk1.to_bytes(),
            sk2.to_bytes(),
            "same secret must yield same secret key"
        );

        let (pk3, _) = derive_key_pair(suite, &[8u8; 32]).unwrap();
        assert_ne!(pk1, pk3, "different secret must yield different key");
    }

    #[test]
    fn test_derive_key_pair_roundtrip_kem() {
        // The derived keypair must actually work for ML-KEM encaps/decaps.
        let suite = CipherSuite::default();
        let secret = vec![42u8; 32];
        let (pk_bytes, sk) = derive_key_pair(suite, &secret).unwrap();

        let kem = MlKem::new(suite.ml_kem_variant());
        let pk =
            saorsa_pqc::api::MlKemPublicKey::from_bytes(suite.ml_kem_variant(), &pk_bytes).unwrap();
        let (ss_send, ct) = kem.encapsulate(&pk).unwrap();
        let ss_recv = kem.decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss_send.to_bytes(), ss_recv.to_bytes());
    }

    #[test]
    fn test_tree_new_and_add() {
        let suite = CipherSuite::default();
        let mut tree = RatchetTree::new(make_key_package(), suite).unwrap();
        assert_eq!(tree.active_leaf_count(), 1);
        assert!(tree.leaf(0).is_some());

        let idx = tree.add_leaf(make_key_package()).unwrap();
        assert_eq!(idx, 1);
        assert_eq!(tree.active_leaf_count(), 2);
        assert!(tree.leaf(1).is_some());

        // third member forces growth to a perfect 4-leaf tree (leaf 3 blank)
        let idx = tree.add_leaf(make_key_package()).unwrap();
        assert_eq!(idx, 2);
        assert_eq!(tree.active_leaf_count(), 3);
        assert_eq!(tree.leaf_capacity(), 4);
        assert!(tree.leaf(3).is_none());
    }

    #[test]
    fn test_add_reuses_blank_leaf() {
        let suite = CipherSuite::default();
        let mut tree = RatchetTree::new(make_key_package(), suite).unwrap();
        tree.add_leaf(make_key_package()).unwrap(); // leaf 1
        tree.add_leaf(make_key_package()).unwrap(); // leaf 2
        assert_eq!(tree.active_leaf_count(), 3);

        tree.blank_leaf(1).unwrap();
        assert_eq!(tree.active_leaf_count(), 2);
        assert!(tree.leaf(1).is_none());

        // next add should reuse the blanked slot 1
        let idx = tree.add_leaf(make_key_package()).unwrap();
        assert_eq!(idx, 1);
        assert_eq!(tree.active_leaf_count(), 3);
    }

    #[test]
    fn test_tree_hash_deterministic_and_sensitive() {
        let suite = CipherSuite::default();
        let kp_a = make_key_package();
        let kp_b = make_key_package();

        let mut tree1 = RatchetTree::new(kp_a.clone(), suite).unwrap();
        tree1.add_leaf(kp_b.clone()).unwrap();
        let mut tree2 = RatchetTree::new(kp_a, suite).unwrap();
        tree2.add_leaf(kp_b).unwrap();

        let h1 = tree1.tree_hash().unwrap();
        let h2 = tree2.tree_hash().unwrap();
        assert_eq!(h1, h2, "identical public trees must hash identically");

        // a structural change must change the hash
        tree2.add_leaf(make_key_package()).unwrap();
        assert_ne!(tree2.tree_hash().unwrap(), h1);
    }

    #[test]
    fn test_tree_suite_mismatch_rejected() {
        let other = CipherSuite::from_id(
            crate::crypto::CipherSuiteId::SPEC2_MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87,
        )
        .unwrap();
        let kp = make_key_package(); // default suite
        assert!(RatchetTree::new(kp, other).is_err());
    }

    #[test]
    fn test_leaf_node_index_conversions() {
        assert!(is_leaf(0) && is_leaf(2) && is_leaf(4));
        assert!(!is_leaf(1) && !is_leaf(3));
        assert_eq!(leaf_to_node(0), 0);
        assert_eq!(leaf_to_node(1), 2);
        assert_eq!(leaf_to_node(3), 6);
        assert_eq!(node_to_leaf(0).unwrap(), 0);
        assert_eq!(node_to_leaf(4).unwrap(), 2);
        assert!(node_to_leaf(1).is_err()); // odd index is not a leaf
        assert!(node_to_leaf(3).is_err());
    }

    #[test]
    fn test_blank_leaf_error_paths() {
        let suite = CipherSuite::default();
        let mut tree = RatchetTree::new(make_key_package(), suite).unwrap();
        // out of range
        assert!(tree.blank_leaf(99).is_err());
        // blank the only leaf, then double-blank must error
        tree.blank_leaf(0).unwrap();
        assert_eq!(tree.active_leaf_count(), 0);
        assert!(tree.blank_leaf(0).is_err());
        // tree_hash over a fully-blank tree must still succeed deterministically
        let h1 = tree.tree_hash().unwrap();
        let h2 = tree.tree_hash().unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_add_leaf_suite_mismatch_rejected() {
        let suite = CipherSuite::default();
        let mut tree = RatchetTree::new(make_key_package(), suite).unwrap();
        // a key package on a different suite
        let other = CipherSuite::from_id(
            crate::crypto::CipherSuiteId::SPEC2_MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87,
        )
        .unwrap();
        let kp_other = {
            let keypair = KeyPair::generate(other);
            let cred = Credential::new_basic(MemberId::generate(), None, &keypair, other).unwrap();
            KeyPackage::new(keypair, cred).unwrap()
        };
        assert!(tree.add_leaf(kp_other).is_err());
    }

    #[test]
    fn test_growth_boundary_beyond_capacity_four() {
        let suite = CipherSuite::default();
        let mut tree = RatchetTree::new(make_key_package(), suite).unwrap();
        // add up to 7 members, crossing the 4->8 perfect-tree growth boundary
        for expected_idx in 1..=6u32 {
            let idx = tree.add_leaf(make_key_package()).unwrap();
            assert_eq!(idx, expected_idx);
        }
        assert_eq!(tree.active_leaf_count(), 7);
        assert_eq!(tree.leaf_capacity(), 8); // grew to perfect 8-leaf tree
        assert_eq!(tree.width(), 15);
        // every active leaf must be retrievable and distinct
        for leaf in 0..7u32 {
            assert!(
                tree.leaf(leaf).is_some(),
                "leaf {leaf} missing after growth"
            );
        }
        assert!(tree.leaf(7).is_none()); // padding leaf is blank
                                         // hash is stable across recomputation
        assert_eq!(tree.tree_hash().unwrap(), tree.tree_hash().unwrap());
    }

    #[test]
    fn test_derive_key_pair_high_security_suite() {
        // exercise the ML-KEM-1024 / SHA-512 suite path through DeriveKeyPair
        let suite = CipherSuite::from_id(
            crate::crypto::CipherSuiteId::SPEC2_MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87,
        )
        .unwrap();
        let secret = vec![3u8; 32];
        let (pk1, sk1) = derive_key_pair(suite, &secret).unwrap();
        let (pk2, _) = derive_key_pair(suite, &secret).unwrap();
        assert_eq!(pk1, pk2, "deterministic for ML-KEM-1024 suite");

        let kem = MlKem::new(suite.ml_kem_variant());
        let pk = saorsa_pqc::api::MlKemPublicKey::from_bytes(suite.ml_kem_variant(), &pk1).unwrap();
        let (ss_send, ct) = kem.encapsulate(&pk).unwrap();
        let ss_recv = kem.decapsulate(&sk1, &ct).unwrap();
        assert_eq!(ss_send.to_bytes(), ss_recv.to_bytes());
    }

    // ---- P3: UpdatePath generation / processing (FS + PCS mechanism) ----

    /// Fixed group context used as AEAD AAD in the P3 UpdatePath tests.
    const CTX: &[u8] = b"saorsa-mls-test-group-context";

    /// Build a member's private view of `public_tree` (a clone of the shared
    /// public state) owned at `leaf` with `identity`'s leaf KEM secret.
    fn member_view(public_tree: &RatchetTree, leaf: u32, identity: &MemberIdentity) -> RatchetTree {
        let mut view = public_tree.clone();
        view.own_leaf = None;
        view.own_leaf_secret = None;
        view.path_secrets.clear();
        view.attach_owner(leaf, identity.kem_secret().unwrap().clone())
            .unwrap();
        view
    }

    #[test]
    fn test_update_path_two_members_converge() {
        let suite = CipherSuite::default();
        let alice = MemberIdentity::generate(MemberId::generate()).unwrap();
        let bob = MemberIdentity::generate(MemberId::generate()).unwrap();

        let mut tree_a = RatchetTree::new(alice.key_package.clone(), suite).unwrap();
        tree_a
            .attach_owner(0, alice.kem_secret().unwrap().clone())
            .unwrap();
        let bob_leaf = tree_a.add_leaf(bob.key_package.clone()).unwrap();

        // Bob's independent instance starts from the same public tree.
        let mut tree_b = member_view(&tree_a, bob_leaf, &bob);

        // Alice commits an UpdatePath; Bob processes it.
        let (update_path, cs_alice) = tree_a.generate_update_path(CTX, None).unwrap();
        let cs_bob = tree_b.process_update_path(&update_path, CTX).unwrap();

        assert_eq!(
            &*cs_alice, &*cs_bob,
            "committer and member must reach the same commit secret"
        );
        assert_eq!(cs_alice.len(), suite.hash_size());
    }

    #[test]
    fn test_update_path_three_members_converge() {
        let suite = CipherSuite::default();
        let alice = MemberIdentity::generate(MemberId::generate()).unwrap();
        let bob = MemberIdentity::generate(MemberId::generate()).unwrap();
        let carol = MemberIdentity::generate(MemberId::generate()).unwrap();

        let mut tree_a = RatchetTree::new(alice.key_package.clone(), suite).unwrap();
        tree_a
            .attach_owner(0, alice.kem_secret().unwrap().clone())
            .unwrap();
        let bob_leaf = tree_a.add_leaf(bob.key_package.clone()).unwrap();
        let carol_leaf = tree_a.add_leaf(carol.key_package.clone()).unwrap();

        let mut tree_b = member_view(&tree_a, bob_leaf, &bob);
        let mut tree_c = member_view(&tree_a, carol_leaf, &carol);

        let (update_path, cs_alice) = tree_a.generate_update_path(CTX, None).unwrap();
        let cs_bob = tree_b.process_update_path(&update_path, CTX).unwrap();
        let cs_carol = tree_c.process_update_path(&update_path, CTX).unwrap();

        assert_eq!(&*cs_alice, &*cs_bob, "Bob must converge with Alice");
        assert_eq!(&*cs_alice, &*cs_carol, "Carol must converge with Alice");
    }

    #[test]
    fn test_update_path_commit_secret_is_fresh() {
        // PCS evidence: each Commit yields a fresh, independent commit secret;
        // an attacker holding a prior epoch's secret learns nothing about the next.
        let suite = CipherSuite::default();
        let alice = MemberIdentity::generate(MemberId::generate()).unwrap();
        let bob = MemberIdentity::generate(MemberId::generate()).unwrap();

        let mut tree_a = RatchetTree::new(alice.key_package.clone(), suite).unwrap();
        tree_a
            .attach_owner(0, alice.kem_secret().unwrap().clone())
            .unwrap();
        let bob_leaf = tree_a.add_leaf(bob.key_package.clone()).unwrap();
        let mut tree_b = member_view(&tree_a, bob_leaf, &bob);

        let (up1, cs1) = tree_a.generate_update_path(CTX, None).unwrap();
        tree_b.process_update_path(&up1, CTX).unwrap();
        let (up2, cs2) = tree_a.generate_update_path(CTX, None).unwrap();
        let cs2_b = tree_b.process_update_path(&up2, CTX).unwrap();

        assert_ne!(
            &*cs1, &*cs2,
            "successive commits must produce distinct secrets"
        );
        assert_eq!(&*cs2, &*cs2_b, "still converges after a second commit");
    }

    #[test]
    fn test_process_own_update_path_rejected() {
        let suite = CipherSuite::default();
        let alice = MemberIdentity::generate(MemberId::generate()).unwrap();
        let bob = MemberIdentity::generate(MemberId::generate()).unwrap();
        let mut tree_a = RatchetTree::new(alice.key_package.clone(), suite).unwrap();
        tree_a
            .attach_owner(0, alice.kem_secret().unwrap().clone())
            .unwrap();
        tree_a.add_leaf(bob.key_package.clone()).unwrap();
        let (up, _cs) = tree_a.generate_update_path(CTX, None).unwrap();
        // Alice cannot process her own UpdatePath.
        assert!(tree_a.process_update_path(&up, CTX).is_err());
    }

    #[test]
    fn test_deterministic_update_path_with_seed() {
        // Same seed + same starting tree → identical commit secret (KAT-friendly).
        let suite = CipherSuite::default();
        let alice = MemberIdentity::generate(MemberId::generate()).unwrap();
        let bob = MemberIdentity::generate(MemberId::generate()).unwrap();

        let build = || {
            let mut t = RatchetTree::new(alice.key_package.clone(), suite).unwrap();
            t.attach_owner(0, alice.kem_secret().unwrap().clone())
                .unwrap();
            t.add_leaf(bob.key_package.clone()).unwrap();
            t
        };
        let seed = [9u8; 32];
        let (_up1, cs1) = build().generate_update_path(CTX, Some(&seed)).unwrap();
        let (_up2, cs2) = build().generate_update_path(CTX, Some(&seed)).unwrap();
        assert_eq!(
            &*cs1, &*cs2,
            "fixed seed must yield deterministic commit secret"
        );
    }

    /// Helper: a fresh group of `n` members; returns (committer tree owning leaf
    /// 0, the identities). All members share the same public tree.
    fn build_group(n: u32) -> (RatchetTree, Vec<MemberIdentity>) {
        let suite = CipherSuite::default();
        let ids: Vec<MemberIdentity> = (0..n)
            .map(|_| MemberIdentity::generate(MemberId::generate()).unwrap())
            .collect();
        let mut tree = RatchetTree::new(ids[0].key_package.clone(), suite).unwrap();
        tree.attach_owner(0, ids[0].kem_secret().unwrap().clone())
            .unwrap();
        for id in &ids[1..] {
            tree.add_leaf(id.key_package.clone()).unwrap();
        }
        (tree, ids)
    }

    #[test]
    fn test_parent_hashes_set_on_update() {
        // After a commit, the committer's direct-path parent nodes carry a
        // non-empty parent hash (root excepted), per RFC 9420 §7.9.
        let (mut tree, _ids) = build_group(4); // width 7, depth 2; owner = leaf 0
        tree.generate_update_path(CTX, None).unwrap();
        // direct_path(0, 7) = [1, 3]; node 3 is the root.
        match tree.node(1) {
            Some(Node::Parent(p)) => assert!(
                !p.parent_hash.is_empty(),
                "non-root path node must have a parent hash"
            ),
            other => panic!("expected populated parent at node 1, got {other:?}"),
        }
        match tree.node(3) {
            Some(Node::Parent(p)) => {
                assert!(p.parent_hash.is_empty(), "root parent hash must be empty")
            }
            other => panic!("expected root parent at node 3, got {other:?}"),
        }
    }

    #[test]
    fn test_parent_hash_binds_sibling_subtree() {
        // Two trees identical except for one leaf in the committer's copath
        // subtree must yield different parent hashes for the same seeded update,
        // proving the sibling subtree is bound into the parent hash.
        let suite = CipherSuite::default();
        let a = MemberIdentity::generate(MemberId::generate()).unwrap();
        let b = MemberIdentity::generate(MemberId::generate()).unwrap();
        let c1 = MemberIdentity::generate(MemberId::generate()).unwrap();
        let c2 = MemberIdentity::generate(MemberId::generate()).unwrap();

        let build = |third: &MemberIdentity| {
            let mut t = RatchetTree::new(a.key_package.clone(), suite).unwrap();
            t.attach_owner(0, a.kem_secret().unwrap().clone()).unwrap();
            t.add_leaf(b.key_package.clone()).unwrap(); // leaf 1 (copath of leaf 0 at node 2)
            t.add_leaf(third.key_package.clone()).unwrap(); // leaf 2 (right subtree)
            t
        };
        let mut t1 = build(&c1);
        let mut t2 = build(&c2);
        let seed = [5u8; 32];
        t1.generate_update_path(CTX, Some(&seed)).unwrap();
        t2.generate_update_path(CTX, Some(&seed)).unwrap();
        // node 1 is the committer's path node whose sibling subtree (node 5)
        // contains the differing leaf 2.
        let ph1 = match t1.node(1) {
            Some(Node::Parent(p)) => p.parent_hash.clone(),
            _ => panic!(),
        };
        let ph2 = match t2.node(1) {
            Some(Node::Parent(p)) => p.parent_hash.clone(),
            _ => panic!(),
        };
        assert_ne!(
            ph1, ph2,
            "parent hash must change when the sibling subtree changes"
        );
    }

    #[test]
    fn test_update_path_eight_members_converge() {
        // depth-3 perfect tree: exercises longer direct paths and deeper overlap
        let (mut tree_a, ids) = build_group(8);
        let mut views: Vec<RatchetTree> = (1..8)
            .map(|leaf| member_view(&tree_a, leaf, &ids[leaf as usize]))
            .collect();
        let (up, cs_a) = tree_a.generate_update_path(CTX, None).unwrap();
        for (k, view) in views.iter_mut().enumerate() {
            let cs = view.process_update_path(&up, CTX).unwrap();
            assert_eq!(&*cs_a, &*cs, "member at leaf {} must converge", k + 1);
        }
    }

    #[test]
    fn test_update_path_different_committers_converge() {
        // PCS healing: a non-creator member commits, others converge with it
        let (mut tree_a, ids) = build_group(3);
        let mut tree_b = member_view(&tree_a, 1, &ids[1]);
        let mut tree_c = member_view(&tree_a, 2, &ids[2]);

        // Bob (leaf 1) is the committer this round.
        let (up, cs_bob) = tree_b.generate_update_path(CTX, None).unwrap();
        let cs_a = tree_a.process_update_path(&up, CTX).unwrap();
        let cs_c = tree_c.process_update_path(&up, CTX).unwrap();
        assert_eq!(&*cs_bob, &*cs_a, "Alice converges with Bob's commit");
        assert_eq!(&*cs_bob, &*cs_c, "Carol converges with Bob's commit");
    }

    #[test]
    fn test_removed_member_cannot_derive_next_epoch() {
        // FS: after Carol is removed (blanked), the next Commit excludes her;
        // her stale instance (still holding her old leaf secret) cannot derive
        // the new commit secret, while a surviving member does.
        let (mut tree_a, ids) = build_group(3); // Alice(0), Bob(1), Carol(2)
        let mut carol_stale = member_view(&tree_a, 2, &ids[2]); // pre-removal view
        let mut bob = member_view(&tree_a, 1, &ids[1]);

        // Alice removes Carol; Bob mirrors the removal; Alice commits.
        tree_a.blank_leaf(2).unwrap();
        bob.blank_leaf(2).unwrap();
        let (up, cs_committer) = tree_a.generate_update_path(CTX, None).unwrap();

        let cs_bob = bob.process_update_path(&up, CTX).unwrap();
        assert_eq!(
            &*cs_committer, &*cs_bob,
            "surviving member converges after a removal"
        );

        assert!(
            carol_stale.process_update_path(&up, CTX).is_err(),
            "removed member must NOT be able to derive the new commit secret"
        );
    }

    #[test]
    fn test_process_rejects_tampered_pubkey() {
        let (mut tree_a, ids) = build_group(2);
        let mut tree_b = member_view(&tree_a, 1, &ids[1]);
        let (mut up, _cs) = tree_a.generate_update_path(CTX, None).unwrap();
        // Tamper with a direct-path node's advertised public key.
        if let Some(node) = up.nodes.last_mut() {
            node.encryption_key[0] ^= 0xFF;
        }
        assert!(
            tree_b.process_update_path(&up, CTX).is_err(),
            "a tampered path public key must be rejected"
        );
    }

    #[test]
    fn test_process_rejects_wrong_context() {
        let (mut tree_a, ids) = build_group(2);
        let mut tree_b = member_view(&tree_a, 1, &ids[1]);
        let (up, _cs) = tree_a.generate_update_path(CTX, None).unwrap();
        // Wrong AAD context must fail the AEAD open.
        assert!(
            tree_b
                .process_update_path(&up, b"different-context")
                .is_err(),
            "mismatched group context must be rejected"
        );
    }

    #[test]
    fn test_process_rejects_out_of_range_committer() {
        let (mut tree_a, ids) = build_group(2);
        let mut tree_b = member_view(&tree_a, 1, &ids[1]);
        let (mut up, _cs) = tree_a.generate_update_path(CTX, None).unwrap();
        // Hostile committer leaf index must be rejected, not panic/hang.
        up.leaf_index = u32::MAX;
        assert!(tree_b.process_update_path(&up, CTX).is_err());
    }
}

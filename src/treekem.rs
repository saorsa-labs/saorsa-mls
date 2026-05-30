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
//! Scope of this module (phase P2):
//!
//! - [`treemath`]: RFC 9420 Appendix C array-based tree math. The tree is kept
//!   as a **perfect** binary tree (its leaf count is always rounded up to a
//!   power of two, with trailing blank leaves), which is what makes the simple
//!   `parent`/`left`/`right`/`sibling` index formulas correct — see the note
//!   on that module.
//! - [`Node`]/[`RatchetTree`]: the public tree state — each node carries a KEM
//!   *public* key (ML-KEM), leaves bind to a member [`KeyPackage`].
//! - [`derive_key_pair`]: deterministic `DeriveKeyPair` — turns a node secret
//!   into the *same* ML-KEM keypair for every member who learns that secret.
//!   This is the primitive the UpdatePath (phase P3) relies on.
//! - [`RatchetTree::tree_hash`]: a deterministic hash over the public tree
//!   state.
//!
//! UpdatePath generation/processing and the per-node *private* keys that ride
//! on it are implemented in phase P3 on top of this structure.

use crate::{
    crypto::{CipherSuite, Hash, KeySchedule},
    member::KeyPackage,
    MlsError, Result,
};
use saorsa_pqc::api::{MlKem, MlKemSecretKey};
use zeroize::Zeroize;

/// Upper bound on the number of leaves (members) a ratchet tree may hold.
///
/// Bounding the leaf count keeps every node/leaf index and the array width well
/// within `u32` (the backing array has at most `2 * MAX_LEAVES - 1` nodes), so
/// the `u32` index arithmetic in this module cannot overflow or truncate in
/// practice. Matches the crate-wide [`crate::MAX_GROUP_SIZE`].
pub const MAX_LEAVES: u32 = 1 << 16;

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
    #[must_use]
    pub fn leaf_to_node(leaf: u32) -> u32 {
        leaf * 2
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

/// A node in the ratchet tree.
#[derive(Clone, Debug)]
pub enum Node {
    /// A leaf node bound to a member's key package.
    Leaf(LeafNodeData),
    /// An intermediate (parent) node holding a derived KEM public key.
    Parent(ParentNodeData),
}

/// Public data carried by a leaf node.
#[derive(Clone, Debug)]
pub struct LeafNodeData {
    /// ML-KEM public key bytes for this leaf (equals
    /// `key_package.agreement_key`).
    pub encryption_key: Vec<u8>,
    /// The member's key package bound to this leaf.
    pub key_package: KeyPackage,
}

/// Public data carried by an intermediate (parent) node.
#[derive(Clone, Debug)]
pub struct ParentNodeData {
    /// ML-KEM public key bytes for this node (derived during an UpdatePath).
    pub encryption_key: Vec<u8>,
    /// Parent hash binding this node to its position (RFC 9420 §7.9).
    pub parent_hash: Vec<u8>,
    /// Leaves added since this node's key was last set, not yet merged into it.
    pub unmerged_leaves: Vec<u32>,
}

/// The public ratchet-tree state shared by all members of a group.
///
/// This holds only **public** material (KEM public keys and key packages).
/// Per-member private path secrets are layered on top in phase P3.
#[derive(Clone, Debug)]
pub struct RatchetTree {
    suite: CipherSuite,
    /// Perfect-tree array of `2*L - 1` slots (`L` a power of two). `None` marks
    /// a blank node.
    nodes: Vec<Option<Node>>,
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
        };
        tree.set_leaf_node(0, creator);
        Ok(tree)
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
    #[must_use]
    pub fn leaf(&self, leaf: u32) -> Option<&LeafNodeData> {
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
    use crate::member::{Credential, KeyPackage, MemberId};

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
}

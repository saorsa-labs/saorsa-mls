// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
//! Wire compatibility of the multi-remove commit with the published 0.3.8
//! crate (the line x0x pins).
//!
//! A [`TreeKemCommit`] from `remove_members` uses the unchanged wire form.
//! These tests move real group state between this crate and saorsa-mls 0.3.8
//! (snapshot + identity secret bytes, both unchanged formats) and check that:
//! - 0.3.8 receivers apply a multi-remove commit produced here and land on the
//!   committer's epoch secret; 0.3.8 removed members are refused;
//! - single-remove commits produced by 0.3.8 still apply here.

use saorsa_mls::treekem_group::{TreeKemCommit, TreeKemGroup};
use saorsa_mls::{CipherSuite, MemberId, MemberIdentity};
use saorsa_mls_v038 as old;

fn identity() -> MemberIdentity {
    MemberIdentity::generate_with_suite(MemberId::generate(), CipherSuite::default()).unwrap()
}

/// `n` members on the current crate; member `i` owns leaf `i`. Returns the
/// groups and the identities (needed to move a member to 0.3.8).
fn build(n: usize) -> (Vec<TreeKemGroup>, Vec<MemberIdentity>) {
    let creator = identity();
    let mut ids = vec![creator.clone()];
    let mut groups = vec![TreeKemGroup::create(b"compat".to_vec(), creator).unwrap()];
    for _ in 1..n {
        let joiner = identity();
        let (commit, welcome) = groups[0].add_member(&joiner.key_package).unwrap();
        for g in groups.iter_mut().skip(1) {
            g.process_commit(&commit).unwrap();
        }
        groups.push(TreeKemGroup::from_welcome(&welcome, joiner.clone()).unwrap());
        ids.push(joiner);
    }
    (groups, ids)
}

/// Move a member's full state to the 0.3.8 crate.
fn to_old(group: &TreeKemGroup, id: &MemberIdentity) -> old::treekem_group::TreeKemGroup {
    let old_id = old::MemberIdentity::from_secret_bytes(&id.to_secret_bytes().unwrap()).unwrap();
    old::treekem_group::TreeKemGroup::from_snapshot_bytes(
        &group.to_snapshot_bytes().unwrap(),
        old_id,
    )
    .unwrap()
}

/// Move a member's full state from the 0.3.8 crate to this crate.
fn from_old(group: &old::treekem_group::TreeKemGroup, id: &MemberIdentity) -> TreeKemGroup {
    TreeKemGroup::from_snapshot_bytes(&group.to_snapshot_bytes().unwrap(), id.clone()).unwrap()
}

fn commit_to_old(commit: &TreeKemCommit) -> old::treekem_group::TreeKemCommit {
    postcard::from_bytes(&postcard::to_stdvec(commit).unwrap()).unwrap()
}

fn commit_from_old(commit: &old::treekem_group::TreeKemCommit) -> TreeKemCommit {
    postcard::from_bytes(&postcard::to_stdvec(commit).unwrap()).unwrap()
}

#[test]
fn v038_receivers_apply_multi_remove_commit() {
    let (mut groups, ids) = build(6);
    let mut olds: Vec<_> = (1..6).map(|i| to_old(&groups[i], &ids[i])).collect();

    let commit = groups[0].remove_members(&[2, 4, 5]).unwrap();
    let wire = postcard::to_stdvec(&commit).unwrap();
    let old_commit: old::treekem_group::TreeKemCommit = postcard::from_bytes(&wire).unwrap();
    // Same bytes both ways: the wire form is unchanged.
    assert_eq!(postcard::to_stdvec(&old_commit).unwrap(), wire);
    assert_eq!(old_commit.removed_leaves, vec![2, 4, 5]);

    let expected = groups[0].export_secret("x", b"", 32).unwrap();
    for (k, og) in olds.iter_mut().enumerate() {
        let leaf = k + 1;
        let res = og.process_commit(&old_commit);
        if [2, 4, 5].contains(&leaf) {
            assert!(
                res.is_err(),
                "0.3.8 removed member {leaf} accepted the commit"
            );
            assert_ne!(og.export_secret("x", b"", 32).unwrap(), expected);
        } else {
            res.unwrap();
            assert_eq!(og.export_secret("x", b"", 32).unwrap(), expected);
            assert_eq!(og.member_count(), 3);
        }
    }

    // A 0.3.8 survivor's next update applies on this crate too.
    let old_update = olds[0].update().unwrap(); // leaf 1
    groups[0]
        .process_commit(&commit_from_old(&old_update))
        .unwrap();
    assert_eq!(
        groups[0].export_secret("y", b"", 32).unwrap(),
        olds[0].export_secret("y", b"", 32).unwrap()
    );
}

#[test]
fn v038_single_remove_commit_applies_here() {
    let (mut groups, ids) = build(4);
    let mut old_committer = to_old(&groups[0], &ids[0]);
    let old_commit = old_committer.remove_member(2).unwrap();
    let commit = commit_from_old(&old_commit);
    assert_eq!(commit.removed_leaves, vec![2]);
    let expected = old_committer.export_secret("x", b"", 32).unwrap();
    for j in [1, 3] {
        assert_eq!(groups[j].check_commit_removals(&commit), Ok(()));
        groups[j].process_commit(&commit).unwrap();
        assert_eq!(groups[j].export_secret("x", b"", 32).unwrap(), expected);
    }
    assert!(groups[2].process_commit(&commit).is_err());
}

#[test]
fn state_round_trips_through_v038_after_multi_remove() {
    // Snapshot formats are unchanged: a survivor moved to 0.3.8 and back after
    // a multi-remove keeps its epoch and keys.
    let (mut groups, ids) = build(4);
    let commit = groups[0].remove_members(&[1, 3]).unwrap();
    groups[2].process_commit(&commit).unwrap();
    let back = from_old(&to_old(&groups[2], &ids[2]), &ids[2]);
    assert_eq!(back.epoch(), groups[0].epoch());
    assert_eq!(
        back.export_secret("x", b"", 32).unwrap(),
        groups[0].export_secret("x", b"", 32).unwrap()
    );
    // And a 0.3.8 receiver of a commit produced here after the removal.
    let mut old_survivor = to_old(&groups[2], &ids[2]);
    let update = groups[0].update().unwrap();
    old_survivor
        .process_commit(&commit_to_old(&update))
        .unwrap();
    assert_eq!(
        old_survivor.export_secret("z", b"", 32).unwrap(),
        groups[0].export_secret("z", b"", 32).unwrap()
    );
}

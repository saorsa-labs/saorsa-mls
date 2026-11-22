// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: MIT OR Apache-2.0
//
//! Tests for [`TreeKemGroup::remove_members`] (one commit that removes several
//! leaves) and the receive-side removal-list check.
#![cfg(test)]

use super::*;
use crate::member::MemberId;
use proptest::prelude::*;
use saorsa_pqc::api::MlKemSecretKey;

fn identity(suite: CipherSuite) -> MemberIdentity {
    MemberIdentity::generate_with_suite(MemberId::generate(), suite).unwrap()
}

/// Build an `n`-member group. Member 0 creates it and adds the others, so
/// member `i` owns leaf `i`. Then every member commits one update (processed
/// by all), so each member holds fresh path secrets along its direct path —
/// the "full prior state" a removed member would try to use.
fn build_group(n: usize) -> Vec<TreeKemGroup> {
    let suite = CipherSuite::default();
    let mut groups = vec![TreeKemGroup::create(b"multi-remove".to_vec(), identity(suite)).unwrap()];
    for _ in 1..n {
        let joiner = identity(suite);
        let (commit, welcome) = groups[0].add_member(&joiner.key_package).unwrap();
        for g in groups.iter_mut().skip(1) {
            g.process_commit(&commit).unwrap();
        }
        groups.push(TreeKemGroup::from_welcome(&welcome, joiner).unwrap());
    }
    for committer in 0..n {
        commit_and_fan_out_update(&mut groups, committer);
    }
    for (i, g) in groups.iter().enumerate() {
        assert_eq!(g.own_leaf(), Some(i as u32));
    }
    groups
}

/// `committer` commits an update that every other member in `groups`
/// processes.
fn commit_and_fan_out_update(groups: &mut [TreeKemGroup], committer: usize) {
    let commit = groups[committer].update().unwrap();
    for (j, g) in groups.iter_mut().enumerate() {
        if j != committer {
            g.process_commit(&commit).unwrap();
        }
    }
}

/// Every KEM secret key `g` holds: its own leaf key and the key of every node
/// whose path secret it knows.
fn keys_held(g: &TreeKemGroup) -> Vec<MlKemSecretKey> {
    let (_leaf, leaf_secret, path_secrets) = g.tree.secret_state();
    let mut keys = Vec::new();
    if let Some(bytes) = leaf_secret {
        keys.push(MlKemSecretKey::from_bytes(g.suite.ml_kem_variant(), &bytes).unwrap());
    }
    for (_node, ps) in path_secrets {
        keys.push(treekem::derive_key_pair(g.suite, &ps).unwrap().1);
    }
    assert!(!keys.is_empty(), "a member always holds its leaf key");
    keys
}

/// Can any key held in `prior` (a member's state BEFORE `commit`) open any
/// path-secret ciphertext in `commit`?
fn can_open_any(prior: &TreeKemGroup, commit: &TreeKemCommit) -> bool {
    let aad = TreeKemGroup::path_context(&prior.group_id, commit.epoch - 1);
    let keys = keys_held(prior);
    commit.update_path.nodes.iter().any(|node| {
        node.encrypted_path_secret.iter().any(|ct| {
            keys.iter()
                .any(|sk| treekem::open_from(prior.suite, sk, ct, &aad).is_ok())
        })
    })
}

/// Assert the full multi-remove contract on `groups` for `committer`
/// removing `removed` in one commit, and return the commit.
fn assert_multi_remove(
    groups: &mut [TreeKemGroup],
    committer: usize,
    removed: &[usize],
) -> TreeKemCommit {
    let leaves: Vec<u32> = removed.iter().map(|&i| i as u32).collect();
    let epoch_before = groups[committer].epoch();
    let member_count = groups[committer].member_count() as usize;
    let old_export = groups[committer].export_secret("e", b"", 32).unwrap();
    let commit = groups[committer].remove_members(&leaves).unwrap();

    let mut sorted = leaves.clone();
    sorted.sort_unstable();
    assert_eq!(
        commit.removed_leaves, sorted,
        "one commit lists every removed leaf"
    );
    assert_eq!(commit.epoch, epoch_before + 1);
    let expected = groups[committer].export_secret("e", b"", 32).unwrap();
    assert_ne!(expected, old_export);

    for (j, g) in groups.iter_mut().enumerate() {
        if j == committer {
            continue;
        }
        if removed.contains(&j) {
            // Full prior state: this member has not processed the commit.
            assert!(
                !can_open_any(g, &commit),
                "removed member {j} can open a path secret of the commit"
            );
            // Bypass the policy check: apply the path directly on a copy of
            // the removed member's tree with the other removed leaves blanked.
            let mut tree = g.tree.clone();
            for &other in &leaves {
                if other != j as u32 {
                    tree.blank_leaf(other).unwrap();
                }
            }
            let aad = TreeKemGroup::path_context(&g.group_id, g.epoch);
            assert!(
                tree.process_update_path(&commit.update_path, &aad).is_err(),
                "removed member {j} derived the commit secret"
            );
            // The normal API refuses and leaves the state untouched.
            let before = g.export_secret("e", b"", 32).unwrap();
            assert!(matches!(
                g.process_commit(&commit),
                Err(MlsError::InvalidGroupState(_))
            ));
            assert_eq!(g.epoch(), epoch_before);
            assert_eq!(g.export_secret("e", b"", 32).unwrap(), before);
            assert_ne!(before, expected);
        } else {
            assert!(
                can_open_any(g, &commit),
                "survivor {j} cannot open its path secret"
            );
            g.process_commit(&commit).unwrap();
            assert_eq!(g.epoch(), epoch_before + 1);
            assert_eq!(
                g.export_secret("e", b"", 32).unwrap(),
                expected,
                "survivor {j} derives the committer's epoch secret"
            );
            assert_eq!(g.member_count() as usize, member_count - removed.len());
        }
    }
    commit
}

/// Survivors (all but `removed`) as indices.
fn survivors(n: usize, removed: &[usize]) -> Vec<usize> {
    (0..n).filter(|i| !removed.contains(i)).collect()
}

/// After a multi-remove, a survivor commits an update: every survivor follows
/// it and no removed member's prior state opens anything in it.
fn assert_follow_up_update(groups: &mut [TreeKemGroup], committer: usize, removed: &[usize]) {
    let live = survivors(groups.len(), removed);
    let follow_committer = *live.iter().find(|&&i| i != committer).unwrap_or(&committer);
    let commit = groups[follow_committer].update().unwrap();
    let expected = groups[follow_committer]
        .export_secret("f", b"", 32)
        .unwrap();
    for &j in &live {
        if j != follow_committer {
            groups[j].process_commit(&commit).unwrap();
            assert_eq!(groups[j].export_secret("f", b"", 32).unwrap(), expected);
        }
    }
    for &r in removed {
        assert!(!can_open_any(&groups[r], &commit));
        // Two epochs behind now: the epoch check refuses it.
        assert!(matches!(
            groups[r].process_commit(&commit),
            Err(MlsError::InvalidEpoch { .. })
        ));
    }
}

fn run_case(n: usize, committer: usize, removed: &[usize]) {
    let mut groups = build_group(n);
    assert_multi_remove(&mut groups, committer, removed);
    let live = survivors(n, removed);
    assert_eq!(groups[committer].member_count() as usize, live.len());
    for &r in removed {
        assert!(groups[committer].leaf_verifying_key(r as u32).is_none());
    }
    // Encrypted traffic in the new epoch reaches survivors only.
    let ct = groups[committer].encrypt_message(b"after").unwrap();
    for &j in &live {
        if j != committer {
            assert_eq!(groups[j].decrypt_message(&ct).unwrap(), b"after");
        }
    }
    for &r in removed {
        assert!(groups[r].decrypt_message(&ct).is_err());
    }
    if live.len() >= 2 {
        assert_follow_up_update(&mut groups, committer, removed);
    }
}

// ---- deterministic blank-node / resolution edge cases (8 leaves) ----

#[test]
fn multi_remove_adjacent_sibling_leaves() {
    // Leaves 2 and 3 are siblings: their parent subtree becomes fully blank.
    run_case(8, 0, &[2, 3]);
}

#[test]
fn multi_remove_adjacent_non_sibling_leaves() {
    // Leaves 3 and 4 are adjacent but sit under different halves of the tree.
    run_case(8, 0, &[3, 4]);
}

#[test]
fn multi_remove_whole_subtree() {
    // The whole right half (leaves 4..=7) goes: a copath resolution is empty.
    run_case(8, 1, &[4, 5, 6, 7]);
}

#[test]
fn multi_remove_committers_sibling() {
    run_case(8, 0, &[1]);
    // Sibling plus the neighbouring pair: the two lowest copath nodes of the
    // committer resolve to nothing.
    run_case(8, 0, &[1, 2, 3]);
    run_case(8, 5, &[4, 6]);
}

#[test]
fn multi_remove_scattered_leaves_non_power_of_two_group() {
    run_case(7, 3, &[0, 2, 6]);
}

#[test]
fn multi_remove_all_but_committer() {
    let mut groups = build_group(4);
    let commit = groups[2].remove_members(&[0, 1, 3]).unwrap();
    assert_eq!(groups[2].member_count(), 1);
    // Every copath resolution is empty: nothing is sealed to anyone.
    assert!(commit
        .update_path
        .nodes
        .iter()
        .all(|n| n.encrypted_path_secret.is_empty()));
    for r in [0, 1, 3] {
        assert!(groups[r].process_commit(&commit).is_err());
    }
}

/// Six members; member 5 updates (populates node 11 over leaves 4..=7); then
/// member 0 adds a seventh member at leaf 6, which is recorded as an unmerged
/// leaf of node 11.
fn group_with_unmerged_leaf() -> Vec<TreeKemGroup> {
    let suite = CipherSuite::default();
    let mut groups = build_group(6);
    commit_and_fan_out_update(&mut groups, 5);
    let joiner = identity(suite);
    let (commit, welcome) = groups[0].add_member(&joiner.key_package).unwrap();
    for g in groups.iter_mut().skip(1) {
        g.process_commit(&commit).unwrap();
    }
    groups.push(TreeKemGroup::from_welcome(&welcome, joiner).unwrap());
    let has_unmerged = groups[1]
        .tree
        .export_public_nodes()
        .iter()
        .any(|n| matches!(n, Some(treekem::Node::Parent(p)) if p.unmerged_leaves.contains(&6)));
    assert!(has_unmerged, "fixture must contain an unmerged leaf");
    groups
}

#[test]
fn multi_remove_with_unmerged_leaf_in_a_copath_resolution() {
    // Committer 3 removes leaves 1 and 2; node 11 stays and resolves to
    // itself plus the unmerged leaf 6.
    let mut groups = group_with_unmerged_leaf();
    assert_multi_remove(&mut groups, 3, &[1, 2]);
    assert_follow_up_update(&mut groups, 3, &[1, 2]);
}

#[test]
fn multi_remove_blanks_parent_holding_unmerged_leaf() {
    // Leaves 4 and 5 go, which blanks node 11; the unmerged leaf 6 survives
    // and is reached through its own leaf key.
    let mut groups = group_with_unmerged_leaf();
    assert_multi_remove(&mut groups, 1, &[4, 5]);
    assert_follow_up_update(&mut groups, 1, &[4, 5]);
}

#[test]
fn multi_remove_unordered_input_is_sorted_in_commit() {
    let mut groups = build_group(5);
    let commit = assert_multi_remove(&mut groups, 0, &[4, 1, 3]);
    assert_eq!(commit.removed_leaves, vec![1, 3, 4]);
}

// ---- the weakness the multi-remove fixes, and single-remove compatibility ----

#[test]
fn sequential_single_removes_leak_to_later_removed_member() {
    // Baseline for the helper above (it is not vacuous): removing 1 then 2
    // with two single-remove commits seals the FIRST commit's path secrets to
    // leaf 2, which is removed only afterwards.
    let mut groups = build_group(4);
    let first = groups[0].remove_member(1).unwrap();
    assert!(can_open_any(&groups[2], &first));
    groups[2].process_commit(&first).unwrap();
    assert_eq!(
        groups[2].export_secret("e", b"", 32).unwrap(),
        groups[0].export_secret("e", b"", 32).unwrap(),
        "leaf 2 learns the intermediate epoch"
    );
}

#[test]
fn single_remove_member_commit_still_processes() {
    let mut groups = build_group(4);
    let commit = groups[0].remove_member(2).unwrap();
    assert_eq!(commit.removed_leaves, vec![2]);
    let expected = groups[0].export_secret("e", b"", 32).unwrap();
    for j in [1, 3] {
        groups[j].process_commit(&commit).unwrap();
        assert_eq!(groups[j].export_secret("e", b"", 32).unwrap(), expected);
    }
    assert!(!can_open_any(&groups[2], &commit));
    assert!(groups[2].process_commit(&commit).is_err());
}

#[test]
fn remove_members_with_one_leaf_matches_remove_member_shape() {
    let mut groups = build_group(3);
    let commit = assert_multi_remove(&mut groups, 0, &[1]);
    assert_eq!(commit.removed_leaves, vec![1]);
    assert!(commit.added.is_empty());
}

// ---- malformed removal lists: producer side ----

#[test]
fn remove_members_rejects_malformed_lists_with_typed_errors() {
    let mut groups = build_group(4);
    let g = &mut groups[1];
    let epoch = g.epoch();
    let export = g.export_secret("e", b"", 32).unwrap();
    let cases: [(&[u32], RemovalError); 6] = [
        (&[], RemovalError::Empty),
        (&[2, 3, 2], RemovalError::Duplicate(2)),
        (&[1], RemovalError::CommitterLeaf(1)),
        (&[0, 1], RemovalError::CommitterLeaf(1)),
        (&[2, 4], RemovalError::OutOfRange(4)),
        (&[u32::MAX], RemovalError::OutOfRange(u32::MAX)),
    ];
    for (leaves, want) in cases {
        match g.remove_members(leaves) {
            Err(RemoveMembersError::Invalid(got)) => assert_eq!(got, want, "{leaves:?}"),
            other => panic!("{leaves:?}: expected {want:?}, got {other:?}"),
        }
        assert_eq!(
            g.epoch(),
            epoch,
            "a rejected list must not change the group"
        );
        assert_eq!(g.export_secret("e", b"", 32).unwrap(), export);
    }
    // Blank leaf: remove 3 first, then name it again.
    g.remove_members(&[3]).unwrap();
    match g.remove_members(&[2, 3]) {
        Err(RemoveMembersError::Invalid(RemovalError::BlankLeaf(3))) => {}
        other => panic!("expected BlankLeaf(3), got {other:?}"),
    }
    // The conversion into MlsError keeps the reason.
    let err: MlsError = RemoveMembersError::Invalid(RemovalError::Empty).into();
    assert!(matches!(err, MlsError::InvalidGroupState(ref m) if m.contains("no leaves")));
}

// ---- malformed removal lists: receiver side ----

/// Tamper with a valid multi-remove commit's removal list; the receiver must
/// refuse it (typed reason via `check_commit_removals`, `InvalidMessage` from
/// `process_commit`) and stay unchanged.
fn assert_receiver_rejects(mutate: impl Fn(&mut Vec<u32>), want: RemovalError) {
    let mut groups = build_group(5);
    let mut commit = groups[0].remove_members(&[2, 3]).unwrap();
    mutate(&mut commit.removed_leaves);
    // Re-sign with the committer's real key, so only the removal-list check
    // (not the signature check) can refuse it.
    let tbs = TreeKemGroup::commit_tbs(
        &groups[0].group_id,
        commit.epoch,
        commit.committer_leaf,
        &commit.added,
        &commit.removed_leaves,
        &commit.update_path,
        &commit.tree_hash_after,
    )
    .unwrap();
    commit.signature = groups[0].identity.sign(&tbs).unwrap().to_bytes();
    let receiver = &mut groups[1];
    assert_eq!(receiver.check_commit_removals(&commit), Err(want));
    let epoch = receiver.epoch();
    let marker = match want {
        RemovalError::CommitterLeaf(_) => "own committer",
        _ => "invalid commit removal list",
    };
    match receiver.process_commit(&commit) {
        Err(MlsError::InvalidMessage(m)) if m.contains(marker) => {}
        other => panic!("expected InvalidMessage({marker}), got {other:?}"),
    }
    assert_eq!(receiver.epoch(), epoch);
}

#[test]
fn receiver_rejects_duplicate_removed_leaf() {
    assert_receiver_rejects(|l| l.push(2), RemovalError::Duplicate(2));
}

#[test]
fn receiver_rejects_out_of_range_removed_leaf() {
    assert_receiver_rejects(|l| l.push(8), RemovalError::OutOfRange(8));
    assert_receiver_rejects(|l| l.push(u32::MAX), RemovalError::OutOfRange(u32::MAX));
}

#[test]
fn receiver_rejects_blank_removed_leaf() {
    // Leaves 5..=7 are blank in a 5-member group (capacity 8).
    assert_receiver_rejects(|l| l.push(6), RemovalError::BlankLeaf(6));
}

#[test]
fn receiver_rejects_committer_in_removed_leaves() {
    assert_receiver_rejects(|l| l.push(0), RemovalError::CommitterLeaf(0));
}

#[test]
fn receiver_accepts_valid_and_update_commits_in_check() {
    let mut groups = build_group(4);
    let update = groups[0].update().unwrap();
    assert_eq!(groups[1].check_commit_removals(&update), Ok(()));
    groups[1].process_commit(&update).unwrap();
    let multi = groups[0].remove_members(&[2, 3]).unwrap();
    assert_eq!(groups[1].check_commit_removals(&multi), Ok(()));
}

// ---- property test: N members, remove k in 1..=N-2 in one commit ----

fn case_strategy() -> impl Strategy<Value = (usize, usize, Vec<usize>)> {
    (3usize..=7).prop_flat_map(|n| {
        (Just(n), 0..n, proptest::collection::vec(any::<bool>(), n)).prop_map(
            |(n, committer, picks)| {
                let mut removed: Vec<usize> = picks
                    .iter()
                    .enumerate()
                    .filter(|&(i, &p)| p && i != committer)
                    .map(|(i, _)| i)
                    .collect();
                if removed.is_empty() {
                    removed.push((committer + 1) % n);
                }
                removed.truncate(n - 2);
                (n, committer, removed)
            },
        )
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 12, ..ProptestConfig::default() })]

    #[test]
    fn prop_multi_remove_survivors_agree_removed_locked_out(
        (n, committer, removed) in case_strategy()
    ) {
        prop_assume!(!removed.is_empty() && removed.len() <= n - 2);
        run_case(n, committer, &removed);
    }
}

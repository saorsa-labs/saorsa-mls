// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Audit logging tests per SPEC-PROD §8 and SPEC-2 §8
//!
//! Both specifications require:
//! - Log ciphersuite negotiation for audit
//! - Log negotiation artifacts
//!
// Allow deprecated cipher suite IDs - this test file validates backward compatibility
#![allow(deprecated)]

use saorsa_mls::{CipherSuiteId, GroupConfig, MemberId, MemberIdentity, MlsGroup};

/// Test that group creation logs cipher suite selection
#[tokio::test]
async fn test_group_creation_logs_cipher_suite() {
    // This test verifies that creating a group generates an audit log entry
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate(MemberId::generate()).expect("create identity");

    let group = MlsGroup::new(config.clone(), creator)
        .await
        .expect("create group");

    // Verify audit log contains cipher suite selection
    let audit_log = group.get_audit_log();
    assert!(
        !audit_log.is_empty(),
        "Audit log should not be empty after group creation"
    );

    let first_entry = &audit_log[0];
    assert_eq!(first_entry.event_type, "group_created");
    assert_eq!(first_entry.cipher_suite_id, config.cipher_suite);
}

/// Test that audit log records PQC-only vs deprecated status
#[tokio::test]
async fn test_audit_log_records_pqc_status() {
    // Test SPEC-2 PQC-only suite
    let spec2_config = GroupConfig::default()
        .with_cipher_suite(CipherSuiteId::SPEC2_MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65);

    let creator = MemberIdentity::generate(MemberId::generate()).expect("create identity");

    let group = MlsGroup::new(spec2_config, creator)
        .await
        .expect("create group");

    let audit_log = group.get_audit_log();
    let entry = &audit_log[0];

    assert!(
        entry.is_pqc_only,
        "SPEC-2 suite should be marked as PQC-only"
    );
    assert!(
        !entry.is_deprecated,
        "SPEC-2 suite should not be deprecated"
    );
}

/// Test that deprecated suites are logged as such
#[tokio::test]
async fn test_audit_log_marks_deprecated_suites() {
    let deprecated_config = GroupConfig::default()
        .with_cipher_suite(CipherSuiteId::MLS_128_MLKEM768_AES128GCM_SHA256_MLDSA65);

    let suite =
        saorsa_mls::CipherSuite::from_id(CipherSuiteId::MLS_128_MLKEM768_AES128GCM_SHA256_MLDSA65)
            .expect("suite exists");

    let creator =
        MemberIdentity::generate_with_suite(MemberId::generate(), suite).expect("create identity");

    let group = MlsGroup::new(deprecated_config, creator)
        .await
        .expect("create group");

    let audit_log = group.get_audit_log();
    let entry = &audit_log[0];

    assert!(
        entry.is_deprecated,
        "SPEC-PROD suite should be marked as deprecated"
    );
}

/// Test that epoch changes are logged
#[tokio::test]
async fn test_epoch_changes_logged() {
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate(MemberId::generate()).expect("create identity");

    let mut group = MlsGroup::new(config, creator).await.expect("create group");

    let initial_log_size = group.get_audit_log().len();

    // Add member (triggers epoch change)
    let new_member = MemberIdentity::generate(MemberId::generate()).expect("create member");

    group.add_member(&new_member).await.expect("add member");

    let new_log_size = group.get_audit_log().len();
    assert!(
        new_log_size > initial_log_size,
        "Epoch change should add audit log entry"
    );

    // Find the epoch_advanced entry
    let audit_log = group.get_audit_log();
    let epoch_entry = audit_log
        .iter()
        .find(|e| e.event_type == "epoch_advanced")
        .expect("Should have epoch_advanced entry");

    assert_eq!(epoch_entry.old_epoch, Some(0));
    assert_eq!(epoch_entry.new_epoch, Some(1));
}

/// Test that member additions are logged
#[tokio::test]
async fn test_member_additions_logged() {
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate(MemberId::generate()).expect("create identity");

    let mut group = MlsGroup::new(config, creator).await.expect("create group");

    let new_member = MemberIdentity::generate(MemberId::generate()).expect("create member");
    let member_id = new_member.id;

    group.add_member(&new_member).await.expect("add member");

    // Find the member_added entry
    let audit_log = group.get_audit_log();
    let add_entry = audit_log
        .iter()
        .find(|e| e.event_type == "member_added")
        .expect("Should have member_added entry");

    assert_eq!(add_entry.member_id, Some(member_id));
}

/// Test that member removals are logged
#[tokio::test]
async fn test_member_removals_logged() {
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate(MemberId::generate()).expect("create identity");

    let mut group = MlsGroup::new(config, creator).await.expect("create group");

    let new_member = MemberIdentity::generate(MemberId::generate()).expect("create member");
    let member_id = new_member.id;

    group.add_member(&new_member).await.expect("add member");

    group
        .remove_member(&member_id)
        .await
        .expect("remove member");

    // Find the member_removed entry
    let audit_log = group.get_audit_log();
    let remove_entry = audit_log
        .iter()
        .find(|e| e.event_type == "member_removed")
        .expect("Should have member_removed entry");

    assert_eq!(remove_entry.member_id, Some(member_id));
}

/// Test that audit log includes timestamps
#[tokio::test]
async fn test_audit_log_has_timestamps() {
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate(MemberId::generate()).expect("create identity");

    let group = MlsGroup::new(config, creator).await.expect("create group");

    let audit_log = group.get_audit_log();
    let entry = &audit_log[0];

    assert!(
        entry.timestamp.elapsed().unwrap() < std::time::Duration::from_secs(1),
        "Timestamp should be recent"
    );
}

/// Test that audit log can be exported
#[tokio::test]
async fn test_audit_log_export() {
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate(MemberId::generate()).expect("create identity");

    let group = MlsGroup::new(config, creator).await.expect("create group");

    // Export to JSON
    let json = group
        .export_audit_log_json()
        .expect("export should succeed");

    assert!(!json.is_empty(), "Exported JSON should not be empty");
    assert!(
        json.contains("group_created"),
        "JSON should contain event type"
    );
}

/// Test SPEC-2 compliance: audit logging requirement
#[tokio::test]
async fn test_spec2_audit_logging_compliance() {
    // SPEC-2 §8: "Log ciphersuite negotiation for audit"

    let config = GroupConfig::default();
    let creator = MemberIdentity::generate(MemberId::generate()).expect("create identity");

    let group = MlsGroup::new(config.clone(), creator)
        .await
        .expect("create group");

    let audit_log = group.get_audit_log();

    // Must have at least one entry for group creation
    assert!(
        !audit_log.is_empty(),
        "SPEC-2 §8 requires logging ciphersuite negotiation"
    );

    // Must log cipher suite selection
    let has_cipher_suite = audit_log
        .iter()
        .any(|e| e.event_type == "group_created" && e.cipher_suite_id == config.cipher_suite);

    assert!(
        has_cipher_suite,
        "SPEC-2 §8 requires logging cipher suite selection"
    );
}

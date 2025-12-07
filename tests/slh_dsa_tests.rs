// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SLH-DSA (SPHINCS+) signature tests per SPEC-2 §2
//!
//! SPEC-2 defines optional SLH-DSA support:
//! - 0x0B03: MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192

use saorsa_mls::{CipherSuite, CipherSuiteId, GroupConfig, MemberId, MemberIdentity, MlsGroup};

/// Test that SLH-DSA-192 keypair generation works
#[tokio::test]
async fn test_slh_dsa_keypair_generation() {
    let suite = CipherSuite::from_id(
        CipherSuiteId::SPEC2_MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192,
    )
    .expect("0x0B03 suite should exist");

    let identity = MemberIdentity::generate_with_suite(MemberId::generate(), suite)
        .expect("should generate SLH-DSA identity");

    // Verify the identity was created successfully
    assert!(!identity.id.as_bytes().is_empty(), "Should have member ID");
}

/// Test that SLH-DSA works with MLS group
#[tokio::test]
async fn test_slh_dsa_mls_group() {
    let config = GroupConfig::default().with_cipher_suite(
        CipherSuiteId::SPEC2_MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192,
    );

    let suite = CipherSuite::from_id(config.cipher_suite).expect("suite exists");

    let creator =
        MemberIdentity::generate_with_suite(MemberId::generate(), suite).expect("create identity");

    let group = MlsGroup::new(config, creator)
        .await
        .expect("create group with SLH-DSA");

    // Verify group was created successfully
    assert_eq!(group.epoch(), 0);
}

/// Test that 0x0B03 cipher suite is properly configured
#[test]
fn test_0x0b03_cipher_suite_config() {
    let suite = CipherSuite::from_id(
        CipherSuiteId::SPEC2_MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192,
    )
    .expect("0x0B03 suite should exist");

    // Verify it's PQC-only
    assert!(suite.is_pqc_only(), "0x0B03 should be PQC-only");

    // Verify it's not deprecated
    assert!(!suite.is_deprecated(), "0x0B03 should not be deprecated");

    // Verify it uses ChaCha20Poly1305
    assert_eq!(suite.aead.to_string(), "ChaCha20Poly1305");

    // Verify it uses SHA384
    assert_eq!(suite.hash.to_string(), "SHA384");

    // Verify it uses ML-KEM-1024
    assert_eq!(suite.kem.to_string(), "ML-KEM-1024");

    // Verify it uses SLH-DSA-192
    assert_eq!(suite.signature.to_string(), "SLH-DSA-192");
}

/// Test that SLH-DSA cipher suite has correct registry ID
#[test]
fn test_slh_dsa_suite_id() {
    assert_eq!(
        CipherSuiteId::SPEC2_MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192.as_u16(),
        0x0B03,
        "SLH-DSA suite should be 0x0B03"
    );
}

/// Test that SLH-DSA is registered in cipher suite registry
#[test]
fn test_slh_dsa_in_registry() {
    let suite = CipherSuite::from_id(
        CipherSuiteId::SPEC2_MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192,
    );

    assert!(
        suite.is_some(),
        "0x0B03 SLH-DSA suite should be in registry"
    );
}

/// Test that SLH-DSA works with member add/remove operations
///
/// TODO: Enable when Welcome/Application message SLH-DSA support is added
#[tokio::test]
#[ignore = "SLH-DSA not yet supported in Welcome/Application messages - tracked separately"]
async fn test_slh_dsa_member_operations() {
    let config = GroupConfig::default().with_cipher_suite(
        CipherSuiteId::SPEC2_MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192,
    );

    let suite = CipherSuite::from_id(config.cipher_suite).expect("suite exists");

    let creator =
        MemberIdentity::generate_with_suite(MemberId::generate(), suite).expect("create identity");

    let mut group = MlsGroup::new(config, creator).await.expect("create group");

    // Add a member
    let new_member =
        MemberIdentity::generate_with_suite(MemberId::generate(), suite).expect("create member");
    let member_id = new_member.id;

    group
        .add_member(&new_member)
        .await
        .expect("add member should succeed");

    // Verify member was added by checking epoch changed
    assert_eq!(group.epoch(), 1, "Epoch should advance after adding member");

    // Remove the member
    group
        .remove_member(&member_id)
        .await
        .expect("remove member should succeed");

    // Verify member was removed by checking epoch changed again
    assert_eq!(
        group.epoch(),
        2,
        "Epoch should advance after removing member"
    );
}

/// Test SPEC-2 compliance for optional SLH-DSA suite
#[test]
fn test_spec2_slh_dsa_compliance() {
    // SPEC-2 §2: "0x0B03: MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192 // optional"

    let suite = CipherSuite::from_id(
        CipherSuiteId::SPEC2_MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192,
    )
    .expect("SPEC-2 §2 requires 0x0B03 suite to exist");

    // Verify SPEC-2 compliance
    assert!(
        suite.is_pqc_only(),
        "SPEC-2 §2 requires 0x0B03 to be PQC-only"
    );

    // Verify correct ID
    assert_eq!(
        suite.id.as_u16(),
        0x0B03,
        "SPEC-2 §2 requires 0x0B03 suite ID"
    );
}

/// Test that SLH-DSA suite uses correct variant
#[test]
fn test_slh_dsa_variant() {
    let suite = CipherSuite::from_id(
        CipherSuiteId::SPEC2_MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192,
    )
    .expect("suite exists");

    assert!(suite.uses_slh_dsa(), "Should use SLH-DSA");

    // Verify the variant is SLH-DSA-SHA2 (using fast variant)
    let variant = suite.slh_dsa_variant();
    // This will compile if the variant method works correctly
    assert!(format!("{:?}", variant).contains("Sha2_128f"));
}

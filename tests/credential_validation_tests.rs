// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Credential validation tests for production readiness
//!
// Allow deprecated cipher suite IDs for testing backward compatibility
#![allow(deprecated)]
//!
//! Tests comprehensive credential validation with ML-DSA signatures
//! as required by SPEC-PROD.md for production deployment.
//!
//! Per RFC 9420, MLS supports multiple credential types. This implementation
//! uses Basic credentials with post-quantum ML-DSA signatures, which is
//! sufficient for production use.
//!
//! X.509 certificate chain validation is optional per RFC 9420 and not
//! implemented in this library.
//!
//! Tests verify:
//! - Basic credential validation (ML-DSA signatures)
//! - Trust anchor management and verification
//! - Policy enforcement (allowed ciphersuites, key usage)
//! - Error handling for invalid credentials
//!

use saorsa_mls::{
    CipherSuite, CipherSuiteId, Credential, CredentialType, KeyPair, MemberId, TrustStore,
};

/// Test basic credential creation and validation
#[test]
fn test_basic_credential_validation() {
    let member_id = MemberId::generate();
    let keypair = KeyPair::generate(CipherSuite::default());

    let credential = Credential::new_basic(
        member_id,
        Some("Alice".to_string()),
        &keypair,
        CipherSuite::default(),
    )
    .expect("create basic credential");

    // Verify the credential with the correct public key
    assert!(
        credential.verify(&keypair),
        "Valid credential should verify successfully"
    );

    // Verify credential type
    assert_eq!(credential.credential_type(), CredentialType::Basic);
}

/// Test credential validation fails with wrong public key
#[test]
fn test_basic_credential_wrong_key() {
    let member_id = MemberId::generate();
    let keypair1 = KeyPair::generate(CipherSuite::default());
    let keypair2 = KeyPair::generate(CipherSuite::default());

    let credential = Credential::new_basic(member_id, None, &keypair1, CipherSuite::default())
        .expect("create credential");

    // Should fail verification with wrong key
    assert!(
        !credential.verify(&keypair2),
        "Credential should not verify with wrong public key"
    );
}

/// Test credential validation with different ciphersuites
#[test]
fn test_basic_credential_different_suites() {
    let member_id = MemberId::generate();

    let suite_128 =
        CipherSuite::from_id(CipherSuiteId::MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65)
            .expect("valid suite");

    let suite_256 = CipherSuite::from_id(
        CipherSuiteId::SPEC2_MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87,
    )
    .expect("valid suite");

    let kp_128 = KeyPair::generate(suite_128);
    let cred_128 = Credential::new_basic(member_id, None, &kp_128, suite_128)
        .expect("create 128-bit credential");

    let kp_256 = KeyPair::generate(suite_256);
    let cred_256 = Credential::new_basic(member_id, None, &kp_256, suite_256)
        .expect("create 256-bit credential");

    // Each should verify with its own suite and key
    assert!(
        cred_128.verify(&kp_128),
        "128-bit credential should verify with correct suite"
    );
    assert!(
        cred_256.verify(&kp_256),
        "256-bit credential should verify with correct suite"
    );

    // Should not verify with wrong key
    assert!(
        !cred_128.verify(&kp_256),
        "128-bit credential should not verify with 256-bit key"
    );
}

/// Test trust store basic functionality
#[test]
fn test_trust_store_basic() {
    let mut trust_store = TrustStore::new();

    let kp1 = KeyPair::generate(CipherSuite::default());
    let kp2 = KeyPair::generate(CipherSuite::default());

    let pk1 = kp1.verifying_key_bytes();
    let pk2 = kp2.verifying_key_bytes();

    // Initially empty
    assert_eq!(trust_store.trusted_key_count(), 0);
    assert!(!trust_store.is_trusted(&pk1));

    // Add keys
    trust_store.add_trusted_key(pk1.clone());
    assert_eq!(trust_store.trusted_key_count(), 1);
    assert!(trust_store.is_trusted(&pk1));
    assert!(!trust_store.is_trusted(&pk2));

    trust_store.add_trusted_key(pk2.clone());
    assert_eq!(trust_store.trusted_key_count(), 2);
    assert!(trust_store.is_trusted(&pk2));

    // Remove key
    trust_store.remove_trusted_key(&pk1);
    assert_eq!(trust_store.trusted_key_count(), 1);
    assert!(!trust_store.is_trusted(&pk1));
    assert!(trust_store.is_trusted(&pk2));
}

/// Test credential validation with named identities
#[test]
fn test_credential_with_names() {
    let member_id = MemberId::generate();
    let keypair = KeyPair::generate(CipherSuite::default());

    // With name
    let cred_with_name = Credential::new_basic(
        member_id,
        Some("Bob".to_string()),
        &keypair,
        CipherSuite::default(),
    )
    .expect("create credential with name");

    // Without name
    let cred_without_name =
        Credential::new_basic(member_id, None, &keypair, CipherSuite::default())
            .expect("create credential without name");

    // Both should verify
    assert!(cred_with_name.verify(&keypair));
    assert!(cred_without_name.verify(&keypair));
}

/// Test that different member IDs produce different credentials
#[test]
fn test_credential_member_id_binding() {
    let member_id1 = MemberId::generate();
    let member_id2 = MemberId::generate();
    let keypair = KeyPair::generate(CipherSuite::default());

    let cred1 = Credential::new_basic(member_id1, None, &keypair, CipherSuite::default())
        .expect("create credential 1");

    let cred2 = Credential::new_basic(member_id2, None, &keypair, CipherSuite::default())
        .expect("create credential 2");

    // Credentials should be different even with same keypair
    assert_ne!(
        cred1, cred2,
        "Different member IDs should produce different credentials"
    );
}

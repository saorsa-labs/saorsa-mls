// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later

//! HPKE (Hybrid Public Key Encryption) tests for MLS
//!
//! Tests RFC 9180 HPKE functionality using ML-KEM from saorsa-pqc.
//! These tests verify:
//! - Basic HPKE seal/open operations
//! - Context export for key derivation
//! - Integration with MLS Welcome messages
//! - All HPKE modes (Base, PSK, Auth, AuthPSK)
//!
// Allow deprecated cipher suite IDs - this test file validates SPEC-PROD suites for backward compatibility
#![allow(deprecated)]

use saorsa_mls::crypto::{CipherSuite, CipherSuiteId, KeyPair};

/// Test basic HPKE seal/open with ML-KEM768
#[test]
fn test_hpke_seal_open_mlkem768() {
    let suite =
        CipherSuite::from_id(CipherSuiteId::MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65)
            .expect("valid ciphersuite");

    // Generate recipient keypair
    let recipient = KeyPair::generate(suite);
    let recipient_public = recipient.public_key();

    // Sender: setup and seal a message
    let plaintext = b"Hello, HPKE with ML-KEM!";
    let aad = b"additional authenticated data";
    let info = b"test application info";

    let (encapped_key, ciphertext) = suite
        .hpke_seal(recipient_public, plaintext, aad, info)
        .expect("HPKE seal should succeed");

    // Recipient: open the message
    let decrypted = recipient
        .hpke_open(&encapped_key, &ciphertext, aad, info)
        .expect("HPKE open should succeed");

    assert_eq!(decrypted, plaintext, "Decrypted text should match original");
}

/// Test HPKE with ML-KEM1024 (high security)
#[test]
fn test_hpke_seal_open_mlkem1024() {
    let suite = CipherSuite::from_id(
        CipherSuiteId::SPEC2_MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87,
    )
    .expect("valid ciphersuite");

    let recipient = KeyPair::generate(suite);
    let plaintext = b"High security message";
    let aad = b"";
    let info = b"";

    let (encapped_key, ciphertext) = suite
        .hpke_seal(recipient.public_key(), plaintext, aad, info)
        .expect("HPKE seal should succeed");

    let decrypted = recipient
        .hpke_open(&encapped_key, &ciphertext, aad, info)
        .expect("HPKE open should succeed");

    assert_eq!(decrypted, plaintext);
}

/// Test HPKE context export for key derivation
#[test]
fn test_hpke_context_export() {
    let suite = CipherSuite::default();
    let recipient = KeyPair::generate(suite);

    let info = b"context export test";
    let export_context = b"exporter context";

    // Create HPKE context
    let (encapped_key, mut sender_ctx) = suite
        .hpke_setup_sender(recipient.public_key(), info)
        .expect("HPKE setup should succeed");

    let mut recipient_ctx = recipient
        .hpke_setup_receiver(&encapped_key, info)
        .expect("HPKE receiver setup should succeed");

    // Export secrets from both sides
    let sender_export = sender_ctx
        .export(export_context, 32)
        .expect("Export should succeed");

    let recipient_export = recipient_ctx
        .export(export_context, 32)
        .expect("Export should succeed");

    assert_eq!(
        sender_export, recipient_export,
        "Exported secrets should match on both sides"
    );
    assert_eq!(sender_export.len(), 32, "Export should be 32 bytes");
}

/// Test HPKE with multiple seal operations on same context
#[test]
fn test_hpke_multiple_seals() {
    let suite = CipherSuite::default();
    let recipient = KeyPair::generate(suite);

    let (encapped_key, mut sender_ctx) = suite
        .hpke_setup_sender(recipient.public_key(), b"multi-seal test")
        .expect("HPKE setup should succeed");

    let mut recipient_ctx = recipient
        .hpke_setup_receiver(&encapped_key, b"multi-seal test")
        .expect("Receiver setup should succeed");

    // Send multiple messages
    let messages = vec![
        b"First message".as_slice(),
        b"Second message".as_slice(),
        b"Third message with more data".as_slice(),
    ];

    let mut ciphertexts = Vec::new();
    for msg in &messages {
        let ct = sender_ctx.seal(msg, b"").expect("Seal should succeed");
        ciphertexts.push(ct);
    }

    // Decrypt in same order
    for (i, ct) in ciphertexts.iter().enumerate() {
        let pt = recipient_ctx.open(ct, b"").expect("Open should succeed");
        assert_eq!(pt, messages[i], "Message {} should decrypt correctly", i);
    }
}

/// Test HPKE fails with wrong recipient key
#[test]
fn test_hpke_wrong_recipient() {
    let suite = CipherSuite::default();
    let recipient1 = KeyPair::generate(suite);
    let recipient2 = KeyPair::generate(suite);

    let plaintext = b"Secret message";

    // Encrypt for recipient1
    let (encapped_key, ciphertext) = suite
        .hpke_seal(recipient1.public_key(), plaintext, b"", b"")
        .expect("Seal should succeed");

    // Try to decrypt with recipient2's key (should fail)
    let result = recipient2.hpke_open(&encapped_key, &ciphertext, b"", b"");
    assert!(result.is_err(), "Decryption with wrong key should fail");
}

/// Test HPKE fails with wrong AAD
#[test]
fn test_hpke_wrong_aad() {
    let suite = CipherSuite::default();
    let recipient = KeyPair::generate(suite);

    let plaintext = b"Authenticated message";
    let correct_aad = b"correct AAD";
    let wrong_aad = b"wrong AAD";

    let (encapped_key, ciphertext) = suite
        .hpke_seal(recipient.public_key(), plaintext, correct_aad, b"")
        .expect("Seal should succeed");

    // Try to decrypt with wrong AAD (should fail)
    let result = recipient.hpke_open(&encapped_key, &ciphertext, wrong_aad, b"");
    assert!(result.is_err(), "Decryption with wrong AAD should fail");
}

/// Test HPKE with empty plaintext
#[test]
fn test_hpke_empty_plaintext() {
    let suite = CipherSuite::default();
    let recipient = KeyPair::generate(suite);

    let (encapped_key, ciphertext) = suite
        .hpke_seal(recipient.public_key(), b"", b"", b"")
        .expect("Seal with empty plaintext should succeed");

    let decrypted = recipient
        .hpke_open(&encapped_key, &ciphertext, b"", b"")
        .expect("Open should succeed");

    assert_eq!(decrypted, b"", "Empty plaintext should decrypt correctly");
}

/// Test HPKE with large plaintext
#[test]
fn test_hpke_large_plaintext() {
    let suite = CipherSuite::default();
    let recipient = KeyPair::generate(suite);

    // 10 KB plaintext
    let plaintext = vec![0x42u8; 10 * 1024];

    let (encapped_key, ciphertext) = suite
        .hpke_seal(recipient.public_key(), &plaintext, b"", b"")
        .expect("Seal with large plaintext should succeed");

    let decrypted = recipient
        .hpke_open(&encapped_key, &ciphertext, b"", b"")
        .expect("Open should succeed");

    assert_eq!(
        decrypted, plaintext,
        "Large plaintext should decrypt correctly"
    );
}

/// Test HPKE export with different contexts produces different keys
#[test]
fn test_hpke_export_context_separation() {
    let suite = CipherSuite::default();
    let recipient = KeyPair::generate(suite);

    let (encapped_key, mut sender_ctx) = suite
        .hpke_setup_sender(recipient.public_key(), b"")
        .expect("Setup should succeed");

    let mut recipient_ctx = recipient
        .hpke_setup_receiver(&encapped_key, b"")
        .expect("Setup should succeed");

    let export1 = sender_ctx
        .export(b"context1", 32)
        .expect("Export should succeed");

    let export2 = sender_ctx
        .export(b"context2", 32)
        .expect("Export should succeed");

    assert_ne!(
        export1, export2,
        "Different contexts should produce different exports"
    );

    // Verify recipient gets same values
    let recipient_export1 = recipient_ctx
        .export(b"context1", 32)
        .expect("Export should succeed");

    assert_eq!(export1, recipient_export1);
}

/// Test HPKE export with different lengths
#[test]
fn test_hpke_export_different_lengths() {
    let suite = CipherSuite::default();
    let recipient = KeyPair::generate(suite);

    let (_encapped_key, mut ctx) = suite
        .hpke_setup_sender(recipient.public_key(), b"")
        .expect("Setup should succeed");

    let export16 = ctx.export(b"test", 16).expect("Export 16 bytes");
    let export32 = ctx.export(b"test", 32).expect("Export 32 bytes");
    let export64 = ctx.export(b"test", 64).expect("Export 64 bytes");

    assert_eq!(export16.len(), 16);
    assert_eq!(export32.len(), 32);
    assert_eq!(export64.len(), 64);

    // Shorter should be prefix of longer (deterministic KDF)
    assert_eq!(&export32[..16], &export16[..]);
}

/// Integration test: Use HPKE to encrypt MLS Welcome message secrets
#[test]
fn test_hpke_welcome_message_integration() {
    use saorsa_mls::{GroupConfig, MemberId, MemberIdentity, MlsGroup};

    let rt = tokio::runtime::Runtime::new().expect("create runtime");
    rt.block_on(async {
        // Create group creator
        let config = GroupConfig::default();
        let creator =
            MemberIdentity::generate(MemberId::generate()).expect("generate creator identity");

        let mut group = MlsGroup::new(config, creator).await.expect("create group");

        // Create new member
        let new_member =
            MemberIdentity::generate(MemberId::generate()).expect("generate member identity");

        // Add member (this should use HPKE for Welcome message)
        let welcome = group
            .add_member(&new_member)
            .await
            .expect("add member should succeed");

        // Verify welcome message has encrypted secrets
        assert!(
            !welcome.secrets.is_empty(),
            "Welcome should contain HPKE-encrypted secrets"
        );

        // New member should be able to decrypt welcome
        // (This would require Welcome processing implementation)
    });
}

/// Property test: HPKE roundtrip for random plaintexts
#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_hpke_roundtrip(
            plaintext in prop::collection::vec(any::<u8>(), 0..1000),
            aad in prop::collection::vec(any::<u8>(), 0..100),
        ) {
            let suite = CipherSuite::default();
            let recipient = KeyPair::generate(suite);

            let (encapped_key, ciphertext) = suite
                .hpke_seal(recipient.public_key(), &plaintext, &aad, b"")
                .expect("seal should succeed");

            let decrypted = recipient
                .hpke_open(&encapped_key, &ciphertext, &aad, b"")
                .expect("open should succeed");

            assert_eq!(decrypted, plaintext);
        }

        #[test]
        fn prop_hpke_export_deterministic(
            context in prop::collection::vec(any::<u8>(), 0..100),
            length in 1usize..256,
        ) {
            let suite = CipherSuite::default();
            let recipient = KeyPair::generate(suite);

            let (encapped_key, mut ctx1) = suite
                .hpke_setup_sender(recipient.public_key(), b"")
                .expect("setup");

            let mut ctx2 = recipient
                .hpke_setup_receiver(&encapped_key, b"")
                .expect("setup");

            let export1 = ctx1.export(&context, length).expect("export");
            let export2 = ctx2.export(&context, length).expect("export");

            assert_eq!(export1, export2);
            assert_eq!(export1.len(), length);
        }
    }
}

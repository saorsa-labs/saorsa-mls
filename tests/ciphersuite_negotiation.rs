use saorsa_mls::{
    CipherSuite, CipherSuiteId, GroupConfig, MemberId, MemberIdentity, MlsAead, MlsGroup, MlsHash,
    MlsKem, MlsSignature,
};

#[test]
fn default_suite_matches_spec2_pqc_only() {
    let suite = CipherSuite::default();
    // SPEC-2 default: 0x0B01 (ChaCha20Poly1305 + SHA256 + ML-DSA-65)
    assert_eq!(
        suite.id(),
        CipherSuiteId::SPEC2_MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65
    );
    assert_eq!(suite.kem(), MlsKem::MlKem768);
    assert_eq!(suite.signature(), MlsSignature::MlDsa65);
    assert_eq!(suite.aead(), MlsAead::ChaCha20Poly1305);
    assert_eq!(suite.hash(), MlsHash::Sha256);
}

#[test]
fn high_security_suite_is_registered() {
    let suite = CipherSuite::from_id(
        CipherSuiteId::SPEC2_MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87,
    )
    .expect("suite must be registered");
    assert_eq!(suite.kem(), MlsKem::MlKem1024);
    assert_eq!(suite.signature(), MlsSignature::MlDsa87);
    // SPEC-2 suites use ChaCha20Poly1305, not AES-GCM
    assert_eq!(suite.aead(), MlsAead::ChaCha20Poly1305);
    assert_eq!(suite.hash(), MlsHash::Sha512);
}

#[tokio::test]
async fn mls_group_uses_requested_suite() {
    let cipher_suite_id = CipherSuiteId::SPEC2_MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87;
    let config = GroupConfig::default().with_cipher_suite(cipher_suite_id);
    let suite = CipherSuite::from_id(cipher_suite_id).expect("suite must exist");

    let creator = MemberIdentity::generate_with_suite(MemberId::generate(), suite)
        .expect("identity generation should succeed");

    let group = MlsGroup::new(config.clone(), creator)
        .await
        .expect("group creation must succeed");

    assert_eq!(group.cipher_suite().id(), cipher_suite_id);
}

use saorsa_mls::{CipherSuite, CipherSuiteId, GroupConfig, MemberId, MemberIdentity, MlsGroup};
#[tokio::test]
async fn welcome_decapsulation_yields_nonzero_secret() {
    let suite = CipherSuite::from_id(
        CipherSuiteId::SPEC2_MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87,
    )
    .expect("suite");
    let config = GroupConfig::default().with_cipher_suite(suite.id());

    let creator =
        MemberIdentity::generate_with_suite(MemberId::generate(), suite).expect("creator");
    let mut group = MlsGroup::new(config, creator.clone())
        .await
        .expect("group init");

    let new_member =
        MemberIdentity::generate_with_suite(MemberId::generate(), suite).expect("new member");

    let welcome = group.add_member(&new_member).await.expect("welcome");
    let secret_entry = &welcome.secrets[0];

    let path_secret = secret_entry
        .decapsulate_path_secret(&suite, new_member.kem_secret().unwrap())
        .expect("decapsulation");

    assert!(!path_secret.iter().all(|&b| b == 0));
    assert_ne!(path_secret, secret_entry.encrypted_path_secret);
}

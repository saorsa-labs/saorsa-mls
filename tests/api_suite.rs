use saorsa_mls::{CipherSuite, CipherSuiteId, GroupConfig, MemberId, MemberIdentity};

#[test]
fn api_group_new_uses_requested_suite() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(async {
        let suite_id = CipherSuiteId::SPEC2_MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87;
        let suite = CipherSuite::from_id(suite_id).expect("suite registered");

        let creator = MemberIdentity::generate_with_suite(MemberId::generate(), suite)
            .expect("identity generation should succeed");
        let members = vec![creator];

        let config = GroupConfig::default().with_cipher_suite(suite_id);

        let result = saorsa_mls::api::group_new_with_config(&members, config).await;
        assert!(
            result.is_ok(),
            "group creation with explicit suite failed: {result:?}"
        );
    });
}

#[test]
fn api_add_member_rejects_suite_mismatch() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(async {
        let suite_id = CipherSuiteId::SPEC2_MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87;
        let suite = CipherSuite::from_id(suite_id).expect("suite registered");

        let creator = MemberIdentity::generate_with_suite(MemberId::generate(), suite)
            .expect("identity generation should succeed");
        let members = vec![creator.clone()];

        let config = GroupConfig::default().with_cipher_suite(suite_id);
        let group_id = saorsa_mls::api::group_new_with_config(&members, config)
            .await
            .expect("group creation must succeed");

        let mismatched_member =
            MemberIdentity::generate(MemberId::generate()).expect("default suite identity");

        let result = saorsa_mls::api::add_member(&group_id, mismatched_member.clone()).await;

        assert!(
            result.is_err(),
            "adding member with mismatched suite should fail"
        );
    });
}

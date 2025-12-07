use saorsa_mls::{
    AeadCipher, CipherSuite, CipherSuiteId, GroupConfig, KeySchedule, MemberId, MemberIdentity,
    MlsGroup,
};

fn xor_nonce(base_nonce: &[u8], sequence: u64) -> Vec<u8> {
    let mut seq_bytes = [0u8; 12];
    seq_bytes[4..].copy_from_slice(&sequence.to_be_bytes());
    base_nonce
        .iter()
        .zip(seq_bytes.iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

#[tokio::test]
async fn new_member_can_decrypt_message_after_welcome() {
    let suite = CipherSuite::from_id(
        CipherSuiteId::SPEC2_MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87,
    )
    .expect("suite");
    let config = GroupConfig::default().with_cipher_suite(suite.id());

    let creator =
        MemberIdentity::generate_with_suite(MemberId::generate(), suite).expect("creator");
    let mut sender_group = MlsGroup::new(config, creator.clone())
        .await
        .expect("group init");

    let new_member_identity =
        MemberIdentity::generate_with_suite(MemberId::generate(), suite).expect("new member");

    let welcome = sender_group
        .add_member(&new_member_identity)
        .await
        .expect("welcome");

    let plaintext = b"hello post-welcome";
    let ciphertext = sender_group.encrypt_message(plaintext).expect("encrypt");

    let application_secret = welcome.secrets[0]
        .decapsulate_path_secret(&suite, new_member_identity.kem_secret().unwrap())
        .expect("decapsulation");

    // Derive key and nonce exactly as the sender does for this member
    let key_schedule = KeySchedule::new(suite);
    let epoch_bytes = sender_group.current_epoch().to_be_bytes();

    let mut info_key = Vec::new();
    info_key.extend_from_slice(b"mls application key");
    info_key.extend_from_slice(ciphertext.sender.as_bytes());
    let app_key = key_schedule
        .derive_key(
            &epoch_bytes,
            &application_secret,
            &info_key,
            suite.key_size(),
        )
        .expect("derive key");

    let mut info_nonce = Vec::new();
    info_nonce.extend_from_slice(b"mls application nonce");
    info_nonce.extend_from_slice(ciphertext.sender.as_bytes());
    let base_nonce = key_schedule
        .derive_key(
            &epoch_bytes,
            &application_secret,
            &info_nonce,
            suite.nonce_size(),
        )
        .expect("derive nonce");

    let derived_nonce = xor_nonce(&base_nonce, ciphertext.sequence);
    let nonce_size = suite.nonce_size();
    let (nonce_bytes, ciphertext_bytes) = ciphertext.ciphertext.split_at(nonce_size);
    assert_eq!(nonce_bytes, derived_nonce.as_slice());

    let mut aad = Vec::new();
    aad.extend_from_slice(sender_group.group_id().as_bytes());
    aad.extend_from_slice(&ciphertext.epoch.to_be_bytes());
    aad.extend_from_slice(&ciphertext.sequence.to_be_bytes());
    aad.extend_from_slice(ciphertext.sender.as_bytes());

    let cipher = AeadCipher::new(app_key, suite).expect("aead");
    let decrypted = cipher
        .decrypt(nonce_bytes, ciphertext_bytes, &aad)
        .expect("decrypt");

    assert_eq!(decrypted, plaintext);
}

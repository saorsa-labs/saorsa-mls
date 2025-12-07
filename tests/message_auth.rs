use saorsa_mls::{
    CipherSuite, CipherSuiteId, GroupConfig, HandshakeMessage, KeyPair, MemberId, MemberIdentity,
    MlsGroup,
};
use saorsa_pqc::api::{MlDsa, MlDsaPublicKey};

#[tokio::test]
async fn application_message_signature_matches_payload() {
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate(MemberId::generate()).expect("creator");
    let group = MlsGroup::new(config, creator.clone())
        .await
        .expect("group initialization");

    let plaintext = b"test message";
    let message = group.encrypt_message(plaintext).expect("encrypt");

    let ml_dsa = MlDsa::new(group.cipher_suite().ml_dsa_variant());

    // Reconstruct ML-DSA public key from bytes for low-level verification
    let pk_bytes = creator.verifying_key_bytes();
    let public_key = MlDsaPublicKey::from_bytes(group.cipher_suite().ml_dsa_variant(), pk_bytes)
        .expect("reconstruct public key");

    ml_dsa
        .verify(&public_key, &message.ciphertext, &message.signature.0)
        .expect("signature should verify");

    let mut tampered = message.clone();
    tampered.ciphertext[0] ^= 1;
    assert!(!ml_dsa
        .verify(&public_key, &tampered.ciphertext, &tampered.signature.0,)
        .expect("signature verification should succeed"));

    // Decrypt succeeds for untampered message
    let decrypted = group.decrypt_message(&message).expect("decrypt");
    assert_eq!(decrypted, plaintext);

    // Decrypt fails for tampered message (signature mismatch)
    assert!(group.decrypt_message(&tampered).is_err());
}

#[tokio::test]
async fn welcome_message_signature_matches_payload() {
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate(MemberId::generate()).expect("creator");
    let mut group = MlsGroup::new(config, creator.clone())
        .await
        .expect("group initialization");

    let new_member =
        MemberIdentity::generate_with_suite(MemberId::generate(), group.cipher_suite())
            .expect("new member");

    let welcome = group.add_member(&new_member).await.expect("welcome");

    let ml_dsa = MlDsa::new(group.cipher_suite().ml_dsa_variant());

    // Reconstruct ML-DSA public key from bytes for low-level verification
    let pk_bytes = creator.verifying_key_bytes();
    let public_key = MlDsaPublicKey::from_bytes(group.cipher_suite().ml_dsa_variant(), pk_bytes)
        .expect("reconstruct public key");

    // Signature should verify for the untampered group info
    assert!(ml_dsa
        .verify(&public_key, &welcome.group_info, &welcome.signature.0,)
        .expect("verification call"));

    // Tampering the group info should invalidate the signature
    let mut tampered = welcome.clone();
    tampered.group_info[0] ^= 1;
    assert!(!ml_dsa
        .verify(&public_key, &tampered.group_info, &tampered.signature.0,)
        .expect("verification call"));
}

#[test]
fn handshake_message_signature_matches_payload() {
    use saorsa_mls::crypto::SignatureKey;

    let suite = CipherSuite::from_id(
        CipherSuiteId::SPEC2_MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87,
    )
    .expect("suite");
    let keypair = KeyPair::generate(suite);
    let sender = MemberId::generate();
    let content = b"handshake payload".to_vec();

    // Extract ML-DSA keys from the signature key
    let (secret, public) = match &keypair.signature_key {
        SignatureKey::MlDsa { secret, public } => (secret, public),
        _ => panic!("Expected ML-DSA keypair"),
    };

    let message = HandshakeMessage::new_signed(1, sender, content.clone(), secret, suite)
        .expect("signed handshake");

    assert!(message
        .verify_signature(public, suite)
        .expect("verification"));

    let mut tampered = message.clone();
    tampered.content[0] ^= 1;
    assert!(!tampered
        .verify_signature(public, suite)
        .expect("verification"));
}

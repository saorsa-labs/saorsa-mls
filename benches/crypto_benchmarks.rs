use criterion::{criterion_group, criterion_main, Criterion};
use saorsa_mls::*;
use std::hint::black_box;

fn benchmark_key_generation(c: &mut Criterion) {
    c.bench_function("key_generation", |b| {
        b.iter(|| {
            let member_id = black_box(MemberId::generate());
            let _identity = black_box(MemberIdentity::generate(member_id));
        })
    });
}

fn benchmark_encryption(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let group = rt.block_on(async {
        let config = GroupConfig::default();
        let creator_identity = MemberIdentity::generate(MemberId::generate()).unwrap();
        MlsGroup::new(config, creator_identity).await.unwrap()
    });

    c.bench_function("encryption", |b| {
        b.iter(|| {
            let message = black_box(b"Hello, secure group!");
            let _encrypted = black_box(group.encrypt_message(message).unwrap());
        })
    });
}

fn benchmark_decryption(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (group, encrypted) = rt.block_on(async {
        let config = GroupConfig::default();
        let creator_identity = MemberIdentity::generate(MemberId::generate()).unwrap();
        let group = MlsGroup::new(config, creator_identity).await.unwrap();
        let message = b"Hello, secure group!";
        let encrypted = group.encrypt_message(message).unwrap();
        (group, encrypted)
    });

    c.bench_function("decryption", |b| {
        b.iter(|| {
            let _decrypted = black_box(group.decrypt_message(&encrypted).unwrap());
        })
    });
}

fn benchmark_group_operations(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    c.bench_function("group_creation", |b| {
        b.iter(|| {
            rt.block_on(async {
                let config = black_box(GroupConfig::default());
                let creator_identity =
                    black_box(MemberIdentity::generate(MemberId::generate()).unwrap());
                let _group = black_box(MlsGroup::new(config, creator_identity).await.unwrap());
            })
        })
    });
}

criterion_group!(
    benches,
    benchmark_key_generation,
    benchmark_encryption,
    benchmark_decryption,
    benchmark_group_operations
);
criterion_main!(benches);

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::Rng;
use recrypt_compute::crypto480::{encryption::recrypt, signature::ed25519::new_signing_keypair};

// const SIZES: [usize; 7] =

fn benchmarks_by_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("recrypt");

    const SIZES: [usize; 7] = [16, 32, 64, 128, 256, 512, 720];

    // Prepare benchmark data for each size
    for size in SIZES {
        let mut data: Vec<u8> = vec![0u8; size];
        let mut rng = rand::thread_rng();
        rng.fill(&mut data[..]);

        // Keys for encryption benchmark
        let (priv_key1, pub_key1) = recrypt::new_encryption_keypair();
        let signing_keys = new_signing_keypair();

        group.bench_with_input(BenchmarkId::new("encrypt", size), &size, |b, _size| {
            b.iter(|| recrypt::encrypt(&data, &pub_key1, &signing_keys).unwrap())
        });

        // Keys for full cycle benchmark
        let (priv_key2, pub_key2) = recrypt::new_encryption_keypair();

        group.bench_with_input(
            BenchmarkId::new("encrypt_transform_decrypt", size),
            &size,
            |b, &size| {
                b.iter(|| {
                    let encrypted = recrypt::encrypt(&data, &pub_key1, &signing_keys).unwrap();
                    let transform_key =
                        recrypt::new_transform_key(&priv_key1, &pub_key2, &signing_keys);
                    let transformed = recrypt::transform(encrypted, transform_key, &signing_keys);
                    recrypt::decrypt(&transformed, &priv_key2, size).unwrap()
                })
            },
        );
    }

    group.finish();
}

fn benchmark_transform_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("transform");

    let mut data: Vec<u8> = vec![0u8; 44];
    let mut rng = rand::thread_rng();
    rng.fill(&mut data[..]);

    // Generate keys for two parties
    let (priv_key1, pub_key1) = recrypt::new_encryption_keypair();
    let (_priv_key2, pub_key2) = recrypt::new_encryption_keypair();
    let signing_keys = new_signing_keypair();

    // Create initial encrypted value
    let encrypted = recrypt::encrypt(&data, &pub_key1, &signing_keys).unwrap();

    group.bench_function("new_transform_key", |b| {
        b.iter(|| recrypt::new_transform_key(&priv_key1, &pub_key2, &signing_keys));
    });

    group.bench_function("transform", |b| {
        b.iter(|| {
            let transform_key = recrypt::new_transform_key(&priv_key1, &pub_key2, &signing_keys);
            recrypt::transform(encrypted.clone(), transform_key, &signing_keys)
        });
    });
}

criterion_group! {
    name = recrypt;
    config = Criterion::default().sample_size(10); // Reduced sample size due to expensive operations
    targets = benchmarks_by_size, benchmark_transform_overhead
}

criterion_main!(recrypt);

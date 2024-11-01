use compute::crypto::{
    encryption::{aes, recrypt},
    signature::ed25519::new_signing_keypair,
};
use criterion::{criterion_group, criterion_main, Criterion};

fn transform(c: &mut Criterion) {
    let msg = "wHat's A kInG 👑 To a God 🔥";

    // Generate new recrypt keys
    let (priv1, pub1) = recrypt::new_encryption_keypair();
    let (_priv2, pub2) = recrypt::new_encryption_keypair();
    let signing_keys = new_signing_keypair();

    // Generate AES key
    let symkey = aes::AesKey::new();
    let _encrypted_plaintext = symkey.encrypt(msg.as_bytes());

    // Envelope encryption
    let enveloped_key = crate::recrypt::encrypt_aes_key(&symkey, &pub1, &signing_keys);

    c.bench_function("transform_operation", |b| {
        b.iter(|| {
            let transform_key = recrypt::new_transform_key(&priv1, &pub2, &signing_keys);
            let _recrypted_value =
                recrypt::transform(enveloped_key.clone(), transform_key, &signing_keys);
        });
    });
}

criterion_group!(benches, transform);
criterion_main!(benches);

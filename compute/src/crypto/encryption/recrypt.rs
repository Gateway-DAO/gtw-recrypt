use super::aes::AesKey;
use base64::Engine;
use gridiron::fp_480::Monty;
pub use recrypt::api::{
    PrivateKey as RecryptPrivateKey, PublicKey as RecryptPublicKey,
    SigningKeypair as Ed25519Keypair,
};
use recrypt::{
    api::{CryptoOps, KeyGenOps, Plaintext, Recrypt, RecryptErr},
    internal::bytedecoder::BytesDecoder,
};

type EncryptionKeypair = (RecryptPrivateKey, RecryptPublicKey);

pub fn new_encryption_keypair() -> EncryptionKeypair {
    let recrypt = Recrypt::new();
    recrypt.generate_key_pair().unwrap()
}

pub fn encryption_keypair_from_encoding(privkey_enc: &str, pubkey_enc: &str) -> EncryptionKeypair {
    let privkey_buff = base64::engine::general_purpose::STANDARD
        .decode(privkey_enc)
        .unwrap();
    let pubkey_buff = base64::engine::general_purpose::STANDARD
        .decode(pubkey_enc)
        .unwrap();

    return (
        RecryptPrivateKey::new_from_slice(privkey_buff.as_slice()).unwrap(),
        pubkey_from_buffer(pubkey_buff).unwrap(),
    );
}

pub fn pubkey_from_buffer(pubkey_buff: Vec<u8>) -> Result<RecryptPublicKey, RecryptErr> {
    RecryptPublicKey::new_from_slice((
        &pubkey_buff[..Monty::ENCODED_SIZE_BYTES],
        &pubkey_buff[Monty::ENCODED_SIZE_BYTES..],
    ))
}

pub fn new_transform_key(
    from: &RecryptPrivateKey,
    to: &RecryptPublicKey,
    sigpair: &Ed25519Keypair,
) -> recrypt::api::TransformKey {
    let recrypt = Recrypt::new();
    recrypt.generate_transform_key(from, to, sigpair).unwrap()
}

pub fn encrypt(
    data: &[u8],
    public_key: &RecryptPublicKey,
    signing_keypair: &Ed25519Keypair,
) -> Result<recrypt::api::EncryptedValue, RecryptErr> {
    let recrypt = Recrypt::new();

    if data.len() > 384 {
        return Err(recrypt::api::RecryptErr::InputWrongSize("&[u8]", 384));
    }

    let mut plaintext_bytes = [0u8; 384];
    plaintext_bytes[..data.len()].copy_from_slice(data);
    let plaintext = Plaintext::new(plaintext_bytes);

    recrypt.encrypt(&plaintext, public_key, signing_keypair)
}

pub fn decrypt(
    encrypted_value: &recrypt::api::EncryptedValue,
    private_key: &RecryptPrivateKey,
    expected_len: usize,
) -> Result<Vec<u8>, RecryptErr> {
    let recrypt = Recrypt::new();
    let decrypted = recrypt.decrypt(encrypted_value.clone(), private_key)?;

    Ok(decrypted.bytes()[..expected_len].to_vec())
}

/**
 * Specialized functions for AES symmetric key
 */

pub fn encrypt_aes_key(
    aes_key: &AesKey,
    public_key: &RecryptPublicKey,
    signing_keys: &Ed25519Keypair,
) -> recrypt::api::EncryptedValue {
    let recrypt = Recrypt::new();

    // Convert key material to plaintext
    let mut plaintext_bytes = [0u8; 384];
    plaintext_bytes[..44].copy_from_slice(&aes_key.to_bytes());
    let plaintext = Plaintext::new(plaintext_bytes);

    recrypt
        .encrypt(&plaintext, public_key, signing_keys)
        .unwrap()
}

pub fn decrypt_to_aes_key(
    encrypted_value: recrypt::api::EncryptedValue,
    private_key: &RecryptPrivateKey,
) -> AesKey {
    let recrypt = Recrypt::new();
    let decrypted = recrypt.decrypt(encrypted_value, private_key).unwrap();
    AesKey::from_bytes(&decrypted.bytes()[..44].try_into().unwrap())
}

pub fn transform(
    encrypted_value: recrypt::api::EncryptedValue,
    transform_key: recrypt::api::TransformKey,
    signing_keys: &Ed25519Keypair,
) -> recrypt::api::EncryptedValue {
    let recrypt = Recrypt::new();
    recrypt
        .transform(encrypted_value, transform_key, signing_keys)
        .unwrap()
}

#[cfg(test)]
pub mod test {
    use rand::Rng;

    use crate::crypto::signature::ed25519::new_signing_keypair;

    use super::{decrypt, encrypt, new_encryption_keypair, new_transform_key, transform};

    #[test]
    fn test_encrypt_transform_decrypt() {
        let size = 44;
        let mut data: Vec<u8> = vec![0u8; size];
        let mut rng = rand::thread_rng();
        rng.fill(&mut data[..]);

        // Keys for encryption benchmark
        let (priv_key1, pub_key1) = new_encryption_keypair();
        let signing_keys = new_signing_keypair();

        let encrypted = encrypt(&data, &pub_key1, &signing_keys).unwrap();

        // Transform the encryption to second delegatee
        let (priv_key2, pub_key2) = new_encryption_keypair();
        let transform_key = new_transform_key(&priv_key1, &pub_key2, &signing_keys);
        let transformed = transform(encrypted, transform_key, &signing_keys);

        let decrypted = decrypt(&transformed, &priv_key2, size).unwrap();

        assert_eq!(decrypted, data);
    }
}

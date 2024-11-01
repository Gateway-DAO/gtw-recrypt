use recrypt::{
    api::{Ed25519Signature, PublicSigningKey},
    api_480::{EncryptedTempKey, HashedValue, PublicKey},
};

const _EPHEMERAL_PUBLIC_KEY_SIZE: usize = std::mem::size_of::<PublicKey>();
const _PUBLIC_KEY_SIZE: usize = std::mem::size_of::<PublicKey>();
const _ENCRYPTED_TEMP_KEY_SIZE: usize = std::mem::size_of::<EncryptedTempKey>();
const _HASHED_VALUE_SIZE: usize = std::mem::size_of::<HashedValue>();
const _PUBLIC_SIGNING_KEY_SIZE: usize = std::mem::size_of::<PublicSigningKey>();
const _SIGNATURE_SIZE: usize = std::mem::size_of::<Ed25519Signature>();

const _TRANSFORM_KEY_SIZE: usize = _EPHEMERAL_PUBLIC_KEY_SIZE
    + _PUBLIC_KEY_SIZE
    + _ENCRYPTED_TEMP_KEY_SIZE
    + _HASHED_VALUE_SIZE
    + _PUBLIC_SIGNING_KEY_SIZE
    + _SIGNATURE_SIZE;

#[cfg(test)]
mod test {
    use recrypt::api_480::TransformKey;

    #[test]
    fn new_serializable_transform_key() {
        let (privkey, pubkey) = crate::crypto::encryption::recrypt::new_encryption_keypair();
        let signing_keypair = crate::crypto::signature::ed25519::new_signing_keypair();

        let data = "something random";
        let encryption =
            crate::crypto::encryption::recrypt::encrypt(data.as_bytes(), &pubkey, &signing_keypair)
                .unwrap();

        let (privkey2, pubkey2) = crate::crypto::encryption::recrypt::new_encryption_keypair();

        let transformkey = crate::crypto::encryption::recrypt::new_transform_key(
            &privkey,
            &pubkey2,
            &signing_keypair,
        );

        let buffer: Vec<u8> = transformkey.to_bytes();
        let transformkey_recovered = TransformKey::from_bytes(&buffer);

        use crate::crypto::encryption::recrypt::transform;
        let transformed_data = transform(encryption, transformkey_recovered, &signing_keypair);

        let unencryption =
            crate::crypto::encryption::recrypt::decrypt(&transformed_data, &privkey2, data.len())
                .unwrap();

        assert_eq!(String::from_utf8(unencryption).unwrap(), data);
    }
}

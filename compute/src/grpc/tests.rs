use recrypt::{
    api::{Ed25519Signature, PublicSigningKey},
    api_480::{EncryptedTempKey, HashedValue, PublicKey},
};

// use crate::macros::encode_base64;

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
    use base64::Engine;
    use recrypt::api_480::{EncryptedValue, PrivateKey, TransformKey};

    #[test]
    fn generate_test_transform_key() {
        let (privkey, pubkey) = crate::crypto::encryption::recrypt::new_encryption_keypair();
        let signing_keypair = crate::crypto::signature::ed25519::new_signing_keypair();

        println!(
            "===public key===\n{}",
            base64::engine::general_purpose::STANDARD.encode(pubkey.to_bytes())
        );
        println!(
            "===private key===\n{}",
            base64::engine::general_purpose::STANDARD.encode(privkey.bytes())
        );

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

        let transformkey_encoded = transformkey.to_bytes();
        let transformkey_decoded = TransformKey::from_bytes(&transformkey_encoded);

        use crate::crypto::encryption::recrypt::transform;
        let transformed_data =
            transform(encryption.clone(), transformkey_decoded, &signing_keypair);

        let unencryption =
            crate::crypto::encryption::recrypt::decrypt(&transformed_data, &privkey2, data.len())
                .unwrap();

        assert_eq!(String::from_utf8(unencryption).unwrap(), data);

        // print grpc-relevant data
        println!("===data length===\n{}", data.len());
        println!();
        println!(
            "===encryption===\n{}",
            base64::engine::general_purpose::STANDARD.encode(encryption.as_bytes())
        );
        println!();
        println!(
            "===transformation key===\n{}",
            base64::engine::general_purpose::STANDARD.encode(transformkey_encoded)
        );
        println!();
        println!(
            "===decryption key===\n{}",
            base64::engine::general_purpose::STANDARD.encode(privkey2.bytes())
        );
        println!();

        // attempt to reconstruct data from encodings
        let reconstruct_privkey = PrivateKey::new_from_slice(privkey2.bytes()).unwrap();
        let reconstruct_transformed =
            EncryptedValue::from_bytes(transformed_data.as_bytes()).unwrap();

        let decryption = crate::crypto::encryption::recrypt::decrypt(
            &reconstruct_transformed,
            &reconstruct_privkey,
            data.len(),
        )
        .unwrap();
        assert_eq!(String::from_utf8(decryption).unwrap(), data);
    }

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

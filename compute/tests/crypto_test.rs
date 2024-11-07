#[cfg(test)]
mod tests {
    use base64::Engine;
    use recrypt::api::{EncryptedValue, Hashable, PrivateKey, TransformKey};
    use recrypt_compute::crypto::{
        encryption::{aes::AesKey, recrypt::*},
        signature::ed25519::new_signing_keypair,
    };

    #[test]
    fn encode64() {
        let data = "eu falo ingles";

        let encoding = base64::engine::general_purpose::STANDARD.encode(data);
        println!("Encoding: {}\n", encoding);
    }

    #[test]
    fn decode64() {
        let encoding = "ZXUgZmFsbyBpbmdsZXM=";

        let decoding = base64::engine::general_purpose::STANDARD
            .decode(encoding)
            .unwrap();
        println!("Decoding: {}\n", String::from_utf8(decoding).unwrap());
    }

    #[test]
    fn test_new_encryption_keys() {
        let (privkey, pubkey) = new_encryption_keypair();

        println!(
            "===public key===\n{}",
            base64::engine::general_purpose::STANDARD.encode(pubkey.to_bytes())
        );
        println!(
            "===private key===\n{}",
            base64::engine::general_purpose::STANDARD.encode(privkey.to_bytes())
        );
    }

    fn _test_decryption() {
        let privkey_encoding = "";
        let transformed_encoding = "";
        let data_len: usize = 14;

        let privkey_serialized = base64::engine::general_purpose::STANDARD
            .decode(privkey_encoding)
            .unwrap();
        let privkey = PrivateKey::new_from_slice(privkey_serialized.as_slice()).unwrap();

        let transformed_serialized = base64::engine::general_purpose::STANDARD
            .decode(transformed_encoding)
            .unwrap();
        let transformed_data = EncryptedValue::from_bytes(transformed_serialized).unwrap();

        // attempt to reconstruct data from encodings

        let decryption = decrypt(&transformed_data, &privkey, data_len).unwrap();
        println!(
            "===DECRYPTION===\n{}\n",
            String::from_utf8(decryption.clone()).unwrap(),
        );
    }

    #[test]
    fn test_end_to_end() {
        let (privkey, pubkey) = new_encryption_keypair();

        println!(
            "===[delegator] public key===\n{}\n",
            base64::engine::general_purpose::STANDARD.encode(pubkey.to_bytes())
        );
        println!(
            "===[delegator] private key===\n{}\n",
            base64::engine::general_purpose::STANDARD.encode(privkey.to_bytes())
        );

        let signing_keypair = new_signing_keypair();
        let signing_keypair2 = new_signing_keypair();
        let signing_keypair3 = new_signing_keypair();

        let data = "eu falo ingles";
        let encryption = encrypt(data.as_bytes(), &pubkey, &signing_keypair).unwrap();

        println!(
            "===encryption===\n{:?}\n",
            base64::engine::general_purpose::STANDARD.encode(encryption.as_bytes())
        );

        let encryption = EncryptedValue::from_bytes(
            base64::engine::general_purpose::STANDARD
                .decode(base64::engine::general_purpose::STANDARD.encode(encryption.as_bytes()))
                .unwrap(),
        )
        .unwrap();

        let (privkey2, pubkey2) = new_encryption_keypair();
        println!(
            "===[delegatee] public key===\n{}\n",
            base64::engine::general_purpose::STANDARD.encode(pubkey2.to_bytes())
        );
        println!(
            "===[delegatee] private key===\n{}\n",
            base64::engine::general_purpose::STANDARD.encode(privkey2.to_bytes())
        );

        // transform key
        let transformkey = new_transform_key(&privkey, &pubkey2, &signing_keypair2);
        let transformkey_serialized = transformkey.to_bytes();
        let transformkey_encoded =
            base64::engine::general_purpose::STANDARD.encode(transformkey_serialized);
        let transformkey_decoded = TransformKey::from_bytes(
            &base64::engine::general_purpose::STANDARD
                .decode(transformkey_encoded.clone())
                .unwrap(),
        );

        let transformed_data =
            transform(encryption.clone(), transformkey_decoded, &signing_keypair3);

        let unencryption = decrypt(&transformed_data, &privkey2, data.len()).unwrap();
        let unencryption = base64::engine::general_purpose::STANDARD
            .decode(base64::engine::general_purpose::STANDARD.encode(unencryption))
            .unwrap();

        assert_eq!(String::from_utf8(unencryption).unwrap(), data);

        println!("===transformation key===\n{}\n", transformkey_encoded);

        // attempt to reconstruct data from encodings
        let reconstruct_privkey = PrivateKey::new_from_slice(privkey2.bytes()).unwrap();
        let reconstruct_transformed =
            EncryptedValue::from_bytes(transformed_data.as_bytes()).unwrap();

        let decryption =
            decrypt(&reconstruct_transformed, &reconstruct_privkey, data.len()).unwrap();
        println!(
            "===DECRYPTION===\n{}\n",
            String::from_utf8(decryption.clone()).unwrap(),
        );
        assert_eq!(String::from_utf8(decryption).unwrap(), data);
    }

    #[test]
    fn test_aes_key_encryption_and_transform() {
        let msg = "👋🏾 HelloOoO! iS It me You're L👀King Fohr?";

        // Create AES key material
        let aes_key = AesKey::new();
        let encrypted_msg = aes_key.encrypt(msg.as_bytes()).unwrap();

        // Generate recrypt keys for two parties
        let (private_key1, public_key1) = new_encryption_keypair();
        let (private_key2, public_key2) = new_encryption_keypair();
        let signing_keys = new_signing_keypair();

        // Encrypt the AES key material
        let encrypted = encrypt_aes_key(&aes_key, &public_key1, &signing_keys);

        // Generate transform key and transform the encrypted value
        let transform_key = new_transform_key(&private_key1, &public_key2, &signing_keys);
        let transformed = transform(encrypted.clone(), transform_key, &signing_keys);

        // Decrypt both the original and transformed encryptions
        let decrypted_original = decrypt_to_aes_key(encrypted, &private_key1);
        let decrypted_transformed = decrypt_to_aes_key(transformed, &private_key2);

        // Verify both decryptions match the original key material
        assert_eq!(aes_key.to_bytes(), decrypted_original.to_bytes());
        assert_eq!(aes_key.to_bytes(), decrypted_transformed.to_bytes());

        let decryption = decrypted_transformed.decrypt(&encrypted_msg).unwrap();
        let binding = String::from_utf8(decryption).unwrap();
        let decrypted_msg = binding.as_str();
        println!("original_msg:\t{}", msg);
        println!("decrypted_msg:\t{}", decrypted_msg);

        assert_eq!(msg, decrypted_msg);
    }
}

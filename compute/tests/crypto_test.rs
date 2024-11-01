#[cfg(test)]
mod tests {
    use base64::Engine;
    use recrypt::api_480::{EncryptedValue, Hashable, PrivateKey, TransformKey};
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

    #[test]
    fn test_decryption() {
        let privkey_encoding =
            "zwT1hb8eMrXXQ682SNoNuq4bD41rItPhu5//veXZJvvaD3lCjS58H3Ni8pQdw1p9NPb3nby1x65Dqg01";
        let transformed_encoding = "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";
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

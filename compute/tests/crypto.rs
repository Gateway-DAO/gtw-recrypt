#[cfg(test)]
mod tests {
    use compute::crypto::{
        encryption::{
            aes::AesKey,
            recrypt::{self, decrypt_to_aes_key, transform},
        },
        signature::ed25519::new_signing_keypair,
    };

    #[test]
    fn test_aes_key_encryption_and_transform() {
        let msg = "👋🏾 HelloOoO! iS It me You're L👀King Fohr?";

        // Create AES key material
        let aes_key = AesKey::new();
        let encrypted_msg = aes_key.encrypt(msg.as_bytes()).unwrap();

        // Generate recrypt keys for two parties
        let (private_key1, public_key1) = recrypt::new_encryption_keypair();
        let (private_key2, public_key2) = recrypt::new_encryption_keypair();
        let signing_keys = new_signing_keypair();

        // Encrypt the AES key material
        let encrypted = recrypt::encrypt_aes_key(&aes_key, &public_key1, &signing_keys);

        // Generate transform key and transform the encrypted value
        let transform_key = recrypt::new_transform_key(&private_key1, &public_key2, &signing_keys);
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

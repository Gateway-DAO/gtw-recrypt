pub mod signature {
    pub mod ed25519 {
        use recrypt::{
            api::SigningKeypair as Ed25519Keypair,
            api_480::{Ed25519Ops, Recrypt480},
        };

        pub fn new_signing_keypair() -> Ed25519Keypair {
            let recrypt = Recrypt480::new();
            recrypt.generate_ed25519_key_pair()
        }
    }
}

pub mod encryption {
    pub mod aes {
        use aes_gcm::{
            aead::{rand_core::RngCore, Aead, OsRng},
            Aes256Gcm, Error, Key, KeyInit, Nonce,
        };

        /**
         *
         */
        pub struct AesKey {
            key: [u8; 32],   // AES-256 key
            nonce: [u8; 12], // Standard nonce size for AES-GCM
        }

        impl AesKey {
            pub fn new() -> Self {
                let mut key = [0u8; 32];
                let mut nonce = [0u8; 12];
                OsRng.fill_bytes(&mut key);
                OsRng.fill_bytes(&mut nonce);
                Self { key, nonce }
            }

            pub fn to_bytes(&self) -> [u8; 44] {
                let mut result = [0u8; 44];
                result[..32].copy_from_slice(&self.key);
                result[32..].copy_from_slice(&self.nonce);
                result
            }

            pub fn from_bytes(bytes: &[u8; 44]) -> Self {
                let mut key = [0u8; 32];
                let mut nonce = [0u8; 12];
                key.copy_from_slice(&bytes[..32]);
                nonce.copy_from_slice(&bytes[32..44]);
                Self { key, nonce }
            }

            pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
                cipher.encrypt(Nonce::from_slice(&self.nonce), plaintext)
            }

            pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
                cipher.decrypt(Nonce::from_slice(&self.nonce), ciphertext)
            }

            pub fn new_with_nonce(nonce: [u8; 12]) -> Self {
                let mut key = [0u8; 32];
                OsRng.fill_bytes(&mut key);
                Self { key, nonce }
            }

            pub fn from_parts(key: [u8; 32], nonce: [u8; 12]) -> Self {
                Self { key, nonce }
            }
        }

        #[cfg(test)]
        mod test {
            use crate::crypto::encryption::aes::AesKey;

            #[test]
            fn aes_encryption() {
                let msg = "wHat's A kInG 👑 To a God 🔥";

                let original_key_material = AesKey::new();
                let encrypted_msg = original_key_material.encrypt(msg.as_bytes()).unwrap();

                assert_eq!(
                    msg.as_bytes().to_vec(),
                    original_key_material
                        .decrypt(encrypted_msg.as_slice())
                        .unwrap()
                )
            }
        }
    }

    pub mod recrypt {
        use super::aes::AesKey;
        pub use recrypt::api_480::{
            PrivateKey as RecryptPrivateKey, PublicKey as RecryptPublicKey,
            SigningKeypair as Ed25519Keypair,
        };
        use recrypt::{
            api::RecryptErr,
            api_480::{CryptoOps, KeyGenOps, Plaintext, Recrypt480},
        };

        pub fn new_encryption_keypair() -> (RecryptPrivateKey, RecryptPublicKey) {
            let recrypt = Recrypt480::new();
            recrypt.generate_key_pair().unwrap()
        }

        pub fn new_transform_key(
            from: &RecryptPrivateKey,
            to: &RecryptPublicKey,
            sigpair: &Ed25519Keypair,
        ) -> recrypt::api_480::TransformKey {
            let recrypt = Recrypt480::new();
            recrypt.generate_transform_key(from, to, sigpair).unwrap()
        }

        pub fn encrypt(
            data: &[u8],
            public_key: &RecryptPublicKey,
            signing_keypair: &Ed25519Keypair,
        ) -> Result<recrypt::api_480::EncryptedValue, RecryptErr> {
            let recrypt = Recrypt480::new();

            if data.len() > 720 {
                return Err(recrypt::api::RecryptErr::InputWrongSize("&[u8]", 720));
            }

            let mut plaintext_bytes = [0u8; 720];
            plaintext_bytes[..data.len()].copy_from_slice(data);
            let plaintext = Plaintext::new(plaintext_bytes);

            recrypt.encrypt(&plaintext, public_key, signing_keypair)
        }

        pub fn decrypt(
            encrypted_value: &recrypt::api_480::EncryptedValue,
            private_key: &RecryptPrivateKey,
            expected_len: usize,
        ) -> Result<Vec<u8>, RecryptErr> {
            let recrypt = Recrypt480::new();
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
        ) -> recrypt::api_480::EncryptedValue {
            let recrypt = Recrypt480::new();

            // Convert key material to plaintext
            let mut plaintext_bytes = [0u8; 720];
            plaintext_bytes[..44].copy_from_slice(&aes_key.to_bytes());
            let plaintext = Plaintext::new(plaintext_bytes);

            recrypt
                .encrypt(&plaintext, public_key, signing_keys)
                .unwrap()
        }

        pub fn decrypt_to_aes_key(
            encrypted_value: recrypt::api_480::EncryptedValue,
            private_key: &RecryptPrivateKey,
        ) -> AesKey {
            let recrypt = Recrypt480::new();
            let decrypted = recrypt.decrypt(encrypted_value, private_key).unwrap();
            AesKey::from_bytes(&decrypted.bytes()[..44].try_into().unwrap())
        }

        pub fn transform(
            encrypted_value: recrypt::api_480::EncryptedValue,
            transform_key: recrypt::api_480::TransformKey,
            signing_keys: &Ed25519Keypair,
        ) -> recrypt::api_480::EncryptedValue {
            let recrypt = Recrypt480::new();
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
    }
}

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
